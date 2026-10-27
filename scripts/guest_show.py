"""Run STRICTLY READ-ONLY commands inside guest operating systems of inventory VMs (machines table), in parallel.

Usage: cfn guest-show [NAME|HOSTNAME|IP ...] [--match GLOB] [--os windows|linux] [--role R] [--cluster C] [--all]
           (-c CMD ... | --preset os|network|disk|services|listening|time ...) [--out] [--grep REGEX ...] [--quiet] [--timeout 30] [--workers 16]

Linux machines (mgmt_protocol ssh) use paramiko exec_command (no sudo, no pty).
Windows machines (mgmt_protocol winrm) use pywinrm run_ps (PowerShell); port 5986 -> https.
Credentials: NET_<credential_ref>_USERNAME / _PASSWORD (linux may use NET_<REF>_SSH_KEY [+ _SSH_KEY_PASSPHRASE]).
Env: WINRM_TRANSPORT (default ntlm), WINRM_CERT_VALIDATION (default ignore for https; set 'validate' to verify).

Every command is checked against the allowlists below BEFORE any connection is made; anything else is rejected.
Selection: positional names / --match / --all choose candidates; --os / --role / --cluster narrow them
(if only narrowing filters are given, all machines with the selected status are candidates).
"""
import argparse
import fnmatch
import json
import os
import posixpath
import re
import shlex
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor

import netlib
from netlib import ROOT

# ----------------------------------------------------------------------------------------------
# Presets (read-only bundles). Every entry must pass readonly_problem() for its OS (checked in tests).
# ----------------------------------------------------------------------------------------------
PRESETS = {
    "os": {
        "linux": ["cat /etc/os-release", "uname -r", "uptime"],
        "windows": ["Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime"],
    },
    "network": {
        "linux": ["ip -br addr", "ip route", "cat /etc/resolv.conf"],
        "windows": ["Get-NetIPConfiguration", "Get-DnsClientServerAddress", "Get-NetRoute -AddressFamily IPv4"],
    },
    "disk": {
        "linux": ["df -hT", "lsblk"],
        "windows": ["Get-Volume", "Get-Disk"],
    },
    "services": {
        "linux": ["systemctl list-units --type=service --state=failed --no-pager"],
        "windows": ["Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'}"],
    },
    "listening": {
        "linux": ["ss -tulpn"],
        "windows": ["Get-NetTCPConnection -State Listen"],
    },
    "time": {
        "linux": ["timedatectl", "chronyc tracking"],
        "windows": ["w32tm /query /status"],
    },
}

# ----------------------------------------------------------------------------------------------
# LINUX allowlist data
# ----------------------------------------------------------------------------------------------
LIN_FIRST_CMDS = {  # command -> note; each has a validator in LIN_CHECKS
    "cat", "head", "tail", "grep", "ls", "uname", "uptime", "hostname", "hostnamectl", "ip", "ss", "netstat",
    "df", "free", "lsblk", "mount", "ps", "top", "systemctl", "journalctl", "timedatectl", "chronyc", "rpm",
    "dpkg", "dmesg", "lscpu", "lspci", "ethtool", "id", "whoami", "w", "last", "date",
}
LIN_PIPE_CMDS = {"grep", "head", "tail", "wc", "sort", "uniq", "cut", "column"}  # allowed after a '|'
LIN_FORBIDDEN_CHARS = (";", "&&", "||", ">", "<", "`", "$(", "\n", "\r")
LIN_SENSITIVE_PATH = re.compile(
    r"(^|/)(g?shadow-?|master\.passwd|id_\w+|[^/]*\.(pem|key|p12|pfx|jks|keystore)|[^/]*_key|\.ssh|private|"
    r"\.netrc|\.pgpass|\.env|\.bash_history|\.git-credentials|credentials?|environ)(/|$)|^/root(/|$)")
LIN_IP_OPTS = {"-br", "-brief", "-s", "-stats", "-statistics", "-ss", "-d", "-details", "-4", "-6", "-o", "-oneline",
               "-j", "-json", "-p", "-pretty", "-c", "-color", "-h", "-human", "-human-readable"}
LIN_IP_OBJECTS = {"addr", "address", "a", "route", "r", "link", "l", "neigh", "neighbor", "neighbour", "n"}
LIN_IP_VERBS = {"show", "list", "ls", "lst", "get", "dev"}
LIN_IP_MUTATING = {"add", "del", "delete", "set", "flush", "change", "replace", "append", "save", "restore",
                   "prepend", "exec", "batch", "annotate", "learn", "update"}
LIN_SYSTEMCTL_SUBS = {"status", "is-active", "is-enabled", "list-units", "list-unit-files", "show"}
LIN_SYSTEMCTL_FLAGS = {"--no-pager", "--no-legend", "--failed", "--all", "-a", "-l", "--full", "--plain", "--value",
                       "--no-ask-password", "--system"}
LIN_SYSTEMCTL_ARG_FLAGS = {"-t", "--type", "--state", "-p", "--property", "-n", "--lines", "-o", "--output"}
LIN_JOURNAL_BAD = ("--vacuum", "--rotate", "--flush", "--sync", "--relinquish-var", "--smart-relinquish-var",
                   "--setup-keys", "--update-catalog", "--follow", "--verify")
LIN_CHRONYC_SUBS = {"tracking", "sources", "sourcestats"}
LIN_TIMEDATECTL_SUBS = {"status", "show", "timesync-status", "show-timesync"}
LIN_HOSTNAME_FLAGS = {"-f", "-s", "-d", "-i", "-I", "-A", "-a", "-y", "--fqdn", "--short", "--domain",
                      "--ip-address", "--all-ip-addresses", "--all-fqdns", "--alias", "--yp", "--nis"}
LIN_HOSTNAMECTL_ARGS = {"status", "--static", "--transient", "--pretty"}
LIN_DATE_FLAGS = {"-u", "-R", "--utc", "--universal", "--rfc-email"}
LIN_DMESG_BAD_SHORT = set("cCDEnwW")
LIN_DMESG_BAD_LONG = ("--clear", "--read-clear", "--console-", "--follow", "--buffer-size", "--color=")  # color ok but unneeded
LIN_ETHTOOL_FLAGS = {"-i", "-S", "-k", "--driver", "--statistics", "--show-features"}
LIN_SORT_BAD_LONG = ("--output", "--compress-program", "--files0-from", "--temporary-directory")
LIN_SS_BAD_SHORT = set("KDFEN")
LIN_SS_BAD_LONG = ("--kill", "--diag", "--filter", "--events", "--net")
LIN_ROOT_WORDS = {"sudo", "su", "doas", "pkexec"}

# ----------------------------------------------------------------------------------------------
# WINDOWS (PowerShell) allowlist data
# ----------------------------------------------------------------------------------------------
WIN_FORBIDDEN_CHARS = ("\n", "\r", ";", ">", "<", "`", "$(", "::")
WIN_FORBIDDEN_RE = re.compile(
    r"\binvoke-expression\b|\biex\b|\binvoke-command\b|\bstart-process\b|-enc(odedcommand)?\b|\[scriptblock\]|"
    r"\.invoke\(|\bcmd(\.exe)?\s+/[ck]\b|\bpowershell(\.exe)?\b|\bpwsh\b", re.IGNORECASE)
WIN_CMDLET_ALLOW = {  # verb -> None (any noun) or set of lower-case allowed full cmdlet names
    "get": None,
    "select": {"select-object", "select-string"},
    "where": {"where-object"},
    "sort": {"sort-object"},
    "format": {"format-table", "format-list", "format-wide", "format-custom"},
    "measure": {"measure-object"},
    "out": {"out-string"},
    "convertto": {"convertto-json", "convertto-csv"},
    "test": {"test-netconnection", "test-connection", "test-path"},
    "resolve": {"resolve-dnsname"},
}
WIN_DENY_CMDLETS = {"get-credential", "get-secret", "get-secretinfo", "get-clipboard"}
WIN_DENY_PARAMS = {"-wait", "-credential"}
WIN_COMPARE_OPS = r"(?:i|c)?(?:eq|ne|gt|lt|ge|le|like|notlike|match|notmatch|contains|notcontains)"
_WIN_ATOM = (r"\$_\.[A-Za-z_]\w*\s+-" + WIN_COMPARE_OPS +
             r"\s+(?:'[^'`$()]*'|\"[^\"`$()]*\"|-?\d+(?:\.\d+)?|\$true|\$false|\$null)")
WIN_BLOCK_RE = re.compile(rf"\s*{_WIN_ATOM}(?:\s+-(?:and|or)\s+{_WIN_ATOM})*\s*")
WIN_NETSTAT_LETTERS = set("anobres")
WIN_SIMPLE_NAME = re.compile(r"[A-Za-z0-9._:-]+")


# ----------------------------------------------------------------------------------------------
# shared string helpers
# ----------------------------------------------------------------------------------------------
def _strip_quoted(s, single_only=False):
    """Return s with quoted spans removed (so operators inside quotes are not seen)."""
    out, q = [], None
    for ch in s:
        if q:
            if ch == q:
                q = None
        elif ch == "'" or (ch == '"' and not single_only):
            q = ch
        else:
            out.append(ch)
    return "".join(out)


def _split_pipes(s, braces=False):
    """Split on '|' that is outside quotes (and outside {} when braces=True)."""
    parts, cur, q, depth = [], [], None, 0
    for ch in s:
        if q:
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif braces and ch == "{":
            depth += 1
        elif braces and ch == "}":
            depth -= 1
        elif ch == "|" and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))
    return parts


def _short_letters(tok):
    return set(tok[1:]) if re.fullmatch(r"-[A-Za-z0-9]+", tok) else set()


def _flag_problem(args, short_bad="", long_bad=()):
    for t in args:
        if t.startswith("--"):
            if any(t.split("=")[0].startswith(b.rstrip("=")) and t.startswith(b) for b in long_bad):
                return f"flag {t} not allowed"
        elif _short_letters(t) & set(short_bad):
            return f"flag {t} not allowed"
    return None


def _path_problem(args):
    for t in args:
        if t.startswith("-") or "/" not in t and not t.startswith("~"):
            continue
        if LIN_SENSITIVE_PATH.search(posixpath.normpath(t)):
            return f"path {t} is sensitive"
    return None


# ----------------------------------------------------------------------------------------------
# LINUX validators: each takes the arg list (after the command name) and returns a problem or None
# ----------------------------------------------------------------------------------------------
def _l_cat(a):
    for t in a:
        if t.startswith("-"):
            if not _short_letters(t) <= set("nbsAETv"):
                return f"flag {t} not allowed"
        elif any(c in t for c in "*?[$~") or t.startswith("-"):
            return "cat takes plain file paths only (no globs/variables)"
    return _path_problem(a)


def _l_follow_free(a):  # head / tail
    return _flag_problem(a, "fF", ("--follow", "--pid")) or _path_problem(a)


def _l_grep(a):
    if any(t == "recurse" for t in a):
        return "recursive grep not allowed"
    return _flag_problem(a, "rR", ("--recursive", "--dereference-recursive", "--directories=recurse")) or _path_problem(a)


def _l_any(a):
    return _path_problem(a)


def _l_bare(a):
    return "takes no arguments" if a else None


def _l_hostname(a):
    return next((f"argument {t} not allowed" for t in a if t not in LIN_HOSTNAME_FLAGS), None)


def _l_hostnamectl(a):
    return next((f"argument {t} not allowed" for t in a if t not in LIN_HOSTNAMECTL_ARGS), None)


def _l_date(a):
    ok = lambda t: t in LIN_DATE_FLAGS or t.startswith(("+", "-I", "--iso-8601"))
    return next((f"argument {t} not allowed (no setting the clock)" for t in a if not ok(t)), None)


def _l_ss(a):
    return _flag_problem(a, LIN_SS_BAD_SHORT, LIN_SS_BAD_LONG)


def _l_top(a):
    return None if "".join(a) in {"-bn1", "-b-n1", "-n1-b", "-bn1-w"} and "-w" not in a else "only 'top -bn1' is allowed"


def _l_ip(a):
    rest = list(a)
    while rest and rest[0].startswith("-"):
        if rest[0] not in LIN_IP_OPTS:
            return f"ip option {rest[0]} not allowed"
        rest.pop(0)
    if not rest or rest[0].lower() not in LIN_IP_OBJECTS:
        return "ip: only addr|route|link|neigh queries allowed"
    tail = [t.lower() for t in rest[1:]]
    if any(t in LIN_IP_MUTATING for t in tail):
        return "ip: mutating verb not allowed"
    if tail and tail[0] not in LIN_IP_VERBS:
        return "ip: only show/list/get forms allowed"
    return None


def _l_systemctl(a):
    sub, i = None, 0
    while i < len(a):
        t = a[i]
        if t.startswith("-"):
            name = t.split("=")[0]
            if name in LIN_SYSTEMCTL_ARG_FLAGS:
                i += 1 if "=" in t else 2
                continue
            if t not in LIN_SYSTEMCTL_FLAGS:
                return f"systemctl flag {t} not allowed"
        elif sub is None:
            sub = t
        elif not re.fullmatch(r"[\w@.:*?\[\]\\-]+", t):
            return f"odd systemctl argument {t}"
        i += 1
    return None if sub in LIN_SYSTEMCTL_SUBS else "systemctl: only status|is-active|is-enabled|list-units|list-unit-files|show"


def _l_journalctl(a):
    for t in a:
        if t.startswith("--") and t.startswith(LIN_JOURNAL_BAD):
            return f"journalctl flag {t} not allowed"
    return _flag_problem(a, "f")


def _l_timedatectl(a):
    return None if not a or (len(a) == 1 and a[0] in LIN_TIMEDATECTL_SUBS) else "timedatectl: bare, status or show only"


def _l_chronyc(a):
    a = [t for t in a if t not in ("-n", "-c")]
    return None if len(a) == 1 and a[0] in LIN_CHRONYC_SUBS else "chronyc: tracking|sources|sourcestats only"


def _l_rpm(a):
    if not a or not (re.fullmatch(r"-q\w*", a[0]) or a[0].startswith("--query")):
        return "rpm: query (-q*) only"
    bad = ("-e", "--erase", "--install", "--upgrade", "--freshen", "--setperms", "--setugids", "--rebuilddb",
           "--import", "--initdb", "--restore", "-U", "-F")
    return next((f"rpm flag {t} not allowed" for t in a if t in bad), None)


def _l_dpkg(a):
    return None if a and a[0] in ("-l", "--list") and all(re.fullmatch(r"[\w.+*?:-]+", t) for t in a[1:]) else "dpkg: -l only"


def _l_dmesg(a):
    for t in a:
        if t.startswith("--"):
            if t.startswith(LIN_DMESG_BAD_LONG[:-1]):
                return f"dmesg flag {t} not allowed"
        elif _short_letters(t) & LIN_DMESG_BAD_SHORT:
            return f"dmesg flag {t} not allowed"
    return None


def _l_ethtool(a):
    iface = lambda t: re.fullmatch(r"[A-Za-z0-9_.:@][A-Za-z0-9_.:@-]*", t)
    if len(a) == 1 and iface(a[0]):
        return None
    if len(a) == 2 and a[0] in LIN_ETHTOOL_FLAGS and iface(a[1]):
        return None
    return "ethtool: only 'ethtool IFACE' or 'ethtool -i|-S|-k IFACE'"


LIN_CHECKS = {
    "cat": _l_cat, "head": _l_follow_free, "tail": _l_follow_free, "grep": _l_grep, "ls": _l_any,
    "uname": _l_any, "uptime": _l_any, "hostname": _l_hostname, "hostnamectl": _l_hostnamectl, "ip": _l_ip,
    "ss": _l_ss, "netstat": _l_any, "df": _l_any, "free": _l_any, "lsblk": _l_any, "mount": _l_bare, "ps": _l_any,
    "top": _l_top, "systemctl": _l_systemctl, "journalctl": _l_journalctl, "timedatectl": _l_timedatectl,
    "chronyc": _l_chronyc, "rpm": _l_rpm, "dpkg": _l_dpkg, "dmesg": _l_dmesg, "lscpu": _l_any, "lspci": _l_any,
    "ethtool": _l_ethtool, "id": _l_any, "whoami": _l_bare, "w": _l_any, "last": _l_any, "date": _l_date,
}
assert set(LIN_CHECKS) == LIN_FIRST_CMDS


def _pipe_stage_problem(cmd, a):
    if cmd not in LIN_PIPE_CMDS:
        return f"'{cmd}' not allowed after a pipe (only {', '.join(sorted(LIN_PIPE_CMDS))})"
    if cmd == "sort":
        return _flag_problem(a, "o", LIN_SORT_BAD_LONG)
    if cmd in ("head", "tail"):
        return _flag_problem(a, "fF", ("--follow",))
    if cmd == "grep":
        return _l_grep(a)
    return _path_problem(a)


def _linux_problem(cmd):
    if any(x in cmd for x in LIN_FORBIDDEN_CHARS):
        return "contains a forbidden shell operator (; && || > < ` $( newline)"
    bare = _strip_quoted(cmd)
    if "&" in bare:
        return "contains '&'"
    if "$" in _strip_quoted(cmd, single_only=True):
        return "variable/command expansion ($) not allowed"
    if any(w in LIN_ROOT_WORDS for w in re.split(r"[\s|]+", bare)):
        return "sudo/su not allowed"
    for n, seg in enumerate(_split_pipes(cmd)):
        try:
            toks = shlex.split(seg)
        except ValueError as e:
            return f"unparseable quoting ({e})"
        if not toks:
            return "empty pipeline segment"
        name, a = toks[0], toks[1:]
        if n == 0:
            if name not in LIN_CHECKS:
                return f"'{name}' is not in the Linux read-only allowlist"
            p = LIN_CHECKS[name](a)
        else:
            p = _pipe_stage_problem(name, a)
        if p:
            return f"{name}: {p}"
    return None


# ----------------------------------------------------------------------------------------------
# WINDOWS validators
# ----------------------------------------------------------------------------------------------
def _w_ipconfig(a):
    return None if not a or [t.lower() for t in a] == ["/all"] else "ipconfig: bare or /all only"


def _w_netstat(a):
    for t in a:
        if not re.fullmatch(r"-[a-z]+", t) or not set(t[1:]) <= WIN_NETSTAT_LETTERS:
            return "netstat: flags -a -n -o -b -r -e -s only"
    return None


def _w_w32tm(a):
    return None if a and a[0].lower() == "/query" else "w32tm: /query only"


def _w_nslookup(a):
    ok = 1 <= len(a) <= 2 and all(WIN_SIMPLE_NAME.fullmatch(t) and not t.startswith("-") for t in a)
    return None if ok else "nslookup: 1-2 plain names required (bare nslookup is interactive)"


WIN_EXE_CHECKS = {  # non-cmdlet first tokens (lower-case)
    "ipconfig": _w_ipconfig,
    "hostname": lambda a: "takes no arguments" if a else None,
    "whoami": lambda a: None if not a or [t.lower() for t in a] == ["/all"] else "whoami: bare or /all only",
    "systeminfo": lambda a: "takes no arguments" if a else None,
    "netstat": _w_netstat,
    "w32tm": _w_w32tm,
    "route": lambda a: None if [t.lower() for t in a] == ["print"] else "route: print only",
    "nslookup": _w_nslookup,
    "gpresult": lambda a: None if [t.lower() for t in a] == ["/r"] else "gpresult: /r only",
    "quser": lambda a: "takes no arguments" if a else None,
}
WIN_PRESET_TEXTS = {c for v in PRESETS.values() for c in v["windows"]}


def _windows_problem(cmd):
    c = cmd.strip()
    if c in WIN_PRESET_TEXTS:
        return None
    if any(x in cmd for x in WIN_FORBIDDEN_CHARS):
        return "contains a forbidden operator (newline ; > < ` $( ::)"
    m = WIN_FORBIDDEN_RE.search(cmd)
    if m:
        return f"forbidden construct '{m.group(0)}'"
    bare = _strip_quoted(cmd)
    if "&" in bare:
        return "contains '&'"
    # script blocks: only simple $_.Prop -op value comparisons, only inside Where-Object
    blocks = re.findall(r"\{([^{}]*)\}", bare if "{" in bare else "")
    work = cmd
    for blk in re.findall(r"\{([^{}]*)\}", cmd):
        if not WIN_BLOCK_RE.fullmatch(blk):
            return "script block must contain only $_.Prop -op value comparisons joined by -and/-or"
    unq = re.sub(r"\{[^{}]*\}", "", _strip_quoted(work))
    if any(ch in unq for ch in "{}[]()@=$"):
        # '$' allowed only as part of the vetted blocks (already removed from unq)
        return "contains braces/brackets/parentheses/assignment/variable syntax outside a vetted comparison block"
    del blocks
    for n, seg in enumerate(_split_pipes(cmd, braces=True)):
        seg = seg.strip()
        if not seg:
            return "empty pipeline segment"
        try:
            toks = shlex.split(re.sub(r"\{[^{}]*\}", "BLOCK", seg), posix=False)
        except ValueError as e:
            return f"unparseable quoting ({e})"
        name, a = toks[0], toks[1:]
        low = name.lower()
        if "{" in seg and low != "where-object":
            return "script blocks are only allowed in Where-Object"
        if re.fullmatch(r"[A-Za-z]+-[A-Za-z0-9]+", name):
            verb = low.split("-")[0]
            if verb not in WIN_CMDLET_ALLOW:
                return f"cmdlet verb '{name.split('-')[0]}' is not allowed (read-only verbs only)"
            allowed = WIN_CMDLET_ALLOW[verb]
            if allowed is not None and low not in allowed:
                return f"cmdlet '{name}' is not allowed"
            if low in WIN_DENY_CMDLETS:
                return f"cmdlet '{name}' is not allowed"
            bad = next((t for t in a if t.lower().split(":")[0] in WIN_DENY_PARAMS), None)
            if bad:
                return f"parameter {bad} not allowed"
        elif n == 0 and low in WIN_EXE_CHECKS:
            p = WIN_EXE_CHECKS[low](a)
            if p:
                return f"{name}: {p}"
        else:
            return f"'{name}' is not in the Windows read-only allowlist"
    return None


def readonly_problem(os_family, cmd):
    """Return why `cmd` is not an allowed read-only command for os_family ('linux'|'windows'), or None if fine."""
    if not cmd or not cmd.strip():
        return "empty command"
    if os_family == "linux":
        if any(x in cmd for x in ("\n", "\r")):  # check before strip(): trailing newlines are not harmless
            return "contains a newline"
        return _linux_problem(cmd.strip())
    if os_family == "windows":
        return _windows_problem(cmd)
    return f"unsupported os_family {os_family!r}"


# ----------------------------------------------------------------------------------------------
# target selection
# ----------------------------------------------------------------------------------------------
def load_machines():
    db = sqlite3.connect(f"file:{ROOT / os.getenv('INVENTORY_DB', 'inventory/inventory.db')}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in db.execute("SELECT * FROM machines ORDER BY name")]
    finally:
        db.close()


def skip_reason(m):
    if m["is_template"]:
        return "template"
    if m["power_state"] != "poweredOn":
        return f"power_state={m['power_state']}"
    if not m["primary_ip"]:
        return "no primary_ip"
    if m["mgmt_protocol"] not in ("ssh", "winrm"):
        return f"mgmt_protocol={m['mgmt_protocol']}"
    if (m["mgmt_protocol"], m["os_family"]) not in (("ssh", "linux"), ("winrm", "windows")):
        return f"mgmt_protocol {m['mgmt_protocol']} does not match os_family {m['os_family']}"
    return None


def select_machines(args, rows):
    """Return (runnable, skipped[(machine, reason)])."""
    if not (args.targets or args.match or args.os or args.role or args.cluster or args.all):
        raise SystemExit("Specify targets, --match, --os, --role, --cluster or --all")
    rows = [r for r in rows if r["status"] == args.status]
    chosen = {}
    for t in args.targets:
        hits = [r for r in rows if t.lower() in ((r["name"] or "").lower(), (r["guest_hostname"] or "").lower(),
                                                 (r["primary_ip"] or "").lower())]
        if not hits:
            raise SystemExit(f"Target {t!r} not found in machines with status {args.status!r}")
        chosen.update({r["id"]: r for r in hits})
    for r in rows:
        if args.all or any(fnmatch.fnmatch(r["name"] or "", g) for g in args.match):
            chosen[r["id"]] = r
    if not (args.targets or args.match or args.all):
        chosen = {r["id"]: r for r in rows}
    sel = [r for r in chosen.values()
           if (not args.os or r["os_family"] == args.os) and (not args.role or r["role"] == args.role)
           and (not args.cluster or r["cluster"] == args.cluster)]
    if not sel:
        raise SystemExit("No machines matched the given filters")
    run, skipped = [], []
    for r in sorted(sel, key=lambda r: r["name"] or ""):
        why = skip_reason(r)
        (skipped.append((r, why)) if why else run.append(r))
    return run, skipped


# ----------------------------------------------------------------------------------------------
# connection + execution
# ----------------------------------------------------------------------------------------------
def scrub(msg, secrets):
    for s in secrets:
        if s:
            msg = msg.replace(s, "***")
    return msg


def err_text(e, secrets=()):
    first = str(e).splitlines()[0] if str(e) else ""
    return f"{type(e).__name__}: {scrub(first, secrets)[:160]}"


def credentials(m):
    ref = m.get("credential_ref") or ("WINDOWS" if m["mgmt_protocol"] == "winrm" else "LINUX")
    names = {k: f"NET_{ref}_{k}" for k in ("USERNAME", "PASSWORD", "SSH_KEY", "SSH_KEY_PASSPHRASE")}
    user, pw = os.getenv(names["USERNAME"]), os.getenv(names["PASSWORD"])
    key, phrase = os.getenv(names["SSH_KEY"]), os.getenv(names["SSH_KEY_PASSPHRASE"])
    need = [names["USERNAME"]] + ([] if (m["mgmt_protocol"] == "ssh" and key) else [names["PASSWORD"]])
    missing = [n for n in need if not os.getenv(n)]
    if missing:
        raise RuntimeError("missing credential env var(s): " + ", ".join(missing))
    return user, pw, key, phrase


def run_ssh(m, cmds, timeout, cred):
    import paramiko
    user, pw, key, phrase = cred
    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # accepted but never persisted
    try:
        cl.connect(m["primary_ip"], port=m["port"] or 22, username=user, password=None if key else pw,
                   key_filename=key or None, passphrase=phrase if key else None, timeout=timeout,
                   banner_timeout=timeout, auth_timeout=timeout, look_for_keys=False, allow_agent=False)
        res = []
        for c in cmds:
            sin, sout, serr = cl.exec_command(c, timeout=timeout, get_pty=False)
            sin.channel.shutdown_write()
            out = sout.read().decode("utf-8", "replace")
            err = serr.read().decode("utf-8", "replace")
            res.append((c, sout.channel.recv_exit_status(), out, err))
        return res
    finally:
        cl.close()


def run_winrm(m, cmds, timeout, cred):
    import winrm
    user, pw, _, _ = cred
    port = m["port"] or 5985
    url = f"{'https' if port == 5986 else 'http'}://{m['primary_ip']}:{port}/wsman"
    kw = {"server_cert_validation": os.getenv("WINRM_CERT_VALIDATION", "ignore")} if port == 5986 else {}
    s = winrm.Session(url, auth=(user, pw), transport=os.getenv("WINRM_TRANSPORT", "ntlm"),
                      operation_timeout_sec=timeout, read_timeout_sec=timeout + 10, **kw)
    res = []
    for c in cmds:
        r = s.run_ps("$ProgressPreference='SilentlyContinue'; " + c)
        err = r.std_err.decode("utf-8", "replace")
        if err.startswith("#< CLIXML"):
            err = getattr(s, "_clean_error_msg", str)(err)  # pywinrm helper turns CLIXML into text
        res.append((c, r.status_code, r.std_out.decode("utf-8", "replace"), err))
    return res


def run_machine(m, cmds_by_os, timeout):
    """Returns dict(machine, os, ok, error, commands=[{cmd, exit}], text)."""
    cmds = cmds_by_os[m["os_family"]]
    rec = {"machine": m["name"], "ip": m["primary_ip"], "os": m["os_family"], "ok": False, "error": None,
           "commands": [], "text": ""}
    secrets = []
    try:
        cred = credentials(m)
        secrets = [cred[1], cred[2], cred[3]]
        fn = run_ssh if m["mgmt_protocol"] == "ssh" else run_winrm
        for c, code, out, err in fn(m, cmds, timeout, cred):
            rec["commands"].append({"cmd": c, "exit": code})
            body = out + (f"[stderr]\n{err}" if err.strip() else "")
            rec["text"] += f"===== {m['name']} ({m['primary_ip']}) :: {c} =====\n{scrub(body, secrets)}\n"
            if code:
                rec["text"] += f"[exit {code}]\n"
        rec["ok"] = True
    except TimeoutError as e:
        rec["error"] = f"timeout after {timeout}s ({type(e).__name__})"
    except Exception as e:  # noqa: BLE001 - report any failure per machine
        rec["error"] = err_text(e, secrets)
    return rec


# ----------------------------------------------------------------------------------------------
def build_commands(args):
    """-> list of (cmd, {os: cmd}) resolved to per-OS command lists; exits on rejected commands."""
    per_os, bad = {"linux": [], "windows": []}, []
    for name in args.preset:
        for osf, cs in PRESETS[name].items():
            for c in cs:
                p = readonly_problem(osf, c)
                (bad.append(f"  preset {name} [{osf}] {c!r}: {p}") if p else per_os[osf].append(c))
    for c in args.commands:
        probs = {osf: readonly_problem(osf, c) for osf in per_os}
        okos = [osf for osf, p in probs.items() if not p]
        if not okos:
            bad.append(f"  {c!r}: " + "; ".join(f"{osf}: {p}" for osf, p in probs.items()))
        for osf in okos:
            per_os[osf].append(c)
    if bad:
        raise SystemExit("Rejected command(s) (read-only allowlist):\n" + "\n".join(bad))
    return {k: list(dict.fromkeys(v)) for k, v in per_os.items()}


def main():
    ap = argparse.ArgumentParser(description="Run read-only commands inside VM guest operating systems.")
    ap.add_argument("targets", nargs="*", help="machine name, guest hostname or primary IP")
    ap.add_argument("--match", action="append", default=[], metavar="GLOB", help="fnmatch glob on VM name (repeatable)")
    ap.add_argument("--os", choices=["windows", "linux"], help="only this os_family")
    ap.add_argument("--role", help="only machines with this role")
    ap.add_argument("--cluster", help="only machines in this cluster")
    ap.add_argument("--all", action="store_true", help="all machines with the selected status")
    ap.add_argument("--status", default="active", help="machine status to target (default: active)")
    ap.add_argument("-c", "--command", action="append", default=[], dest="commands",
                    help="read-only command (repeatable); sent only to OS families it validates for")
    ap.add_argument("--preset", action="append", default=[], choices=sorted(PRESETS), help="built-in read-only bundle (repeatable)")
    ap.add_argument("--out", action="store_true", help="save outputs/<timestamp>/<vm>.txt and summary.json")
    ap.add_argument("--grep", action="append", default=[], metavar="REGEX",
                    help="print only matching lines (case-insensitive, repeatable) prefixed 'vm: '; --out files stay unfiltered")
    ap.add_argument("--quiet", action="store_true", help="print only one status line per machine")
    ap.add_argument("--timeout", type=int, default=30, help="connect/command timeout in seconds (default 30)")
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

    if not (args.commands or args.preset):
        ap.error("give at least one -c CMD or --preset NAME")
    try:
        pats = [re.compile(g, re.IGNORECASE) for g in args.grep]
    except re.error as e:
        ap.error(f"bad --grep regex: {e}")
    cmds_by_os = build_commands(args)  # validated before any connection
    runnable, skipped = select_machines(args, load_machines())
    for m, why in skipped:
        print(f"SKIP {m['name']:30} {m['primary_ip'] or '-':15} {why}")
    targets = []
    for m in runnable:
        if cmds_by_os[m["os_family"]]:
            targets.append(m)
        else:
            print(f"SKIP {m['name']:30} {m['primary_ip']:15} no given command applies to {m['os_family']}")
    if not targets:
        raise SystemExit("No runnable machines (all skipped)")
    outdir = ROOT / "outputs" / netlib.timestamp() if args.out else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)

    with ThreadPoolExecutor(max(1, min(args.workers, len(targets)))) as ex:
        results = list(ex.map(lambda m: run_machine(m, cmds_by_os, args.timeout), targets))

    ok = 0
    for r in results:
        name, ip = r["machine"], r["ip"]
        if not r["ok"]:
            print(f"FAIL {name:30} {ip:15} {r['error']}")
            continue
        ok += 1
        nz = sum(1 for c in r["commands"] if c["exit"])
        if args.quiet:
            print(f"OK   {name:30} {ip:15} {len(r['commands'])} cmds{f', {nz} non-zero' if nz else ''}")
        elif pats:
            for line in r["text"].splitlines():
                if any(p.search(line) for p in pats):
                    print(f"{name}: {line}")
        else:
            print(r["text"], end="")
    if outdir:
        for r in results:
            if r["ok"]:
                (outdir / (re.sub(r"[^\w.-]", "_", r["machine"]) + ".txt")).write_text(r["text"])
        summary = [{k: v for k, v in r.items() if k != "text"} for r in results]
        (outdir / "summary.json").write_text(json.dumps(summary, indent=2))
        print(f"saved to {outdir}")
    print(f"{ok} ok / {len(results) - ok} failed / {len(skipped)} skipped")
    sys.exit(1 if ok < len(results) else 0)


if __name__ == "__main__":
    main()
