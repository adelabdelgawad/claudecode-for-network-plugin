"""READ-ONLY in-guest OS security audit of inventory VMs (checklist section E2: items E36-E44).

Usage:
    cfn guest-security [NAME|HOSTNAME|IP ...] [--match GLOB] [--os windows|linux] [--role R]
        [--cluster C] [--all] [--workers 16] [--timeout 60] [--out DIR]
    cfn guest-security --from DIR [--out DIR]     # parse an existing cfn guest-show --out directory

Live mode runs guest_show's `security` preset (allowlisted read-only commands over WinRM/SSH) concurrently and
analyzes the output; nothing is ever changed in a guest. `--from DIR` skips collection and parses the
`cfn guest-show --preset security --out` directory (<vm>.txt files + summary.json). Suggestions in the report are
text only, never executed.

Outputs under --out (default reports/guest_security/<YYYYmmdd-HHMMSS>):
    summary.json   shared checklist contract (merged by vsphere_checklist.py): scope, hosts, items[]
    report.md      item overview, per-item findings, unreachable hosts
    findings.csv   one row per finding
    raw/<vm>.txt   raw command output (live mode only)
"""
import argparse
import csv
import json
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import guest_show
from netlib import ROOT

# ----------------------------------------------------------------------------------------------
# Thresholds (edit here)
# ----------------------------------------------------------------------------------------------
PATCH_WARN_DAYS, PATCH_CRIT_DAYS = 60, 120          # age of the last installed update / hotfix
SEC_UPDATES_WARN, SEC_UPDATES_CRIT = 0, 20          # Linux pending security updates: > value
AV_SIG_WARN_DAYS = 3                                # Defender signature age
FAILED_LOGON_WARN, FAILED_LOGON_CRIT = 20, 200      # failed logons in 24h
TIME_OFFSET_WARN_S, TIME_OFFSET_CRIT_S = 5.0, 60.0  # clock offset in seconds
RISKY_PORTS = {21: "ftp", 23: "telnet", 512: "rexec", 513: "rlogin", 514: "rsh"}
# Automatic services that are normally stopped (trigger/delayed start or on-demand updaters); matched case-insensitively
NORMALLY_STOPPED = {"gupdate", "gupdatem", "sppsvc", "remoteregistry", "mapsbroker", "edgeupdate", "edgeupdatem",
                    "wbiosrvc", "shellhwdetection", "tiledatamodelsvc", "cdpusersvc", "onesyncsvc", "dosvc",
                    "googlecrashhandler", "googlecrashhandler64", "googleupdaterinternalservice", "googleupdaterservice",
                    "ccmsetup", "tbs", "stisvc", "wmiapsrv", "swprv", "vss"}
NORMALLY_STOPPED_RE = re.compile(r"^(clr_optimization_.*|.*_[0-9a-f]{4,8})$", re.IGNORECASE)  # .NET ngen, per-user services
DEFAULT_ADMIN_RE = re.compile(r"(^|\\)(administrator|domain admins|enterprise admins)$", re.IGNORECASE)

SECTION = "E2. In-guest OS security"
ITEMS = [("E36", "Patches"), ("E37", "Antivirus/Defender"), ("E38", "Host firewall"), ("E39", "Risky services"),
         ("E40", "Local admins/accounts"), ("E41", "Failed-logon spikes"), ("E42", "Stopped Automatic services"),
         ("E43", "Time sync"), ("E44", "Linux hardening")]
SEV_RANK = {"INFO": 0, "WARN": 1, "CRIT": 2}
STATUS_BY_SEV = {2: "crit", 1: "warn"}


# ----------------------------------------------------------------------------------------------
# parsing of guest_show output ("===== vm (ip) :: command =====" blocks)
# ----------------------------------------------------------------------------------------------
HDR = re.compile(r"^===== (.+?) \((.*?)\) :: (.*) =====$", re.MULTILINE)


def parse_text(text):
    """-> {command: {"out", "err", "exit"}}; 'exit' is 0 unless guest_show printed an [exit N] line."""
    ms = list(HDR.finditer(text))
    cmds = {}
    for i, m in enumerate(ms):
        body = text[m.end() + 1:ms[i + 1].start() if i + 1 < len(ms) else len(text)]
        code = 0
        x = re.search(r"\[exit (-?\d+)\]\n?$", body)
        if x:
            code, body = int(x.group(1)), body[:x.start()]
        out, _, err = body.partition("[stderr]\n")
        cmds[m.group(3)] = {"out": out.strip(), "err": err.strip(), "exit": code}
    return cmds


def get(host, needle):
    """First command record whose text contains `needle`, else None. Adds ok (usable output) and error (first message)."""
    for c, r in host["cmds"].items():
        if needle in c:
            first = (r["out"].splitlines() or [""])[0]
            r["ok"] = not first.startswith("ERROR:") and r["exit"] != 127
            r["error"] = first if first.startswith("ERROR:") else (r["err"].splitlines() or [""])[0]
            return r
    return None


def lines_with(rec, prefix):
    return [l[len(prefix):].strip() for l in rec["out"].splitlines() if l.startswith(prefix)] if rec else []


def kv(s):
    """'A=1 B=two' -> {'A': '1', 'B': 'two'} (keys are single words, values run to the next key)."""
    parts = re.split(r"\s*\b(\w+)=", " " + s)
    return {parts[i]: parts[i + 1].strip() for i in range(1, len(parts) - 1, 2)}


def truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def parse_date(s):
    try:
        return datetime.strptime(s.strip()[:10], "%Y-%m-%d")
    except ValueError:
        pass
    m = re.search(r"(\d{1,2}) (\w{3}) (\d{4})", s)  # rpm --last: 'Tue 01 Oct 2024 10:22:33 AM UTC'
    try:
        return datetime.strptime(" ".join(m.groups()), "%d %b %Y") if m else None
    except ValueError:
        return None


def listening_ports(h):
    """Set of (port, address) for TCP listeners that are not loopback-only; None if the listing is unavailable."""
    if h["os"] == "linux":
        rec = get(h, "ss -tlnp")
        locs = [r[3] for r in (l.split() for l in rec["out"].splitlines() if l.startswith("LISTEN")) if len(r) > 3] if rec else []
    else:
        rec = get(h, "Get-NetTCPConnection")  # Get-NetTCPConnection lines, or the 'netstat -ano' fallback
        locs = [l.split()[0] for l in lines_with(rec, "LISTEN ")]
        locs += [l.split()[1] for l in (rec["out"].splitlines() if rec else []) if l.split()[:1] == ["TCP"] and "LISTENING" in l]
    if not (rec and rec["ok"]):
        return None
    out = set()
    for loc in locs:
        addr, _, port = loc.rpartition(":")
        if port.isdigit() and not (addr.startswith("127.") or addr.strip("[]") == "::1"):
            out.add((int(port), addr))
    return out


def fnd(sev, detail, suggestion=""):
    return {"severity": sev, "detail": detail, "suggestion": suggestion}


# ----------------------------------------------------------------------------------------------
# checks: each takes a host dict and returns None (no data from this host) or a list of findings (empty = pass)
# ----------------------------------------------------------------------------------------------
def age_finding(last, now, what, fix):
    age = (now - last).days
    sev = "CRIT" if age > PATCH_CRIT_DAYS else "WARN" if age > PATCH_WARN_DAYS else None
    return [fnd(sev, f"{what} {last:%Y-%m-%d} ({age} days ago)", fix)] if sev else []


def e36_patches(h, now):
    f, data = [], False
    if h["os"] == "windows":
        dates = [d for d in (parse_date(l.split()[-1]) for l in lines_with(get(h, "Get-HotFix"), "HOTFIX ")) if d]
        if dates:
            data = True
            f += age_finding(max(dates), now, "last hotfix installed", "Install the latest cumulative update (WSUS/WU), then reboot.")
        rb = get(h, "RebootPending")
        if rb and rb["ok"] and rb["out"]:
            data, flags = True, kv(rb["out"].replace("REBOOT ", ""))
            on = [k for k in ("CBS", "WU") if truthy(flags.get(k))]
            if on:
                f.append(fnd("WARN", "reboot pending (" + ", ".join(on) + ")", "Schedule a reboot in the next maintenance window."))
    else:
        last, hist, rpm = None, get(h, "history.log"), get(h, "rpm -qa --last")
        if hist and hist["out"]:
            last = parse_date(hist["out"].split(":", 1)[-1])
        if not last and rpm and rpm["ok"] and rpm["out"]:
            last = parse_date(rpm["out"].splitlines()[0])
        if last:
            data = True
            f += age_finding(last, now, "last package update", "Apply pending updates (apt upgrade / dnf update) in a maintenance window.")
        sec, apt = None, get(h, "apt list")
        if apt and apt["ok"] and apt["exit"] == 0:
            sec = sum(1 for l in apt["out"].splitlines() if "[upgradable" in l and "security" in l.lower())
        for needle in ("dnf -C", "yum -C"):  # advisory lines like 'RHSA-2024:1234 Important/Sec. kernel-...'
            r = get(h, needle)
            if r and r["ok"] and r["exit"] == 0:
                sec = max(sec or 0, sum(1 for l in r["out"].splitlines() if re.search(r"/Sec\.|^\S*(RHSA|ALAS|ELSA|ALSA|RLSA|CESA)", l)))
        if sec is not None:
            data = True
            sev = "CRIT" if sec > SEC_UPDATES_CRIT else "WARN" if sec > SEC_UPDATES_WARN else None
            if sev:
                f.append(fnd(sev, f"{sec} pending security update(s)", "Apply security updates (unattended-upgrades / dnf update --security)."))
        rr = get(h, "reboot-required")
        if rr is not None:
            data = True
            if rr["exit"] == 0 and rr["out"]:
                f.append(fnd("WARN", "reboot required (/var/run/reboot-required present)", "Schedule a reboot in the next maintenance window."))
    return f if data else None


def e37_antivirus(h, now):
    if h["os"] != "windows":
        return None
    d, av = get(h, "Get-MpComputerStatus"), get(h, "AntiVirusProduct")
    if d is None and av is None:
        return None
    third = []  # non-Defender products in Security Center: (name, enabled, signatures_stale) from productState bits
    for l in lines_with(av, "AVPRODUCT "):
        m = re.match(r"name=(.*?) productState=(\d+)", l)
        if m and "defender" not in m.group(1).lower():
            st = int(m.group(2))
            third.append((m.group(1), (st >> 12) & 0xF == 1, (st >> 4) & 0xF == 1))
    live = [t for t in third if t[1]]
    dl, f = lines_with(d, "DEFENDER "), []
    if dl:
        v = kv(dl[0])
        problems = []
        if not (truthy(v.get("AMServiceEnabled")) and truthy(v.get("AntivirusEnabled"))):
            problems.append("Defender antivirus disabled")
        if not truthy(v.get("RealTimeProtectionEnabled")):
            problems.append("real-time protection off")
        if problems and live:
            f.append(fnd("INFO", f"Defender not active ({'; '.join(problems)}); third-party AV active: " + ", ".join(t[0] for t in live)))
        elif problems:
            f.append(fnd("CRIT", "; ".join(problems), "Enable Defender real-time protection or install the corporate AV agent."))
        if v.get("SignatureAgeDays", "").isdigit() and int(v["SignatureAgeDays"]) > AV_SIG_WARN_DAYS and not (problems and live):
            f.append(fnd("WARN", f"Defender signatures are {v['SignatureAgeDays']} days old", "Update signatures (WSUS / Update-MpSignature) and check the update source."))
    elif live:
        f.append(fnd("INFO", "third-party AV active: " + ", ".join(t[0] for t in live)))
        f += [fnd("WARN", f"{t[0]} signatures out of date", "Check the AV management console.") for t in live if t[2]]
    else:
        why = ((d or {}).get("error") or "no Defender status")[:100]
        f.append(fnd("CRIT", "no active antivirus found" + (f" ({len(third)} registered product(s) disabled)" if third else "") + f" - {why}",
                     "Install/enable the corporate antivirus (or Defender) and confirm real-time protection."))
    return f


def e38_firewall(h, now):
    if h["os"] == "windows":
        rec = get(h, "Get-NetFirewallProfile")
        if not (rec and rec["ok"]):
            return None
        off = [m.group(1) for l in lines_with(rec, "FWPROFILE ") if (m := re.match(r"(\w+) Enabled=(\w+)", l)) and not truthy(m.group(2))]
        return [fnd("WARN", "Windows Firewall profile(s) disabled: " + ", ".join(off),
                    "Enable the profile after reviewing rules; this is a change and needs an approved CHG.")] if off else []
    rec = get(h, "is-active")
    if not rec or rec["exit"] == 127:
        return None
    states = dict(zip(["firewalld", "ufw", "nftables", "iptables"], rec["out"].splitlines()))
    if "active" in states.values():
        return []
    return [fnd("WARN", "no active host firewall (" + ", ".join(f"{k}={v}" for k, v in states.items()) + ")",
                "Enable ufw/firewalld with a default-deny inbound policy; this is a change and needs an approved CHG.")]


def e39_risky(h, now):
    f, data = [], False
    if h["os"] == "windows":
        smb = get(h, "EnableSMB1Protocol")
        if smb and smb["out"].startswith("SMB1 "):
            data, v = True, kv(smb["out"][5:])
            if "EnableSMB1Protocol" in v:
                on, how = truthy(v["EnableSMB1Protocol"]), "EnableSMB1Protocol=" + v["EnableSMB1Protocol"]
            else:  # fallback registry read: an absent value means SMB1 is on by default on 2008R2-2012R2
                reg = smb["out"].split("=", 1)[-1].strip()
                on, how = reg != "0", f"registry SMB1={reg or 'absent, on by default on this OS'}"
            if on:
                f.append(fnd("CRIT", f"SMB1 enabled ({how})", "Disable SMB1 (registry SMB1=0 / remove the SMB1 feature) after checking legacy clients."))
        rdp = get(h, "fDenyTSConnections")
        if rdp and rdp["out"].startswith("RDP "):
            data, v = True, kv(rdp["out"][4:])
            if v.get("fDenyTSConnections") == "0" and v.get("UserAuthentication") == "0":
                f.append(fnd("WARN", "RDP enabled without Network Level Authentication", "Require NLA (UserAuthentication=1) or disable RDP; use a jump host."))
    ports = listening_ports(h)
    if ports is not None:
        data, nums = True, {p for p, _ in ports}
        for p in sorted(nums & set(RISKY_PORTS)):
            f.append(fnd("CRIT", f"{RISKY_PORTS[p]} listening on tcp/{p}", f"Disable the {RISKY_PORTS[p]} service; use SSH/SFTP/RDP with NLA instead."))
        other = sorted(nums - set(RISKY_PORTS))
        if other:
            f.append(fnd("INFO", f"{len(other)} other listening TCP port(s): " + ", ".join(map(str, other))))
    return f if data else None


def e40_accounts(h, now):
    f, data = [], False
    if h["os"] == "windows":
        ur = get(h, "Get-LocalUser")
        users = [(m.group(1).strip(), kv(m.group(2).replace(" | ", " "))) for l in lines_with(ur, "USER ") if (m := re.match(r"(.*?) \| (.*)", l))]
        if ur and ur["ok"] and users:
            data = True
            bi = [n for n, v in users if v.get("sid", "").endswith("-500") and truthy(v.get("enabled"))]
            if bi:
                f.append(fnd("WARN", f"built-in Administrator account (SID -500) is enabled ({bi[0]})", "Disable or rename it and use named admin accounts (LAPS for local admin)."))
            nev = [n for n, v in users if truthy(v.get("enabled")) and truthy(v.get("pwdneverexpires"))]
            if nev:
                f.append(fnd("WARN", "enabled local user(s) with password never expires: " + ", ".join(nev), "Set a password expiry or convert to managed service accounts."))
        ar = get(h, "Get-LocalGroupMember")
        if ar and ar["ok"]:
            data = True
            members = [l.split(" | ")[0].strip() for l in lines_with(ar, "ADMIN ")]
            if not members and "-----" in ar["out"]:  # 'net localgroup' fallback: names sit between the dashes and the footer
                members = [l.strip() for l in ar["out"].split("-----", 1)[1].splitlines()[1:]
                           if l.strip() and not l.startswith("The command completed")]
            extra = [m for m in members if not DEFAULT_ADMIN_RE.search(m)]
            if extra:
                f.append(fnd("INFO", "non-default local Administrators member(s): " + ", ".join(extra)))
    else:
        g = get(h, "/etc/group")
        if g and g["ok"]:
            data = True
            for p in (l.split(":") for l in g["out"].splitlines()):
                if len(p) == 4 and p[3]:
                    f.append(fnd("INFO", f"group {p[0]} members: {p[3]}"))
    return f if data else None


def e41_failed_logons(h, now):
    n, srcs, accts, data = 0, Counter(), Counter(), False
    if h["os"] == "windows":
        c, g = get(h, "FAILED_LOGONS_24H"), get(h, "FAILGROUP")
        m = re.search(r"FAILED_LOGONS_24H=(\d+)", c["out"]) if c else None
        if m:
            data, n = True, int(m.group(1))
        for l in lines_with(g, "FAILGROUP "):
            x = re.match(r"count=(\d+) account=(.*?) ip=(\S*)", l)
            if x:
                srcs[x.group(3)] += int(x.group(1))
                accts[x.group(2)] += int(x.group(1))
    else:
        c, g, idr = get(h, "grep -c"), get(h, "tail -n 300"), get(h, "id")
        can_read = bool(idr and re.search(r"uid=0\(|\b(adm|systemd-journal)\b", idr["out"]))  # a 0 only counts if the journal is readable
        if c and c["ok"] and c["out"].isdigit() and (int(c["out"]) > 0 or can_read):
            data, n = True, int(c["out"])
        for l in g["out"].splitlines() if g else []:
            x = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", l)
            if x:
                accts[x.group(1)] += 1
                srcs[x.group(2)] += 1
    if not data:
        return None
    sev = "CRIT" if n > FAILED_LOGON_CRIT else "WARN" if n > FAILED_LOGON_WARN else None
    top = lambda c: ", ".join(f"{k} x{v}" for k, v in c.most_common(5)) or "n/a"
    return [fnd(sev, f"{n} failed logons in 24h; top source IPs: {top(srcs)}; top accounts: {top(accts)}",
                "Check for password spraying/brute force; block the source IPs, enforce lockout and restrict RDP/SSH exposure.")] if sev else []


def e42_services(h, now):
    if h["os"] == "windows":
        rec = get(h, "Win32_Service")
        if not (rec and rec["ok"]):
            return None
        bad = [n for n in (l.split(" | ")[0] for l in lines_with(rec, "STOPPED "))
               if n.lower() not in NORMALLY_STOPPED and not NORMALLY_STOPPED_RE.match(n)]
        kind = "stopped Automatic service(s)"
    else:
        rec = get(h, "--state=failed")
        if not (rec and rec["ok"] and rec["exit"] == 0):
            return None
        bad, kind = [l.split()[0] for l in rec["out"].splitlines() if l.split()], "failed systemd unit(s)"
    return [fnd("WARN", f"{len(bad)} {kind}: " + ", ".join(bad[:15]) + (" ..." if len(bad) > 15 else ""),
                "Start or fix the service, or set it to Manual/Disabled if intentionally stopped.")] if bad else []


def e43_time(h, now):
    off, why = None, None
    sug = "Configure NTP (domain hierarchy on Windows, chrony/timesyncd on Linux) against the corporate time source."
    if h["os"] == "windows":
        rec = get(h, "w32tm")
        if not rec:
            return None
        if not rec["ok"] or rec["exit"] or "error occurred" in rec["out"].lower():
            return [fnd("WARN", "time service not responding: " + ((rec["out"] or rec["err"]).splitlines() or ["w32tm failed"])[0][:100], sug)]
        m = re.search(r"^Source:\s*(.+)$", rec["out"], re.MULTILINE)
        src = m.group(1).strip() if m else ""
        if re.search(r"local cmos clock|free-running system clock", src, re.IGNORECASE) or "not synchronized" in rec["out"].lower():
            why = f"not synchronized (source: {src or 'unknown'})"
        o = re.search(r"Phase Offset:\s*([+-]?[\d.]+)s", rec["out"])
        off = abs(float(o.group(1))) if o else None
    else:
        ch, ts, td = get(h, "chronyc"), get(h, "timesync-status"), get(h, "timedatectl")
        chrony = bool(ch and ch["ok"] and ch["exit"] == 0)
        if chrony:
            o = re.search(r"System time\s*:\s*([\d.]+) seconds", ch["out"])
            off = float(o.group(1)) if o else None
            if re.search(r"not synchroni[sz]ed", ch["out"], re.IGNORECASE):
                why = "chrony reports not synchronised"
        elif ts and ts["ok"] and ts["exit"] == 0:
            o = re.search(r"Offset:\s*([+-]?[\d.]+)\s*(us|ms|s|min)\b", ts["out"])
            off = abs(float(o.group(1)) * {"us": 1e-6, "ms": 1e-3, "s": 1.0, "min": 60.0}[o.group(2)]) if o else None
        if not why and not chrony and td and td["ok"]:
            m = re.search(r"(?:System clock|NTP) synchronized:\s*(\w+)", td["out"])
            if m and m.group(1).lower() != "yes":
                why = "system clock not synchronized (no working NTP client)"
        if off is None and not why and not (td and td["ok"]):
            return None
    f = [fnd("WARN", why, sug)] if why else []
    if off is not None and off > TIME_OFFSET_WARN_S:
        f.append(fnd("CRIT" if off > TIME_OFFSET_CRIT_S else "WARN", f"clock offset {off:.1f}s", sug))
    return f


def e44_linux(h, now):
    if h["os"] != "linux":
        return None
    f, data = [], False
    ssh = get(h, "sshd_config")
    if ssh and (ssh["out"] or ssh["exit"] == 0):
        data, seen = True, {}
        # grep output is 'file:Key value'. sshd uses the first value it reads and the drop-ins (sshd_config.d) are
        # included at the top of the main file, so they win. 'Match' blocks are NOT visible to this grep.
        rows = [(l.split(":", 1)[0], l.split(":", 1)[1].split()) for l in ssh["out"].splitlines() if ":" in l]
        for _, w in sorted(rows, key=lambda r: r[0] == "/etc/ssh/sshd_config"):
            if len(w) >= 2:
                seen.setdefault(w[0].lower(), w[1].lower())
        if seen.get("permitrootlogin") == "yes":
            f.append(fnd("CRIT", "sshd PermitRootLogin yes", "Set PermitRootLogin no (or prohibit-password) and use a named sudo user."))
        pa = seen.get("passwordauthentication")
        if pa in (None, "yes"):
            f.append(fnd("WARN", "sshd PasswordAuthentication yes" + (" (OpenSSH default, not set explicitly)" if pa is None else ""),
                         "Use key-based authentication and set PasswordAuthentication no."))
    ge, aa, sysfs = get(h, "getenforce"), get(h, "aa-status"), get(h, "apparmor/parameters")
    if ge or aa or sysfs:
        data = True
        mode = ge["out"].strip().lower() if ge and ge["ok"] and ge["exit"] == 0 else None
        apparmor = (aa and aa["exit"] == 0) or (sysfs and sysfs["exit"] == 0 and sysfs["out"].strip() == "Y")
        if mode == "enforcing" or (mode is None and apparmor):
            pass
        elif mode:
            f.append(fnd("WARN", f"SELinux is {mode}", "Set SELinux to enforcing (/etc/selinux/config) after testing."))
        else:
            f.append(fnd("WARN", "neither SELinux nor AppArmor is enabled", "Enable AppArmor (Debian/Ubuntu) or SELinux enforcing (RHEL family)."))
    return f if data else None


CHECKS = {"E36": e36_patches, "E37": e37_antivirus, "E38": e38_firewall, "E39": e39_risky, "E40": e40_accounts,
          "E41": e41_failed_logons, "E42": e42_services, "E43": e43_time, "E44": e44_linux}


# ----------------------------------------------------------------------------------------------
# analysis
# ----------------------------------------------------------------------------------------------
def analyze(hosts, failures, scope, now):
    """hosts: reachable [{name, ip, os, cmds}] -> the shared summary.json contract."""
    items = []
    for iid, title in ITEMS:
        findings, with_data, no_data = [], 0, []
        for h in hosts:
            try:
                res = CHECKS[iid](h, now)
            except Exception as e:  # noqa: BLE001 - one odd output must not sink the audit
                res = [fnd("INFO", f"could not analyze output ({type(e).__name__}: {e})")]
            if res is None:
                if iid not in ("E37", "E44"):  # OS-specific items: the other OS is not "missing data"
                    no_data.append(h["name"])
                continue
            with_data += 1
            findings += [{"target": h["name"], "vcenter": None, **x} for x in res]
        worst = max((SEV_RANK[x["severity"]] for x in findings), default=-1)
        status = STATUS_BY_SEV.get(worst) or ("info" if findings else "pass")
        reason = None
        if not with_data:
            status = "skip"
            reason = "no reachable hosts" if not hosts else f"no data from any of {len(hosts)} reachable host(s) (command unavailable or not applicable)"
        elif no_data:
            reason = f"no data from {len(no_data)} host(s): " + ", ".join(no_data[:10])
        findings.sort(key=lambda x: (-SEV_RANK[x["severity"]], x["target"].lower()))
        items.append({"id": iid, "section": SECTION, "title": title, "status": status, "reason": reason, "findings": findings})
    return {"generated": now.isoformat(timespec="seconds"), "scope": scope,
            "hosts": {"ok": len(hosts), "failed": len(failures), "failures": failures}, "items": items}


# ----------------------------------------------------------------------------------------------
# reporting
# ----------------------------------------------------------------------------------------------
def os_summary(h):
    r = get(h, "Win32_OperatingSystem") if h["os"] == "windows" else get(h, "/etc/os-release")
    if not r:
        return h["os"]
    if h["os"] == "windows":
        l = lines_with(r, "OS=")
        return l[0].split(" | ")[0] if l else h["os"]
    m = re.search(r'^PRETTY_NAME="?(.*?)"?$', r["out"], re.MULTILINE)
    return m.group(1) if m else "linux"


def write_outputs(out, summary, hosts):
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    with open(out / "findings.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "title", "status", "severity", "target", "detail", "suggestion"])
        for it in summary["items"]:
            for x in it["findings"]:
                w.writerow([it["id"], it["title"], it["status"], x["severity"], x["target"], x["detail"], x["suggestion"]])
    hs = summary["hosts"]
    L = ["# In-guest OS Security Report", "", (f"Generated {summary['generated']} - read-only, "
          f"{hs['ok']} host(s) analyzed, {hs['failed']} unreachable"), "", "## Item overview", "",
         "| Item | Title | Status | Findings | Note |", "|---|---|---|---|---|"]
    for it in summary["items"]:
        L.append(f"| {it['id']} | {it['title']} | {it['status'].upper()} | {len(it['findings'])} | {it['reason'] or ''} |")
    for it in summary["items"]:
        if not it["findings"]:
            continue
        L += ["", f"## {it['id']} {it['title']} - {it['status'].upper()}", "",
              "| Severity | Host | Detail | Suggestion (not applied) |", "|---|---|---|---|"]
        L += [f"| {x['severity']} | {x['target']} | {x['detail'].replace('|', '/')} | {x['suggestion'].replace('|', '/')} |" for x in it["findings"]]
    L += ["", "## Hosts analyzed", "", "| Host | OS |", "|---|---|"] + [f"| {h['name']} | {os_summary(h)} |" for h in hosts]
    L += ["", "## Unreachable / failed hosts", ""]
    L += [f"- {x['machine']}: {x['error']}" for x in hs["failures"]] or ["None."]
    (out / "report.md").write_text("\n".join(L) + "\n")


# ----------------------------------------------------------------------------------------------
# collection
# ----------------------------------------------------------------------------------------------
def safe_name(n):
    return re.sub(r"[^\w.-]", "_", n)  # same file naming as cfn guest-show --out


def load_dir(src):
    """Parse a cfn guest-show --out directory -> (hosts, failures)."""
    summ = src / "summary.json"
    recs = json.loads(summ.read_text()) if summ.exists() else [{"machine": p.stem, "ok": True} for p in sorted(src.glob("*.txt"))]
    hosts, failures = [], []
    for r in recs:
        f = src / (safe_name(r["machine"]) + ".txt")
        if not r.get("ok") or not f.exists():
            failures.append({"machine": r["machine"], "error": r.get("error") or "no output file"})
            continue
        cmds = parse_text(f.read_text())
        osf = r.get("os") or ("linux" if any("os-release" in c for c in cmds) else "windows")
        hosts.append({"name": r["machine"], "ip": r.get("ip"), "os": osf, "cmds": cmds})
    return hosts, failures


def collect_live(args, out):
    cmds_by_os = guest_show.build_commands(argparse.Namespace(preset=["security"], commands=[]))
    runnable, skipped = guest_show.select_machines(args, guest_show.load_machines())
    if not runnable:
        sys.exit("No runnable machines (all skipped)")
    print(f"Auditing {len(runnable)} guest(s) read-only ({len(skipped)} skipped), workers={args.workers}, out={out}")
    with ThreadPoolExecutor(max(1, min(args.workers, len(runnable)))) as ex:
        results = list(ex.map(lambda m: guest_show.run_machine(m, cmds_by_os, args.timeout), runnable))
    (out / "raw").mkdir(exist_ok=True)
    hosts, failures = [], []
    for r in results:
        if not r["ok"]:
            failures.append({"machine": r["machine"], "error": r["error"]})
            continue
        (out / "raw" / (safe_name(r["machine"]) + ".txt")).write_text(r["text"])
        hosts.append({"name": r["machine"], "ip": r["ip"], "os": r["os"], "cmds": parse_text(r["text"])})
    return hosts, failures, len(skipped)


def main():
    ap = argparse.ArgumentParser(description="Read-only in-guest OS security audit (E36-E44)")
    ap.add_argument("targets", nargs="*", help="machine name, guest hostname or primary IP")
    ap.add_argument("--match", action="append", default=[], metavar="GLOB", help="fnmatch glob on VM name (repeatable)")
    ap.add_argument("--os", choices=["windows", "linux"], help="only this os_family")
    ap.add_argument("--role", help="only machines with this role")
    ap.add_argument("--cluster", help="only machines in this cluster")
    ap.add_argument("--all", action="store_true", help="all machines with the selected status")
    ap.add_argument("--status", default="active", help="machine status to target (default: active)")
    ap.add_argument("--from", dest="src", metavar="DIR", help="analyze an existing cfn guest-show --preset security --out directory")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--timeout", type=int, default=60, help="per-command timeout in seconds (default 60; log queries are slow)")
    ap.add_argument("--out", help="output dir (default reports/guest_security/<timestamp>)")
    ap.add_argument("--now", help=argparse.SUPPRESS)  # fixed reference date (YYYY-MM-DD) for the offline fixture test
    args = ap.parse_args()

    now = datetime.strptime(args.now, "%Y-%m-%d") if args.now else datetime.now()
    out = Path(args.out) if args.out else ROOT / "reports" / "guest_security" / now.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    if args.src:
        hosts, failures = load_dir(Path(args.src))
        scope = {"mode": "from", "source": args.src, "skipped": 0}
    else:
        hosts, failures, skipped = collect_live(args, out)
        scope = {"mode": "live", "targets": args.targets, "match": args.match, "os": args.os, "role": args.role,
                 "cluster": args.cluster, "all": args.all, "skipped": skipped}
    summary = analyze(hosts, failures, scope, now)
    write_outputs(out, summary, hosts)

    print(f"Hosts: {len(hosts)} ok, {len(failures)} failed")
    for it in summary["items"]:
        c = Counter(x["severity"] for x in it["findings"])
        print(f"  {it['id']} {it['title']:28} {it['status'].upper():5} CRIT={c['CRIT']} WARN={c['WARN']} INFO={c['INFO']}"
              + (f"  ({it['reason']})" if it["status"] == "skip" else ""))
    for x in failures:
        print(f"  FAIL {x['machine']:24} {x['error'][:80]}")
    print(f"Report: {out / 'report.md'}\nJSON:   {out / 'summary.json'}\nCSV:    {out / 'findings.csv'}")


if __name__ == "__main__":
    main()
