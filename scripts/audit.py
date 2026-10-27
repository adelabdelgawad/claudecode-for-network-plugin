"""Read-only security audit of Cisco switches from the inventory.

Usage: cfn audit [--hosts HOSTNAME|IP ...] [--workers 16] [--outdir audits]

Runs only `show` commands. Raw output goes to audits/<date>/<hostname>/<command>.txt (dirs 700, files 600);
findings go to audits/<date>/findings.json, findings.csv and summary.txt. Secrets are masked in findings.
"""
import argparse
import csv
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path

from dotenv import load_dotenv
from netmiko import ConnectHandler

import paths

ROOT = paths.site_root()
load_dotenv(ROOT / ".env")
DB = ROOT / os.getenv("INVENTORY_DB", "inventory/inventory.db")

COMMANDS = [
    "show version",
    "show running-config",
    "show ip ssh",
    "show snmp community",
    "show vstack config",
    "show ip http server status",
    "show line",
    "show cdp neighbors",
    "show interfaces status",
    "show users",
    "show ntp status",
    "show logging | include Logging|Trap|host",
    "show spanning-tree summary",
    "show ip dhcp snooping",
    "show ip arp inspection",
    "show vtp status",
    "show vtp password",
    "show crypto key mypubkey rsa",  # public key only; used to size the RSA key
]
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
WELL_KNOWN = {"public", "private", "cisco", "secret", "community", "manager", "admin", "snmp",
              "test", "default", "monitor", "write", "read", "cable-docsis", "ilmi"}
INVALID = re.compile(r"% ?(Invalid input|Ambiguous|Incomplete command|Unknown command|Unrecognized)", re.I)
SECRET_RE = re.compile(r"\b(password|secret|community|key-string|key|md5|string)\b((?:\s+\d)?)\s+(\S+)", re.I)


def slug(cmd):
    return re.sub(r"[^A-Za-z0-9]+", "_", cmd).strip("_").lower()[:60]


def m(text):
    """Mask secret-like tokens in a config-derived string."""
    return SECRET_RE.sub(lambda x: f"{x.group(1)}{x.group(2)} ***", text)


def blocks(cfg):
    """Split a running-config into (header, [stripped body lines]) top-level blocks."""
    out, cur = [], None
    for ln in cfg.splitlines():
        if not ln.strip() or ln.startswith("!"):
            cur = None
            continue
        if ln[0] != " ":
            cur = (ln.strip(), [])
            out.append(cur)
        elif cur:
            cur[1].append(ln.strip())
    return out


def ssh_key_bits(txt, host=""):
    """Estimate RSA modulus size of the SSH host key (key named after the host, else any user key)
    from the DER length in `show crypto key mypubkey rsa` output. System keys (SUDI/self-signed) are ignored."""
    entries = re.split(r"(?m)^Key name:\s*", txt)[1:]
    skip = re.compile(r"^(CISCO_IDEVID|TP-self-signed)|Usage: Encryption", re.I | re.M)
    entries = [e for e in entries if not skip.search(e)]
    named = [e for e in entries if e.lower().startswith(host.lower().split(".")[0])] if host else []
    sizes = []
    for part in sum((re.split(r"Key Data:", e)[1:] for e in (named or entries)), []):
        hexs = "".join(re.findall(r"\b[0-9A-Fa-f]{2,8}\b", part.split("%")[0]))[:12]
        try:
            first = int(hexs[2:4], 16)
            length = int(hexs[4:4 + 2 * (first & 0x7F)], 16) if first & 0x80 else first
        except ValueError:
            continue
        for limit, bits in ((0x70, 512), (0xB0, 1024), (0xF0, 1536), (0x130, 2048), (0x1B0, 3072)):
            if length <= limit:
                sizes.append(bits)
                break
        else:
            sizes.append(4096)
    return sizes


def analyze(dev, o):
    host, ip, ostype = dev["hostname"], dev["mgmt_ip"], dev["os_type"]
    cfg = o.get("show running-config", "")
    res = []

    def f(sev, fid, title, evidence, fix):
        res.append({"hostname": host, "ip": ip, "severity": sev, "id": fid, "title": title,
                    "evidence": evidence, "remediation": fix})

    cl = [ln.strip() for ln in cfg.splitlines()]
    has = lambda pat: any(re.match(pat, ln) for ln in cl)  # noqa: E731
    first = lambda pat: next((ln for ln in cl if re.match(pat, ln)), None)  # noqa: E731
    bl = blocks(cfg)
    if not cfg.strip():
        f("info", "CFG-UNAVAILABLE", "Running config could not be read", "empty output",
          "Check privilege level / permissions of the audit account.")

    # OS version
    ver = None
    mv = re.search(r"Version\s+([0-9][^\s,]*)", o.get("show version", ""))
    if mv:
        ver = mv.group(1)
        eol = re.match(r"12\.2\(", ver) or re.match(r"15\.0\(2\)EZ", ver)
        if eol:
            f("high", "OS-EOL", "Software train is end-of-life / end-of-support", f"IOS version {ver}",
              "Upgrade to a supported release (e.g. 15.2(7)E or IOS XE 16.12/17.x) or replace the hardware.")
        else:
            f("info", "OS-VERSION", "Software version recorded", f"version {ver}", "Keep on a supported, patched release.")

    # Smart Install
    vs = o.get("show vstack config", "")
    if vs and not INVALID.search(vs) and (re.search(r"SmartInstall enabled", vs, re.I) or re.search(r"Oper Mode:\s*Enabled", vs, re.I)):
        f("critical", "SMI-ENABLED", "Smart Install enabled (CVE-2018-0171)",
          "show vstack config reports Smart Install enabled", "Apply `no vstack` and upgrade to a fixed release.")

    # HTTP(S) server
    hs = o.get("show ip http server status", "")
    http = bool(re.search(r"HTTP server status:\s*Enabled", hs, re.I)) or (not hs.strip() and has(r"ip http server"))
    https = bool(re.search(r"HTTP secure server status:\s*Enabled", hs, re.I)) or (not hs.strip() and has(r"ip http secure-server"))
    if hs and INVALID.search(hs):
        http, https = has(r"ip http server"), has(r"ip http secure-server")
    if http or https:
        which = " and ".join(x for x, on in (("ip http server", http), ("ip http secure-server", https)) if on)
        sev = "critical" if ostype == "cisco_xe" else "high"
        f(sev, "HTTP-ENABLED", "Web UI / HTTP(S) server enabled (CVE-2023-20198 / CVE-2023-20273 on IOS XE)",
          f"enabled: {which}", "Apply `no ip http server` and `no ip http secure-server`; patch IOS XE.")

    # vty / console lines
    vty_blocks = [(h, b) for h, b in bl if re.match(r"line vty", h)]
    con_blocks = [(h, b) for h, b in bl if re.match(r"line con", h)]
    telnet, noacl, notimeout, zerotimeout, vty_pw = [], [], [], [], []
    for h, b in vty_blocks:
        ti = [x for x in b if x.startswith("transport input")]
        if ti:
            toks = ti[-1].split()[2:]
            if "all" in toks or "telnet" in toks:
                telnet.append(f"{h}: {' '.join(ti[-1].split())}")
        elif ostype == "cisco_ios":
            telnet.append(f"{h}: transport input not set (default allows telnet)")
        if not any(re.match(r"access-class \S+ in", x) for x in b):
            noacl.append(h)
        for x in b:
            if re.match(r"password\b", x):
                vty_pw.append(f"{h}: {m(x)}")
    for h, b in vty_blocks + con_blocks:
        et = [x for x in b if x.startswith("exec-timeout")]
        if not et:
            notimeout.append(h)
        elif re.fullmatch(r"exec-timeout 0( 0)?", et[-1]):
            zerotimeout.append(h)
    if telnet:
        f("high", "VTY-TELNET", "Telnet allowed on vty lines", "; ".join(telnet)[:300], "Set `transport input ssh` on all vty lines.")
    if noacl and vty_blocks:
        f("medium", "VTY-NO-ACL", "No access-class on vty lines", "; ".join(noacl),
          "Restrict management access with `access-class <ACL> in` on vty lines.")
    if zerotimeout:
        f("medium", "LINE-TIMEOUT-NONE", "exec-timeout disabled (0 0) on lines", "; ".join(zerotimeout), "Set e.g. `exec-timeout 10 0`.")
    if notimeout:
        f("low", "LINE-TIMEOUT-DEFAULT", "No explicit exec-timeout on lines (default 10 min)", "; ".join(notimeout), "Set an explicit `exec-timeout`.")
    if vty_pw:
        f("medium", "LINE-PASSWORD", "Shared line password configured on vty", "; ".join(vty_pw)[:300],
          "Use AAA / `login local` with individual accounts.")

    # SSH
    ssh = o.get("show ip ssh", "")
    mver = re.search(r"SSH Enabled\s*-\s*version\s*([\d.]+)", ssh)
    if mver and mver.group(1) != "2.0":
        f("high", "SSH-V1", "SSH version 1 / 1.99 allowed", f"show ip ssh: version {mver.group(1)}", "Configure `ip ssh version 2`.")
    elif not mver and cfg and not has(r"ip ssh version 2") and "SSH Disabled" not in ssh and ssh and not INVALID.search(ssh):
        f("high", "SSH-V1", "SSH version 1 / 1.99 allowed", "ip ssh version 2 not configured", "Configure `ip ssh version 2`.")
    bits = ssh_key_bits(o.get("show crypto key mypubkey rsa", ""), host)
    if bits and min(bits) < 2048:
        f("high" if min(bits) < 1024 else "medium", "SSH-WEAK-RSA", "RSA key smaller than 2048 bits",
          f"RSA key sizes: {sorted(set(bits))}", "Regenerate: `crypto key generate rsa modulus 2048` (or 4096).")

    # Credentials
    ep = first(r"enable password")
    if ep:
        f("high", "ENABLE-PASSWORD", "`enable password` used instead of `enable secret`", m(ep), "Configure `enable algorithm-type scrypt secret` and remove `enable password`.")
    es = first(r"enable secret")
    if es:
        t = re.match(r"enable secret (?:(\d)\s)?", es).group(1)
        if t in (None, "0", "4"):
            f("high", "ENABLE-SECRET-WEAK", "Enable secret is weak/cleartext", f"enable secret type {t or 'unspecified'}", "Use type 8/9 (`algorithm-type scrypt`).")
        elif t == "5":
            f("medium", "ENABLE-SECRET-MD5", "Enable secret hashed with MD5 (type 5)", "enable secret type 5", "Use `algorithm-type scrypt` (type 9) or sha256 (type 8).")
    upw = [ln for ln in cl if re.match(r"username \S+ .*\bpassword\b", ln)]
    if upw:
        sev = "high" if any(re.search(r"password (0 |[^\d])", ln) for ln in upw) else "medium"
        f(sev, "USER-PASSWORD", "Local users with `password` (type 0/7) instead of `secret`",
          f"{len(upw)} user(s): " + "; ".join(m(ln) for ln in upw[:3]), "Re-create users with `username <u> algorithm-type scrypt secret ...`.")
    usec = [ln for ln in cl if re.match(r"username \S+ .*\bsecret 5\b", ln)]
    if usec:
        f("medium", "USER-SECRET-MD5", "Local users with MD5 (type 5) secret", f"{len(usec)} user(s) with type 5 hash",
          "Re-create with `algorithm-type scrypt secret`.")
    type0 = [ln for ln in cl if re.match(r"(enable password|username \S+ .*password|password) (0 )?[^\d\s]", ln) or re.match(r"(enable password|username \S+ .*password|password) 0 ", ln)]
    if has(r"no service password-encryption") and type0:
        f("medium", "NO-PWD-ENCRYPTION", "`no service password-encryption` with cleartext passwords", f"{len(type0)} cleartext password line(s)",
          "Enable `service password-encryption` and migrate to secrets.")

    # SNMP
    comm = [ln for ln in cl if ln.startswith("snmp-server community ")]
    for ln in comm:
        toks = ln.split()
        name, rest, mode, acl, i = toks[2], toks[3:], None, None, 0
        while i < len(rest):
            t = rest[i]
            if t in ("view", "ipv6"):
                i += 2
                continue
            if t.upper() in ("RO", "RW"):
                mode = t.upper()
            else:
                acl = t
            i += 1
        wk = name.lower() in WELL_KNOWN
        sev = "critical" if mode == "RW" else ("high" if wk else "medium")
        f(sev, "SNMP-COMMUNITY", "SNMP v1/v2c community configured",
          f"community *** ({mode or '?'}{', well-known name' if wk else ''}{', ACL ' + acl if acl else ''})",
          "Remove v1/v2c communities; use SNMPv3 with authPriv.")
        if not acl:
            f("medium", "SNMP-NO-ACL", "SNMP community without ACL", f"community *** ({mode or '?'}) has no ACL", "Bind the community to a management-only ACL.")

    # AAA / login
    if not has(r"aaa new-model"):
        f("medium", "NO-AAA", "AAA not enabled (`aaa new-model` absent)", "aaa new-model not found", "Enable AAA with TACACS+/RADIUS and local fallback.")
    if not has(r"login block-for"):
        f("low", "NO-LOGIN-BLOCK", "No `login block-for` brute-force protection", "login block-for not found", "Configure `login block-for 120 attempts 5 within 60`.")

    # Logging / NTP / banner
    lg = o.get("show logging | include Logging|Trap|host", "")
    if not (has(r"logging (host )?\d") or has(r"logging host ") or has(r"logging server ") or re.search(r"Logging to \d", lg)):
        f("low", "NO-REMOTE-LOG", "No remote syslog host configured", "no `logging host` found", "Configure `logging host <syslog-ip>`.")
    if not (has(r"ntp (server|peer) ") or "synchronized" in o.get("show ntp status", "").lower().replace("unsynchronized", "")):
        f("low", "NO-NTP", "No NTP server configured", "no `ntp server` found", "Configure `ntp server <ip>` for time sync.")
    if not has(r"banner (login|motd)"):
        f("info", "NO-BANNER", "No login/MOTD banner", "banner login|motd not found", "Add a legal warning banner.")

    # Legacy services
    for fid, title, cond, ev, fix in (
        ("SVC-SOURCE-ROUTE", "IP source routing enabled", not has(r"no ip source-route"), "`no ip source-route` absent", "Configure `no ip source-route`."),
        ("SVC-PAD", "service pad enabled", has(r"service pad"), "service pad present", "Configure `no service pad`."),
        ("SVC-BOOTP", "BOOTP server enabled", not has(r"no ip bootp server"), "`no ip bootp server` absent", "Configure `no ip bootp server`."),
        ("SVC-SMALL-SERVERS", "TCP/UDP small servers enabled", has(r"service (tcp|udp)-small-servers"), "small-servers present", "Configure `no service tcp-small-servers` / `no service udp-small-servers`."),
        ("SVC-FINGER", "Finger service enabled", has(r"ip finger"), "ip finger present", "Configure `no ip finger`."),
        ("SVC-DOMAIN-LOOKUP", "DNS domain-lookup enabled", not has(r"no ip domain[- ]lookup"), "`no ip domain-lookup` absent", "Configure `no ip domain-lookup` if DNS is not needed."),
    ):
        if cfg and cond:
            f("low", fid, title, ev, fix)

    # CDP
    if cfg and not has(r"no cdp run"):
        n = max(0, len(re.findall(r"^\S+\s*\n?\s+(?:Gig|Fas|Ten|Eth|Twe)\S*\s", o.get("show cdp neighbors", ""), re.M)))
        f("info", "CDP-ENABLED", "CDP enabled globally", f"cdp run active (neighbor entries ~{n})", "Disable on edge ports (`no cdp enable`) or globally if unused.")

    # L2 security features
    if cfg and not has(r"ip dhcp snooping$") and not re.search(r"DHCP snooping is enabled", o.get("show ip dhcp snooping", ""), re.I):
        f("low", "NO-DHCP-SNOOPING", "DHCP snooping not enabled", "ip dhcp snooping not configured", "Enable `ip dhcp snooping` + `ip dhcp snooping vlan ...`.")
    if cfg and not has(r"ip arp inspection vlan"):
        f("low", "NO-DAI", "Dynamic ARP Inspection not enabled", "ip arp inspection vlan not configured", "Enable `ip arp inspection vlan ...` (needs DHCP snooping).")

    # VTP
    vt = o.get("show vtp status", "")
    mm = re.search(r"VTP Operating Mode\s*:\s*(\w+)", vt)
    if mm and mm.group(1).lower() in ("server", "client") and "not configured" in o.get("show vtp password", "").lower():
        f("medium", "VTP-NO-PASSWORD", "VTP server/client mode without password", f"VTP mode {mm.group(1)}", "Use VTP transparent/off or set `vtp password`.")

    # Interfaces
    st = o.get("show interfaces status", "")
    unused = vlan1 = 0
    for ln in st.splitlines():
        mt = re.match(r"^((?:Gi|Fa|Te|Twe|Fo|Eth)\S+)\s+.*?\b(connected|notconnect|disabled|err-disabled|inactive|monitoring|suspended)\s+(\S+)", ln)
        if not mt:
            continue
        if mt.group(2) == "notconnect":
            unused += 1
        if mt.group(3) == "1" and mt.group(2) in ("connected", "notconnect"):
            vlan1 += 1
    if unused:
        f("info", "UNUSED-PORTS", "Unused interfaces not shut down", f"{unused} notconnect port(s)", "Shut down unused ports and park them in an unused VLAN.")
    if vlan1:
        f("low", "ACCESS-VLAN1", "Access ports in VLAN 1", f"{vlan1} port(s) in VLAN 1", "Move user ports out of VLAN 1.")
    nat = [h.split()[1] for h, b in bl if h.startswith("interface ") and "switchport mode trunk" in b
           and not any(x.startswith("switchport trunk native vlan") for x in b)]
    if nat:
        f("low", "TRUNK-NATIVE-VLAN1", "Trunks using native VLAN 1", f"{len(nat)} trunk(s): " + ", ".join(nat[:6]),
          "Set `switchport trunk native vlan <unused>` on trunks.")
    return res, ver


def audit_device(dev, outroot):
    host = dev["hostname"]
    cred = dev["credential_ref"] or "DEFAULT"
    params = {
        "device_type": dev["os_type"] or "cisco_ios",
        "host": dev["mgmt_ip"],
        "username": os.getenv(f"NET_{cred}_USERNAME"),
        "password": os.getenv(f"NET_{cred}_PASSWORD"),
        "secret": os.getenv(f"NET_{cred}_ENABLE") or "",
        "conn_timeout": 15,
        "auth_timeout": 20,
    }
    outputs, cmd_errors = {}, {}
    try:
        with ConnectHandler(**params) as conn:
            if params["secret"] and not conn.check_enable_mode():
                conn.enable()
            for cmd in COMMANDS:
                try:
                    outputs[cmd] = conn.send_command(cmd, read_timeout=120)
                except Exception as e:  # noqa: BLE001
                    outputs[cmd] = ""
                    cmd_errors[cmd] = f"{type(e).__name__}"
    except Exception as e:  # noqa: BLE001 - never stop the run
        msg = str(e).splitlines()[0][:120] if str(e) else ""
        return {"hostname": host, "ip": dev["mgmt_ip"], "error": f"{type(e).__name__}: {msg}", "findings": []}

    ddir = outroot / re.sub(r"[^\w.-]", "_", host)
    ddir.mkdir(mode=0o700, exist_ok=True)
    for cmd, out in outputs.items():
        p = ddir / f"{slug(cmd)}.txt"
        p.write_text(out)
        p.chmod(0o600)
    parsed = {c: ("" if INVALID.search(out[:200]) else out) for c, out in outputs.items()}
    try:
        findings, ver = analyze(dev, parsed)
    except Exception as e:  # noqa: BLE001
        return {"hostname": host, "ip": dev["mgmt_ip"], "error": f"analysis {type(e).__name__}: {e}", "findings": []}
    return {"hostname": host, "ip": dev["mgmt_ip"], "version": ver, "findings": findings, "cmd_errors": cmd_errors}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", nargs="+", help="limit to these hostnames / IPs")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--outdir", default="audits")
    args = ap.parse_args()

    os.umask(0o077)
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    devs = [dict(r) for r in db.execute("SELECT * FROM devices WHERE status='active' ORDER BY mgmt_ip")]
    if args.hosts:
        want = {h.lower() for h in args.hosts}
        devs = [d for d in devs if d["hostname"].lower() in want or d["mgmt_ip"] in want]
    if not devs:
        raise SystemExit("no matching active devices")

    base = ROOT / args.outdir
    base.mkdir(mode=0o700, exist_ok=True)
    base.chmod(0o700)
    outroot = base / date.today().isoformat()
    outroot.mkdir(mode=0o700, exist_ok=True)
    print(f"auditing {len(devs)} device(s) -> {outroot}")

    with ThreadPoolExecutor(args.workers) as ex:
        results = list(ex.map(lambda d: audit_device(d, outroot), devs))

    findings = [x for r in results for x in r["findings"]]
    findings.sort(key=lambda x: (SEV_ORDER.index(x["severity"]), x["id"], x["hostname"]))
    (outroot / "findings.json").write_text(json.dumps(findings, indent=2))
    with open(outroot / "findings.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["hostname", "ip", "severity", "id", "title", "evidence", "remediation"])
        w.writeheader()
        w.writerows(findings)

    ok = [r for r in results if "error" not in r]
    bad = [r for r in results if "error" in r]
    lines = [f"Audit {date.today()}: {len(ok)} audited, {len(bad)} failed, {len(findings)} findings", "", "Per-device severity counts"]
    for r in sorted(ok, key=lambda r: r["hostname"]):
        c = Counter(x["severity"] for x in r["findings"])
        lines.append(f"  {r['hostname']:28} {r['ip']:15} " + " ".join(f"{s}={c.get(s, 0)}" for s in SEV_ORDER))
    per_check = defaultdict(set)
    meta = {}
    for x in findings:
        per_check[x["id"]].add(x["hostname"])
        meta[x["id"]] = (x["severity"], x["title"])
    lines += ["", "Per-check affected devices"]
    for cid in sorted(per_check, key=lambda i: (SEV_ORDER.index(meta[i][0]), i)):
        lines.append(f"  [{meta[cid][0]:8}] {cid:22} {len(per_check[cid]):3} device(s)  {meta[cid][1]}")
    lines += ["", "Unreachable / failed devices"]
    lines += [f"  {r['hostname']:28} {r['ip']:15} {r['error']}" for r in bad] or ["  none"]
    skipped = [(r["hostname"], c, e) for r in ok for c, e in r.get("cmd_errors", {}).items()]
    if skipped:
        lines += ["", "Command errors (output empty)"] + [f"  {h}: {c}: {e}" for h, c, e in skipped]
    (outroot / "summary.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:1] + [""] + [l for l in lines if l.startswith("  ") and "device(s)" not in l][:0]))
    for r in ok:
        c = Counter(x["severity"] for x in r["findings"])
        print(f"OK   {r['hostname']:28} {r['ip']:15} " + " ".join(f"{s}={c.get(s, 0)}" for s in SEV_ORDER))
    for r in bad:
        print(f"FAIL {r['hostname']:28} {r['ip']:15} {r['error']}")


if __name__ == "__main__":
    main()
