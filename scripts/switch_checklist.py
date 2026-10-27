"""READ-ONLY switch / router checklist for Cisco IOS and IOS-XE devices from the inventory.

Usage:
    cfn switch-checklist [TARGETS...] [--match GLOB] [--role R] [--all]
        [--workers 16] [--timeout 30] [--out DIR] [--from-raw DIR] [--threshold KEY=VALUE ...]

Default target is --all (every active cisco_ios / cisco_xe device). Items SW01-SW34 are defined in
.claude/skills/checklist/switch.md (the approved spec); thresholds are the TH constants below (keep both in sync).

One concurrent netmiko pass per device sends only `show` commands (checked with netlib.require_readonly). A command the
device rejects (`% Invalid input`) means the item is skipped for that device, not an error. Unreachable and `auth_failed`
devices are reported under SW01 and never abort the run. Suggestions are text only, never sent.

SW02 and SW14-SW28 reuse audit.analyze() findings (AUDIT_MAP); SW12, SW25, SW28, SW29 reuse log_audit.assess().
audit.py findings without a checklist item (legacy services such as source-route, PAD, BOOTP) are kept as
`other_findings` in summary.json and in the "Other hardening findings" section of checklist.md.
Core devices (SW13, SW14) = role `core` in the inventory, else every collected hostname containing `core`.
Raw output is saved masked (audit.py's secret masking, SNMP communities included) under <out>/raw/<host>/ together
with meta.json, so `--from-raw DIR` re-analyzes a saved run offline with identical results.

Outputs under --out (default reports/checklist/switch/<YYYYmmdd-HHMMSS>):
    summary.json   {generated, scope, items[{id, section, title, status, reason, findings[]}], counts, other_findings}
    checklist.md   every item as a checkbox line, findings tables under non-pass items
    findings.csv   one row per finding
    raw/<host>/    masked raw command output (dirs 700, files 600)
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import traceback
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

import audit
import log_audit
import netlib
from netlib import ROOT
from netmiko import ConnectHandler

SEV_RANK = {"INFO": 0, "WARN": 1, "CRIT": 2}
STATUS_ICON = {"pass": "✅", "warn": "⚠️", "crit": "❌", "info": "ℹ️", "skip": "➖"}
SUPPORTED_OS = ("cisco_ios", "cisco_xe")

# Thresholds (switch.md). Override with --threshold KEY=VALUE.
TH = {
    "uptime_warn_days": 365,                      # SW03
    "cpu_warn": 70, "cpu_crit": 90,               # SW06 5-minute average %
    "mem_free_warn": 20,                          # SW06 % free
    "flash_free_warn": 15,                        # SW07 % free
    "poe_warn": 85,                               # SW08 % used
    "err_min": 100,                               # SW10 input errors (FCS+align+rcv+runts) per port before warning
    "uplink_min_mbps": 1000,                      # SW11 trunk/uplink speed
    "stp_tc_min": 1,                              # SW13 topology changes in the last 24 h
    "backup_max_days": 7,                         # SW31
    "log_hours": 24,                              # logging window for SW12/SW25/SW29/SW33
}

ITEMS = [
    ("SW01", "A. Reachability and platform", "SSH reachable + login; auth_failed devices listed"),
    ("SW02", "A. Reachability and platform", "Software EOL; version spread across fleet"),
    ("SW03", "A. Reachability and platform", "Uptime; last reload reason crash/power"),
    ("SW04", "A. Reachability and platform", "Inventory drift: serial/model/version differ from inventory DB"),
    ("SW05", "B. Hardware health", "PSU / fans / temperature (show environment)"),
    ("SW06", "B. Hardware health", "CPU 5-min avg; memory free"),
    ("SW07", "B. Hardware health", "Flash free"),
    ("SW08", "B. Hardware health", "Stack members / ring; PoE budget"),
    ("SW09", "B. Hardware health", "SFP optics out of range (show interfaces transceiver)"),
    ("SW10", "C. Interfaces and L2", "CRC / input errors / runts; err-disabled ports"),
    ("SW11", "C. Interfaces and L2", "Half duplex / duplex mismatch; uplinks below expected speed"),
    ("SW12", "C. Interfaces and L2", "Flapping interfaces (logs)"),
    ("SW13", "C. Interfaces and L2", "STP root is the core; topology changes in 24 h; edge ports without BPDU guard"),
    ("SW14", "C. Interfaces and L2", "Native VLAN 1 / access VLAN 1; VLANs on access switches missing on core"),
    ("SW15", "C. Interfaces and L2", "EtherChannel members down/suspended"),
    ("SW16", "C. Interfaces and L2", "Unused ports not shut down"),
    ("SW17", "D. Security hardening", "Smart Install enabled"),
    ("SW18", "D. Security hardening", "Telnet on vty; SSH v1; RSA key under 2048 bits"),
    ("SW19", "D. Security hardening", "No vty ACL; no/disabled exec-timeout; no login block-for"),
    ("SW20", "D. Security hardening", "enable password, weak/type-5 secrets, no password-encryption"),
    ("SW21", "D. Security hardening", "No AAA; local accounts only"),
    ("SW22", "D. Security hardening", "SNMP default/weak community; no ACL; v1/v2c"),
    ("SW23", "D. Security hardening", "HTTP/HTTPS server enabled"),
    ("SW24", "D. Security hardening", "VTP server/client without password"),
    ("SW25", "D. Security hardening", "DHCP snooping / DAI off; port-security violations in 24 h"),
    ("SW26", "D. Security hardening", "No banner; CDP enabled"),
    ("SW27", "E. Management and operations", "NTP configured and synchronized"),
    ("SW28", "E. Management and operations", "Remote syslog; logging buffer size"),
    ("SW29", "E. Management and operations", "Critical log events (sev 0-2) in 24 h"),
    ("SW30", "E. Management and operations", "Running config not saved to startup"),
    ("SW31", "E. Management and operations", "Latest backup in backups/<host>/"),
    ("SW32", "E. Management and operations", "Users logged in now"),
    ("SW33", "F. Routing (L3 devices only)", "OSPF/EIGRP/BGP neighbors up; flaps in 24 h"),
    ("SW34", "F. Routing (L3 devices only)", "Default route present; HSRP/VRRP state"),
]

# audit.py finding id -> (checklist item, severity; None = derive from the audit severity)
AUDIT_MAP = {
    "OS-EOL": ("SW02", "CRIT"),
    "ACCESS-VLAN1": ("SW14", "WARN"), "TRUNK-NATIVE-VLAN1": ("SW14", "WARN"),
    "UNUSED-PORTS": ("SW16", "INFO"),
    "SMI-ENABLED": ("SW17", "CRIT"),
    "VTY-TELNET": ("SW18", "CRIT"), "SSH-V1": ("SW18", "CRIT"), "SSH-WEAK-RSA": ("SW18", "WARN"),
    "VTY-NO-ACL": ("SW19", "WARN"), "LINE-TIMEOUT-NONE": ("SW19", "WARN"), "LINE-TIMEOUT-DEFAULT": ("SW19", "WARN"),
    "NO-LOGIN-BLOCK": ("SW19", "WARN"),
    "ENABLE-PASSWORD": ("SW20", "CRIT"), "ENABLE-SECRET-WEAK": ("SW20", "CRIT"), "ENABLE-SECRET-MD5": ("SW20", "WARN"),
    "USER-PASSWORD": ("SW20", None), "USER-SECRET-MD5": ("SW20", "WARN"), "NO-PWD-ENCRYPTION": ("SW20", "WARN"),
    "LINE-PASSWORD": ("SW20", "WARN"),
    "NO-AAA": ("SW21", "WARN"),
    "SNMP-COMMUNITY": ("SW22", None), "SNMP-NO-ACL": ("SW22", "WARN"),
    "HTTP-ENABLED": ("SW23", "WARN"),
    "VTP-NO-PASSWORD": ("SW24", "WARN"),
    "NO-DHCP-SNOOPING": ("SW25", "INFO"), "NO-DAI": ("SW25", "INFO"),
    "NO-BANNER": ("SW26", "INFO"), "CDP-ENABLED": ("SW26", "INFO"),
    "NO-NTP": ("SW27", "WARN"),
    "NO-REMOTE-LOG": ("SW28", "WARN"),
}
IGNORED_AUDIT_IDS = ("OS-VERSION", "CFG-UNAVAILABLE")
CONFIG_ITEMS = ["SW14", "SW16", "SW17", "SW18", "SW19", "SW20", "SW21", "SW22", "SW23", "SW24", "SW25", "SW26", "SW27", "SW28"]

HEAVY = ("show running-config", "show startup-config", "show logging", "show interfaces transceiver",
         "show archive config differences", "show crypto key mypubkey rsa", "show interfaces status",
         "show interfaces counters errors", "show vlan brief", "show spanning-tree detail")
# canonical command -> fallbacks tried in order when the previous one is rejected
FALLBACKS = {
    "show environment all": ["show env all", "show environment"],
    "show processes cpu sorted | include CPU": ["show processes cpu | include CPU"],
    "show processes memory sorted | include Processor": ["show processes memory | include Processor"],
}
ARCHIVE_CMD = "show archive config differences nvram:startup-config system:running-config"
STARTUP_CMD = "show startup-config"
EXTRA_COMMANDS = [
    "show environment all",
    "show processes cpu sorted | include CPU",
    "show processes memory sorted | include Processor",
    "show memory statistics",
    "show file systems",
    "show switch",
    "show switch stack-ring speed",
    "show power inline | include Available|Used",
    "show interfaces transceiver",
    "show interfaces counters errors",
    "show interfaces status err-disabled",
    "show spanning-tree root",
    "show spanning-tree detail | include occurr|from|ieee",
    "show etherchannel summary",
    "show vlan brief",
    ARCHIVE_CMD,
    "show ntp associations",
    "show ip route 0.0.0.0",
    "show ip ospf neighbor",
    "show ip eigrp neighbors",
    "show ip bgp summary",
    "show standby brief",
    "show vrrp brief",
    "show logging",
    "show clock",
]
COMMANDS = list(dict.fromkeys(audit.COMMANDS + EXTRA_COMMANDS))
INVALID = re.compile(audit.INVALID.pattern + r"|% ?(BGP not active|IP routing not enabled|Command rejected|No such)", re.IGNORECASE)
ARCHIVE_FAIL = re.compile(r"archive|not (?:supported|enabled|configured)|% ?Invalid|% ?Incomplete|path", re.IGNORECASE)
VOLATILE = re.compile(r"^(Building configuration|Current configuration|Using \d+ out of|!|ntp clock-period)", re.IGNORECASE)
IFACE = re.compile(r"^(?:Gi|Fa|Te|Twe|Fo|Hu|Eth|Et|Po|Ap)[A-Za-z]*\d")
MASK_PREFIXES = ("show running-config", "show startup-config", "show archive", "show snmp")


# --------------------------------------------------------------------------- helpers
def slug(cmd):
    return re.sub(r"[^A-Za-z0-9]+", "_", cmd).strip("_").lower()[:60]


def safe(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def mask_secrets(text):
    """audit.py's masking (audit.m) of secret-like tokens; well-known SNMP community names stay visible for the analysis."""
    def sub(x):
        if x.group(1).lower() == "community":
            val = x.group(3) if x.group(3).lower() in audit.WELL_KNOWN else "***"
            return f"{x.group(1)}{x.group(2)} {val}"
        return f"{x.group(1)}{x.group(2)} ***"
    text = audit.SECRET_RE.sub(sub, text)
    return re.sub(r"(?im)^(\s*Community name:\s*)\S+", r"\1***", text)


def err_text(e):
    return f"{type(e).__name__}: {str(e).splitlines()[0][:140] if str(e) else ''}"


def sev_from_audit(s):
    return "CRIT" if s in ("critical", "high") else "WARN" if s == "medium" else "INFO"


def pct(a, b):
    return round(100 * a / b, 1) if b else None


def short(items, n=5, sep=", "):
    items = list(items)
    return sep.join(items[:n]) + (f" (+{len(items) - n} more)" if len(items) > n else "")


class Res:
    """Per-item findings plus the devices on which an item was (or could not be) evaluated."""

    def __init__(self):
        self.findings = defaultdict(list)
        self.ran = defaultdict(set)
        self.skips = defaultdict(dict)

    def ok(self, item, host):
        self.ran[item].add(host)

    def add(self, item, host, sev, detail, sugg=""):
        self.ran[item].add(host)
        self.findings[item].append({"target": host, "vcenter": "", "severity": sev, "detail": detail, "suggestion": sugg})

    def skip(self, item, host, why):
        self.skips[item][host] = why


# --------------------------------------------------------------------------- collection
def run_cmd(conn, cmd, timeout):
    mult = 4 if cmd.startswith(HEAVY) else 1
    return conn.send_command(cmd, read_timeout=timeout * mult)


def cmd_unusable(text, errors, cmd):
    return cmd in errors or bool(INVALID.search(text[:200])) or (
        bool(ARCHIVE_FAIL.search(text[:300])) and not re.search(r"No changes were found|Contextual Config Diffs|^[+-]", text, re.MULTILINE))


def latest_backup(host):
    d = ROOT / "backups" / host
    files = [p for p in d.glob("*") if p.is_file()] if d.is_dir() else []
    best = None
    for p in files:
        m = re.search(r"(\d{8})-(\d{6})", p.name)
        t = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S") if m else datetime.fromtimestamp(p.stat().st_mtime)
        if best is None or t > best[1]:
            best = (p.name, t)
    return {"name": best[0], "time": best[1].isoformat(timespec="seconds")} if best else None


def collect_device(dev, args, stamp_dir):
    host = dev["hostname"]
    meta = {"hostname": host, "ip": dev["mgmt_ip"], "model": dev.get("model"), "os_version": dev.get("os_version"),
            "serial": dev.get("serial"), "os_type": dev.get("os_type"), "role": dev.get("role"),
            "collected_at": datetime.now().isoformat(timespec="seconds"), "connect_error": None, "error_kind": None,
            "cmd_errors": {}, "variants": {}, "latest_backup": latest_backup(host)}
    outputs = {}
    try:
        params = netlib.conn_params(dev)
        params.update({"conn_timeout": max(15, args.timeout // 2), "auth_timeout": max(20, args.timeout), "banner_timeout": 25})
        with ConnectHandler(**params) as conn:
            if params["secret"] and not conn.check_enable_mode():
                conn.enable()
            for cmd in COMMANDS:
                tries = [cmd] + FALLBACKS.get(cmd, [])
                out = ""
                for variant in tries:
                    try:
                        out = run_cmd(conn, variant, args.timeout)
                    except Exception as e:  # noqa: BLE001 - per-command failure, keep going
                        meta["cmd_errors"][cmd] = err_text(e)
                        out = ""
                        break
                    if not INVALID.search(out[:200]) or variant == tries[-1]:
                        meta["variants"][cmd] = variant
                        break
                outputs[cmd] = mask_secrets(out) if cmd.startswith(MASK_PREFIXES) else out
            if cmd_unusable(outputs.get(ARCHIVE_CMD, ""), meta["cmd_errors"], ARCHIVE_CMD):
                try:  # fallback for SW30: compare running vs saved config
                    outputs[STARTUP_CMD] = mask_secrets(run_cmd(conn, STARTUP_CMD, args.timeout))
                except Exception as e:  # noqa: BLE001
                    meta["cmd_errors"][STARTUP_CMD] = err_text(e)
                    outputs[STARTUP_CMD] = ""
    except Exception as e:  # noqa: BLE001 - never crash the run
        name = type(e).__name__
        msg = str(e).splitlines()[0][:140] if str(e) else ""
        meta["connect_error"] = f"{name}: {msg}"
        meta["error_kind"] = ("auth" if "Authentication" in name else
                              "timeout" if "Timeout" in name or "timed out" in msg.lower() else "other")
    save_raw(stamp_dir, host, meta, outputs)
    return meta, outputs


def save_raw(stamp_dir, host, meta, outputs):
    d = stamp_dir / "raw" / safe(host)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    for cmd, out in outputs.items():
        p = d / f"{slug(cmd)}.txt"
        p.write_text(out)
        p.chmod(0o600)
    p = d / "meta.json"
    p.write_text(json.dumps(dict(meta, files={cmd: f"{slug(cmd)}.txt" for cmd in outputs}), indent=2))
    p.chmod(0o600)


def load_raw(src):
    raw = src / "raw" if (src / "raw").is_dir() else src
    devs = []
    for mp in sorted(raw.glob("*/meta.json")):
        meta = json.loads(mp.read_text())
        outputs = {cmd: (mp.parent / fn).read_text() for cmd, fn in meta.get("files", {}).items() if (mp.parent / fn).exists()}
        devs.append((meta, outputs))
    inv = raw / "_inventory.json"
    return devs, (json.loads(inv.read_text()).get("auth_failed", []) if inv.exists() else [])


# --------------------------------------------------------------------------- parsing
def version_of(show_version):
    m = re.search(r"Version\s+([0-9][^\s,]*)", show_version or "")
    return m.group(1) if m else None


def parse_uptime_days(show_version):
    m = re.search(r"(?m)^\S+ uptime is (.+)$", show_version or "")
    if not m:
        return None, None
    days = 0.0
    for n, unit in re.findall(r"(\d+)\s+(year|week|day|hour|minute)", m.group(1)):
        days += int(n) * {"year": 365, "week": 7, "day": 1, "hour": 1 / 24, "minute": 1 / 1440}[unit]
    return days, m.group(1).strip()


UNEXPECTED_RELOAD = re.compile(r"power[- ]?(on|cycle|fail|loss|supply)|crash|exception|abnormal|watchdog|panic|critical process|"
                               r"kernel|bus error|fault|unexpected|error|hw reset|software forced|fatal|cpu reset", re.IGNORECASE)
# 3850/9200 report "Power Failure or Unknown" / "power-on" after ordinary restarts too: a power-type reason is only
# a WARN when the restart is recent (a real power event worth a look); a crash-type reason always is.
CRASH_RELOAD = re.compile(r"crash|exception|watchdog|panic|critical process|kernel|bus error|fatal|cpu reset", re.IGNORECASE)
RECENT_RESTART_DAYS = 7


def reload_reason(show_version):
    m = re.search(r"(?im)^\s*Last reload (?:reason|cause)\s*:\s*(.+)$", show_version or "") or \
        re.search(r"(?im)^System returned to ROM by (.+?)\s*$", show_version or "")
    return m.group(1).strip() if m else None


STATUS_RX = re.compile(r"^(\S+)\s+(?:(.*?)\s+)?(connected|notconnect|disabled|err-disabled|inactive|monitoring|suspended|"
                       r"sfp-config-mismatch|routed|faulty)\s+(\S+)\s+((?:a-)?(?:full|half)|auto)\s+((?:a-)?\d+[GMK]?|auto)(?:\s+(.*?))?\s*$", re.IGNORECASE)


def parse_status_rows(text):
    rows = []
    for ln in (text or "").splitlines():
        m = STATUS_RX.match(ln)
        if m and IFACE.match(m.group(1)):
            rows.append({"port": m.group(1), "name": m.group(2) or "", "status": m.group(3).lower(), "vlan": m.group(4),
                         "duplex": m.group(5).lower(), "speed": m.group(6).lower(), "type": m.group(7) or ""})
    return rows


def speed_mbps(tok):
    t = tok.replace("a-", "")
    if t == "auto":
        return None
    n = int(re.sub(r"\D", "", t) or 0)
    return n * 1000 if t.endswith("g") else n


def parse_counters_errors(text):
    ports, cols = defaultdict(dict), None
    for ln in (text or "").splitlines():
        t = ln.split()
        if not t:
            continue
        if t[0] == "Port" and len(t) > 2:
            cols = t[1:]
        elif cols and IFACE.match(t[0]) and len(t) == len(cols) + 1 and all(x.isdigit() for x in t[1:]):
            for c, v in zip(cols, t[1:]):
                ports[t[0]][c] = int(v)
    return ports


FLAG_RX = re.compile(r"^-?\d+(?:\.\d+)?(\+\+|--|\+|-)$")


def parse_transceiver(text):
    bad = {}
    for ln in (text or "").splitlines():
        t = ln.split()
        if t and IFACE.match(t[0]) and len(t) > 1:
            flagged = [x for x in t[1:] if FLAG_RX.match(x)]
            if flagged:
                bad[t[0]] = " ".join(flagged)
    return bad


def parse_env(text):
    crit, warn = [], []
    for ln in (text or "").splitlines():
        s = ln.strip()
        low = s.lower()
        if not s or "threshold" in low or re.search(r"not present|not installed|n/a|absent|not supported", low):
            continue
        if re.search(r"\bstate\s*:\s*red\b|\b(fail(ed|ure)?|faulty|fault|critical|not ok|bad|not functioning|shutdown|overtemp\w*)\b", low) \
                and not re.search(r"\b(no|0)\s+(fail|fault)", low):
            crit.append(s[:100])
        elif re.search(r"\bstate\s*:\s*yellow\b", low):
            warn.append(s[:100])
    return crit, warn


def parse_memory(proc_mem, mem_stats):
    m = re.search(r"Processor\s+Pool\s+Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)", proc_mem or "")
    if m:
        return int(m.group(1)), int(m.group(3))
    m = re.search(r"(?m)^\s*Processor\s+\w+\s+(\d+)\s+(\d+)\s+(\d+)", mem_stats or "")
    return (int(m.group(1)), int(m.group(3))) if m else (None, None)


def parse_flash(text):
    out = []
    for ln in (text or "").splitlines():
        m = re.search(r"(\d+)\s+(\d+)\s+(?:flash|disk|unknown|opaque|nvram)\s+\S+\s+(\S*flash\S*:)", ln, re.IGNORECASE)
        if m and int(m.group(1)):
            out.append((m.group(3), int(m.group(1)), int(m.group(2))))
    return out


def parse_vlans(text):
    """{vlan id: has_ports} for active VLANs from `show vlan brief` (the port list may wrap onto continuation lines)."""
    vl, cur = {}, None
    for ln in (text or "").splitlines():
        m = re.match(r"^(\d+)\s+(\S+)\s+(active|act/unsup|act/lshut|suspended)\b\s*(.*)$", ln)
        if m:
            cur = int(m.group(1))
            vl[cur] = bool(m.group(4).strip()) and m.group(3) == "active"
        elif cur and re.match(r"^\s+\S", ln) and re.search(r"\d/\d", ln):
            vl[cur] = True
        elif ln.strip() and not ln.startswith(" "):
            cur = None
    return vl


STP_ROOT_RX = re.compile(r"^(VLAN\d+|MST\d+)\s+(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\d+)\s+\d+\s+\d+\s+\d+\s*(.*)$", re.IGNORECASE)


def parse_stp_root(text):
    return {m.group(1): {"prio": m.group(2), "addr": m.group(3).lower(), "cost": int(m.group(4))}
            for ln in (text or "").splitlines() if (m := STP_ROOT_RX.match(ln.strip()))}


def parse_stp_detail(text):
    blocks, cur = [], None
    for ln in (text or "").splitlines():
        m = re.search(r"(VLAN\d+|MST\d+) is executing the ieee", ln)
        if m:
            cur = {"id": m.group(1), "tc": 0, "recent": False, "from": None}
            blocks.append(cur)
            continue
        if cur is None:
            continue
        m = re.search(r"Number of topology changes (\d+) last change occurred (\S+) ago", ln)
        if m:
            cur["tc"] = int(m.group(1))
            hm = re.match(r"(\d+):\d+:\d+", m.group(2))
            cur["recent"] = bool(hm and int(hm.group(1)) < 24)
            continue
        m = re.match(r"^\s+from\s+(\S+)\s*$", ln)
        if m:
            cur["from"] = m.group(1)
    return blocks


def edge_ports_without_bpduguard(cfg):
    cl = [ln.strip() for ln in cfg.splitlines()]
    global_guard = any(re.match(r"spanning-tree portfast (edge )?bpduguard default", ln) for ln in cl)
    global_pf = any(re.match(r"spanning-tree portfast (edge )?default", ln) for ln in cl)
    bad = []
    for h, b in audit.blocks(cfg):
        if not h.startswith("interface ") or "switchport mode trunk" in b:
            continue
        pf = any(re.match(r"spanning-tree portfast( edge)?$", x) for x in b) or (global_pf and "switchport mode access" in b)
        if pf and not (global_guard or any(x.startswith("spanning-tree bpduguard enable") for x in b)):
            bad.append(h.split(None, 1)[1])
    return bad


def parse_etherchannel(text):
    members = re.findall(r"((?:Gi|Fa|Te|Twe|Fo|Hu|Eth)[A-Za-z]*\d\S*?)\((\w+)\)", text or "")
    pos = re.findall(r"\b(Po\d+)\((\w+)\)", text or "")
    return members, pos


def parse_log_clock(show_clock, fallback_iso):
    m = re.search(r"(\d+:\d+:\d+)(?:\.\d+)?\s+\S+\s+\w{3}\s+(\w{3})\s+(\d+)\s+(\d{4})", show_clock or "")
    if m:
        try:
            return datetime.strptime(f"{m.group(4)} {m.group(2)} {m.group(3)} {m.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
    return datetime.fromisoformat(fallback_iso)


LOG_TS = re.compile(r"^\s*(?:\d+:\s*)?[*.]?\s*([A-Z][a-z]{2})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d\d:\d\d:\d\d)")


def filter_log(text, now, hours):
    """Keep only log-buffer lines from the last `hours` (device clock). Lines without a datetime stamp are kept."""
    header, lines, size = log_audit.split_logging(text or "")
    if size is None:
        return text or ""
    keep = []
    for ln in lines:
        m = LOG_TS.match(ln)
        if m:
            try:
                dt = datetime.strptime(f"{m.group(3) or now.year} {m.group(1)} {m.group(2)} {m.group(4)}", "%Y %b %d %H:%M:%S")
            except ValueError:
                keep.append(ln)
                continue
            if dt > now + timedelta(days=1):
                dt = dt.replace(year=dt.year - 1)
            if now - dt > timedelta(hours=hours):
                continue
        keep.append(ln)
    return header + f"Log Buffer ({size} bytes):\n" + "\n".join(keep) + "\n"


def strip_volatile(text):
    return [ln.rstrip() for ln in (text or "").splitlines() if ln.strip() and not VOLATILE.match(ln.strip())]


# --------------------------------------------------------------------------- per-device checks
class Dev:
    """One device's collected outputs; `has` = the device accepted the command."""

    def __init__(self, meta, outputs):
        self.meta, self.o = meta, outputs
        self.host, self.ip = meta["hostname"], meta["ip"]
        self.errors = meta.get("cmd_errors", {})

    def has(self, cmd):
        return cmd in self.o and cmd not in self.errors and not INVALID.search(self.o[cmd][:200])

    def get(self, cmd):
        return self.o.get(cmd, "") if self.has(cmd) else ""

    @property
    def cfg(self):
        return self.o.get("show running-config", "")


def check_platform(d, R):
    host, sv, inv = d.host, d.get("show version"), d.meta
    if not sv.strip():
        for i in ("SW03", "SW04"):
            R.skip(i, host, "show version unavailable")
        return
    days, up = parse_uptime_days(sv)
    if days is None:
        R.skip("SW03", host, "uptime not found in show version")
    else:
        R.ok("SW03", host)
        if days > TH["uptime_warn_days"]:
            R.add("SW03", host, "WARN", f"uptime {up} (> {TH['uptime_warn_days']} days)",
                  "Plan a maintenance window for patching and a restart")
        why = reload_reason(sv)
        if why and UNEXPECTED_RELOAD.search(why):
            sev = "WARN" if CRASH_RELOAD.search(why) or days < RECENT_RESTART_DAYS else "INFO"
            R.add("SW03", host, sev, f"last restart reason: {why[:120]} (uptime {up})",
                  "Investigate the crash / power event (show logging, crashinfo, power feed)")
    drift = []
    ver = version_of(sv)
    if inv.get("serial") and inv["serial"].lower() not in sv.lower():
        drift.append(f"serial {inv['serial']} not in show version")
    if inv.get("model") and inv["model"].lower() not in sv.lower():
        drift.append(f"model {inv['model']} not reported")
    iv = inv.get("os_version")
    if iv and ver and iv.lower() not in ver.lower() and ver.lower() not in iv.lower() and iv.lower() not in sv.lower():
        drift.append(f"version inventory {iv} vs device {ver}")
    R.ok("SW04", host)
    if drift:
        R.add("SW04", host, "INFO", "; ".join(drift), "Refresh the inventory: cfn discover <ip>")


def check_hardware(d, R):
    host = d.host
    env = d.get("show environment all")
    if not env.strip():
        R.skip("SW05", host, "show environment unsupported or empty")
    else:
        crit, warn = parse_env(env)
        R.ok("SW05", host)
        if crit:
            R.add("SW05", host, "CRIT", short(crit, 3, " | "), "Check PSU / fan / temperature; replace the failed part")
        if warn:
            R.add("SW05", host, "WARN", short(warn, 3, " | "), "Check airflow and ambient temperature")
    cpu_t = d.get("show processes cpu sorted | include CPU")
    cm = re.search(r"five minutes:\s*(\d+)%", cpu_t)
    total, free = parse_memory(d.get("show processes memory sorted | include Processor"), d.get("show memory statistics"))
    if not cm and total is None:
        R.skip("SW06", host, "CPU / memory output not parsable")
    else:
        R.ok("SW06", host)
        if cm and int(cm.group(1)) > TH["cpu_warn"]:
            c = int(cm.group(1))
            R.add("SW06", host, "CRIT" if c > TH["cpu_crit"] else "WARN", f"CPU 5-min average {c}%",
                  "Find the busy process: show processes cpu sorted")
        if total and pct(free, total) < TH["mem_free_warn"]:
            R.add("SW06", host, "WARN", f"processor memory {pct(free, total)}% free ({free // 1024} of {total // 1024} KB)",
                  "Check show processes memory sorted for leaks; plan a restart")
    fl = parse_flash(d.get("show file systems"))
    if not fl:
        R.skip("SW07", host, "no flash file system in show file systems")
    else:
        R.ok("SW07", host)
        low = [f"{n} {pct(fr, sz)}% free ({fr // 1048576} of {sz // 1048576} MB)" for n, sz, fr in fl if pct(fr, sz) < TH["flash_free_warn"]]
        if low:
            R.add("SW07", host, "WARN", "; ".join(low), "Remove old images / unused files from flash")
    check_stack_poe(d, R)
    xc = d.get("show interfaces transceiver")
    if not xc.strip():
        R.skip("SW09", host, "show interfaces transceiver unsupported or no optics")
    else:
        R.ok("SW09", host)
        bad = parse_transceiver(xc)
        if bad:
            R.add("SW09", host, "WARN", f"{len(bad)} optic(s) out of range: " + short(f"{p} ({v})" for p, v in bad.items()),
                  "Clean / reseat or replace the SFP and check the fibre")


def check_stack_poe(d, R):
    host = d.host
    sw, ring = d.get("show switch"), d.get("show switch stack-ring speed")
    poe = d.get("show power inline | include Available|Used")
    problems, ran = [], False
    if sw.strip():
        ran = True
        for m in re.finditer(r"(?m)^\s*\*?(\d+)\s+(Active|Standby|Member|Master|Slave)\s+\S+\s+\d+\s+\S+\s+(.+?)\s*$", sw):
            if m.group(3).strip().lower() != "ready":
                problems.append(f"member {m.group(1)} ({m.group(2)}) state {m.group(3).strip()}")
    if ring.strip():
        ran = True
        if re.search(r"\bhalf\b", ring, re.IGNORECASE):
            problems.append("stack ring is half (a cable or stack port is down)")
    if problems:
        R.add("SW08", host, "CRIT", "; ".join(problems), "Check stack cables and member power: show switch detail")
    pcts = [(pct(float(u), float(a)), a, u) for a, u in re.findall(r"Available:\s*([\d.]+)\D*?Used:\s*([\d.]+)", poe) if float(a) > 0]
    if pcts:
        ran = True
        worst = max(pcts)
        if worst[0] > TH["poe_warn"]:
            R.add("SW08", host, "WARN", f"PoE budget {worst[0]}% used ({worst[2]} of {worst[1]} W)",
                  "Reduce PoE load or add power supply capacity")
    if ran:
        R.ok("SW08", host)
    else:
        R.skip("SW08", host, "not a stack and no PoE budget reported")


def check_interfaces(d, R, logs):
    host = d.host
    ce = d.get("show interfaces counters errors")
    if not ce.strip() and not d.has("show interfaces status err-disabled"):
        R.skip("SW10", host, "interface counters / err-disabled output unavailable")
    else:
        R.ok("SW10", host)
        bad = []
        for port, c in parse_counters_errors(ce).items():
            tot = sum(c.get(k, 0) for k in ("FCS-Err", "Align-Err", "Rcv-Err", "Runts"))
            if tot >= TH["err_min"]:
                bad.append((tot, port))
        if bad:
            bad.sort(reverse=True)
            R.add("SW10", host, "WARN", f"{len(bad)} port(s) with input errors/runts >= {TH['err_min']}: " +
                  short(f"{p} ({t})" for t, p in bad), "Check cable / SFP / duplex on those ports")
        ed = [ln.split() for ln in d.get("show interfaces status err-disabled").splitlines() if "err-disabled" in ln and IFACE.match(ln.strip())]
        if ed:
            R.add("SW10", host, "CRIT", f"{len(ed)} err-disabled port(s): " + short(f"{t[0]} ({t[-1]})" for t in ed),
                  "Fix the cause (bpduguard, psecure, loop, link-flap), then recover the port")
    rows = parse_status_rows(d.get("show interfaces status"))
    if not rows:
        R.skip("SW11", host, "show interfaces status not parsable")
    else:
        R.ok("SW11", host)
        half = [r["port"] for r in rows if r["status"] == "connected" and r["duplex"].endswith("half")]
        if half:
            R.add("SW11", host, "WARN", f"{len(half)} connected port(s) at half duplex: " + short(half), "Set both ends to auto or full duplex")
        slow = [f"{r['port']} ({r['speed'].replace('a-', '')})" for r in rows if r["status"] == "connected" and
                r["vlan"] in ("trunk", "routed") and re.match(r"(Gi|Te|Twe|Fo|Hu)", r["port"]) and
                (speed_mbps(r["speed"]) or TH["uplink_min_mbps"]) < TH["uplink_min_mbps"]]
        if slow:
            R.add("SW11", host, "WARN", f"{len(slow)} uplink(s) below {TH['uplink_min_mbps']} Mbps: " + short(slow),
                  "Check the cable, SFP and far-end speed / duplex settings")
        if logs["cdp"]:
            R.add("SW11", host, "WARN", "CDP duplex / native-VLAN mismatch in logs: " + logs["cdp"], "Fix the mismatched ends")
    if logs["ok"]:
        R.ok("SW12", host)
        if logs["flaps"]:
            R.add("SW12", host, "WARN", f"{len(logs['flaps'])} interface(s) flapping in {TH['log_hours']} h: " + short(logs["flaps"]),
                  "Check cable / SFP / far-end device on those ports")
    else:
        R.skip("SW12", host, "show logging unavailable")
    et = d.get("show etherchannel summary")
    if not et.strip() or re.search(r"No channel-groups in use", et):
        R.skip("SW15", host, "no EtherChannels")
    else:
        R.ok("SW15", host)
        members, pos = parse_etherchannel(et)
        bad = [f"{p} ({f})" for p, f in members if not set(f) & set("PHp")]
        down = [f"{p} ({f})" for p, f in pos if "D" in f]
        if bad or down:
            parts = ([f"{len(bad)} member(s) not bundled: " + short(bad)] if bad else []) + ([f"port-channel down: {short(down)}"] if down else [])
            R.add("SW15", host, "WARN", "; ".join(parts), "Check the member links and the LACP/PAgP config on both ends")


def check_stp(d, R, core_roots):
    host = d.host
    root = parse_stp_root(d.get("show spanning-tree root"))
    if not root:
        R.skip("SW13", host, "show spanning-tree root unavailable")
        return
    R.ok("SW13", host)
    if core_roots is not None:
        nonroot = [f"{v} ({r['addr']})" for v, r in root.items() if r["addr"] not in core_roots]
        if nonroot:
            R.add("SW13", host, "CRIT", f"STP root is not the core on {len(nonroot)}/{len(root)} instance(s): " + short(nonroot, 3),
                  "Lower the core's STP priority (root primary) and raise it on the other switches")
    tcs = [b for b in parse_stp_detail(d.get("show spanning-tree detail | include occurr|from|ieee"))
           if b["recent"] and b["tc"] >= TH["stp_tc_min"]]
    if tcs:
        R.add("SW13", host, "WARN", f"topology change in the last 24 h on {len(tcs)} instance(s): " +
              short((f"{b['id']} x{b['tc']} from {b['from']}" for b in tcs), 3), "Find the flapping port (the 'from' interface)")
    if d.cfg.strip():
        edge = edge_ports_without_bpduguard(d.cfg)
        if edge:
            R.add("SW13", host, "INFO", f"{len(edge)} PortFast edge port(s) without BPDU guard: " + short(edge),
                  "Enable spanning-tree portfast bpduguard default")


def check_audit(d, R, findings, other):
    host = d.host
    for i in CONFIG_ITEMS:
        R.ok(i, host)
    for f in findings:
        item = AUDIT_MAP.get(f["id"])
        if item:
            R.add(item[0], host, item[1] or sev_from_audit(f["severity"]), f"{f['title']}: {f['evidence']}", f["remediation"])
        elif f["id"] not in IGNORED_AUDIT_IDS:
            other.append({"target": host, "id": f["id"], "severity": sev_from_audit(f["severity"]), "detail": f["title"],
                          "evidence": f["evidence"], "suggestion": f["remediation"]})


def check_mgmt(d, R, assess):
    host, cl = d.host, [ln.strip() for ln in d.cfg.splitlines()]
    if d.cfg.strip():
        has_aaa = any(re.match(r"aaa new-model", x) for x in cl)
        servers = any(re.match(r"(tacacs|radius)(-server| server)", x) for x in cl)
        if has_aaa and not servers and any(x.startswith("username ") for x in cl):
            R.add("SW21", host, "INFO", "local accounts only (no TACACS+/RADIUS server configured)",
                  "Centralize authentication with TACACS+/RADIUS and a local fallback")
        ntp, assoc = d.get("show ntp status"), d.get("show ntp associations")
        unsync = "unsynchronized" in ntp.lower() or (not ntp.strip() and assoc.strip() and not re.search(r"(?m)^\s*\*", assoc))
        if unsync and any(re.match(r"ntp (server|peer) ", x) for x in cl):
            R.add("SW27", host, "CRIT", "NTP configured but the clock is not synchronized",
                  "Check reachability / ACLs to the NTP servers (show ntp associations)")
    if assess is None:
        R.skip("SW29", host, "show logging unavailable or not parsable")
        return
    R.ok("SW29", host)
    for e in assess["events"]:
        if e["severity"] <= 2:
            R.add("SW29", host, "CRIT", f"{e['key']} x{e['count']} (last {e['last']}): {e['sample'][:110]}",
                  "Investigate this event; see show logging for context")
    buf = assess["logging"]["buffer"]
    if buf["enabled"] is False:
        R.add("SW28", host, "INFO", "buffer logging disabled", "Enable a larger logging buffer (>= 64000 bytes)")
    elif buf["enabled"] and buf["size"] is not None and buf["size"] < log_audit.MIN_BUFFER_BYTES:
        R.add("SW28", host, "INFO", f"logging buffer {buf['size']} bytes (< {log_audit.MIN_BUFFER_BYTES})",
              "Increase the logging buffer to 128000 bytes")


def diff_changes(diff):
    """Changed lines in a contextual `archive config differences` output. Certificate chains always differ
    between NVRAM and the running config (stored in a different form), so they are ignored."""
    n, skip = 0, False
    for ln in diff.splitlines():
        if ln.startswith("!List of Rollback"):
            break
        if ln and not ln[0].isspace() and ln[0] not in "+-!":
            skip = ln.startswith("crypto pki certificate chain")
        elif re.match(r"^\s*[+-]\s*\S", ln) and not skip:
            n += 1
    return n


def check_ops(d, R):
    host, cfg = d.host, d.cfg
    diff, startup = d.get(ARCHIVE_CMD), d.o.get(STARTUP_CMD, "")
    if diff.strip() and not cmd_unusable(diff, d.errors, ARCHIVE_CMD):
        R.ok("SW30", host)
        n = diff_changes(diff)
        if n:
            R.add("SW30", host, "WARN", f"running config differs from startup ({n} changed line(s))",
                  "Review the difference, then save the configuration if intended")
    elif startup.strip() and cfg.strip():
        R.ok("SW30", host)
        a, b = strip_volatile(cfg), strip_volatile(startup)
        if a != b:
            R.add("SW30", host, "WARN", f"running config differs from startup (~{len(set(a) ^ set(b))} differing line(s), volatile lines ignored)",
                  "Review the difference, then save the configuration if intended")
    else:
        R.skip("SW30", host, "archive diff and startup-config unavailable")
    R.ok("SW31", host)
    lb = d.meta.get("latest_backup")
    if not lb:
        R.add("SW31", host, "WARN", f"no backup in backups/{host}", f"Run cfn backup {host}")
    else:
        age = datetime.fromisoformat(d.meta["collected_at"]) - datetime.fromisoformat(lb["time"])
        if age > timedelta(days=TH["backup_max_days"]):
            R.add("SW31", host, "WARN", f"latest backup {lb['name']} is {age.days} days old (> {TH['backup_max_days']})",
                  f"Run cfn backup {host}")
    users = d.get("show users")
    if not users.strip():
        R.skip("SW32", host, "show users unavailable")
        return
    R.ok("SW32", host)
    others = []
    for ln in users.splitlines():
        m = re.match(r"^(\*?)\s*(\d+)\s+(vty|con|aux|tty)\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S*)", ln)
        if m and not m.group(1) and m.group(4).lower() not in ("idle", "-"):
            others.append(f"{m.group(4)} on {m.group(3)} {m.group(2)}" + (f" from {m.group(7)}" if m.group(7) else ""))
    if others:
        R.add("SW32", host, "INFO", f"{len(others)} other session(s): " + short(others), "Confirm these sessions are expected")


def check_routing(d, R, logtxt):
    host = d.host
    cl = [ln.strip() for ln in d.cfg.splitlines()]
    if not d.cfg.strip():
        for i in ("SW33", "SW34"):
            R.skip(i, host, "running-config unavailable")
        return
    protos = sorted({m.group(1) for ln in cl if (m := re.match(r"router (ospf|eigrp|bgp|rip|isis)\b", ln))})
    fhrp = any(re.match(r"(standby (\d+ )?(ip|priority|version)\b|vrrp \d+ ip\b)", ln) for ln in cl)
    if not protos and not fhrp:
        for i in ("SW33", "SW34"):
            R.skip(i, host, "not L3 (no routing protocol or HSRP/VRRP configured)")
        return
    if not protos:
        R.skip("SW33", host, "not L3 (no routing protocol configured)")
    else:
        R.ok("SW33", host)
        down = []
        for m in re.finditer(r"(?m)^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\w+)(?:/(\S+))?\s", d.get("show ip ospf neighbor")):
            st, role = m.group(2).upper(), (m.group(3) or "").upper()
            if st != "FULL" and not (st == "2WAY" and role == "DROTHER"):
                down.append(f"OSPF {m.group(1)} {st}")
        for m in re.finditer(r"(?m)^(\S+)\s+\d\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(.+?)\s*$", d.get("show ip bgp summary")):
            state = m.group(3).strip()
            if not state.isdigit() and "(Admin)" not in state:
                down.append(f"BGP {m.group(1)} {state}")
        for name, cmd, rx in (("ospf", "show ip ospf neighbor", r"(?m)^\d+\.\d+\.\d+\.\d+\s"),
                              ("eigrp", "show ip eigrp neighbors", r"(?m)^\s*\d+\s+\d+\.\d+\.\d+\.\d+\s")):
            if name in protos and not re.search(rx, d.get(cmd)):
                down.append(f"{name.upper()} configured but no neighbors")
        if down:
            R.add("SW33", host, "CRIT", f"{len(down)} neighbor problem(s): " + short(down),
                  "Check the link, interface/area/AS settings and authentication on both ends")
        flaps = len(re.findall(r"(?i)(?:OSPF-\d-ADJCHG|DUAL-\d-NBRCHANGE|BGP-\d-ADJCHANGE|BGP-\d-NBR_RESET)[^\n]*"
                               r"(?:\bdown\b|reset|\bdead\b|\bidle\b)", logtxt))
        if flaps:
            R.add("SW33", host, "WARN", f"{flaps} adjacency down event(s) in {TH['log_hours']} h", "Check link stability toward the neighbors")
    if d.has("show ip route 0.0.0.0"):
        R.ok("SW34", host)
        if "Routing entry for 0.0.0.0" not in d.get("show ip route 0.0.0.0"):
            R.add("SW34", host, "CRIT", "no default route (0.0.0.0/0) in the routing table",
                  "Check the upstream next hop or default-route origination")
    else:
        R.skip("SW34", host, "show ip route 0.0.0.0 unavailable")
    if fhrp:
        bad = [f"HSRP {m.group(1)} grp {m.group(2)} {m.group(4)}" for m in re.finditer(
            r"(?m)^(\S+)\s+(\d+)\s+(\d+)\s+(?:P\s+)?(Init|Speak|Learn)\b", d.get("show standby brief"), re.IGNORECASE)]
        bad += [f"VRRP {m.group(1)} grp {m.group(2)} Init" for m in re.finditer(
            r"(?m)^(\S+)\s+(\d+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(Init)\b", d.get("show vrrp brief"), re.IGNORECASE)]
        if bad:
            R.ok("SW34", host)
            R.add("SW34", host, "WARN", f"{len(bad)} unexpected first-hop redundancy state(s): " + short(bad),
                  "Check the HSRP/VRRP peers, priorities and tracking")


# --------------------------------------------------------------------------- fleet analysis
def find_cores(devs):
    cores = [d for d in devs if d.meta.get("role") == "core"]
    return cores or [d for d in devs if "core" in d.host.lower()]


def synth_log_outputs(d, logtxt):
    """The output dict log_audit.assess() expects, built from data already collected (no extra commands)."""
    c = [x[0] for x in log_audit.COMMANDS]
    cfg_inc = "\n".join(ln for ln in d.cfg.splitlines() if re.match(r"(logging|no logging|service timestamps|ntp|clock)", ln))
    ver_inc = "\n".join(ln for ln in d.get("show version").splitlines() if "uptime" in ln)
    return {c[0]: logtxt, c[1]: cfg_inc, c[2]: d.get("show clock"), c[3]: d.get("show ntp status"), c[4]: ver_inc}


def analyze_device(d, R, core_roots, other):
    host = d.host
    sv = d.get("show version")
    if sv.strip():
        R.ok("SW02", host)
    else:
        R.skip("SW02", host, "show version unavailable")
    check_platform(d, R)
    check_hardware(d, R)
    now = parse_log_clock(d.get("show clock"), d.meta["collected_at"])
    logtxt = filter_log(d.get("show logging"), now, TH["log_hours"]) if d.get("show logging").strip() else ""
    assess, logs = None, {"ok": False, "flaps": [], "cdp": ""}
    if logtxt.strip():
        try:
            assess = log_audit.assess({"outputs": synth_log_outputs(d, logtxt)})
        except Exception:  # noqa: BLE001 - a parse problem must not drop the device
            assess = None
        if assess:
            logs = {"ok": True, "flaps": assess["buffer_stats"]["flapping_interfaces"],
                    "cdp": short(f"{e['key']} x{e['count']}" for e in assess["events"] if e["category"] == "cdp-mismatch")}
    check_interfaces(d, R, logs)
    check_stp(d, R, core_roots)
    if d.cfg.strip():
        parsed = {c: ("" if audit.INVALID.search(d.o.get(c, "")[:200]) else d.o.get(c, "")) for c in audit.COMMANDS}
        findings, _ = audit.analyze({"hostname": host, "mgmt_ip": d.ip, "os_type": d.meta.get("os_type")}, parsed)
        check_audit(d, R, findings, other)
        if logtxt.strip():
            psec = len(re.findall(r"PSECURE_VIOLATION|psecure-violation", logtxt))
            if psec:
                R.add("SW25", host, "WARN", f"{psec} port-security violation log message(s) in {TH['log_hours']} h",
                      "Identify the offending MAC / port (show port-security)")
    else:
        for i in CONFIG_ITEMS:
            R.skip(i, host, "running-config unavailable")
    check_mgmt(d, R, assess)
    check_ops(d, R)
    check_routing(d, R, logtxt)


def check_vlans_on_core(d, R, core_vlans, core_names):
    mine = {v for v, used in parse_vlans(d.get("show vlan brief")).items() if used and v != 1 and not 1002 <= v <= 1005}
    missing = sorted(mine - core_vlans)
    if missing:
        R.add("SW14", d.host, "WARN", f"{len(missing)} VLAN(s) with ports here but missing on the core ({', '.join(core_names)}): " +
              short(map(str, missing), 10), "Create / allow these VLANs on the core, or remove them from this switch")


def spread_findings(R, versions):
    by_model = defaultdict(list)
    for host, (model, ver) in versions.items():
        if ver:
            by_model[model].append((host, ver))
    for model, lst in by_model.items():
        cnt = Counter(v for _, v in lst)
        if len(cnt) > 1:
            mode, n = cnt.most_common(1)[0]
            for host, ver in lst:
                if ver != mode:
                    R.add("SW02", host, "INFO", f"{model}: version {ver}; most devices of this model run {mode} ({n}/{len(lst)})",
                          "Standardize on one tested release per model")


def analyze_all(devdata, auth_failed):
    R, other = Res(), []
    reach = [Dev(m, o) for m, o in devdata if not m.get("connect_error")]
    unreach = [m for m, _ in devdata if m.get("connect_error")]
    for m in unreach:
        kind = {"auth": "authentication failed", "timeout": "connection timed out"}.get(m["error_kind"], "unreachable")
        R.add("SW01", m["hostname"], "CRIT", f"{kind}: {m['connect_error']}",
              "Check the management IP, SSH reachability and the credential_ref in the inventory")
    for a in auth_failed:
        R.add("SW01", a["hostname"], "CRIT", f"inventory status auth_failed ({a['ip']})" + (f": {a['notes'][:100]}" if a.get("notes") else ""),
              "Find the right credential_ref for this device and update the inventory")
    for d in reach:
        R.ok("SW01", d.host)

    cores = find_cores(reach)
    core_roots = core_vlans = None
    core_names = [c.host for c in cores]
    if cores:
        core_roots, core_vlans = set(), set()
        for c in cores:
            core_roots |= {r["addr"] for r in parse_stp_root(c.get("show spanning-tree root")).values() if r["cost"] == 0}
            core_vlans |= set(parse_vlans(c.get("show vlan brief")))
        core_vlans = core_vlans or None
    versions = {}
    for d in reach:
        try:
            versions[d.host] = (d.meta.get("model") or "?", version_of(d.get("show version")))
            analyze_device(d, R, core_roots, other)
            if d not in cores and d.cfg.strip() and core_vlans:
                R.ok("SW14", d.host)
                check_vlans_on_core(d, R, core_vlans, core_names)
        except Exception as e:  # noqa: BLE001 - one device's parse failure must not stop the run
            R.add("SW01", d.host, "INFO", f"analysis error: {type(e).__name__}: {e} [{traceback.format_exc(limit=2).splitlines()[-2].strip()}]",
                  "Report this to the maintainer of switch_checklist.py")
    if not cores:
        for d in reach:
            R.skip("SW13", d.host, "core not in this run (no role core / 'core' hostname collected)")
    spread_findings(R, versions)
    return R, reach, unreach, other, core_names


# --------------------------------------------------------------------------- assemble and report
def assemble(R, n_reach, auth_failed):
    items = []
    for iid, section, title in ITEMS:
        f = sorted(R.findings.get(iid, []), key=lambda x: (-SEV_RANK[x["severity"]], x["target"], x["detail"]))
        ran, skips = R.ran.get(iid, set()), R.skips.get(iid, {})
        skips = {h: w for h, w in skips.items() if h not in ran}
        reason = None
        if iid == "SW01":
            status = "crit" if f else "pass"
            reason = f"{n_reach} device(s) reachable" if f else None
        elif not ran:
            why = Counter(skips.values()).most_common(1)[0][0] if skips else "no device evaluated"
            status, f = "skip", []
            reason = f"{why} ({len(skips)} device(s))" if skips else why
        else:
            worst = max((SEV_RANK[x["severity"]] for x in f), default=None)
            status = "pass" if worst is None else {0: "info", 1: "warn", 2: "crit"}[worst]
            if skips:
                reason = f"evaluated on {len(ran)} device(s); skipped on {len(skips)}: " + \
                    "; ".join(f"{w} ({n})" for w, n in Counter(skips.values()).most_common(3))
        items.append({"id": iid, "section": section, "title": title, "status": status, "reason": reason, "findings": f})
    counts = {k: sum(1 for i in items if i["status"] == k) for k in ("pass", "info", "warn", "crit", "skip")}
    counts["findings"] = dict(Counter(x["severity"] for i in items for x in i["findings"]))
    return items, counts


def md_table(rows, head):
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]


def write_outputs(out, summary):
    items, counts, sc, other = summary["items"], summary["counts"], summary["scope"], summary["other_findings"]
    fc = counts["findings"]
    L = [f"# Switch / router checklist - {summary['generated']}", "",
         (f"Scope: {sc['devices']} device(s) collected, {len(sc['unreachable'])} unreachable, "
          f"{len(sc['auth_failed'])} auth_failed in inventory. Core: {', '.join(sc['core']) or 'none collected'}"), "",
         (f"Items: {len(items)} | ✅ pass {counts['pass']} | ℹ️ info {counts['info']} | ⚠️ warn {counts['warn']} | "
          f"❌ crit {counts['crit']} | ➖ skip {counts['skip']}"), "",
         (f"Findings: CRIT={fc.get('CRIT', 0)} WARN={fc.get('WARN', 0)} INFO={fc.get('INFO', 0)} "
          "(read-only; suggestions are text only, never executed). Boxes: [x] pass/info, [ ] needs attention or skipped.")]
    sec = None
    for it in items:
        if it["section"] != sec:
            sec = it["section"]
            L += ["", f"## {sec}", ""]
        n, devs = len(it["findings"]), len({x["target"] for x in it["findings"]})
        L.append(f"- [{'x' if it['status'] in ('pass', 'info') else ' '}] {STATUS_ICON[it['status']]} **{it['id']}** {it['title']} "
                 f"({n} finding{'s' if n != 1 else ''}, {devs} device{'s' if devs != 1 else ''})" + (f" - {it['reason']}" if it["reason"] else ""))
        if it["status"] != "pass" and it["findings"]:
            rows = it["findings"][:300]
            L += [""] + md_table([(x["severity"], x["target"], x["detail"], x["suggestion"]) for x in rows],
                                 ["Sev", "Target", "Detail", "Suggestion"])
            if n > len(rows):
                L.append(f"\n... {n - len(rows)} more in findings.csv")
            L.append("")
    L += ["", "## Other hardening findings", "",
          "audit.py findings with no checklist item (legacy services). Not part of SW01-SW34.", ""]
    if other:
        L += md_table([(o["severity"], o["target"], o["id"], o["detail"], o["suggestion"]) for o in other[:300]],
                      ["Sev", "Target", "Audit id", "Detail", "Suggestion"])
        if len(other) > 300:
            L.append(f"\n... {len(other) - 300} more in summary.json (other_findings)")
    else:
        L.append("None.")
    (out / "checklist.md").write_text("\n".join(L) + "\n")
    with open(out / "findings.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["item_id", "section", "title", "status", "severity", "target", "detail", "suggestion"])
        for it in items:
            for x in it["findings"]:
                w.writerow([it["id"], it["section"], it["title"], it["status"], x["severity"], x["target"], x["detail"], x["suggestion"]])


def parse_thresholds(pairs):
    for p in pairs:
        k, _, v = p.partition("=")
        if k not in TH:
            sys.exit(f"unknown threshold {k!r}; known: {', '.join(TH)}")
        try:
            TH[k] = float(v) if "." in v else int(v)
        except ValueError:
            sys.exit(f"threshold {k} needs a number, got {v!r}")


def inventory_auth_failed():
    db = netlib.open_db()
    try:
        rows = db.execute("SELECT hostname, mgmt_ip, notes, os_type FROM devices WHERE status='auth_failed' ORDER BY hostname").fetchall()
    finally:
        db.close()
    return [{"hostname": h, "ip": ip, "notes": n or ""} for h, ip, n, ot in rows if ot in (None, *SUPPORTED_OS)]


def main():
    ap = argparse.ArgumentParser(description="Read-only switch / router checklist (SW01-SW34)")
    netlib.add_target_args(ap)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--timeout", type=int, default=30, help="per-command read timeout in seconds (heavy commands get 4x)")
    ap.add_argument("--out", help="output dir (default reports/checklist/switch/<timestamp>)")
    ap.add_argument("--from-raw", metavar="DIR", help="re-analyze a saved run (its dir or its raw/ dir) offline; no device is contacted")
    ap.add_argument("--threshold", action="append", default=[], metavar="KEY=VALUE", help=f"override a threshold ({', '.join(TH)})")
    args = ap.parse_args()
    parse_thresholds(args.threshold)
    netlib.require_readonly(COMMANDS + [STARTUP_CMD] + [v for vs in FALLBACKS.values() for v in vs])

    t0 = time.time()
    started = datetime.now()
    os.umask(0o077)
    out = Path(args.out) if args.out else ROOT / "reports" / "checklist" / "switch" / started.strftime("%Y%m%d-%H%M%S")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)

    if args.from_raw:
        devdata, auth_failed = load_raw(Path(args.from_raw))
        if not devdata and not auth_failed:
            sys.exit(f"no raw device data under {args.from_raw}")
        print(f"Re-analyzing {len(devdata)} saved device(s) from {args.from_raw}, out={out}")
    else:
        explicit = bool(args.targets or args.match or args.role)
        if not explicit:
            args.all = True
        devs = [d for d in netlib.resolve_targets(args) if d.get("os_type") in SUPPORTED_OS]
        if not devs:
            sys.exit("no cisco_ios / cisco_xe devices matched")
        auth_failed = inventory_auth_failed() if not explicit and args.status == "active" else []
        print(f"Checking {len(devs)} device(s) read-only, workers={args.workers}, out={out}")
        with ThreadPoolExecutor(max(1, min(args.workers, len(devs)))) as ex:
            devdata = list(ex.map(lambda dv: collect_device(dv, args, out), devs))
        (out / "raw" / "_inventory.json").write_text(json.dumps({"auth_failed": auth_failed}, indent=2))

    R, reach, unreach, other, core_names = analyze_all(devdata, auth_failed)
    items, counts = assemble(R, len(reach), auth_failed)
    summary = {"generated": started.isoformat(timespec="seconds"), "read_only": True,
               "scope": {"devices": len(devdata), "reachable": len(reach), "unreachable": [m["hostname"] for m in unreach],
                         "auth_failed": [a["hostname"] for a in auth_failed], "core": core_names},
               "items": items, "counts": counts, "other_findings": other}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    write_outputs(out, summary)

    print("Status: " + ", ".join(f"{k}={counts[k]}" for k in ("crit", "warn", "info", "pass", "skip")) +
          " | findings: " + ", ".join(f"{k}={v}" for k, v in sorted(counts["findings"].items())))
    for it in items:
        if it["status"] in ("crit", "warn"):
            n = len({x["target"] for x in it["findings"] if SEV_RANK[x["severity"]] >= 1})
            print(f"  {STATUS_ICON[it['status']]} {it['id']} {it['title']} - {n} device(s)")
    for it in items:
        if it["status"] == "skip":
            print(f"  {STATUS_ICON['skip']} {it['id']} skipped: {it['reason']}")
    print(f"Unreachable: {', '.join(m['hostname'] for m in unreach) or 'none'}; auth_failed in inventory: {len(auth_failed)}")
    print(f"Runtime {time.time() - t0:.0f}s\nReport: {out / 'checklist.md'}\nJSON:   {out / 'summary.json'}")


if __name__ == "__main__":
    main()
