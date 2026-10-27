"""READ-ONLY log audit across active inventory switches.

Usage:
    cfn log-audit [--host HOSTNAME ...] [--workers 10] [--out DIR]

Only `show` commands (plus `terminal length 0`, a session setting) are sent. Nothing is ever
configured. Remediation commands in the report are SUGGESTIONS (text only), never sent.

Outputs under --out (default reports/log_audit/<YYYYmmdd-HHMMSS>):
    raw/<hostname>.txt   raw command output (ntp authentication keys redacted)
    summary.json         machine-readable per-device results
    report.md            fleet overview, coverage gaps, abnormal findings, unreachable list
"""
import argparse
import json
import os
import re
import sqlite3
import sys
import traceback
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from netmiko import ConnectHandler

import paths

ROOT = paths.site_root()
load_dotenv(ROOT / ".env")
DB = ROOT / os.getenv("INVENTORY_DB", "inventory/inventory.db")

COMMANDS = [
    ("show logging", True, 120),
    ("show running-config | include ^logging|^no logging|^service timestamps|^ntp|^clock", False, 60),
    ("show clock", False, 30),
    ("show ntp status", False, 30),
    ("show version | include uptime", False, 30),
]

LEVELS = {"emergencies": 0, "alerts": 1, "critical": 2, "errors": 3, "warnings": 4,
          "notifications": 5, "informational": 6, "debugging": 7}
MIN_BUFFER_BYTES = 64000
FLAP_THRESHOLD = 5
SEV_RANK = {"OK": 0, "INFO": 0, "WARN": 1, "CRIT": 2}

MSG_RE = re.compile(r"%([A-Za-z0-9_]+)-([0-7])-([A-Za-z0-9_]+)\s*:?\s*(.*)")


# --------------------------------------------------------------------------- collection
def redact(text):
    """Mask secrets that can show up in the `^ntp` include (authentication keys)."""
    return re.sub(r"(?im)^(ntp authentication-key \d+ \S+) \S+(.*)$", r"\1 <redacted>\2", text)


def collect(dev, stamp_dir):
    host = dev["hostname"]
    cred = dev["credential_ref"] or "DEFAULT"
    res = {"hostname": host, "ip": dev["mgmt_ip"], "model": dev["model"], "os_version": dev["os_version"],
           "os_type": dev["os_type"], "outputs": OrderedDict(), "cmd_errors": {}, "connect_error": None,
           "error_kind": None}
    params = {
        "device_type": dev["os_type"] or "cisco_ios",
        "host": dev["mgmt_ip"],
        "username": os.getenv(f"NET_{cred}_USERNAME"),
        "password": os.getenv(f"NET_{cred}_PASSWORD"),
        "secret": os.getenv(f"NET_{cred}_ENABLE") or "",
        "conn_timeout": 20,
        "auth_timeout": 25,
        "banner_timeout": 25,
        "global_delay_factor": 1,
    }
    try:
        with ConnectHandler(**params) as conn:
            if params["secret"] and not conn.check_enable_mode():
                conn.enable()
            try:
                conn.send_command("terminal length 0")
            except Exception as e:  # noqa: BLE001 - session_preparation already did it
                res["cmd_errors"]["terminal length 0"] = type(e).__name__
            for cmd, required, timeout in COMMANDS:
                try:
                    res["outputs"][cmd] = redact(conn.send_command(cmd, read_timeout=timeout))
                except Exception as e:  # noqa: BLE001
                    res["cmd_errors"][cmd] = f"{type(e).__name__}: {str(e).splitlines()[0][:100] if str(e) else ''}"
                    res["outputs"][cmd] = ""
    except Exception as e:  # noqa: BLE001 - never crash the run
        name = type(e).__name__
        msg = str(e).splitlines()[0][:140] if str(e) else ""
        res["connect_error"] = f"{name}: {msg}"
        res["error_kind"] = ("auth" if "Authentication" in name else
                             "timeout" if "Timeout" in name or "timed out" in msg.lower() else "other")
    # save raw (even partial)
    raw_dir = stamp_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    with open(raw_dir / f"{safe}.txt", "w") as f:
        f.write(f"# {host} {dev['mgmt_ip']} {dev['model']} {dev['os_version']}\n")
        if res["connect_error"]:
            f.write(f"# CONNECT ERROR: {res['connect_error']}\n")
        for cmd, out in res["outputs"].items():
            f.write(f"\n##### {cmd}\n")
            if cmd in res["cmd_errors"]:
                f.write(f"# ERROR: {res['cmd_errors'][cmd]}\n")
            f.write(out + "\n")
    return res


# --------------------------------------------------------------------------- parsing
def lvl(name):
    return LEVELS.get((name or "").lower())


def split_logging(text):
    """Return (header, buffer_lines). The header is everything before 'Log Buffer'."""
    m = re.search(r"^Log Buffer \((\d+) bytes\):?", text, re.MULTILINE)
    if not m:
        return text, [], None
    return text[:m.start()], text[m.end():].splitlines(), int(m.group(1))


def parse_logging(text, cfg):
    d = {}
    header, buf_lines, buf_size = split_logging(text)
    flat = re.sub(r"\s*\n\s+", " ", header)  # unwrap wrapped status lines

    m = re.search(r"Syslog logging:\s*(enabled|disabled)(?:\s*\((.*?)\))?", flat, re.IGNORECASE)
    d["syslog_enabled"] = (m.group(1).lower() == "enabled") if m else None
    stats = m.group(2) if m and m.group(2) else ""
    for key, pat in (("dropped", r"(\d+) messages? dropped"), ("rate_limited", r"(\d+) messages? rate-limited"),
                     ("overruns", r"(\d+) overruns?")):
        mm = re.search(pat, stats)
        d[key] = int(mm.group(1)) if mm else None

    def target(label):
        mm = re.search(rf"{label} logging:\s*(disabled|level (\w+)(?:,\s*(\d+) messages? logged)?)", flat, re.IGNORECASE)
        if not mm:
            return {"enabled": None, "level": None, "messages": None}
        if mm.group(1).lower() == "disabled":
            return {"enabled": False, "level": None, "messages": None}
        return {"enabled": True, "level": mm.group(2).lower(),
                "messages": int(mm.group(3)) if mm.group(3) else None}

    d["console"], d["monitor"], d["buffer"] = target("Console"), target("Monitor"), target("Buffer")
    d["buffer"]["size"] = buf_size
    mm = re.search(r"Exception Logging: size \((\d+) bytes\)", flat)
    d["exception_log_bytes"] = int(mm.group(1)) if mm else None

    mm = re.search(r"Trap logging:\s*level (\w+)(?:,\s*(\d+) message lines? logged)?", flat, re.IGNORECASE)
    d["trap"] = {"level": mm.group(1).lower() if mm else None,
                 "messages": int(mm.group(2)) if mm and mm.group(2) else None}
    hosts = re.findall(r"Logging to\s+(\S+)", flat)
    hosts += re.findall(r"(?im)^logging host (\S+)", cfg)
    hosts += re.findall(r"(?im)^logging (\d{1,3}(?:\.\d{1,3}){3})\b", cfg)
    d["syslog_hosts"] = sorted(set(hosts))
    mm = re.search(r"(?:Persistent|File) logging:\s*(\S+)", flat, re.IGNORECASE)
    d["persistent_logging"] = (mm.group(1).rstrip(",").lower() if mm else None)
    d["persistent_cfg"] = bool(re.search(r"(?im)^logging (persistent|file)\b", cfg))
    d["buffer_lines"] = buf_lines
    return d


def parse_config(cfg, log):
    c = {}
    m = re.search(r"(?im)^logging buffered(?: (\d+))?(?: (\w+))?\s*$", cfg)
    c["buffered_cfg"] = m.group(0).strip() if m else None
    c["buffered_disabled_cfg"] = bool(re.search(r"(?im)^no logging buffered", cfg))
    m = re.search(r"(?im)^service timestamps log (.*)$", cfg)
    c["ts_log_cfg"] = m.group(1).strip() if m else None
    c["no_ts_log_cfg"] = bool(re.search(r"(?im)^no service timestamps log", cfg))
    c["ntp_servers"] = sorted(set(re.findall(r"(?im)^ntp (?:server|peer) (?:vrf \S+ )?(\S+)", cfg)))
    c["clock_cfg"] = re.findall(r"(?im)^clock .*$", cfg)
    return c


def classify_ts_style(cfgd, buf_lines):
    """Return (style, msec) with style in datetime|uptime|none|unknown."""
    t = cfgd["ts_log_cfg"]
    if cfgd["no_ts_log_cfg"]:
        return "none", False
    if t:
        if t.startswith("datetime"):
            return "datetime", "msec" in t.split()
        if t.startswith("uptime"):
            return "uptime", False
    # fall back on observed buffer lines
    for ln in buf_lines:
        mm = re.search(r"^\s*(?:\d+:\s*)?[*.]?(.*?)\s*%[A-Za-z0-9_]+-\d-", ln)
        if not mm:
            continue
        ts = mm.group(1).strip().rstrip(":")
        if re.match(r"^\d+:\d\d:\d\d", ts) or re.match(r"^\d+[wdh]\d+[dh]", ts):
            return "uptime", False
        if re.search(r"[A-Z][a-z]{2}\s+\d+", ts):
            return "datetime", bool(re.search(r"\d:\d\d\.\d{3}", ts))
        if not ts:
            return "none", False
    return "unknown", False


def parse_ntp(ntp_out, clock_out, ntp_cfg_servers):
    n = {"status": "unknown", "detail": None, "configured_servers": ntp_cfg_servers, "clock": None,
         "clock_authoritative": None}
    t = ntp_out or ""
    if re.search(r"Clock is synchronized", t, re.IGNORECASE):
        n["status"] = "synchronized"
    elif re.search(r"Clock is unsynchronized", t, re.IGNORECASE):
        n["status"] = "unsynchronized"
    elif re.search(r"not enabled|% ?Invalid|% ?Incomplete|Unrecognized", t, re.IGNORECASE):
        n["status"] = "not_enabled"
    elif not t.strip():
        n["status"] = "unknown"
    n["detail"] = (t.strip().splitlines() or [""])[0][:120]
    c = (clock_out or "").strip().splitlines()
    if c:
        line = c[-1].strip()
        n["clock"] = line
        if line.startswith("*"):
            n["clock_authoritative"] = False  # not authoritative
        elif line.startswith("."):
            n["clock_authoritative"] = False  # authoritative but not synced
    return n


# Rules: (category, level, predicate(key, sev, mnem, text))
def _rx(p):
    r = re.compile(p, re.IGNORECASE)
    return lambda key, sev, mnem, text: bool(r.search(key))


RULES = [
    ("memory", "CRIT", _rx(r"MALLOCFAIL|NOMEMORY|MEMORY|MEM_|SYS-\d-LOWMEM")),
    ("environment", "CRIT", lambda k, s, m, t: s <= 4 and bool(re.search(
        r"PLATFORM_ENV|ENVIRONMENT|ENV_MON|(^|[-_])FAN|(^|[-_])TEMP(?!LATE)|THERMAL|PSU|POWER_?SUPPLY|(^|[-_])RPS|OVERTEMP", k, re.IGNORECASE))),
    ("traceback", "WARN", lambda k, s, m, t: "Traceback=" in t or "TRACEBACK" in m.upper()),
    ("err-disable", "WARN", _rx(r"ERR_?DISABLE|ERRDIS")),
    ("spanning-tree", "WARN", _rx(r"SPANTREE-\d-\w*(BLOCK|LOOPGUARD|BPDUGUARD|ROOTGUARD|RECV_1Q|PVSTSIM|BAD_PORTID)")),
    ("stp-topology-change", "INFO", _rx(r"SPANTREE-\d-(TOPOTRAP|TOPOLOGY\w*)|SPANTREE-\d-\w*TOPO")),
    ("mac-move", "WARN", _rx(r"MAC_?MOVE|MAC_?FLAP|HOST_?FLAP|MACFLAP_NOTIF")),
    ("cdp-mismatch", "WARN", _rx(r"CDP-\d-(DUPLEX_MISMATCH|NATIVE_VLAN_MISMATCH)")),
    ("poe", "WARN", lambda k, s, m, t: k.upper().startswith("ILPOWER") and (
        s <= 4 or bool(re.search(r"POWER_DENY|PD_FAULT|SHUT|OVERLOAD|INSUFFICIENT|SHORT|FAULT|DENIED", m, re.IGNORECASE)))),
    ("auth-failure", "WARN", lambda k, s, m, t: bool(
        re.search(r"SEC_LOGIN-\d-LOGIN_FAILED|AUTHFAIL|AUTH_FAIL|SNMP-3-AUTHFAIL|SEC-\d-ATTACK|AAA.*FAIL", k, re.IGNORECASE))
        or (m.upper().startswith("SSH2_USERAUTH") and re.search(r"fail", t, re.IGNORECASE) is not None)
        ),
    ("ssh-error", "WARN", lambda k, s, m, t: k.upper().startswith("SSH-") and s <= 4),
    ("dhcp-snooping", "WARN", _rx(r"DHCP_SNOOPING")),
    ("storm-control", "WARN", _rx(r"STORM_CONTROL|STORM_CNTRL")),
    ("udld", "WARN", _rx(r"UDLD")),
    ("loop", "WARN", _rx(r"LOOPDETECT|LOOP_DETECT|LOOPBACK_DETECT|LOOP_BACK")),
    ("routing-adjacency", "WARN", _rx(r"DUAL-\d-NBRCHANGE|OSPF-\d-ADJCHG|BGP-\d-ADJCHANGE|BGP-\d-NBR_RESET|EIGRP.*NBR")),
    ("interface-errors", "WARN", _rx(r"CRC|FCS|INPUT_ERR|LATECOLL|RUNT|ALIGN_?ERR|INPUT_ERRORS")),
    ("restart", "INFO", _rx(r"SYS-\d-(RESTART|RELOAD)|RELOAD_REASON|SYS-\d-BOOTTIME")),
]


def classify_event(key, sev, mnem, text):
    """Return (category, level) or None if routine."""
    cat, lv = None, None
    for c, l, pred in RULES:
        if pred(key, sev, mnem, text):
            cat, lv = c, l
            break
    sev_lv = "CRIT" if sev <= 2 else "WARN" if sev <= 4 else None
    if cat is None and sev_lv is None:
        return None
    if cat is None:
        return (f"severity-{sev}", sev_lv)
    if sev_lv and SEV_RANK[sev_lv] > SEV_RANK[lv]:
        lv = sev_lv
    return (cat, lv)


def analyse_buffer(buf_lines):
    groups = OrderedDict()
    flaps = {"LINK-3-UPDOWN": {}, "LINEPROTO-5-UPDOWN": {}}
    link_total = 0
    parsed_msgs = 0
    for ln in buf_lines:
        m = MSG_RE.search(ln)
        if not m:
            continue
        parsed_msgs += 1
        fac, sev, mnem, text = m.group(1), int(m.group(2)), m.group(3), m.group(4)
        key = f"{fac}-{sev}-{mnem}"
        prefix = ln[:m.start()]
        ts = re.sub(r"^\s*\d+:\s*", "", prefix).strip().lstrip("*.").strip().rstrip(":").strip()
        if key in flaps:
            link_total += 1
            im = re.search(r"Interface (\S+?),", text)
            iface = im.group(1) if im else "?"
            e = flaps[key].setdefault(iface, {"count": 0, "first": ts, "last": ts, "sample": ln.strip()[:220]})
            e["count"] += 1
            e["last"] = ts
            continue
        cl = classify_event(key, sev, mnem, text)
        if not cl:
            continue
        cat, lv = cl
        g = groups.get(key)
        if not g:
            g = groups[key] = {"key": key, "severity": sev, "category": cat, "level": lv, "count": 0,
                               "first": ts, "last": ts, "sample": ln.strip()[:220]}
        g["count"] += 1
        g["last"] = ts
    for key, per_if in flaps.items():
        for iface, e in per_if.items():
            if e["count"] >= FLAP_THRESHOLD:
                gk = f"{key} flap {iface}"
                groups[gk] = {"key": gk, "severity": int(key.split("-")[1]), "category": "flap", "level": "WARN",
                              "count": e["count"], "first": e["first"], "last": e["last"], "sample": e["sample"],
                              "interface": iface}
    events = sorted(groups.values(), key=lambda g: (-SEV_RANK[g["level"]], g["severity"], -g["count"]))
    return events, {"parsed_messages": parsed_msgs, "link_updown_total": link_total,
                    "flapping_interfaces": sorted({g["interface"] for g in events if g["category"] == "flap"})}


def assess(res):
    o = res["outputs"]
    log_txt = o.get("show logging", "")
    cfg_txt = o.get("show running-config | include ^logging|^no logging|^service timestamps|^ntp|^clock", "")
    log = parse_logging(log_txt, cfg_txt)
    cfgd = parse_config(cfg_txt, log)
    ts_style, ts_msec = classify_ts_style(cfgd, log["buffer_lines"])
    ntp = parse_ntp(o.get("show ntp status", ""), o.get("show clock", ""), cfgd["ntp_servers"])
    up = re.search(r"uptime is (.*)", o.get("show version | include uptime", ""))
    events, stats = analyse_buffer(log.pop("buffer_lines"))

    gaps, fixes = [], []
    buf = log["buffer"]
    parsed_ok = buf["enabled"] is not None or log["syslog_enabled"] is not None
    if not parsed_ok:
        gaps.append("could not parse 'show logging' output")
    else:
        if buf["enabled"] is False:
            gaps.append("buffer logging disabled")
            fixes.append("logging buffered 128000 debugging")
        else:
            bl = lvl(buf["level"])
            if bl is None or bl < 7:
                gaps.append(f"buffer level is {buf['level']} (want debugging)")
                fixes.append("logging buffered 128000 debugging")
            sz = buf["size"]
            if sz is not None and sz < MIN_BUFFER_BYTES:
                gaps.append(f"buffer size {sz} bytes" + (" (default)" if sz == 4096 else "") +
                            f" (< {MIN_BUFFER_BYTES})")
                fixes.append("logging buffered 128000 debugging")
        if log.get("overruns"):
            gaps.append(f"{log['overruns']} log overruns")
        if log.get("dropped"):
            gaps.append(f"{log['dropped']} log messages dropped")
        if not log["syslog_hosts"]:
            gaps.append("no syslog host configured")
            fixes.append("logging host <SYSLOG_SERVER_IP>")
        tl = lvl(log["trap"]["level"])
        if log["syslog_hosts"] and (tl is None or tl < 6):
            gaps.append(f"syslog trap level {log['trap']['level']} (want informational or debugging)")
            fixes.append("logging trap informational")
        if log["syslog_hosts"] and log["trap"]["level"] is None:
            gaps.pop()
            gaps.append("syslog trap level not found in output")
    if ts_style != "datetime":
        gaps.append(f"log timestamps: {ts_style} (want datetime msec)")
        fixes.append("service timestamps log datetime msec localtime show-timezone")
    elif not ts_msec:
        gaps.append("log timestamps are datetime without msec")
        fixes.append("service timestamps log datetime msec localtime show-timezone")
    if ntp["status"] == "synchronized":
        pass
    else:
        gaps.append(f"NTP {ntp['status'].replace('_', ' ')} - log times unreliable")
        if not cfgd["ntp_servers"]:
            fixes.append("ntp server <NTP_SERVER_IP>")
        fixes.append("clock timezone <ZONE> <OFFSET>")
    info = []
    if log.get("persistent_logging") or log.get("persistent_cfg"):
        info.append(f"persistent/file logging: {log.get('persistent_logging')}, cfg={log.get('persistent_cfg')}")
    fixes = list(OrderedDict.fromkeys(fixes))

    crit = [e for e in events if e["level"] == "CRIT"]
    warn = [e for e in events if e["level"] == "WARN"]
    status = "CRIT" if crit else "WARN" if warn else "OK"
    abnormal = sum(e["count"] for e in crit + warn)
    return {
        "status": status, "uptime": up.group(1).strip() if up else None,
        "logging": log, "config": cfgd, "timestamps": {"style": ts_style, "msec": ts_msec},
        "ntp": ntp, "coverage_gaps": gaps, "suggested_remediation": fixes, "info": info,
        "abnormal_event_count": abnormal, "events": events, "buffer_stats": stats,
    }


# --------------------------------------------------------------------------- reporting
def short(s, n=90):
    s = (s or "").replace("|", "/")
    return s if len(s) <= n else s[:n - 3] + "..."


def write_report(out, results, started):
    L = []
    ok = [r for r in results if r.get("status") in ("OK", "WARN", "CRIT")]
    cnt = {k: sum(1 for r in results if r.get("status") == k) for k in ("CRIT", "WARN", "OK", "UNREACHABLE", "ERROR")}
    L += ["# Log Audit Report", "", f"Generated {started:%Y-%m-%d %H:%M:%S} - read-only, {len(results)} device(s)", "",
          (f"CRIT {cnt['CRIT']} | WARN {cnt['WARN']} | OK {cnt['OK']} | UNREACHABLE {cnt['UNREACHABLE']} | "
           f"COLLECTION ERROR {cnt['ERROR']}"), "", "## Fleet overview", "",
          "| Hostname | IP | Model | Status | Buffer level/size | Syslog host | Timestamps ok | NTP sync | Abnormal events |",
          "|---|---|---|---|---|---|---|---|---|"]
    order = {"CRIT": 0, "WARN": 1, "ERROR": 2, "UNREACHABLE": 3, "OK": 4}
    for r in sorted(results, key=lambda r: (order.get(r["status"], 9), r["hostname"].lower())):
        if "logging" not in r:
            L.append(f"| {r['hostname']} | {r['ip']} | {r.get('model') or ''} | {r['status']} | - | - | - | - | - |")
            continue
        b = r["logging"]["buffer"]
        bs = "disabled" if b["enabled"] is False else f"{b['level']}/{b['size']}"
        ts = r["timestamps"]
        L.append(f"| {r['hostname']} | {r['ip']} | {r.get('model') or ''} | {r['status']} | {bs} | "
                 f"{'yes' if r['logging']['syslog_hosts'] else 'NO'} | "
                 f"{'yes' if ts['style'] == 'datetime' and ts['msec'] else 'NO (' + ts['style'] + ')'} | "
                 f"{'yes' if r['ntp']['status'] == 'synchronized' else 'NO (' + r['ntp']['status'] + ')'} | "
                 f"{r['abnormal_event_count']} |")

    L += ["", "## Logging coverage gaps", ""]
    gapped = [r for r in ok if r["coverage_gaps"]]
    if not gapped:
        L.append("No coverage gaps found.")
    for r in sorted(gapped, key=lambda r: r["hostname"].lower()):
        L += [f"### {r['hostname']} ({r['ip']}, {r.get('model')})", ""]
        L += [f"- {g}" for g in r["coverage_gaps"]]
        if r["suggested_remediation"]:
            L += ["", "Suggested (NOT applied):", "```"] + r["suggested_remediation"] + ["```"]
        L.append("")

    L += ["## Abnormal log findings", ""]
    anyf = False
    for r in sorted(ok, key=lambda r: (order[r["status"]], r["hostname"].lower())):
        evs = [e for e in r["events"] if e["level"] in ("CRIT", "WARN")]
        if not evs:
            continue
        anyf = True
        L += [f"### [{r['status']}] {r['hostname']} ({r['ip']})", "",
              "| Level | Message key | Category | Count | First | Last | Sample |", "|---|---|---|---|---|---|---|"]
        for e in evs:
            L.append(f"| {e['level']} | {e['key']} | {e['category']} | {e['count']} | {short(e['first'], 28)} | "
                     f"{short(e['last'], 28)} | {short(e['sample'])} |")
        infos = [e for e in r["events"] if e["level"] == "INFO"]
        if infos:
            L.append("")
            L.append("Informational: " + ", ".join(f"{e['key']} x{e['count']}" for e in infos))
        L.append("")
    if not anyf:
        L.append("No abnormal events found in the log buffers.")
        L.append("")

    L += ["## Unreachable / collection errors", ""]
    bad = [r for r in results if r["status"] in ("UNREACHABLE", "ERROR")]
    if not bad:
        L.append("None.")
    else:
        L += ["| Hostname | IP | Kind | Error |", "|---|---|---|---|"]
        for r in sorted(bad, key=lambda r: r["hostname"].lower()):
            L.append(f"| {r['hostname']} | {r['ip']} | {r.get('error_kind') or r['status']} | "
                     f"{short(r.get('error'), 140)} |")
    (out / "report.md").write_text("\n".join(L) + "\n")


def process(dev, out):
    res = collect(dev, out)
    base = {k: res[k] for k in ("hostname", "ip", "model", "os_version", "os_type")}
    if res["connect_error"]:
        return {**base, "status": "UNREACHABLE", "error_kind": res["error_kind"], "error": res["connect_error"]}
    try:
        a = assess(res)
    except Exception as e:  # noqa: BLE001
        return {**base, "status": "ERROR", "error_kind": "parse",
                "error": f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}"}
    if not res["outputs"].get("show logging", "").strip():
        return {**base, "status": "ERROR", "error_kind": "collect",
                "error": res["cmd_errors"].get("show logging", "empty 'show logging' output")}
    out_d = {**base, **a}
    if res["cmd_errors"]:
        out_d["command_errors"] = res["cmd_errors"]
    return out_d


def main():
    ap = argparse.ArgumentParser(description="Read-only log audit of active inventory switches")
    ap.add_argument("--host", action="append", help="hostname to audit (repeatable); default all active")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--out", help="output dir (default reports/log_audit/<timestamp>)")
    args = ap.parse_args()

    started = datetime.now()
    out = Path(args.out) if args.out else ROOT / "reports" / "log_audit" / started.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)

    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    rows = [dict(r) for r in db.execute(
        "SELECT hostname, mgmt_ip, model, os_type, os_version, credential_ref FROM devices "
        "WHERE status='active' ORDER BY mgmt_ip")]
    db.close()
    if args.host:
        wanted = {h.lower() for h in args.host}
        missing = wanted - {r["hostname"].lower() for r in rows}
        if missing:
            print(f"warning: not active in inventory: {', '.join(sorted(missing))}", file=sys.stderr)
        rows = [r for r in rows if r["hostname"].lower() in wanted]
    if not rows:
        sys.exit("no target devices")
    print(f"Auditing {len(rows)} device(s) read-only, workers={args.workers}, out={out}")

    with ThreadPoolExecutor(max(1, args.workers)) as ex:
        results = list(ex.map(lambda d: process(d, out), rows))

    summary = {"generated": started.isoformat(timespec="seconds"), "read_only": True,
               "device_count": len(results), "devices": results}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    write_report(out, results, started)

    cnt = {}
    for r in results:
        cnt[r["status"]] = cnt.get(r["status"], 0) + 1
    gaps = sum(1 for r in results if r.get("coverage_gaps"))
    print("Status: " + ", ".join(f"{k}={v}" for k, v in sorted(cnt.items())))
    print(f"Devices with logging coverage gaps: {gaps}/{len(results)}")
    for r in results:
        if r["status"] in ("CRIT", "WARN"):
            print(f"  {r['status']:4} {r['hostname']:24} {r['abnormal_event_count']} abnormal events")
        elif r["status"] in ("UNREACHABLE", "ERROR"):
            print(f"  {r['status']:11} {r['hostname']:20} {str(r.get('error'))[:80]}")
    print(f"Report: {out / 'report.md'}\nJSON:   {out / 'summary.json'}")


if __name__ == "__main__":
    main()
