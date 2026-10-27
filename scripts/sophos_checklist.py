"""READ-ONLY Sophos XG / SFOS firewall checklist (XML API <Get> only, items FW01-FW27).

Usage:
    cfn sophos-checklist [TARGETS...] [--match GLOB] [--role R] [--all] [--status S]
        [--workers 4] [--timeout 30] [--out DIR] [--from-raw DIR] [--threshold KEY=VALUE ...]
    (no selector given = every active Sophos firewall)

Items (stable IDs, see ITEMS): A platform/health, B firewall rules, C NAT/exposure, D admin/access security,
E threat protection, F VPN, G logging/time. Spec and thresholds: .claude/skills/checklist/sophos.md.

READ-ONLY GUARANTEE: every request goes through sophos_api.fetch_entity() -> build_get_request(), which can only emit
<Login> + <Get>; nothing in this file builds a request, and nothing is written to a firewall. Entities the firmware does
not know (529) or the account may not read (599) or that time out make the related item `skip` with the entity named in
`reason`; an unreachable firewall is reported by FW01 and never fatal. Values the XML API does not expose (CPU/memory,
licence dates, tunnel state, HA peer state, NTP sync) are `skip` with "not exposed by the XML API on firmware X".
No SSH console scraping.

FW07-FW10 and the undefined-object part of FW13 reuse sophos_api.analyze(). Its NAT object check flags `#Port..`
interface addresses and country groups, so those names are filtered out here before FW13 uses them.

Outputs under --out (default reports/checklist/sophos/<YYYYmmdd-HHMMSS>):
    summary.json   {generated, scope, items[{id, section, title, status, reason, findings[]}], counts}
    checklist.md   every item by section, with findings tables under non-pass items
    findings.csv   one row per finding
    raw/<host>/<Entity>.xml + _meta.json   masked API responses (passwords, PSKs, SNMP communities, tokens);
                                           re-run offline with --from-raw <out dir or its raw/ dir>
"""
import argparse
import copy
import csv
import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import netlib
import sophos_api as sa
from netlib import ROOT

SEV_RANK = {"INFO": 0, "WARN": 1, "CRIT": 2}
STATUS_ICON = {"pass": "✅", "warn": "⚠️", "crit": "❌", "info": "ℹ️", "skip": "➖"}

# Thresholds (override with --threshold KEY=VALUE).
TH = {
    "usage_warn": 80, "usage_crit": 90,                  # FW04 %
    "lic_warn_days": 60, "lic_crit_days": 15,            # FW05
    "backup_warn_days": 7,                               # FW06
    "eos_api_below": 1950,                               # FW02: API schema < this = SFOS 19.0 or older, out of support
    "latest_api": 2200,                                  # FW02: newest API schema known to this script (update it)
    "def_stale_days": 3,                                 # FW21 (pattern age is not exposed; kept for the spec)
    "admin_min_pwd_len": 8,                              # FW18
    "admin_timeout_max_min": 30,                         # FW18
    "api_ip_broad_prefix": 16,                           # FW19: allowed-IP networks wider than /16 are broad
    "dh_min_group": 14,                                  # FW24
    "clock_drift_warn_s": 300,                           # FW27 (proxy for NTP sync)
    "list_limit": 6,                                     # findings listed one by one before they are grouped
}

# FW08 ports that must not be reachable from WAN, FW14 ports that must not be port-forwarded.
WAN_BAD_PORTS = {3389: "RDP", 445: "SMB", 139: "NetBIOS/SMB", 22: "SSH", 23: "telnet"}
DNAT_BAD_PORTS = {3389: "RDP", 445: "SMB", 139: "NetBIOS/SMB", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
                  1521: "Oracle", 5900: "VNC", 22: "SSH", 23: "telnet"}
DEFAULT_COMMUNITIES = {"public", "private", "community", "snmp", "admin", "cisco", "default"}
UNTRUSTED_ZONE_RE = re.compile(r"guest|dmz|wi-?fi|wireless|public|untrust|visitor|iot", re.IGNORECASE)
SECRET_RE = re.compile(r"(password|passphrase|secret|psk|presharedkey|sharedkey|token|community|apikey|passwordhash)$"
                       r"|preshared|^psk", re.IGNORECASE)
PERMISSION_WORDS = {"read-write", "read-only", "none"}
OFFISH = sa.OFF | {"none", ""}

# Entities fetched per firewall. The first one is the cheap reachability probe for FW01.
CORE_ENTITIES = [
    "Time", "FirewallRule", "NATRule", "IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "Services", "ServiceGroup",
    "CountryGroup", "Zone", "Interface", "AdminSettings", "AdministrationProfile", "User", "AuthenticationServer",
    "OTPSettings", "AdminAuthentication", "LocalServiceACL", "SNMPCommunity", "SNMPv3User", "SyslogServers",
    "VPNIPSecConnection", "VPNProfile", "SSLVPNPolicy", "IPSPolicy", "WebFilterPolicy", "ApplicationFilterPolicy",
    "IPSSwitch", "ATP", "PatternDownload", "HAConfigure", "BackupRestore", "SystemServices",
]
# Honest attempts at data the API may expose on some firmware (all skipped on 20.0 / 21.0 / 22.0 units seen so far).
PROBE_ENTITIES = ["SystemStatus", "Licensing", "Subscription", "HAStatus", "FirmwareUpdate", "AutoUpdate",
                  "NTPServer", "ZeroDayProtection", "APIConfiguration"]
ENTITIES = CORE_ENTITIES + PROBE_ENTITIES

# (id, section, title)
ITEMS = [
    ("FW01", "A. Platform and health", "API reachable + login; firmware recorded"),
    ("FW02", "A. Platform and health", "Firmware end of support / not latest MR"),
    ("FW03", "A. Platform and health", "HA mode, peer state, sync"),
    ("FW04", "A. Platform and health", "CPU / memory / disk"),
    ("FW05", "A. Platform and health", "Licence / subscription expiry"),
    ("FW06", "A. Platform and health", "Latest XML backup; scheduled backup"),
    ("FW07", "B. Firewall rules", "Any-any-any rules"),
    ("FW08", "B. Firewall rules", "WAN -> LAN rules (RDP/SMB/SSH/telnet)"),
    ("FW09", "B. Firewall rules", "Disabled rules; rules without description"),
    ("FW10", "B. Firewall rules", "Rules with logging off"),
    ("FW11", "B. Firewall rules", "Allow rules without IPS / web / app-control policy"),
    ("FW12", "B. Firewall rules", "Shadowed / duplicate rules"),
    ("FW13", "B. Firewall rules", "Referenced-but-undefined objects; unused objects"),
    ("FW14", "C. NAT and exposure", "DNAT / port forwards; RDP/SMB/DB ports exposed"),
    ("FW15", "C. NAT and exposure", "Exposed services without source restriction"),
    ("FW16", "D. Admin and access security", "Admin HTTPS/SSH from WAN / guest / untrusted zones"),
    ("FW17", "D. Admin and access security", "Default admin enabled; admins without MFA"),
    ("FW18", "D. Admin and access security", "Weak admin password policy / long session timeout"),
    ("FW19", "D. Admin and access security", "API enabled with broad allowed-IP list"),
    ("FW20", "D. Admin and access security", "SNMP v1/v2c with default community"),
    ("FW21", "E. Threat protection", "IPS / ATP / web / zero-day off or definitions stale"),
    ("FW22", "E. Threat protection", "Pattern / firmware auto-update off"),
    ("FW23", "F. VPN", "IPsec tunnels configured active but down"),
    ("FW24", "F. VPN", "Weak crypto (DES/3DES/MD5/SHA1, DH group < 14)"),
    ("FW25", "F. VPN", "SSL VPN without MFA; split tunnel + reachable networks"),
    ("FW26", "G. Logging and time", "No remote syslog / central reporting"),
    ("FW27", "G. Logging and time", "NTP not configured / not synced"),
]
ITEM_IDS = [i[0] for i in ITEMS]
_t, _field, _leaves, _values = sa._t, sa._field, sa._leaves, sa._values


class Skip(Exception):
    """The item cannot be evaluated on this firewall (reason text goes into the report)."""


# --------------------------------------------------------------------------- masking and raw handling
def mask_root(root):
    """Mask secrets in place: password/PSK/token/community values and the Response TOKEN attribute."""
    for rec in root.iter("SNMPCommunity"):
        for x in rec.iter():
            if x.tag in ("Name", "Community", "CommunityName", "CommunityString") and _t(x).lower() in DEFAULT_COMMUNITIES:
                rec.set("default_community", "1")
        for x in rec.iter():
            if x.tag in ("Name", "Community", "CommunityName", "CommunityString") and _t(x):
                x.text = "********"
    for x in root.iter():
        if SECRET_RE.search(x.tag) and _t(x) and _t(x).lower() not in PERMISSION_WORDS:
            x.text = "********"
        for k in list(x.attrib):
            if k.upper() == "TOKEN":
                x.set(k, "********")
    return root


def is_status_marker(k):
    """An API message (<Status code=..> or 'No. of records Zero.'), not data such as IPSSwitch's <Status>Disable."""
    return k.tag == "Status" and ("code" in k.attrib or "record" in (k.text or "").lower())


def real_records(root, entity):
    """Records holding data: an entity element whose only children are <Status> messages is a marker, not a record."""
    out = []
    for e in root.findall(entity):
        kids = list(e)
        if kids and not all(is_status_marker(k) for k in kids):
            out.append(e)
    return out


def safe(s):
    return re.sub(r"[^\w.-]", "_", str(s))


def gather(dev, timeout):
    """Fetch ENTITIES (Get only) for one firewall -> dict with masked response roots. Never raises."""
    g = {"host": dev["hostname"], "ip": dev["mgmt_ip"], "api": None, "time_fetched_at": None, "error": None, "entities": {}}
    try:
        for i, ent in enumerate(ENTITIES):
            try:
                r = sa.fetch_entity(dev, ent, timeout)
            except sa.ApiError as e:
                if i == 0:
                    raise
                g["entities"][ent] = {"state": "error", "status": f"{e.kind}: {e}"[:200], "root": None}
                continue
            if i == 0:
                g["time_fetched_at"] = datetime.now(UTC).isoformat(timespec="seconds")
            root = mask_root(copy.deepcopy(r["root"]))
            g["api"] = g["api"] or root.get("APIVersion")
            state = "ok" if real_records(root, ent) else ("skipped" if r["state"] == "skipped" else "empty")
            g["entities"][ent] = {"state": state, "status": r["status"], "root": root}
    except sa.ApiError as e:
        g["error"] = f"{e.kind}: {e}"
    except Exception as e:  # noqa: BLE001 - one firewall must not stop the run
        g["error"] = netlib.err_text(e)
    return g


def save_raw(out, g):
    d = out / "raw" / safe(g["host"])
    d.mkdir(parents=True, exist_ok=True)
    d.parent.chmod(0o700)
    d.chmod(0o700)
    meta = {"host": g["host"], "ip": g["ip"], "api": g["api"], "time_fetched_at": g["time_fetched_at"],
            "error": g["error"], "entities": {}}
    for ent, v in g["entities"].items():
        meta["entities"][ent] = {"state": v["state"], "status": v["status"]}
        if v["root"] is not None and v["state"] in ("ok", "empty"):
            p = d / f"{ent}.xml"
            p.write_text(ET.tostring(v["root"], encoding="unicode"))
            p.chmod(0o600)
    (d / "_meta.json").write_text(json.dumps(meta, indent=2))
    (d / "_meta.json").chmod(0o600)


def load_raw(path):
    base = Path(path)
    if (base / "raw").is_dir():
        base = base / "raw"
    if not base.is_dir():
        raise SystemExit(f"--from-raw: {path} is not a directory")
    out = []
    for d in sorted(p for p in base.iterdir() if p.is_dir()):
        mp = d / "_meta.json"
        if not mp.exists():
            continue
        meta = json.loads(mp.read_text())
        g = {"host": meta.get("host") or d.name, "ip": meta.get("ip"), "api": meta.get("api"),
             "time_fetched_at": meta.get("time_fetched_at"), "error": meta.get("error"), "entities": {}}
        for ent, m in meta.get("entities", {}).items():
            root = None
            xp = d / f"{ent}.xml"
            if xp.exists():
                text = xp.read_text()
                if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
                    raise SystemExit(f"{xp}: DTD/entity declaration; refusing to parse")
                root = ET.fromstring(text)
            g["entities"][ent] = {"state": m.get("state"), "status": m.get("status"), "root": root}
        out.append(g)
    if not out:
        raise SystemExit(f"--from-raw: no <host>/_meta.json found under {base}")
    return out


def inventory_details():
    """hostname -> firewall_details/devices columns the checks use (empty when the DB has no such rows)."""
    try:
        db = netlib.open_db()
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT d.hostname, d.mgmt_ip, f.ha_mode, f.ha_role, f.license_expiry FROM devices d "
                          "LEFT JOIN firewall_details f ON f.device_id = d.id "
                          "WHERE d.vendor='sophos' AND d.device_type='firewall'").fetchall()
        db.close()
        return {r["hostname"]: dict(r) for r in rows}
    except sqlite3.Error:
        return {}


# --------------------------------------------------------------------------- per-firewall context
class Ctx:
    def __init__(self, g, inv, now):
        self.g, self.host, self.ip, self.api = g, g["host"], g["ip"], g["api"]
        self.inv, self.now = inv or {}, now
        self.unreachable = g["error"]
        self.latest_seen = 0
        self.E = {}
        for ent, v in g["entities"].items():
            recs = real_records(v["root"], ent) if v["root"] is not None else []
            state = v["state"] if v["state"] in ("error", "skipped", "missing") else ("ok" if recs else "empty")
            self.E[ent] = {"state": state, "status": v["status"], "recs": recs}
        self.findings, self.ran, self.skips, self.notes = [], set(), {}, {}
        self._analysis = None
        self._cache = {}

    @property
    def fw(self):
        return f"API {self.api}" if self.api else "unknown firmware"

    def recs(self, ent):
        """Records of an entity; an empty list when the entity answered with zero records; Skip when unreadable."""
        e = self.E.get(ent)
        if e is None:
            raise Skip(f"{ent}: not fetched")
        if e["state"] in ("skipped", "error", "missing"):
            raise Skip(f"{ent} unavailable on {self.fw} ({(e['status'] or e['state'])[:90]})")
        return e["recs"]

    def one(self, ent):
        r = self.recs(ent)
        if not r:
            raise Skip(f"{ent} returned no record on {self.fw}")
        return r[0]

    def unexposed(self, what):
        raise Skip(f"{what} is not exposed by the XML API on firmware {self.fw}")

    def note(self, iid, text):
        self.notes.setdefault(iid, []).append(text)

    def analysis(self):
        if self._analysis is None:
            self.recs("FirewallRule")
            secs = {ent: (e["state"] if e["state"] != "error" else "skipped", e["recs"]) for ent, e in self.E.items()}
            meta = {"host": self.host, "timestamp": self.g.get("time_fetched_at"), "api_version": self.api}
            self._analysis = sa.analyze(meta, secs)
        return self._analysis

    def cached(self, key, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]


def leaf_map(rec):
    """{tag: text} of leaf descendants (first occurrence wins)."""
    out = {}
    for x in rec.iter():
        if len(x) == 0 and x is not rec and not is_status_marker(x):
            out.setdefault(x.tag, _t(x))
    return out


def is_on(v):
    return str(v).strip().lower() in sa.ON


def is_off(v):
    return str(v).strip().lower() in OFFISH


def num(v, default=None):
    m = re.search(r"-?\d+(?:\.\d+)?", str(v or ""))
    return float(m.group()) if m else default


def parse_date(s):
    s = (s or "").strip()
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%b %d, %Y", "%B %d, %Y", "%d %b %Y", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d"):
        try:
            return datetime.strptime(s[:len(datetime.now().strftime(fmt))], fmt)
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------- object helpers
def group_members(ctx):
    """name -> set of direct member names for IPHostGroup, FQDNHostGroup, ServiceGroup."""
    def build():
        groups = {}
        for ent in ("IPHostGroup", "FQDNHostGroup", "ServiceGroup"):
            e = ctx.E.get(ent)
            for rec in (e["recs"] if e else []):
                n = _t(_field(rec, "Name"))
                if n:
                    groups[n] = {v for k, v in ((x.tag, _t(x)) for x in rec.iter() if len(x) == 0 and x is not rec)
                                 if v and k not in ("Name", "Description", "IPFamily", "Type", "Status")}
        return groups
    return ctx.cached("groups", build)


def expand(names, groups):
    seen, stack = set(), list(names)
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(groups.get(n, ()))
    return seen


def service_ports(ctx):
    """service name -> [(proto, lo, hi)]; ServiceGroup members are expanded."""
    def build():
        recs = ctx.recs("Services")
        base = {}
        for rec in recs:
            n = _t(_field(rec, "Name"))
            rows = []
            for det in rec.iter("ServiceDetail"):
                proto = (_t(_field(det, "Protocol")) or "").upper()
                port = _t(_field(det, "DestinationPort"))
                if proto in ("TCP", "UDP") and port:
                    for part in port.split(","):
                        m = re.fullmatch(r"\s*(\d+)(?::(\d+))?\s*", part)
                        if m:
                            rows.append((proto, int(m.group(1)), int(m.group(2) or m.group(1))))
            base[n] = rows
        groups = group_members(ctx)
        return {n: [r for m in expand([n], groups) for r in base.get(m, [])] for n in set(base) | set(groups)}
    return ctx.cached("svcports", build)


def risky_ports(names, ports_map, bad):
    """{port: label} from `bad` covered by any service in `names`."""
    hit = {}
    for n in names:
        for _, lo, hi in ports_map.get(n, ()):
            for p, label in bad.items():
                if lo <= p <= hi:
                    hit[p] = label
    return hit


def sel(rec, *tags):
    """frozenset of selector values, or None for Any."""
    found, vals = _values(rec, *tags)
    return None if sa._is_any(found, vals) else frozenset(vals)


def rule_info(r):
    name = _t(_field(r, "Name")) or "(unnamed)"
    st = _field(r, "Status")
    return {
        "name": name, "rec": r, "enabled": (_t(st).lower() if st is not None else "") not in sa.OFF,
        "action": _t(_field(r, "Action")).lower(), "family": _t(_field(r, "IPFamily")),
        "ptype": _t(_field(r, "PolicyType")), "sched": _t(_field(r, "Schedule")),
        "sz": sel(r, "SourceZones", "SourceZone"), "dz": sel(r, "DestinationZones", "DestinationZone"),
        "src": sel(r, "SourceNetworks", "SourceNetwork"), "dst": sel(r, "DestinationNetworks", "DestinationNetwork"),
        "svc": sel(r, "Services", "Service"),
        "ident": any(_leaves(x) for t in ("Identity", "UserGroups", "Users", "Members") for x in r.iter(t)),
    }


def rules_of(ctx):
    return ctx.cached("rules", lambda: [rule_info(r) for r in ctx.recs("FirewallRule")
                                         if _t(_field(r, "Action")) or _field(r, "SourceZones") is not None])


def add_many(add, sev, label, rows, suggestion, limit):
    """One finding per row up to `limit`, else a single grouped finding listing the first names."""
    if not rows:
        return
    if len(rows) <= limit:
        for r in rows:
            add(sev, f"{label}: {r}", suggestion)
    else:
        add(sev, f"{len(rows)} {label}: " + "; ".join(rows[:25]) + (f"; ... +{len(rows) - 25} more" if len(rows) > 25 else ""),
            suggestion)


# --------------------------------------------------------------------------- checks
CHECKS = {}


def check(iid):
    def deco(fn):
        CHECKS[iid] = fn
        return fn
    return deco


def api_num(api):
    return num(api, None)


@check("FW01")
def fw01(ctx, add):
    ctx.note("FW01", f"{ctx.fw}")  # firmware recorded; the API schema version is the only version string the API gives
    if not ctx.api:
        add("WARN", "login worked but no APIVersion attribute in the response; firmware not recorded", "")


@check("FW02")
def fw02(ctx, add):
    v = api_num(ctx.api)
    if v is None:
        ctx.unexposed("firmware version")
    ctx.note("FW02", "firmware build string is not exposed; judged by the API schema version (static table in this script)")
    if v < TH["eos_api_below"]:
        add("CRIT", f"{ctx.fw} is SFOS 19.0 or older (below API {TH['eos_api_below']}): end of support", "Plan an upgrade to a supported release")
    latest = max(TH["latest_api"], ctx.latest_seen)
    if v < latest and v >= TH["eos_api_below"]:
        add("WARN", f"{ctx.fw} is behind the newest known API {latest:g}", "Review the Sophos release notes and plan a firmware update")


@check("FW03")
def fw03(ctx, add):
    inv_ha = (ctx.inv.get("ha_mode") or "").strip().lower()
    scans = []
    if ctx.E.get("HAStatus", {}).get("state") == "ok":
        scans.append(ctx.E["HAStatus"]["recs"][0])
    rec = ctx.one("HAConfigure")
    leaves = leaf_map(rec)
    fail = [v for v in leaves.values() if "transaction fail" in v.lower()]
    if fail and len(fail) == len(leaves):
        if inv_ha not in ("", "standalone", "none"):
            add("WARN", f"inventory says HA ({inv_ha}) but HAConfigure returned 'Transaction fail' (HA not configured or not readable)",
                "Verify HA in the web admin; if HA is expected, check the API user's rights")
        else:
            ctx.note("FW03", "HAConfigure returned 'Transaction fail': HA not configured (or not readable); treated as standalone")
        if not scans:
            return
    scans.append(rec)
    bad = ("fault", "not in sync", "notinsync", "out of sync", "outofsync", "unsync", "down", "failed")
    keyed = False
    for s in scans:
        for k, v in leaf_map(s).items():
            if re.search(r"peer|sync|state|status", k, re.IGNORECASE) and "transaction fail" not in v.lower():
                keyed = True
                if any(b in v.lower() for b in bad):
                    add("CRIT", f"HA {k} = {v}", "Check the HA peer and synchronisation in the web admin")
    if not keyed and not fail:
        ctx.unexposed("HA peer state and sync")


@check("FW04")
def fw04(ctx, add):
    e = ctx.E.get("SystemStatus")
    if not e or e["state"] != "ok":
        ctx.unexposed("CPU / memory / disk usage (SystemStatus not available)")
    got = False
    for k, v in leaf_map(e["recs"][0]).items():
        if re.search(r"cpu|mem|disk|storage|swap", k, re.IGNORECASE) and num(v) is not None and "%" in v or re.search(r"usage|used", k, re.IGNORECASE) and num(v) is not None:
            got = True
            n = num(v)
            if n > TH["usage_warn"]:
                add("CRIT" if n > TH["usage_crit"] else "WARN", f"{k} = {v}", "Investigate load / capacity")
    if not got:
        ctx.unexposed("CPU / memory / disk percentages")


@check("FW05")
def fw05(ctx, add):
    dates = []
    for ent in ("Licensing", "Subscription"):
        e = ctx.E.get(ent)
        if e and e["state"] == "ok":
            for rec in e["recs"]:
                label = _t(_field(rec, "Name")) or ent
                for k, v in leaf_map(rec).items():
                    if re.search(r"expir", k, re.IGNORECASE) and parse_date(v):
                        dates.append((label, parse_date(v)))
    src = "API"
    if not dates and ctx.inv.get("license_expiry"):
        d = parse_date(str(ctx.inv["license_expiry"]))
        if d:
            dates, src = [("licence", d)], "inventory firewall_details.license_expiry (stored value, not live)"
    if not dates:
        ctx.unexposed("licence / subscription expiry (Licensing and Subscription entities unavailable)")
    if src != "API":
        ctx.note("FW05", f"from {src}")
    for label, d in dates:
        days = (d - ctx.now.replace(tzinfo=None)).days
        if days < TH["lic_warn_days"]:
            add("CRIT" if days < TH["lic_crit_days"] else "WARN",
                f"{label} {'expired' if days < 0 else 'expires'} {d:%Y-%m-%d} ({days} d)", "Renew the licence / subscription")


@check("FW06")
def fw06(ctx, add):
    p = sa.newest_backup(ctx.host)
    if p is None:
        add("WARN", f"no XML backup in backups/{ctx.host}/", "Run cfn sophos-api backup (read-only) and keep it on a schedule")
    else:
        m = re.match(r"(\d{8}-\d{6})", p.stem)
        try:
            when = datetime.strptime(m.group(1), "%Y%m%d-%H%M%S") if m else datetime.fromtimestamp(p.stat().st_mtime)
        except ValueError:
            when = datetime.fromtimestamp(p.stat().st_mtime)
        age = (ctx.now.replace(tzinfo=None) - when).total_seconds() / 86400
        ctx.note("FW06", f"{ctx.host}: newest backup {p.name} ({age:.1f} d old)")
        if age > TH["backup_warn_days"]:
            add("WARN", f"newest XML backup {p.name} is {age:.0f} days old (> {TH['backup_warn_days']} d)", "Take a fresh backup with cfn sophos-api backup")
    try:
        br = ctx.one("BackupRestore")
    except Skip as e:
        ctx.note("FW06", f"scheduled backup not evaluated: {e}")
        return
    sb = _field(br, "ScheduleBackup")
    lv = leaf_map(sb) if sb is not None else {}
    mode, freq = lv.get("BackupMode", "").lower(), lv.get("BackupFrequency", "").lower()
    if sb is None or mode in ("disable", "disabled", "off", "none") or freq in ("", "never", "disable", "disabled", "off"):
        add("WARN", "scheduled backup is off", "Enable a scheduled backup (Backup & firmware > Backup & restore)")
    else:
        ctx.note("FW06", f"{ctx.host}: scheduled backup {freq} via {mode}")


@check("FW07")
def fw07(ctx, add):
    a = ctx.analysis()
    by = {ri["name"]: ri for ri in rules_of(ctx)}
    for n in a["findings"]["any_any_any"]:
        ri = by.get(n)
        zones = f" ({','.join(sorted(ri['sz'] or ['Any']))} -> {','.join(sorted(ri['dz'] or ['Any']))})" if ri else ""
        add("CRIT", f"rule '{n}' accepts any source, destination and service{zones}", "Restrict source/destination/service to what is needed")


@check("FW08")
def fw08(ctx, add):
    a = ctx.analysis()
    by = {ri["name"]: ri for ri in rules_of(ctx)}
    try:
        ports = service_ports(ctx)
    except Skip:
        ports = None
        ctx.note("FW08", "Services entity unavailable: risky ports not classified, all WAN -> LAN rules reported as WARN")
    plain = []
    for n in a["findings"]["wan_to_lan"]:
        ri = by.get(n)
        hit = {}
        if ri and ports is not None:
            hit = dict(WAN_BAD_PORTS) if ri["svc"] is None else risky_ports(expand(ri["svc"], group_members(ctx)), ports, WAN_BAD_PORTS)
        if hit:
            what = "any service" if ri["svc"] is None else ", ".join(f"{v} ({p})" for p, v in sorted(hit.items()))
            add("CRIT", f"rule '{n}' allows WAN -> LAN: {what}", "Remove the rule or restrict it (source IPs, VPN instead of direct exposure)")
        else:
            plain.append(f"'{n}'" + (f" [{','.join(sorted(ri['svc']))}]" if ri and ri["svc"] else ""))
    add_many(add, "WARN", "WAN -> LAN accept rules", plain, "Confirm each WAN -> LAN rule is intended and source-restricted", TH["list_limit"])


@check("FW09")
def fw09(ctx, add):
    f = ctx.analysis()["findings"]
    dis = set(f["disabled"])
    add_many(add, "INFO", "disabled rules", [f"'{n}'" for n in f["disabled"]], "Delete rules that are no longer needed", TH["list_limit"])
    add_many(add, "INFO", "enabled rules without description", [f"'{n}'" for n in f["no_description"] if n not in dis],
             "Add a description (owner / purpose)", TH["list_limit"])
    if f["unparsed"]:
        ctx.note("FW09", f"{ctx.host}: {len(f['unparsed'])} rule(s) with an unrecognised structure were not evaluated")


@check("FW10")
def fw10(ctx, add):
    add_many(add, "WARN", "enabled rules with logging off", [f"'{n}'" for n in ctx.analysis()["findings"]["logging_disabled"]],
             "Enable Log traffic on the rule", TH["list_limit"])


@check("FW11")
def fw11(ctx, add):
    rows = []
    for ri in rules_of(ctx):
        if not ri["enabled"] or ri["action"] in sa.BLOCK_ACTIONS:
            continue
        r = ri["rec"]
        ips, web, app = (_t(_field(r, t)) for t in ("IntrusionPrevention", "WebFilter", "ApplicationControl"))
        if all(v.lower() in ("", "none") for v in (ips, web, app)):
            rows.append(f"'{ri['name']}' ({','.join(sorted(ri['sz'] or ['Any']))} -> {','.join(sorted(ri['dz'] or ['Any']))})")
    add_many(add, "WARN", "accept rules with no IPS, web filter or application control", rows,
             "Attach an IPS policy (and web / app control where traffic is user web traffic)", TH["list_limit"])


@check("FW12")
def fw12(ctx, add):
    groups = group_members(ctx)
    rules = [ri for ri in rules_of(ctx) if ri["enabled"]]
    ctx.note("FW12", "assumes the rule list order returned by the API is the evaluation order; groups expanded one name at a time")
    ex = lambda s: None if s is None else expand(s, groups)
    exp = [{k: ex(ri[k]) for k in ("sz", "dz", "src", "dst", "svc")} for ri in rules]

    def covers(i, j):
        e, l = rules[i], rules[j]
        if (e["family"], e["ptype"]) != (l["family"], l["ptype"]) or e["ident"] or e["sched"] not in (l["sched"], "All The Time"):
            return False
        for k in ("sz", "dz", "src", "dst", "svc"):
            a, b = exp[i][k], exp[j][k]
            if a is not None and (b is None or not b <= a):
                return False
        return True

    rows = []
    for j in range(len(rules)):
        for i in range(j):
            if covers(i, j):
                same = rules[i]["action"] == rules[j]["action"]
                dup = same and covers(j, i)
                kind = "duplicate of" if dup else ("redundant (same action) behind" if same else "shadowed (different action) by")
                rows.append(f"'{rules[j]['name']}' is {kind} earlier rule '{rules[i]['name']}'")
                break
    add_many(add, "INFO", "shadowed / duplicate rules", rows, "Review and remove or reorder", TH["list_limit"])


def defined_names(ctx):
    names = set()
    for ent in ("IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "Services", "ServiceGroup", "CountryGroup", "Zone", "Schedule"):
        e = ctx.E.get(ent)
        for rec in (e["recs"] if e else []):
            n = _t(_field(rec, "Name"))
            if n:
                names.add(n)
            if ent == "CountryGroup":  # single countries are valid rule selectors too
                names.update(_t(c) for c in rec.iter("Country") if _t(c))
    return names


@check("FW13")
def fw13(ctx, add):
    a = ctx.analysis()
    known = defined_names(ctx)
    missing = []
    for m in a["nat_missing_objects"] or []:
        miss = [v for v in m["missing"] if not v.startswith("#") and v not in known]
        if miss:
            missing.append(f"NAT rule '{m['rule']}' references {', '.join(miss)}")
    if a["nat_missing_objects"] is None:
        ctx.note("FW13", "object entities unavailable: NAT references not evaluated")
    elif ctx.E["Services"]["state"] != "skipped":
        for ri in rules_of(ctx):
            miss = set()
            for k in ("src", "dst", "svc"):
                for v in ri[k] or ():
                    if v.lower() not in sa.NAT_LITERALS and not v.startswith("#") and v not in known:
                        miss.add(v)
            if miss:
                missing.append(f"rule '{ri['name']}' references {', '.join(sorted(miss))}")
    add_many(add, "CRIT", "references to undefined objects", missing, "Recreate the object or fix the rule", TH["list_limit"])
    sysnames = set()
    for rec in ctx.E["IPHost"]["recs"]:
        if _t(_field(rec, "HostType")).lower() == "system host":
            sysnames.add(_t(_field(rec, "Name")))
    unused_h = [n for n in (a["unused_iphost"] or []) if n not in sysnames]
    add_many(add, "INFO", "unused IPHost objects", unused_h, "Delete objects nobody references", 0 if unused_h else 1)
    if a["unused_services"]:
        ctx.note("FW13", f"{ctx.host}: {len(a['unused_services'])} unreferenced Services objects not listed (built-ins cannot be told apart)")


def dnat_rules(ctx):
    out = []
    for r in ctx.recs("NATRule"):
        st = _field(r, "Status")
        if st is not None and _t(st).lower() in sa.OFF:
            continue
        td = _t(_field(r, "TranslatedDestination"))
        if td and td.lower() not in ("original", "masq", "none"):
            out.append(r)
    return out


def nat_services(r):
    found, vals = _values(r, "OriginalServices", "OriginalService")
    anysvc = sa._is_any(found, vals)
    ts = _t(_field(r, "TranslatedService"))
    return anysvc, [v for v in vals if v.lower() != "any"], ("" if ts.lower() in ("", "original", "none") else ts)


@check("FW14")
def fw14(ctx, add):
    ports = service_ports(ctx)
    groups = group_members(ctx)
    plain = []
    for r in dnat_rules(ctx):
        name = _t(_field(r, "Name"))
        anysvc, svcs, tsvc = nat_services(r)
        td = _t(_field(r, "TranslatedDestination"))
        hit = risky_ports(expand(svcs + ([tsvc] if tsvc else []), groups), ports, DNAT_BAD_PORTS)
        desc = f"-> {td}" + (f" (translated service {tsvc})" if tsvc else "")
        if anysvc:
            add("CRIT", f"DNAT '{name}' forwards ANY service {desc}: includes RDP/SMB/DB ports", "Restrict the forward to the needed service")
        elif hit:
            add("CRIT", f"DNAT '{name}' exposes " + ", ".join(f"{v} ({p})" for p, v in sorted(hit.items())) + f" {desc}",
                "Remove the forward; reach the service through VPN")
        else:
            plain.append(f"'{name}' [{','.join(svcs)}] {desc}")
    add_many(add, "INFO", "DNAT / port forwards", plain, "Confirm each forward is intended", TH["list_limit"])


@check("FW15")
def fw15(ctx, add):
    by = {ri["name"]: ri for ri in rules_of(ctx)}
    rows = []
    for r in dnat_rules(ctx):
        name = _t(_field(r, "Name"))
        if sel(r, "OriginalSourceNetworks", "OriginalSourceNetwork") is not None:
            continue
        linked = _t(_field(r, "LinkedFirewallrule"))
        fr = by.get(linked) if linked and linked.lower() != "none" else by.get(name)
        if fr is not None and fr["src"] is not None:
            continue
        _, svcs, _ = nat_services(r)
        rows.append(f"'{name}' [{','.join(svcs) or 'any'}] -> {_t(_field(r, 'TranslatedDestination'))}"
                    + ("" if fr is not None else " (no linked firewall rule found)"))
    add_many(add, "WARN", "exposed services without source restriction", rows,
             "Limit the original source to the networks/countries that need it", TH["list_limit"])


@check("FW16")
def fw16(ctx, add):
    for z in ctx.recs("Zone"):
        n, ztype = _t(_field(z, "Name")), _t(_field(z, "Type"))
        adm = _field(z, "AdminServices")
        svc = {k: v for k, v in leaf_map(adm).items() if k in ("HTTPS", "SSH")} if adm is not None else {}
        on = sorted(k for k, v in svc.items() if is_on(v))
        if not on:
            continue
        if ztype.upper() == "WAN" or n.upper() == "WAN":
            add("CRIT", f"zone '{n}' (WAN): admin {'/'.join(on)} enabled in the zone's device access", "Disable admin services on the WAN zone; use VPN or a restricted local-service ACL")
        elif UNTRUSTED_ZONE_RE.search(n) or ztype.upper() in ("DMZ", "WIFI", "WI-FI", "GUEST"):
            add("WARN", f"zone '{n}' ({ztype or 'untrusted'}): admin {'/'.join(on)} enabled", "Disable admin services on guest/untrusted zones")
    try:
        acls = ctx.recs("LocalServiceACL")
    except Skip as e:
        ctx.note("FW16", f"local service ACL not evaluated: {e}")
        return
    for r in acls:
        if _t(_field(r, "Action")).lower() not in ("accept", "allow"):
            continue
        zone = _t(_field(r, "SourceZone"))
        found, svcs = _values(r, "Services")
        adm = sorted({s.upper() for s in svcs if s.upper() in ("HTTPS", "SSH")} | ({"HTTPS", "SSH"} if sa._is_any(found, svcs) else set()))
        if not adm:
            continue
        hosts = _values(r, "Hosts")[1]
        unrestricted = sa._is_any(*_values(r, "Hosts"))
        name = _t(_field(r, "RuleName"))
        if zone.upper() == "WAN":
            if unrestricted:
                add("CRIT", f"local service ACL '{name}': {'/'.join(adm)} from WAN, any source", "Restrict the ACL to admin source IPs or remove it")
            else:
                add("WARN", f"local service ACL '{name}': {'/'.join(adm)} from WAN restricted to {', '.join(hosts)}", "Confirm only trusted admin hosts are listed; prefer VPN")
        elif UNTRUSTED_ZONE_RE.search(zone):
            add("WARN", f"local service ACL '{name}': {'/'.join(adm)} from {zone}", "Remove admin access from guest/untrusted zones")


@check("FW17")
def fw17(ctx, add):
    users = ctx.recs("User")
    admins = [u for u in users if _t(_field(u, "UserType")).lower() in ("administrator", "admin")]
    for u in admins:
        if _t(_field(u, "Username")).lower() == "admin" and _t(_field(u, "Status")).lower() in ("active", "enable", "enabled", ""):
            add("WARN", "default 'admin' account is active", "Disable or rename the default admin; use named admin accounts")
    otp = None
    try:
        otp = leaf_map(ctx.one("OTPSettings"))
    except Skip as e:
        ctx.note("FW17", f"MFA not evaluated: {e}")
    if otp is not None and admins:
        if not is_on(otp.get("otpWebAdmin", "0")):
            add("WARN", f"OTP (MFA) is not enabled for the web admin console; {len(admins)} administrator account(s)", "Enable one-time password for web admin")
        elif not is_on(otp.get("otp", "1")):
            add("INFO", f"OTP flags: otpWebAdmin=1 but master 'otp'=0 (allUsers={otp.get('allUsers')}); {len(admins)} administrator account(s)",
                "Verify in Authentication > One-time password that MFA is actually enforced for admins")


@check("FW18")
def fw18(ctx, add):
    s = ctx.one("AdminSettings")
    lv = leaf_map(s)
    if not is_on(lv.get("PasswordComplexityCheck", "")):
        add("WARN", "admin password complexity check is off", "Enable the password complexity check")
    else:
        miss = [k for k in ("IncludeAlphabeticCharacters", "IncludeNumericCharacter", "IncludeSpecialCharacter")
                if not is_on(lv.get(k, "Enable"))]
        if miss:
            add("WARN", "password policy does not require: " + ", ".join(m.replace("Include", "").replace("Characters", "").replace("Character", "") for m in miss), "Require alphabetic, numeric and special characters")
    if is_on(lv.get("MinimumPasswordLength", "Enable")):
        n = num(lv.get("MinimumPasswordLengthValue"))
        if n is not None and n < TH["admin_min_pwd_len"]:
            add("WARN", f"minimum password length is {n:g} (< {TH['admin_min_pwd_len']})", "Raise the minimum password length")
    else:
        add("WARN", "minimum password length is not enforced", "Enable a minimum password length")
    lo = lv.get("LogoutSession", "")
    n = num(lo)
    if is_off(lo):
        add("WARN", "admin session never times out (LogoutSession = Disable)", f"Set an idle timeout of {TH['admin_timeout_max_min']} minutes or less")
    elif n is not None and n > TH["admin_timeout_max_min"]:
        add("WARN", f"admin session timeout is {n:g} min (> {TH['admin_timeout_max_min']})", "Shorten the admin idle timeout")
    if is_off(lv.get("BlockLogin", "Enable")):
        add("WARN", "admin login lockout after failed attempts is off", "Enable login blocking")


@check("FW19")
def fw19(ctx, add):
    e = ctx.E.get("APIConfiguration")
    if not e or e["state"] != "ok":
        ctx.unexposed("API enabled state and allowed-IP list (APIConfiguration unavailable; the API itself answered, so it is enabled)")
    broad = []
    for rec in e["recs"]:
        for v in leaf_map(rec).values():
            for tok in re.split(r"[,\s]+", v):
                if tok.lower() in ("any", "0.0.0.0", "0.0.0.0/0", "all"):
                    broad.append(tok)
                m = re.fullmatch(r"[\d.]+/(\d+)", tok)
                if m and int(m.group(1)) < TH["api_ip_broad_prefix"]:
                    broad.append(tok)
    if broad:
        add("WARN", "API allowed-IP list is broad: " + ", ".join(sorted(set(broad))), "Allow only the management hosts")


@check("FW20")
def fw20(ctx, add):
    recs = ctx.recs("SNMPCommunity")
    for r in recs:
        lv = leaf_map(r)
        ver = " ".join(v for k, v in lv.items() if re.search(r"version", k, re.IGNORECASE)) or "v1/v2c"
        if r.get("default_community") == "1":
            add("CRIT", f"SNMP community uses a default name (public/private/...) [{ver}]", "Replace it with a long random community or use SNMPv3")
        else:
            add("INFO", f"SNMP v1/v2c community configured [{ver}] (name masked)", "Prefer SNMPv3; restrict the allowed hosts")
    if not recs:
        ctx.note("FW20", f"{ctx.host}: no SNMP v1/v2c communities configured")


@check("FW21")
def fw21(ctx, add):
    ran = False
    try:
        sw = _t(_field(ctx.one("IPSSwitch"), "Status"))
        ran = True
        if is_off(sw):
            add("WARN", "IPS is switched off (IPSSwitch Status = Disable)", "Enable IPS")
    except Skip as e:
        ctx.note("FW21", f"IPS switch not evaluated: {e}")
    try:
        atp = _t(_field(ctx.one("ATP"), "ThreatProtectionStatus"))
        ran = True
        if is_off(atp):
            add("WARN", "Advanced Threat Protection is off (ThreatProtectionStatus = Disable)", "Enable ATP if licensed")
    except Skip as e:
        ctx.note("FW21", f"ATP not evaluated: {e}")
    try:
        ss = ctx.one("SystemServices")
        ran = True
        for tag, label in (("WebProxy", "web filtering (WebProxy)"), ("IPS", "IPS engine"), ("AntiVirus", "AntiVirus")):
            st = _t(_field(_field(ss, tag), "Status")) if _field(ss, tag) is not None else ""
            if st and st.upper() != "RUNNING":
                add("WARN", f"{label} service is {st}", "Start the service / check licence")
    except Skip as e:
        ctx.note("FW21", f"service state not evaluated: {e}")
    try:
        rules = [ri for ri in rules_of(ctx) if ri["enabled"] and ri["action"] not in sa.BLOCK_ACTIONS]
        ran = True
        zd = sum(1 for ri in rules if is_on(_t(_field(ri["rec"], "ZeroDayProtection"))))
        if rules and zd == 0:
            add("INFO", "no enabled accept rule uses zero-day protection (no global zero-day switch is exposed; inferred from rules)",
                "Enable zero-day protection on rules for web/mail traffic if licensed")
    except Skip:
        pass
    if not ran:
        raise Skip("IPSSwitch, ATP, SystemServices and FirewallRule all unavailable")
    ctx.note("FW21", "signature / definition age is not exposed by the XML API (PatternDownload carries no timestamp)")


@check("FW22")
def fw22(ctx, add):
    pd = ctx.one("PatternDownload")
    if is_off(_t(_field(pd, "AutoUpdate"))):
        add("WARN", "pattern auto-update is off (PatternDownload AutoUpdate = Off)", "Enable automatic pattern updates")
    for ent in ("AutoUpdate", "FirmwareUpdate"):
        e = ctx.E.get(ent)
        if e and e["state"] == "ok":
            for k, v in leaf_map(e["recs"][0]).items():
                if re.search(r"auto", k, re.IGNORECASE) and is_off(v):
                    add("WARN", f"{ent} {k} = {v}", "Enable automatic firmware update downloads")
    ctx.note("FW22", "firmware auto-update setting is not exposed by the XML API (AutoUpdate / FirmwareUpdate unavailable)")


@check("FW23")
def fw23(ctx, add):
    recs = ctx.recs("VPNIPSecConnection")
    conns = [c for r in recs for c in r.iter("Configuration") if any(k.tag != "Status" for k in c)]
    if conns:
        names = ", ".join(_t(_field(c, "Name")) or "(unnamed)" for c in conns[:10])
        ctx.unexposed(f"IPsec tunnel up/down state for {len(conns)} configured connection(s) ({names})")
    ctx.note("FW23", f"{ctx.host}: no IPsec connections configured")


def weak_algos(lv_items):
    out = []
    for k, v in lv_items:
        vl = v.lower()
        if re.match(r"(encryption|authentication)algorithm\d*$", k, re.IGNORECASE) and vl:
            if ("des" in vl and "aes" not in vl) or vl in ("md5", "sha1", "sha-1", "sha1_96") \
                    or re.fullmatch(r"hmac[_-]?(md5|sha1)", vl):
                out.append(f"{k}={v}")
    return out


@check("FW24")
def fw24(ctx, add):
    profiles = ctx.recs("VPNProfile")
    try:
        used = {v for r in ctx.recs("VPNIPSecConnection") for v in _leaves(r)}
    except Skip:
        used = set()
    unused_weak = []
    for p in profiles:
        name = _t(_field(p, "Name"))
        weak = weak_algos((x.tag, _t(x)) for x in p.iter() if len(x) == 0)
        for x in p.iter("DHGroup"):
            n = num(_t(x))
            if n is not None and n < TH["dh_min_group"]:
                weak.append(f"DH group {_t(x)}")
        pfs = _t(_field(p, "PFSGroup"))
        if num(pfs) is not None and num(pfs) < TH["dh_min_group"]:
            weak.append(f"PFS group {pfs}")
        if weak and name in used:
            add("WARN", f"VPN profile '{name}' (in use by an IPsec connection): " + ", ".join(sorted(set(weak))),
                "Use AES-GCM/AES-256, SHA-256+ and DH group 14 or higher")
        elif weak:
            unused_weak.append(f"'{name}' ({', '.join(sorted(set(weak)))})")
    if unused_weak:
        add("WARN", f"{len(unused_weak)} VPN profile(s) with weak crypto, not referenced by any IPsec connection "
            "(may still back L2TP / remote access): " + "; ".join(unused_weak),
            "Delete unused legacy profiles or move them to AES-256 / SHA-256+ / DH 14+")


@check("FW25")
def fw25(ctx, add):
    recs = ctx.recs("SSLVPNPolicy")
    pols = [t for r in recs for t in r.iter("TunnelPolicy") if any(k.tag != "Status" for k in t)]
    otp = None
    try:
        otp = leaf_map(ctx.one("OTPSettings"))
    except Skip as e:
        ctx.note("FW25", f"MFA not evaluated: {e}")
    for p in pols:
        n = _t(_field(p, "Name"))
        if otp is not None and not is_on(otp.get("otpSSLVPN", "0")):
            add("WARN", f"SSL VPN policy '{n}': one-time password (MFA) is not enabled for SSL VPN", "Enable OTP for SSL VPN")
        res = _values(p, "PermittedNetworkResourcesIPv4", "PermittedNetworkResources")[1]
        if not is_on(_t(_field(p, "UseAsDefaultGateway"))):
            add("INFO", f"SSL VPN policy '{n}': split tunnel, reachable networks: {', '.join(res) or 'none listed'}", "Confirm the permitted networks are the minimum needed")
    if not pols:
        ctx.note("FW25", f"{ctx.host}: no SSL VPN tunnel policy")


@check("FW26")
def fw26(ctx, add):
    recs = ctx.recs("SyslogServers")
    remote = [r for r in recs if _t(_field(r, "ServerAddress")) and not _t(_field(r, "ServerAddress")).startswith("127.")]
    if not remote:
        add("WARN", "no remote syslog server configured", "Send logs to a central syslog / reporting server")
    else:
        ctx.note("FW26", f"{ctx.host}: {len(remote)} remote syslog server(s)")
    ctx.note("FW26", "central reporting (Sophos Central / iView) is not exposed by the XML API")


@check("FW27")
def fw27(ctx, add):
    t = ctx.one("Time")
    tz = _t(_field(t, "TimeZone"))
    try:
        d, hm = _field(t, "Date"), _field(t, "Time")
        dev = datetime(int(_t(_field(d, "Year"))), int(_t(_field(d, "Month"))), int(_t(_field(d, "Day"))),
                       int(_t(_field(hm, "HH"))), int(_t(_field(hm, "MM"))), int(_t(_field(hm, "SS"))), tzinfo=ZoneInfo(tz))
        fetched = datetime.fromisoformat(ctx.g["time_fetched_at"])
    except Exception:  # noqa: BLE001 - schema or timezone not understood
        ctx.unexposed("device clock / NTP state (Time entity not parseable)")
    drift = (dev - fetched).total_seconds()
    ctx.note("FW27", f"{ctx.host}: clock {drift:+.0f}s vs this host ({tz}); the NTP server list and sync state are not exposed by the XML API")
    if abs(drift) > TH["clock_drift_warn_s"]:
        add("WARN", f"device clock differs from this host by {drift:+.0f}s (> {TH['clock_drift_warn_s']}s): NTP likely not working", "Check NTP servers and sync in the web admin")


# --------------------------------------------------------------------------- run
def run_checks(ctx):
    if ctx.unreachable:
        return
    for iid in ITEM_IDS:
        def add(sev, detail, suggestion="", iid=iid):
            ctx.findings.append((iid, {"target": ctx.host, "vcenter": "", "firewall": ctx.host, "severity": sev,
                                       "detail": detail, "suggestion": suggestion}))
        try:
            CHECKS[iid](ctx, add)
            ctx.ran.add(iid)
        except Skip as e:
            ctx.skips[iid] = str(e)
        except Exception as e:  # noqa: BLE001 - a parse problem skips the item, never the run
            ctx.skips[iid] = f"could not evaluate on {ctx.fw}: {netlib.err_text(e)}"


def assemble(ctxs):
    reach = [c for c in ctxs if not c.unreachable]
    unreach = [c for c in ctxs if c.unreachable]
    items = []
    for iid, section, title in ITEMS:
        f = [x for c in reach for i, x in c.findings if i == iid]
        ok = [c for c in reach if iid in c.ran]
        reasons = []
        if iid == "FW01":
            f += [{"target": c.host, "vcenter": "", "firewall": c.host, "severity": "CRIT",
                   "detail": f"API unreachable or login failed: {c.unreachable}",
                   "suggestion": "Check the API is enabled, this host's IP is allowed, and NET_SOPHOSAPI_* credentials"} for c in unreach]
            ok = ctxs
        bad = [f"{c.host}: {c.skips[iid]}" for c in reach if iid in c.skips]
        notes = []
        for c in reach:
            if iid in c.ran:
                notes += c.notes.get(iid, [])
        if unreach and iid != "FW01":
            reasons.append("not evaluated on unreachable firewall(s): " + ", ".join(c.host for c in unreach))
        if not ok:
            status, reason, f = "skip", "; ".join(bad) or "no reachable firewall", []
        else:
            worst = max((SEV_RANK[x["severity"]] for x in f), default=None)
            status = "pass" if worst is None else {0: "info", 1: "warn", 2: "crit"}[worst]
            reason = "; ".join(dict.fromkeys(bad + notes + reasons)) or None
            if iid == "FW01":
                reason = "; ".join(f"{c.host}: {c.fw}" for c in reach) or None
        f.sort(key=lambda x: (-SEV_RANK[x["severity"]], x["target"], x["detail"]))
        items.append({"id": iid, "section": section, "title": title, "status": status, "reason": reason, "findings": f})
    counts = {k: sum(1 for i in items if i["status"] == k) for k in ("pass", "info", "warn", "crit", "skip")}
    counts["findings"] = dict(Counter(x["severity"] for i in items for x in i["findings"]))
    return items, counts


def md_table(rows, head):
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]


def write_outputs(out, summary):
    items, counts, sc, fc = summary["items"], summary["counts"], summary["scope"], summary["counts"]["findings"]
    L = [f"# Sophos firewall checklist - {summary['generated']}", "",
         f"Scope: {', '.join(sc['firewalls']) or 'none'}" + (f" (unreachable: {', '.join(sc['unreachable'])})" if sc["unreachable"] else ""),
         "Firmware (API schema version): " + ", ".join(f"{h}={v or '?'}" for h, v in sc["firmware"].items()), "",
         (f"Items: {len(items)} | ✅ pass {counts['pass']} | ℹ️ info {counts['info']} | ⚠️ warn {counts['warn']} | "
          f"❌ crit {counts['crit']} | ➖ skip {counts['skip']}"), "",
         (f"Findings: CRIT={fc.get('CRIT', 0)} WARN={fc.get('WARN', 0)} INFO={fc.get('INFO', 0)} "
          "(read-only; suggestions are text only, never executed). Boxes: [x] pass/info, [ ] needs attention or skipped.")]
    sec = None
    for it in items:
        if it["section"] != sec:
            sec = it["section"]
            L += ["", f"## {sec}", ""]
        n = len(it["findings"])
        L.append(f"- [{'x' if it['status'] in ('pass', 'info') else ' '}] {STATUS_ICON[it['status']]} **{it['id']}** {it['title']} "
                 f"({n} finding{'s' if n != 1 else ''})" + (f" - {it['reason']}" if it["reason"] else ""))
        if it["status"] != "pass" and it["findings"]:
            rows = it["findings"][:300]
            L += [""] + md_table([(x["severity"], x["target"], x["detail"], x["suggestion"]) for x in rows],
                                 ["Sev", "Firewall", "Detail", "Suggestion"])
            if n > len(rows):
                L.append(f"\n... {n - len(rows)} more in findings.csv")
            L.append("")
    (out / "checklist.md").write_text("\n".join(L) + "\n")
    with open(out / "findings.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["item_id", "section", "title", "status", "severity", "firewall", "target", "detail", "suggestion"])
        for it in items:
            for x in it["findings"]:
                w.writerow([it["id"], it["section"], it["title"], it["status"], x["severity"], x["firewall"], x["target"],
                            x["detail"], x["suggestion"]])
    (out / "summary.json").write_text(json.dumps(summary, indent=2))


def parse_thresholds(pairs):
    for p in pairs:
        k, _, v = p.partition("=")
        if k not in TH or not v:
            raise SystemExit(f"--threshold: unknown key or empty value in {p!r}; keys: {', '.join(TH)}")
        TH[k] = type(TH[k])(float(v)) if isinstance(TH[k], (int, float)) else v


def main():
    ap = argparse.ArgumentParser(description="Read-only Sophos XG/SFOS checklist (XML API Get only)")
    netlib.add_target_args(ap)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=30, help="per-request timeout seconds")
    ap.add_argument("--out", help="output dir (default reports/checklist/sophos/<timestamp>)")
    ap.add_argument("--from-raw", metavar="DIR", help="re-run the checks on a saved run (its dir or its raw/ dir); no firewall contact")
    ap.add_argument("--threshold", action="append", default=[], metavar="KEY=VALUE", help=f"override a threshold ({', '.join(TH)})")
    args = ap.parse_args()
    parse_thresholds(args.threshold)
    started = datetime.now(UTC)
    out = Path(args.out) if args.out else ROOT / "reports" / "checklist" / "sophos" / datetime.now().strftime("%Y%m%d-%H%M%S")
    inv = inventory_details()

    if args.from_raw:
        gathered = load_raw(args.from_raw)
        wanted = set(args.targets)
        if wanted:
            gathered = [g for g in gathered if g["host"] in wanted or g["ip"] in wanted]
        out.mkdir(parents=True, exist_ok=True)
        source = str(Path(args.from_raw))
    else:
        if not (args.targets or args.match or args.role or args.all):
            args.all = True
        devs = sa.resolve_firewalls(args)
        out.mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max(1, min(args.workers, len(devs)))) as ex:
            gathered = list(ex.map(lambda d: gather(d, args.timeout), devs))
        for g in gathered:
            save_raw(out, g)
        source = None
    out.chmod(0o700)
    seen = [api_num(g["api"]) for g in gathered if api_num(g["api"])]
    ctxs = [Ctx(g, inv.get(g["host"]), datetime.now()) for g in gathered]
    for c in ctxs:
        c.latest_seen = max(seen) if seen else 0
        run_checks(c)
    items, counts = assemble(ctxs)
    summary = {"generated": started.isoformat(timespec="seconds"), "read_only": True, "source_raw": source,
               "scope": {"firewalls": [c.host for c in ctxs], "unreachable": [c.host for c in ctxs if c.unreachable],
                         "firmware": {c.host: c.api for c in ctxs}},
               "items": items, "counts": counts}
    write_outputs(out, summary)

    print(f"Sophos checklist: {len(ctxs)} firewall(s)" + (f" (from raw {source})" if source else " (live, Get only)"))
    for c in ctxs:
        print(f"  {c.host:24} {c.ip or '':15} {c.fw if not c.unreachable else 'UNREACHABLE: ' + c.unreachable}")
    print(f"Items: {len(items)} | pass {counts['pass']} | info {counts['info']} | warn {counts['warn']} | "
          f"crit {counts['crit']} | skip {counts['skip']}   Findings: " + " ".join(f"{k}={v}" for k, v in sorted(counts["findings"].items())))
    for it in items:
        if it["status"] != "pass":
            print(f"  {STATUS_ICON[it['status']]} {it['id']} {it['title']} ({len(it['findings'])})"
                  + (f" - {it['reason'][:110]}" if it["status"] == "skip" and it["reason"] else ""))
    print(f"Report: {out / 'checklist.md'}\nJSON:   {out / 'summary.json'}\nCSV:    {out / 'findings.csv'}")


if __name__ == "__main__":
    main()
