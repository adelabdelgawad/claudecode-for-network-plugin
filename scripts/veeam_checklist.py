"""READ-ONLY Veeam Backup & Replication checklist: items VB01-VB20 from .claude/skills/checklist/veeam.md.

Usage: cfn veeam-checklist --host H [--host H ...] [--port 9419] [--cred VEEAM]
           [--api-version 1.1-rev0] [--out DIR] [--from-raw DIR] [--workers 4] [--timeout 60] [--json]

Data comes from the Veeam REST API through veeam_api.py (GET only; the OAuth token POST/logout stay the only
non-GET calls). VB17/VB18 compare job includes with the vSphere inventory DB (`machines`, opened read-only).
Endpoints that a given Veeam version does not expose (404/400) or that the account may not read (403) turn the
item into skip with the reason, never a traceback. Suggestions in the report are text only and never executed.

Output (reports/checklist/veeam/<ts>/, same item schema as vsphere_checklist.py):
    summary.json   {generated, scope, items[{id, section, title, status, reason, findings[]}], counts}
    checklist.md   every item by section with findings tables
    findings.csv   one row per finding
    raw/<host>/*.json   API responses (no tokens or credentials); `--from-raw DIR` re-runs the analysis from them
"""
import argparse
import csv
import json
import os
import re
import sqlite3
import sys
from argparse import Namespace
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import netlib
import veeam_api
from veeam_api import ApiError, data_of, parse_ts

ROOT = netlib.ROOT
STATUS_ICON = {"pass": "✅", "warn": "⚠️", "crit": "❌", "info": "ℹ️", "skip": "➖"}
SEV_RANK = {"INFO": 0, "WARN": 1, "CRIT": 2}

# ---- thresholds / editable constants (keep in sync with .claude/skills/checklist/veeam.md)
# UPDATE THIS when Veeam ships a newer 12.x cumulative patch (VB01 warns when the server build is older).
LATEST_KNOWN_12X = "12.3.2.3617"
LICENSE_WARN_DAYS = 60
LICENSE_USED_WARN_PCT = 90.0
CONFIG_BACKUP_WARN_HOURS = 48
CONFIG_BACKUP_CRIT_DAYS = 7
NO_SUCCESS_WARN_HOURS = 48
NO_SUCCESS_CRIT_DAYS = 7
RUNNING_WARN_HOURS = 12
MIN_RESTORE_POINTS = 7
REPO_FREE_WARN_PCT = 20.0
REPO_FREE_CRIT_PCT = 10.0
SESSION_WINDOW_DAYS = 30          # session look-back for VB03/VB05/VB16
# VB08: VMs that should be backed up application-aware. Matched as whole name tokens (so "ad" does not hit "head").
VB08_NAME_RE = re.compile(r"(?:^|[^a-z])(db|sql|dc|ad|exch\w*|postgres\w*|mysql\w*|oracle\w*)(?:[^a-z]|$)", re.IGNORECASE)
VB08_ROLES = {"dc", "ad", "db", "database", "sql", "exchange", "mail"}   # inventory machines.role
VB08_OS_RE = re.compile(r"sql|exchange", re.IGNORECASE)                           # inventory machines.guest_os
MAX_LISTED = 40

ITEMS = [
    ("VB01", "A. Server", "API reachable + login; version/build vs latest patch"),
    ("VB02", "A. Server", "Licence expiry; instances used vs licensed"),
    ("VB03", "A. Server", "Configuration backup: present, recent success, encrypted"),
    ("VB04", "B. Backup jobs", "Last result per job"),
    ("VB05", "B. Backup jobs", "No successful run (daily jobs)"),
    ("VB06", "B. Backup jobs", "Running too long"),
    ("VB07", "B. Backup jobs", "Disabled jobs; jobs with no schedule"),
    ("VB08", "B. Backup jobs", "Application-aware processing off on DB / DC / Exchange VMs"),
    ("VB09", "B. Backup jobs", "Retention below minimum restore points; no GFS anywhere"),
    ("VB10", "B. Backup jobs", "Retry disabled"),
    ("VB11", "C. Repositories and storage", "Repository free space; offline repository"),
    ("VB12", "C. Repositories and storage", "No immutable / hardened repository"),
    ("VB13", "C. Repositories and storage", "Backup encryption off"),
    ("VB14", "D. 3-2-1 and resilience", "No backup copy job / second copy"),
    ("VB15", "D. 3-2-1 and resilience", "All jobs on a single repository"),
    ("VB16", "D. 3-2-1 and resilience", "SureBackup / restore verification never run"),
    ("VB17", "E. Coverage (vs vCenter)", "Powered-on VMs with no backup job"),
    ("VB18", "E. Coverage (vs vCenter)", "Jobs pointing at VMs that no longer exist"),
    ("VB19", "F. Infrastructure", "Proxies / managed servers offline; outdated components"),
    ("VB20", "F. Infrastructure", "Active alarms / malware detection events"),
]
ITEM_IDS = [i[0] for i in ITEMS]

# raw name -> (path, params builder, paged list?). Single objects use api_get, lists use get_all.
ENDPOINTS = {
    "serverInfo": ("/api/v1/serverInfo", None, False),
    "license": ("/api/v1/license", None, False),
    "license_instances": ("/api/v1/license/instances", None, True),
    "configBackup": ("/api/v1/configBackup", None, False),
    "jobs": ("/api/v1/jobs", None, True),
    "jobs_states": ("/api/v1/jobs/states", None, True),
    "sessions": ("/api/v1/sessions", "sessions", True),
    "repos": ("/api/v1/backupInfrastructure/repositories", None, True),
    "repos_states": ("/api/v1/backupInfrastructure/repositories/states", None, True),
    "proxies": ("/api/v1/backupInfrastructure/proxies", None, True),
    "managedServers": ("/api/v1/backupInfrastructure/managedServers", None, True),
    "backups": ("/api/v1/backups", None, True),
    "malware": ("/api/v1/malwareDetection/events", None, True),
    "encryptionPasswords": ("/api/v1/encryptionPasswords", None, True),
}


class Skip(Exception):
    """Raised inside a check when its data is unavailable; the item becomes skip with this reason."""


def err_text(e):
    return f"{type(e).__name__}: {str(e)[:150]}"


# --------------------------------------------------------------------------- collection
def session_params():
    after = (datetime.now(UTC) - timedelta(days=SESSION_WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {"orderColumn": "CreationTime", "orderAsc": "false", "createdAfterFilter": after}


def classify(e, api_version):
    """ApiError -> short reason used as the skip text."""
    m = str(e)
    if "HTTP 404" in m or "HTTP 400" in m:
        return f"endpoint not available on this Veeam version (API {api_version}): {m[:120]}"
    if "HTTP 403" in m:
        return f"account lacks permission for this endpoint: {m[:120]}"
    return m[:200]


def fetch_host(args, host):
    """Login, probe every endpoint, logout -> (raw {name: json}, errs {name: reason}). ApiError if login fails."""
    user, pw = veeam_api.credentials(args.cred)
    cli = veeam_api.Veeam(host, args.port, args.api_version, args.verify_ssl, args.timeout)
    cli.login(user, pw)
    raw, errs = {}, {}
    try:
        for name, (path, params, paged) in ENDPOINTS.items():
            try:
                p = session_params() if params == "sessions" else None
                raw[name] = cli.get_all(path, p) if paged else cli.api_get(path)
            except ApiError as e:
                errs[name] = classify(e, args.api_version)
            except Exception as e:  # noqa: BLE001
                errs[name] = err_text(e)
    finally:
        cli.logout()
    return raw, errs


def save_raw(out, host, raw, errs):
    d = out / "raw" / veeam_api.safe_name(host)
    for name, v in raw.items():
        veeam_api.write_json(d / f"{name}.json", v)
    veeam_api.write_json(d / "_errors.json", errs)


def load_raw(path):
    """--from-raw DIR (report dir or its raw/ dir) -> {host: (raw, errs, None)}."""
    p = Path(path)
    if (p / "raw").is_dir():
        p = p / "raw"
    if not p.is_dir():
        raise SystemExit(f"--from-raw: {path} is not a directory")
    res = {}
    for hd in sorted(x for x in p.iterdir() if x.is_dir()):
        raw, errs = {}, {}
        for f in hd.glob("*.json"):
            try:
                v = json.loads(f.read_text())
            except ValueError:
                continue
            if f.stem == "_errors":
                errs = v
            else:
                raw[f.stem] = v
        res[hd.name] = (raw, errs, None)
    if not res:
        raise SystemExit(f"--from-raw: no <host>/*.json under {p}")
    return res


# --------------------------------------------------------------------------- helpers
def aslist(v):
    return v if isinstance(v, list) else ([] if v is None else [v])


def include_rows(items):
    """Normalise includes/excludes entries -> [{type, name, object_id, host}]."""
    rows = []
    for it in aslist(items):
        if not isinstance(it, dict):
            continue
        inv = it.get("inventoryObject") if isinstance(it.get("inventoryObject"), dict) else it
        rows.append({"type": str(inv.get("type") or "").lower(), "name": str(inv.get("name") or ""),
                     "object_id": str(inv.get("objectId") or ""), "host": str(inv.get("hostName") or "")})
    return rows


def short(h):
    h = (h or "").lower()
    return h if not h or h.replace(".", "").isdigit() else h.split(".")[0]


def moref_of(object_id):
    m = re.search(r"(?:^|[.:])((?:vm|vapp)-\d+)$", (object_id or "").lower())
    return m.group(1) if m else None


def find_key(obj, key):
    """First value stored under `key` anywhere in a nested dict/list, else None."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def build_tuple(s):
    return tuple(int(x) for x in re.findall(r"\d+", s or ""))[:4]


class Ctx:
    """One Veeam server: raw API data plus the findings/skips each check produced."""

    def __init__(self, host, raw, errs, args):
        self.host, self.raw, self.errs, self.args = host, raw, errs, args
        self.findings = {i: [] for i in ITEM_IDS}
        self.skips = {}
        self.notes = {i: [] for i in ITEM_IDS}
        self.now = datetime.now(UTC)
        self._jobs = None
        self._inv = None

    def get(self, name):
        """Endpoint data or raise Skip with the reason it is missing."""
        if name in self.raw:
            return self.raw[name]
        raise Skip(self.errs.get(name) or f"endpoint {name} was not collected")

    def rows(self, name):
        return data_of(self.get(name))

    def add(self, iid, target, severity, detail, suggestion="", vcenter=""):
        self.findings[iid].append({"target": str(target), "vcenter": vcenter, "severity": severity,
                                   "detail": detail, "suggestion": suggestion})

    # ---- jobs
    def jobs(self):
        """Merge /jobs (config) with /jobs/states by id -> list of dicts."""
        if self._jobs is None:
            cfg = {j.get("id"): j for j in self.rows("jobs")}
            states = {}
            try:
                states = {s.get("id"): s for s in self.rows("jobs_states")}
            except Skip:
                pass
            out = []
            for jid in list(cfg) + [k for k in states if k not in cfg]:
                c, s = cfg.get(jid, {}), states.get(jid, {})
                vms = c.get("virtualMachines") if isinstance(c.get("virtualMachines"), dict) else {}
                inc = include_rows(vms.get("includes"))
                exc = vms.get("excludes")
                exc = include_rows(exc.get("vms") if isinstance(exc, dict) else exc)
                out.append({"id": jid, "name": c.get("name") or s.get("name") or jid,
                            "type": c.get("type") or s.get("type") or "", "cfg": c, "state": s,
                            "disabled": bool(c.get("isDisabled")) or s.get("status") == "disabled",
                            "includes": inc, "excludes": exc,
                            "vc": next((i["host"] for i in inc if i["host"]), "")})
            self._jobs = out
        return self._jobs

    def backup_jobs(self):
        return [j for j in self.jobs() if j["type"].lower() == "backup" or (j["cfg"].get("virtualMachines") and "copy" not in j["type"].lower())]

    # ---- sessions
    def last_success(self):
        """job name (lower) -> latest end/creation time of a Success/Warning Job session in the window."""
        res = {}
        for s in self.rows("sessions"):
            if s.get("sessionType") != "Job":
                continue
            r = veeam_api.result_of(s).lower()
            if r not in ("success", "warning"):
                continue
            t = parse_ts(s.get("endTime")) or parse_ts(s.get("creationTime"))
            k = (s.get("name") or "").lower()
            if t and (k not in res or t > res[k]):
                res[k] = t
        return res

    # ---- inventory (read-only)
    def inventory(self):
        if self._inv is None:
            self._inv = load_inventory()
        return self._inv


def load_inventory():
    """-> {"vcenters": [{id,name,host}], "machines": [rows]} from inventory.db opened read-only."""
    import vmlib
    db = sqlite3.connect(f"file:{vmlib.DB}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        vcs = [dict(r) for r in db.execute("SELECT id, name, host, status FROM vcenters WHERE status != 'decommissioned'")]
        ms = [dict(r) for r in db.execute(
            "SELECT name, vcenter_id, moref, power_state, is_template, role, guest_os, guest_hostname, primary_ip, status "
            "FROM machines WHERE status='active'")]
    finally:
        db.close()
    have = {m["vcenter_id"] for m in ms}
    for v in vcs:   # only a vCenter with an active status and discovered VMs can be cross-checked
        v["checkable"] = v["status"] == "active" and v["id"] in have
    return {"vcenters": vcs, "machines": ms}


def vc_for_host(inv, host, checkable=True):
    """Inventory vCenter for a Veeam hostName; with checkable=True only one that can be cross-checked."""
    h, sh = (host or "").lower(), short(host)
    for v in inv["vcenters"]:
        if (h in (v["host"].lower(), v["name"].lower()) or sh in (short(v["host"]), short(v["name"]))) \
                and (v["checkable"] or not checkable):
            return v
    return None


def sev_status(findings):
    worst = max((SEV_RANK[x["severity"]] for x in findings), default=None)
    return "pass" if worst is None else {0: "info", 1: "warn", 2: "crit"}[worst]


def hours(td):
    return td.total_seconds() / 3600


def fmt_age(td):
    h = hours(td)
    return f"{h:.0f} h" if h < 72 else f"{h / 24:.0f} d"


# --------------------------------------------------------------------------- checks
CHECKS = []


def check(*ids):
    def deco(fn):
        CHECKS.append((ids, fn))
        return fn
    return deco


@check("VB01")
def c_server(c):
    info = c.get("serverInfo")
    build = info.get("buildVersion")
    c.notes["VB01"].append(f"login OK; {info.get('name')} build {build}, {len(info.get('patches') or [])} patches listed "
                           f"(latest known 12.x build {LATEST_KNOWN_12X})")
    if build_tuple(build) and build_tuple(build) < build_tuple(LATEST_KNOWN_12X):
        c.add("VB01", c.host, "WARN", f"build {build} is older than the latest known 12.x build {LATEST_KNOWN_12X}",
              "Plan an upgrade to the latest cumulative patch / 12.x release (check Veeam KB2680)")


@check("VB02")
def c_license(c):
    lic = c.get("license")
    exp = parse_ts(str(find_key(lic, "expirationDate") or ""))
    if exp:
        days = (exp - c.now).days
        if days < 0:
            c.add("VB02", "licence", "CRIT", f"licence expired {-days} d ago ({exp:%Y-%m-%d})", "Renew or install a new licence file")
        elif days < LICENSE_WARN_DAYS:
            c.add("VB02", "licence", "WARN", f"licence expires in {days} d ({exp:%Y-%m-%d})", "Renew the licence")
    used = num(find_key(lic, "usedInstancesNumber"))
    total = num(find_key(lic, "licensedInstancesNumber"))
    if used is None or total is None:
        try:
            for r in c.rows("license_instances"):
                u, t = num(r.get("usedInstancesNumber")), num(r.get("licensedInstancesNumber"))
                used, total = (used or 0) + (u or 0), (total or 0) + (t or 0)
        except Skip:
            pass
    if used is not None and total:
        pct = used / total * 100
        c.notes["VB02"].append(f"{used:g}/{total:g} instances ({pct:.0f}%)")
        if pct > LICENSE_USED_WARN_PCT:
            c.add("VB02", "licence", "WARN", f"{used:g} of {total:g} instances used ({pct:.0f}%)", "Add licence capacity or reduce protected workloads")
    if not exp and used is None:
        raise Skip("licence response has no expiry or instance fields")


def config_backup_sessions(c):
    return sorted((s for s in c.rows("sessions") if s.get("sessionType") == "ConfigurationBackup"),
                  key=lambda s: s.get("creationTime") or "", reverse=True)


@check("VB03")
def c_config_backup(c):
    sug = "Enable the configuration backup and set a password (Veeam console > Configuration Backup)"
    try:
        cb = c.get("configBackup")
    except Skip as e:
        cb, why = None, str(e)
    if cb is not None:
        if cb.get("isEnabled") is False:
            c.add("VB03", "configuration backup", "CRIT", "configuration backup is disabled", sug)
        ls = cb.get("lastSuccessfulBackup")
        last = parse_ts(str((ls.get("lastSuccessfulTime") if isinstance(ls, dict) else ls) or ""))
        if last is None:
            c.add("VB03", "configuration backup", "WARN", "no last-successful time reported", sug)
        elif c.now - last > timedelta(days=CONFIG_BACKUP_CRIT_DAYS):
            c.add("VB03", "configuration backup", "CRIT", f"last success {fmt_age(c.now - last)} ago", sug)
        elif c.now - last > timedelta(hours=CONFIG_BACKUP_WARN_HOURS):
            c.add("VB03", "configuration backup", "WARN", f"last success {fmt_age(c.now - last)} ago", sug)
        if isinstance(cb.get("encryption"), dict) and cb["encryption"].get("isEnabled") is False:
            c.add("VB03", "configuration backup", "WARN", "configuration backup is not encrypted",
                  "Set an encryption password so credentials in the backup are protected")
        return
    # /configBackup unreadable: judge presence and recency from the ConfigurationBackup sessions instead
    sess = config_backup_sessions(c)
    if not sess:
        raise Skip(f"/configBackup unavailable ({why}) and no ConfigurationBackup session in the last {SESSION_WINDOW_DAYS} d")
    c.notes["VB03"].append(f"/configBackup unreadable ({why[:60]}); judged from sessions; encryption state cannot be read")
    ok = [s for s in sess if veeam_api.result_of(s).lower() in ("success", "warning")]
    latest = sess[0]
    lr = veeam_api.result_of(latest)
    if lr.lower() == "failed":
        c.add("VB03", "configuration backup", "CRIT", f"latest configuration backup session failed ({veeam_api.fmt_ts(latest.get('creationTime'))})",
              "Check the Backup Configuration Job session in the console")
    elif lr.lower() == "warning":
        c.add("VB03", "configuration backup", "WARN", f"latest configuration backup session ended with Warning ({veeam_api.fmt_ts(latest.get('creationTime'))})",
              "Open the session for the warning text")
    t = parse_ts((ok[0] if ok else {}).get("creationTime"))
    if t is None:
        c.add("VB03", "configuration backup", "CRIT", f"no successful configuration backup in {SESSION_WINDOW_DAYS} d", sug)
    elif c.now - t > timedelta(days=CONFIG_BACKUP_CRIT_DAYS):
        c.add("VB03", "configuration backup", "CRIT", f"last success {fmt_age(c.now - t)} ago", sug)
    elif c.now - t > timedelta(hours=CONFIG_BACKUP_WARN_HOURS):
        c.add("VB03", "configuration backup", "WARN", f"last success {fmt_age(c.now - t)} ago", sug)


@check("VB04")
def c_last_result(c):
    for j in c.jobs():
        if j["type"].lower() not in ("backup", "") and not j["cfg"].get("virtualMachines") and "copy" not in j["type"].lower():
            continue
        lr = (j["state"].get("lastResult") or "").lower()
        when = veeam_api.fmt_ts(j["state"].get("lastRun"))
        if lr == "failed":
            c.add("VB04", j["name"], "CRIT", f"last result Failed ({when})", "Open the job's last session in Veeam, fix the cause, then re-run", j["vc"])
        elif lr == "warning":
            c.add("VB04", j["name"], "WARN", f"last result Warning ({when})", "Open the job's last session for the warning text", j["vc"])
    if not c.jobs():
        raise Skip("no jobs returned")


def scheduled_often(j):
    s = j["cfg"].get("schedule") or {}
    return any((s.get(k) or {}).get("isEnabled") for k in ("daily", "periodically", "continuously"))


@check("VB05")
def c_no_success(c):
    try:
        last = c.last_success()
        window = f"{SESSION_WINDOW_DAYS} d session window"
    except Skip:
        last, window = None, None
    for j in c.jobs():
        if j["disabled"] or not scheduled_often(j):
            continue
        t = last.get(j["name"].lower()) if last is not None else None
        if t is None and last is None and (j["state"].get("lastResult") or "").lower() in ("success", "warning"):
            t = parse_ts(j["state"].get("lastRun"))
        if t is None:
            if last is None:
                continue
            c.add("VB05", j["name"], "CRIT", f"no successful run in the last {SESSION_WINDOW_DAYS} d", "Check why the job is not completing", j["vc"])
            continue
        age = c.now - t
        if age > timedelta(days=NO_SUCCESS_CRIT_DAYS):
            c.add("VB05", j["name"], "CRIT", f"last successful run {fmt_age(age)} ago ({t:%Y-%m-%d %H:%M})", "Check why the job is not completing", j["vc"])
        elif age > timedelta(hours=NO_SUCCESS_WARN_HOURS):
            c.add("VB05", j["name"], "WARN", f"last successful run {fmt_age(age)} ago ({t:%Y-%m-%d %H:%M})", "Check why the job is not completing", j["vc"])
    if window:
        c.notes["VB05"].append(f"daily/periodic jobs only; success looked up in the {window}")


@check("VB06")
def c_running_long(c):
    for j in c.jobs():
        if j["state"].get("status") != "running":
            continue
        t = parse_ts(j["state"].get("lastRun"))
        if t and c.now - t > timedelta(hours=RUNNING_WARN_HOURS):
            c.add("VB06", j["name"], "WARN", f"running for {fmt_age(c.now - t)} (started {t:%Y-%m-%d %H:%M})",
                  "Check the session for a stuck task, a slow source or a full repository", j["vc"])


def has_schedule(j):
    s = j["cfg"].get("schedule") or {}
    kinds = ("daily", "monthly", "periodically", "continuously", "afterThisJob")
    return bool(s.get("runAutomatically")) and any((s.get(k) or {}).get("isEnabled") for k in kinds)


@check("VB07")
def c_disabled(c):
    for j in c.jobs():
        if j["disabled"]:
            c.add("VB07", j["name"], "WARN", "job is disabled", "Enable the job or remove it if it is obsolete", j["vc"])
        elif j["cfg"] and not has_schedule(j):
            c.add("VB07", j["name"], "INFO", "job has no automatic schedule (manual / chained only)", "Confirm that manual runs are intended", j["vc"])
    if not c.jobs():
        raise Skip("no jobs returned")


def aware_vms(c):
    """Yield (job, include, why) for VMs in app-aware-off jobs that look like DB / DC / Exchange servers."""
    inv = None
    try:
        inv = c.inventory()
    except Exception:  # noqa: BLE001 - the name regex still works without the DB
        c.notes["VB08"].append("inventory DB unreadable; name regex only")
    for j in c.backup_jobs():
        if (((j["cfg"].get("guestProcessing") or {}).get("appAwareProcessing")) or {}).get("isEnabled"):
            continue
        for i in j["includes"]:
            if "virtualmachine" not in i["type"] and i["type"] not in ("vm", ""):
                continue
            why = []
            if VB08_NAME_RE.search(i["name"]):
                why.append("name looks like a DB/DC/Exchange server")
            if inv:
                vc = vc_for_host(inv, i["host"])
                mo = moref_of(i["object_id"])
                for m in inv["machines"]:
                    if vc and m["vcenter_id"] != vc["id"]:
                        continue
                    if (mo and m["moref"] == mo) or m["name"].lower() == i["name"].lower():
                        if (m["role"] or "").lower() in VB08_ROLES:
                            why.append(f"inventory role '{m['role']}'")
                        if VB08_OS_RE.search(m["guest_os"] or ""):
                            why.append(f"guest OS '{m['guest_os']}'")
                        break
            if why:
                yield j, i, "; ".join(why)


@check("VB08")
def c_app_aware(c):
    c.jobs()
    n_jobs = len(c.backup_jobs())
    off = sum(1 for j in c.backup_jobs() if not (((j["cfg"].get("guestProcessing") or {}).get("appAwareProcessing")) or {}).get("isEnabled"))
    if n_jobs:
        c.notes["VB08"].append(f"{off}/{n_jobs} jobs have application-aware processing off")
    for j, i, why in aware_vms(c):
        c.add("VB08", i["name"], "WARN", f"job '{j['name']}': application-aware processing is off ({why})",
              "Enable application-aware processing (with guest credentials) so databases/AD are backed up consistently", j["vc"])


@check("VB09")
def c_retention(c):
    jobs = c.backup_jobs()
    if not jobs:
        raise Skip("no backup jobs returned")
    for j in jobs:
        st = j["cfg"].get("storage") or {}
        rp = st.get("retentionPolicy") or {}
        q = num(rp.get("quantity"))
        if q is not None and q < MIN_RESTORE_POINTS:
            c.add("VB09", j["name"], "WARN", f"retention {q:g} {rp.get('type') or ''} (< {MIN_RESTORE_POINTS})",
                  "Raise retention to at least 7 restore points / days", j["vc"])
    with_gfs = [j for j in jobs if ((j["cfg"].get("storage") or {}).get("gfsPolicy") or {}).get("isEnabled")]
    if not with_gfs:
        c.add("VB09", "all jobs", "INFO", f"no job has a GFS (long-term) retention policy ({len(jobs)} jobs)",
              "Consider weekly/monthly/yearly GFS points for long-term retention")


@check("VB10")
def c_retry(c):
    jobs = [j for j in c.jobs() if j["cfg"]]
    if not jobs:
        raise Skip("no jobs returned")
    for j in jobs:
        r = (j["cfg"].get("schedule") or {}).get("retry")
        if isinstance(r, dict) and r.get("isEnabled") is False:
            c.add("VB10", j["name"], "INFO", "automatic retry is disabled", "Enable retries (3 attempts, 10 min) to ride out transient failures", j["vc"])


def repo_rows(c):
    """Merge repositories (config) and states (capacity) by id."""
    states = {}
    try:
        states = {s.get("id"): s for s in c.rows("repos_states")}
    except Skip:
        if "repos" not in c.raw:
            raise
    cfg = {}
    try:
        cfg = {r.get("id"): r for r in c.rows("repos")}
    except Skip:
        if not states:
            raise
    out = []
    for rid in list(cfg) + [k for k in states if k not in cfg]:
        out.append({"id": rid, "cfg": cfg.get(rid, {}), "state": states.get(rid, {}),
                    "name": (cfg.get(rid) or states.get(rid) or {}).get("name") or rid,
                    "type": (cfg.get(rid) or states.get(rid) or {}).get("type") or ""})
    return out


@check("VB11")
def c_repo_space(c):
    repos = repo_rows(c)
    if not any(r["state"] for r in repos):
        raise Skip("repository states (capacity) not available")
    nocap = []
    for r in repos:
        s = r["state"]
        online = s.get("isOnline")
        if online is False:
            c.add("VB11", r["name"], "CRIT", "repository is offline", "Bring the repository back online or remove it from Veeam")
        elif "offline" in r["name"].lower():
            c.add("VB11", r["name"], "WARN", "name says OFFLINE (the API does not expose repository online state)",
                  "Confirm the repository is intentionally offline; remove it if retired")
        cap, free = num(s.get("capacityGB")), num(s.get("freeGB"))
        if not cap:
            nocap.append(r["name"])
            continue
        if free is None:
            continue
        pct = free / cap * 100
        d = f"{free:,.0f} GB free of {cap:,.0f} GB ({pct:.1f}% free)"
        if pct < REPO_FREE_CRIT_PCT:
            c.add("VB11", r["name"], "CRIT", d, "Free space or add capacity before backups fail")
        elif pct < REPO_FREE_WARN_PCT:
            c.add("VB11", r["name"], "WARN", d, "Plan capacity: reduce retention or add storage")
    if nocap:
        c.notes["VB11"].append("no capacity reported (object storage?): " + ", ".join(nocap))


def immutable(r):
    if r["type"].lower() in ("linuxhardened", "hardenedrepository"):
        return True
    v = find_key(r["cfg"], "immutability")
    return isinstance(v, dict) and bool(v.get("isEnabled"))


@check("VB12")
def c_immutable(c):
    repos = [r for r in repo_rows(c) if r["cfg"]]
    if not repos:
        raise Skip("repository configuration not available")
    imm = [r["name"] for r in repos if immutable(r)]
    if imm:
        c.notes["VB12"].append("immutable: " + ", ".join(imm))
        return
    c.add("VB12", "all repositories", "WARN",
          f"no immutable or hardened repository among {len(repos)}: " + ", ".join(f"{r['name']} ({r['type']})" for r in repos),
          "Add a hardened Linux repository or enable immutability on object storage to resist ransomware")


@check("VB13")
def c_encryption(c):
    jobs = c.backup_jobs()
    if not jobs:
        raise Skip("no backup jobs returned")
    for j in jobs:
        enc = ((((j["cfg"].get("storage") or {}).get("advancedSettings") or {}).get("storageData")) or {}).get("encryption") or {}
        if not enc.get("isEnabled"):
            c.add("VB13", j["name"], "WARN", "backup file encryption is off", "Enable job encryption with a managed password", j["vc"])


@check("VB14")
def c_copy(c):
    copy_jobs = [j for j in c.jobs() if "copy" in j["type"].lower()]
    sess_copy = 0
    try:
        sess_copy = sum(1 for s in c.rows("sessions") if "copy" in str(s.get("sessionType")).lower())
    except Skip:
        pass
    if copy_jobs or sess_copy:
        c.notes["VB14"].append(f"{len(copy_jobs)} copy job(s), {sess_copy} copy session(s) in window")
        return
    types = sorted({j["type"] for j in c.jobs()})
    c.add("VB14", "backup copy", "CRIT", f"no backup copy job (job types seen: {', '.join(types) or 'none'}) and no copy sessions in {SESSION_WINDOW_DAYS} d",
          "Add a backup copy job to a second repository (3-2-1 rule); the REST API 1.1 may not list some copy-job types, so verify in the console")
    try:
        names = {r["id"]: r["name"] for r in repo_rows(c)}
        used = Counter(names.get(b.get("repositoryId"), b.get("repositoryId")) for b in c.rows("backups"))
        c.notes["VB14"].append("backups by repository: " + ", ".join(f"{k}={v}" for k, v in used.most_common()))
    except Skip:
        pass


@check("VB15")
def c_single_repo(c):
    jobs = c.backup_jobs()
    if not jobs:
        raise Skip("no backup jobs returned")
    ids = Counter((j["cfg"].get("storage") or {}).get("backupRepositoryId") for j in jobs)
    ids.pop(None, None)
    if len(ids) == 1:
        rid = next(iter(ids))
        try:
            name = next((r["name"] for r in repo_rows(c) if r["id"] == rid), rid)
        except Skip:
            name = rid
        c.add("VB15", name, "WARN", f"all {len(jobs)} backup jobs write to this one repository",
              "Spread jobs over a second repository so one failure does not lose all backups")
    elif ids:
        c.notes["VB15"].append(f"{len(ids)} repositories in use")


@check("VB16")
def c_surebackup(c):
    sb_jobs = [j for j in c.jobs() if "surebackup" in j["type"].lower() or "verif" in j["type"].lower()]
    sess = 0
    try:
        sess = sum(1 for s in c.rows("sessions") if re.search(r"surebackup|verif", str(s.get("sessionType")), re.IGNORECASE))
    except Skip:
        pass
    if sb_jobs or sess:
        c.notes["VB16"].append(f"{len(sb_jobs)} verification job(s), {sess} session(s) in window")
        return
    c.add("VB16", "SureBackup", "INFO", f"no SureBackup / verification job or session seen (sessions looked at: last {SESSION_WINDOW_DAYS} d)",
          "Schedule SureBackup (or periodic test restores) for critical VMs")


def vm_includes(c):
    """(job, include) for every VM-level include of enabled+disabled backup jobs, plus the container-type names."""
    for j in c.backup_jobs():
        for i in j["includes"]:
            yield j, i


def is_vm(i):
    return "virtualmachine" in i["type"] or i["type"] in ("vm", "")


def inc_matches(i, m, vc):
    if i["host"] and vc and short(i["host"]) not in (short(vc["host"]), short(vc["name"])):
        return False
    mo = moref_of(i["object_id"])
    return bool((mo and m["moref"] and mo == m["moref"].lower()) or i["name"].lower() == (m["name"] or "").lower())


@check("VB17")
def c_uncovered(c):
    inv = c.inventory()
    if not c.backup_jobs():
        raise Skip("no backup jobs returned")
    vcs = {v["id"]: v for v in inv["vcenters"]}
    cont = sorted({f"{i['type']}:{i['name']}" for _, i in vm_includes(c) if not is_vm(i)})
    if cont:
        c.notes["VB17"].append("container/tag includes not resolved: " + ", ".join(cont[:8]))
    hosts_seen = {i["host"] for _, i in vm_includes(c) if i["host"]}
    ref_vcs = {vc_for_host(inv, h)["id"] for h in hosts_seen if vc_for_host(inv, h)}
    if not ref_vcs:
        c.notes["VB17"].append("no job references a vCenter that is in the inventory; coverage not evaluated")
        raise Skip("no job references a vCenter in the inventory (" + (", ".join(sorted(hosts_seen)) or "none") + ")")
    uncovered = 0
    for m in inv["machines"]:
        if m["vcenter_id"] not in ref_vcs or m["is_template"] or m["power_state"] != "poweredOn":
            continue
        vc = vcs.get(m["vcenter_id"])
        cover = [j for j in c.backup_jobs() for i in j["includes"]
                 if is_vm(i) and inc_matches(i, m, vc) and not any(inc_matches(x, m, vc) for x in j["excludes"])]
        on = [j for j in cover if not j["disabled"]]
        if on:
            continue
        uncovered += 1
        why = f"only in disabled job(s): {', '.join(sorted({j['name'] for j in cover}))}" if cover else "not in any Veeam backup job"
        c.add("VB17", m["name"], "WARN", why, "Add the VM to a backup job, or document why it is excluded", vc["name"] if vc else "")
    skipped = [v["name"] for v in inv["vcenters"] if v["id"] not in ref_vcs]
    if skipped:
        c.notes["VB17"].append("vCenters with no Veeam job reference not checked: " + ", ".join(skipped))
    c.notes["VB17"].append("inventory may lag the live vCenter; refresh with cfn vsphere discover")


@check("VB18")
def c_orphans(c):
    inv = c.inventory()
    if not c.backup_jobs():
        raise Skip("no backup jobs returned")
    by_vc = {}
    for m in inv["machines"]:
        by_vc.setdefault(m["vcenter_id"], []).append(m)
    unknown = {}
    checked = 0
    for j, i in vm_includes(c):
        if not is_vm(i):
            continue
        vc = vc_for_host(inv, i["host"])
        if vc is None:
            other = vc_for_host(inv, i["host"], checkable=False)
            key = i["host"] or "(no host)"
            why = f"in the inventory but status '{other['status']}' / no VMs discovered" if other else "not in the inventory"
            unknown.setdefault((key, why), []).append(i["name"])
            continue
        checked += 1
        if not any(inc_matches(i, m, vc) for m in by_vc.get(vc["id"], [])):
            c.add("VB18", i["name"], "WARN", f"job '{j['name']}' includes a VM that is not in vCenter {vc['name']} inventory (deleted or renamed?)",
                  "Remove the VM from the job or re-add it; confirm with a vSphere discover first", vc["name"])
    for (host, why), names in sorted(unknown.items()):
        u = sorted(set(names))
        extra = f" (+{len(u) - MAX_LISTED} more)" if len(u) > MAX_LISTED else ""
        c.add("VB18", host, "INFO", f"vCenter '{host}' is {why}: {len(u)} job VM(s) not cross-checked: "
              + ", ".join(u[:MAX_LISTED]) + extra, "Add / fix the vCenter and run cfn vsphere discover to enable the check")
    c.notes["VB18"].append(f"{checked} job VM(s) checked against the inventory")


@check("VB19")
def c_infra(c):
    parts = []
    for name, label in (("proxies", "proxies"), ("managedServers", "managed servers")):
        try:
            parts.append(f"{len(c.rows(name))} {label}")
        except Skip:
            pass
    # API 1.1-rev0 exposes no online state for proxies / managed servers and no component versions.
    raise Skip("proxy / managed-server online state and component versions are not exposed by API "
               f"{c.args.api_version} ({', '.join(parts) or 'lists unavailable'} inventoried only)")


@check("VB20")
def c_malware(c):
    ev = c.rows("malware")
    for e in ev:
        st = str(e.get("status") or e.get("state") or "").lower()
        if st in ("resolved", "closed", "false positive", "falsepositive"):
            continue
        c.add("VB20", e.get("machine", {}).get("displayName") if isinstance(e.get("machine"), dict) else (e.get("name") or "event"),
              "CRIT", f"malware event {e.get('type') or ''} {e.get('detectionTimeUtc') or ''} {e.get('details') or ''}".strip(),
              "Investigate in the Veeam console (Malware Detection) before restoring from affected points")


def run_checks(c):
    for ids, fn in CHECKS:
        try:
            fn(c)
        except Skip as e:
            for i in ids:
                c.skips[i] = str(e)
                c.findings[i] = []
        except sqlite3.Error as e:
            for i in ids:
                c.skips[i] = f"inventory DB unavailable: {err_text(e)}"
                c.findings[i] = []
        except Exception as e:  # noqa: BLE001 - one failing check must not stop the rest
            for i in ids:
                c.skips[i] = f"check failed: {err_text(e)}"
                c.findings[i] = []


# --------------------------------------------------------------------------- assemble + output
def assemble(ctxs, fatal):
    multi = len(ctxs) + len(fatal) > 1
    items = []
    for iid, section, title in ITEMS:
        f, reasons, skips = [], [], []
        for c in ctxs:
            pre = f"[{c.host}] " if multi else ""
            if iid in c.skips:
                skips.append(f"{pre}{c.skips[iid]}")
            else:
                for x in c.findings[iid]:
                    f.append({**x, "detail": pre + x["detail"]})
                reasons += [f"{pre}{n}" for n in c.notes[iid]]
        for host, why in fatal.items():
            if iid == "VB01":
                f.append({"target": host, "vcenter": "", "severity": "CRIT", "detail": f"unreachable or login failed: {why}",
                          "suggestion": "Check the host, port 9419, the REST API service and the NET_VEEAM_* credentials"})
            else:
                skips.append(f"[{host}] host unreachable")
        if not f and len(skips) == len(ctxs) + len(fatal):
            status, reason, f = "skip", "; ".join(dict.fromkeys(skips)), []
        else:
            status = sev_status(f)
            reason = "; ".join(reasons + [f"skipped on some hosts: {s}" for s in skips]) or None
        f.sort(key=lambda x: (-SEV_RANK[x["severity"]], x["target"].lower()))
        items.append({"id": iid, "section": section, "title": title, "status": status, "reason": reason, "findings": f})
    counts = {k: sum(1 for i in items if i["status"] == k) for k in ("pass", "info", "warn", "crit", "skip")}
    counts["findings"] = dict(Counter(x["severity"] for i in items for x in i["findings"]))
    return items, counts


def md_table(rows, head):
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]


def write_outputs(out, summary):
    items, counts, fc = summary["items"], summary["counts"], summary["counts"]["findings"]
    L = [f"# Veeam Backup & Replication checklist - {summary['generated']}", "",
         f"Scope: {', '.join(summary['scope']['hosts'])}" + (f" (unreachable: {', '.join(summary['scope']['unreachable'])})" if summary["scope"]["unreachable"] else ""), "",
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
            L += [""] + md_table([(x["severity"], x["vcenter"], x["target"], x["detail"], x["suggestion"]) for x in rows],
                                 ["Sev", "vCenter", "Target", "Detail", "Suggestion"])
            if n > len(rows):
                L.append(f"\n... {n - len(rows)} more in findings.csv")
            L.append("")
    p = out / "checklist.md"
    p.write_text("\n".join(L) + "\n")
    os.chmod(p, 0o600)
    p = out / "findings.csv"
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["item_id", "section", "title", "status", "severity", "vcenter", "target", "detail", "suggestion"])
        for it in items:
            for x in it["findings"]:
                w.writerow([it["id"], it["section"], it["title"], it["status"], x["severity"], x["vcenter"], x["target"],
                            x["detail"], x["suggestion"]])
    os.chmod(p, 0o600)
    veeam_api.write_json(out / "summary.json", summary)


def print_console(summary, out):
    items, counts = summary["items"], summary["counts"]
    fc = counts["findings"]
    print(f"Veeam checklist: {len(items)} items | pass {counts['pass']} | info {counts['info']} | warn {counts['warn']} | "
          f"crit {counts['crit']} | skip {counts['skip']}")
    print(f"Findings: CRIT={fc.get('CRIT', 0)} WARN={fc.get('WARN', 0)} INFO={fc.get('INFO', 0)}")
    for it in items:
        n = len(it["findings"])
        line = f"  {STATUS_ICON[it['status']]} {it['id']} {it['title']}"
        if n:
            line += f"  [{n}]"
        if it["status"] == "skip":
            line += f"  - {it['reason'][:110]}"
        print(line)
    print(f"\nReport: {out / 'checklist.md'}\nJSON:   {out / 'summary.json'}\nCSV:    {out / 'findings.csv'}")


def main():
    ap = argparse.ArgumentParser(description="Read-only Veeam Backup & Replication health and security checklist (VB01-VB20)")
    ap.add_argument("--host", action="append", metavar="HOST", help="Veeam server hostname or IP (repeatable); not needed with --from-raw")
    ap.add_argument("--port", type=int, default=veeam_api.DEFAULT_PORT, help="REST API port (default 9419)")
    ap.add_argument("--cred", default=veeam_api.DEFAULT_CRED, metavar="REF", help="credential set NET_<REF>_USERNAME/_PASSWORD (default VEEAM)")
    ap.add_argument("--api-version", default=veeam_api.DEFAULT_API_VERSION, help="x-api-version header (default 1.1-rev0)")
    ap.add_argument("--verify-ssl", action="store_true", help="verify the TLS certificate (default off; self-signed is normal)")
    ap.add_argument("--out", help="output dir (default reports/checklist/veeam/<timestamp>)")
    ap.add_argument("--from-raw", metavar="DIR", help="re-run the analysis from a previous run's dir (or its raw/ dir); no network")
    ap.add_argument("--workers", type=int, default=4, help="Veeam servers collected concurrently")
    ap.add_argument("--timeout", type=int, default=60, help="per-request timeout seconds")
    ap.add_argument("--json", action="store_true", help="print summary.json to stdout instead of the console summary")
    args = ap.parse_args()
    if not args.host and not args.from_raw:
        ap.error("--host is required unless --from-raw is given")
    started = datetime.now()
    out = Path(args.out) if args.out else ROOT / "reports" / "checklist" / "veeam" / started.strftime("%Y%m%d-%H%M%S")
    if not out.is_absolute():
        out = ROOT / out
    (out / "raw").mkdir(parents=True, exist_ok=True)

    if args.from_raw:
        collected = load_raw(args.from_raw)
    else:
        hosts = list(dict.fromkeys(veeam_api.check_host(h) for h in args.host))

        def one(h):
            try:
                raw, errs = fetch_host(args, h)
                return h, (raw, errs, None)
            except ApiError as e:
                return h, (None, None, f"{e.kind}: {e}")
            except Exception as e:  # noqa: BLE001
                return h, (None, None, err_text(e))

        with ThreadPoolExecutor(min(args.workers, len(hosts))) as ex:
            collected = dict(ex.map(one, hosts))
    ctxs, fatal = [], {}
    for host, (raw, errs, err) in collected.items():
        if err:
            fatal[host] = err
            continue
        if not args.from_raw:
            save_raw(out, host, raw, errs)
        c = Ctx(host, raw, errs, Namespace(api_version=args.api_version))
        run_checks(c)
        ctxs.append(c)
    items, counts = assemble(ctxs, fatal)
    summary = {"generated": started.isoformat(timespec="seconds"), "read_only": True,
               "scope": {"hosts": [c.host for c in ctxs] + list(fatal), "unreachable": list(fatal),
                         "api_version": args.api_version, "from_raw": bool(args.from_raw)},
               "items": items, "counts": counts}
    write_outputs(out, summary)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_console(summary, out)
    sys.exit(0)


if __name__ == "__main__":
    main()
