"""READ-ONLY comprehensive vSphere health and security checklist (pyvmomi + inventory + optional Veeam).

Usage:
    cfn vsphere-checklist [--vcenter NAME ...] [--veeam-host HOST] [--guest-results DIR]
        [--perf-minutes 30] [--out DIR] [--workers 4] [--threshold KEY=VALUE ...] [--json]

Items (stable IDs, see ITEMS): A vCenter, B clusters, C ESXi hosts, D datastores, E1 VM OS/security (vCenter data),
E2 in-guest security (merged from cfn guest-security), F VM resource use, G guest storage, H backup coverage.

Only property reads and performance queries are performed; every vSphere call goes through vmlib.call_ro() and
Veeam is reached only through veeam_api.py's GET path. Suggestions are text only, never executed. An item that
cannot be evaluated becomes `skip` with a reason; unreachable or auth-failed vCenters are reported (A01), never fatal.
Thresholds are the TH constants below; override with --threshold KEY=VALUE (e.g. --threshold host_use_warn=70).

--guest-results: a reports/guest_security/<ts>/ dir (its summary.json `items` carry ids E36-E44). Without the flag the
newest reports/guest_security/*/summary.json under 24h old is used, otherwise E36-E44 are skipped.

Outputs under --out (default reports/checklist/vsphere/<YYYYmmdd-HHMMSS>):
    summary.json   {generated, scope, items[{id, section, title, status, reason, findings[]}], rankings, counts}
    checklist.md   every item as a checkbox line with its finding count, findings tables under non-pass items
    findings.csv   one row per finding
    raw/*.json     gathered data per vCenter (+ veeam, guest); no credentials
"""
import argparse
import csv
import json
import re
import sys
from argparse import Namespace
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import veeam_api
import vmlib
import vsphere
import vsphere_audit
import vsphere_storage
from pyVmomi import vim
from vmlib import ROOT, aslist, call_ro, collect, mid

SEV_RANK = {"INFO": 0, "WARN": 1, "CRIT": 2}
STATUS_ICON = {"pass": "✅", "warn": "⚠️", "crit": "❌", "info": "ℹ️", "skip": "➖"}

# Thresholds (override with --threshold KEY=VALUE).
TH = {
    "cluster_use_warn": 75, "cluster_use_crit": 90,           # B06 %
    "host_use_warn": 80, "host_use_crit": 90,                 # C11 %
    "uptime_warn_days": 180,                                  # C14
    "cert_warn_days": 60, "cert_crit_days": 15,               # C18
    "ready_warn": 5.0, "ready_crit": 10.0,                    # C21 % per vCPU
    "ds_free_warn": 20, "ds_free_crit": 10,                   # D23 %
    "overcommit_warn": 100, "overcommit_crit": 150,           # D24 %
    "latency_warn_ms": 20, "latency_crit_ms": 50,             # D26
    "snapshot_warn_days": 3, "snapshot_crit_days": 14, "snapshot_crit_gb": 100,   # E35
    "min_hw": 15,                                             # E35c (vmx-15)
    "vm_cpu_warn": 80, "vm_mem_warn": 90,                     # F45 / F46 %
    "oversize_vcpu": 8, "oversize_mem_gb": 32, "oversize_cpu_max": 20, "oversize_mem_max": 30,   # F48
    "guest_free_warn": 15, "guest_free_crit": 10,             # G50 %
    "veeam_stale_hours": 48,                                  # H52
    "rank_top": 10,                                           # F49
}

# E27 end-of-life guest OS table: (label, regex on the lowercased OS name, max major version or None = any match).
# Edit this list to change what counts as out of support.
EOL_RULES = [
    ("Windows 2000/XP/Vista/7/8/8.1", r"windows (?:2000|xp|vista|7\b|8(?:\.1)?\b)", None),
    ("Windows Server 2000/2003/2008/2008 R2/2012/2012 R2", r"windows (?:server )?(?:2000|2003|2008|2012)\b", None),
    ("RHEL 7 or older", r"(?:red hat enterprise linux|rhel)\D{0,40}?(\d+)", 7),
    ("CentOS 8 or older", r"centos\D{0,20}?(\d+)", 8),
    ("Ubuntu 18.04 or older (non-ESM)", r"ubuntu\D{0,20}?(\d{2})\.\d{2}", 18),
    ("Debian 9 or older", r"debian\D{0,20}?(\d+)", 9),
    ("SLES 11 or older", r"(?:suse linux enterprise(?: server)?|sles)\D{0,20}?(\d+)", 11),
    ("Other 2.x kernel Linux", r"other 2\.\d+\.x linux", None),
]
# E29 guest ids treated as "unknown or Other" (a name starting with "Other" also counts).
OTHER_GUEST_IDS = {"otherGuest", "otherGuest64", "otherLinuxGuest", "otherLinux64Guest", "other24xLinuxGuest",
                   "other24xLinux64Guest", "other26xLinuxGuest", "other26xLinux64Guest", "other3xLinuxGuest",
                   "other3xLinux64Guest", "other4xLinuxGuest", "other4xLinux64Guest", "other5xLinuxGuest",
                   "other5xLinux64Guest", "genericLinuxGuest", "unknown"}
# E28 families used to compare the Tools-reported OS with the configured OS (first match wins).
OS_FAMILIES = [("windows server", r"windows server\s*(\d{4})"), ("windows", r"windows\s*(xp|vista|\d+)"),
               ("rhel", r"(?:red hat enterprise linux|rhel)\D{0,40}?(\d+)"), ("centos", r"centos\D{0,20}?(\d+)"),
               ("rocky", r"rocky\D{0,20}?(\d+)"), ("alma", r"alma\D{0,20}?(\d+)"),
               ("oracle", r"oracle linux\D{0,20}?(\d+)"), ("ubuntu", r"ubuntu(?:\D{0,20}?(\d{2})\.\d{2})?"),
               ("debian", r"debian\D{0,20}?(\d+)"),
               ("suse", r"(?:suse linux enterprise(?: server)?|sles)\D{0,20}?(\d+)")]
EXPOSURE_RE = re.compile(r"(?<![a-z])(dmz|internet|public|outside|wan|mgmt|management)(?![a-z])", re.IGNORECASE)  # E32
ISOLATION_KEYS = ("isolation.tools.copy.disable", "isolation.tools.paste.disable", "isolation.tools.dnd.disable")  # E33

# (id, section, title); IDs are stable and used by the task list.
ITEMS = [
    ("A01", "A. vCenter", "vCenter reachable, login OK, version/build"),
    ("A02", "A. vCenter", "Active alarms"),
    ("A03", "A. vCenter", "Inventory drift vs inventory DB"),
    ("B04", "B. Clusters", "HA enabled with admission control"),
    ("B05", "B. Clusters", "DRS enabled and automation level"),
    ("B06", "B. Clusters", "Cluster CPU/memory usage"),
    ("B07", "B. Clusters", "N+1: demand fits if the largest host fails"),
    ("B08", "B. Clusters", "Mixed ESXi builds in a cluster"),
    ("C09", "C. ESXi hosts", "Connection/power state and maintenance mode"),
    ("C10", "C. ESXi hosts", "Overall status (red/yellow)"),
    ("C11", "C. ESXi hosts", "Host CPU and memory usage"),
    ("C12", "C. ESXi hosts", "Hardware sensors"),
    ("C13", "C. ESXi hosts", "Reboot required"),
    ("C14", "C. ESXi hosts", "Uptime over 180 days"),
    ("C15", "C. ESXi hosts", "NTP configured and ntpd running"),
    ("C16", "C. ESXi hosts", "SSH / ESXi Shell enabled"),
    ("C17", "C. ESXi hosts", "Lockdown mode"),
    ("C18", "C. ESXi hosts", "Host certificate expiry"),
    ("C19", "C. ESXi hosts", "Dead/degraded storage paths"),
    ("C20", "C. ESXi hosts", "Uplink NICs with link down"),
    ("C21", "C. ESXi hosts", "CPU ready (host and top VMs)"),
    ("D22", "D. Datastores", "Accessible/mounted, status, maintenance mode"),
    ("D23", "D. Datastores", "Datastore free space"),
    ("D24", "D. Datastores", "Datastore overcommit"),
    ("D25", "D. Datastores", "Datastore mounted on all hosts of its cluster"),
    ("D26", "D. Datastores", "Datastore latency"),
    ("E27", "E1. VM OS and security", "Out-of-support guest OS"),
    ("E28", "E1. VM OS and security", "Tools-reported OS differs from configured OS"),
    ("E29", "E1. VM OS and security", "Unknown / Other guest OS"),
    ("E30", "E1. VM OS and security", "VMware Tools not running / not installed / old"),
    ("E31", "E1. VM OS and security", "Powered-on VM reports no IP or hostname"),
    ("E32", "E1. VM OS and security", "Network exposure (DMZ/mgmt port groups, multi-VLAN VMs)"),
    ("E33", "E1. VM OS and security", "Insecure VM settings"),
    ("E34", "E1. VM OS and security", "VM state (orphaned, question, consolidation, status)"),
    ("E35", "E1. VM OS and security", "Old or large snapshots"),
    ("E35b", "E1. VM OS and security", "Powered-off VMs and templates"),
    ("E35c", "E1. VM OS and security", "Old VM hardware version"),
    ("E36", "E2. In-guest security", "Missing OS patches"),
    ("E37", "E2. In-guest security", "Antivirus / Defender status"),
    ("E38", "E2. In-guest security", "Host firewall"),
    ("E39", "E2. In-guest security", "Risky services (SMBv1, RDP without NLA, telnet, ftp)"),
    ("E40", "E2. In-guest security", "Local administrators and accounts"),
    ("E41", "E2. In-guest security", "Failed-logon spikes"),
    ("E42", "E2. In-guest security", "Stopped automatic-start services"),
    ("E43", "E2. In-guest security", "Time synchronisation"),
    ("E44", "E2. In-guest security", "Linux SSH config, updates, SELinux"),
    ("F45", "F. VM resource use", "VM CPU above 80% of allocation"),
    ("F46", "F. VM resource use", "Guest active memory above 90% of allocation"),
    ("F47", "F. VM resource use", "Ballooned / swapped / compressed memory"),
    ("F48", "F. VM resource use", "Oversized VMs (low usage)"),
    ("F49", "F. VM resource use", "Top 10 VMs by CPU, memory and provisioned disk"),
    ("G50", "G. Guest storage", "Guest volume free space"),
    ("H51", "H. Backup coverage", "Powered-on VMs not in any Veeam job"),
    ("H52", "H. Backup coverage", "Veeam job failed/warning or not run recently"),
]
GUEST_IDS = [f"E{n}" for n in range(36, 45)]


class Skip(Exception):
    """Raised by a check (or ctx.need) when it cannot be evaluated; becomes a `skip` item with this reason."""


def err_text(e):
    return f"{type(e).__name__}: {str(e).splitlines()[0][:140] if str(e) else ''}"


def pct(a, b):
    return round(100 * a / b, 1) if b else None


def sev_of(limits, p):
    """CRIT/WARN/None for a percentage against (warn, crit) thresholds."""
    return "CRIT" if p > limits[1] else "WARN" if p > limits[0] else None


def safe(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


# --------------------------------------------------------------------------- per-vCenter gathering
class Ctx:
    """Data gathered from one vCenter plus the stages that failed (check functions read it via need())."""

    def __init__(self, vc, args):
        self.vc, self.name, self.args = vc, vc["name"], args
        self.errors, self.d = {}, {}
        self.findings, self.skips, self.ran = [], {}, set()
        self.rankings = {}

    def need(self, *stages):
        for s in stages:
            if s in self.errors:
                raise Skip(f"{s} data not collected: {self.errors[s]}")
        return [self.d[s] for s in stages]


def host_row(o):
    qs, hw = o.get("summary.quickStats"), o.get("summary.hardware")
    prod = o.get("summary.config.product")
    hs = o.get("runtime.healthSystemRuntime")
    sensors = []
    for s in aslist(getattr(getattr(hs, "systemHealthInfo", None), "numericSensorInfo", None)):
        sensors.append({"name": s.name, "state": str(getattr(getattr(s, "healthState", None), "key", "unknown")).lower()})
    hwi = getattr(hs, "hardwareStatusInfo", None)
    for grp in ("cpuStatusInfo", "memoryStatusInfo", "storageStatusInfo"):
        for e in aslist(getattr(hwi, grp, None)):
            sensors.append({"name": e.name, "state": str(getattr(getattr(e, "status", None), "key", "unknown")).lower()})
    cert, cert_end = o.get("config.certificate"), None
    if cert:
        try:
            from cryptography import x509
            c = x509.load_pem_x509_certificate(bytes(cert))
            cert_end = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=UTC)
        except Exception:  # noqa: BLE001 - unparsable certificate: no expiry finding
            cert_end = None
    pnics = {p.key: {"device": p.device, "up": p.linkSpeed is not None, "speed": getattr(p.linkSpeed, "speedMb", None)}
             for p in aslist(o.get("config.network.pnic"))}
    switches = [{"name": s.name, "type": "standard", "pnics": aslist(s.pnic)} for s in aslist(o.get("config.network.vswitch"))]
    switches += [{"name": s.dvsName, "type": "distributed", "pnics": aslist(s.pnic)}
                 for s in aslist(o.get("config.network.proxySwitch"))]
    luns = []
    for lun in aslist(getattr(o.get("config.storageDevice.multipathInfo"), "lun", None)):
        luns.append({"id": lun.id, "paths": len(aslist(lun.path)),
                     "states": dict(Counter(str(p.pathState) for p in aslist(lun.path)))})
    services = {s.key: bool(s.running) for s in aslist(getattr(o.get("config.service"), "service", None))}
    ntp = getattr(getattr(o.get("config.dateTimeInfo"), "ntpConfig", None), "server", None)
    mhz, cores = getattr(hw, "cpuMhz", 0) or 0, getattr(hw, "numCpuCores", 0) or 0
    lock = o.get("config.lockdownMode")
    return {"name": o.get("name"), "id": o["_id"], "cluster_id": mid(o.get("parent")),
            "connection_state": str(o.get("runtime.connectionState")), "power_state": str(o.get("runtime.powerState")),
            "maintenance": bool(o.get("runtime.inMaintenanceMode")), "overall_status": str(o.get("overallStatus")),
            "cpu_mhz": mhz, "cpu_total_mhz": mhz * cores, "mem_total_mb": (getattr(hw, "memorySize", 0) or 0) // 1024 ** 2,
            "cpu_used_mhz": getattr(qs, "overallCpuUsage", None), "mem_used_mb": getattr(qs, "overallMemoryUsage", None),
            "uptime_s": getattr(qs, "uptime", None), "reboot_required": bool(o.get("summary.rebootRequired")),
            "version": getattr(prod, "version", None), "build": getattr(prod, "build", None),
            "sensors": sensors, "ntp_servers": aslist(ntp), "services": services,
            "lockdown": str(lock) if lock is not None else None,
            "cert_expires": cert_end.isoformat() if cert_end else None, "luns": luns, "pnics": pnics, "switches": switches}


HOST_PROPS = ["name", "parent", "runtime.connectionState", "runtime.powerState", "runtime.inMaintenanceMode", "overallStatus",
              "summary.quickStats", "summary.hardware", "summary.rebootRequired", "summary.config.product",
              "runtime.healthSystemRuntime", "config.dateTimeInfo", "config.service", "config.lockdownMode",
              "config.certificate", "config.storageDevice.multipathInfo", "config.network.pnic",
              "config.network.vswitch", "config.network.proxySwitch"]
VM_PROPS = ["name", "config.template", "config.guestId", "config.guestFullName", "guest.guestFullName",
            "config.extraConfig", "config.hardware.device", "config.hardware.numCPU", "config.hardware.memoryMB",
            "config.version", "runtime.connectionState", "runtime.question", "runtime.consolidationNeeded",
            "runtime.powerState", "runtime.host", "overallStatus", "summary.quickStats"]


def vm_row(o):
    qs, extra = o.get("summary.quickStats"), {k.key: str(k.value) for k in aslist(o.get("config.extraConfig"))}
    serial, cdroms = [], []
    for dev in aslist(o.get("config.hardware.device")):
        if isinstance(dev, (vim.vm.device.VirtualSerialPort, vim.vm.device.VirtualParallelPort)):
            serial.append(dev.deviceInfo.label if dev.deviceInfo else type(dev).__name__)
        elif isinstance(dev, vim.vm.device.VirtualCdrom):
            kind, con = type(dev.backing).__name__, bool(dev.connectable and dev.connectable.connected)
            if con and "Iso" in kind:
                cdroms.append(f"ISO {getattr(dev.backing, 'fileName', '')}")
            elif con and ("Passthrough" in kind or "Atapi" in kind):
                cdroms.append(f"host device {getattr(dev.backing, 'deviceName', '')}")
    q = o.get("runtime.question")
    return {"name": o.get("name"), "id": o["_id"], "template": bool(o.get("config.template")),
            "guest_id": o.get("config.guestId"), "config_os": o.get("config.guestFullName"),
            "tools_os": o.get("guest.guestFullName"), "isolation": {k: extra.get(k) for k in ISOLATION_KEYS},
            "serial_ports": serial, "cdroms": cdroms, "vcpu": o.get("config.hardware.numCPU"),
            "mem_mb": o.get("config.hardware.memoryMB"), "hw_version": o.get("config.version"),
            "connection_state": str(o.get("runtime.connectionState")),
            "question": (getattr(q, "text", None) or "question pending") if q else None,
            "consolidation_needed": bool(o.get("runtime.consolidationNeeded")),
            "power": str(o.get("runtime.powerState")), "host_id": mid(o.get("runtime.host")),
            "overall_status": str(o.get("overallStatus")),
            "cpu_used_mhz": getattr(qs, "overallCpuUsage", None), "mem_active_mb": getattr(qs, "guestMemoryUsage", None),
            "ballooned_mb": getattr(qs, "balloonedMemory", None), "swapped_mb": getattr(qs, "swappedMemory", None),
            "compressed_kb": getattr(qs, "compressedMemory", None)}


def cluster_row(o):
    c = o.get("configurationEx")
    das, drs = getattr(c, "dasConfig", None), getattr(c, "drsConfig", None)
    return {"name": o["name"], "id": o["_id"], "host_ids": sorted(mid(h) for h in aslist(o.get("host"))),
            "ha_enabled": bool(getattr(das, "enabled", False)),
            "admission_control": bool(getattr(das, "admissionControlEnabled", False)),
            "drs_enabled": bool(getattr(drs, "enabled", False)),
            "drs_behavior": str(getattr(drs, "defaultVmBehavior", None))}


def ds_mount_row(o):
    s, mounts = o["summary"], []
    for m in aslist(o.get("host")):
        mi = m.mountInfo
        mounts.append({"host_id": mid(m.key), "mounted": bool(getattr(mi, "mounted", True)),
                       "accessible": bool(getattr(mi, "accessible", True))})
    parts = [p for p in (s.url or "").split("/") if p]
    return {"name": o["name"], "id": o["_id"], "uuid": parts[-1] if parts else None, "type": s.type,
            "multiple_host_access": bool(s.multipleHostAccess), "mounts": mounts}


def perf_query(si, entities, names, minutes, instance):
    """QueryPerf realtime (20 s) samples for `entities` -> {moref: {counter: {instance: [values]}}}."""
    pm = si.content.perfManager
    cid = {f"{c.groupInfo.key}.{c.nameInfo.key}.{c.rollupType}": c.key for c in pm.perfCounter}
    missing = [n for n in names if n not in cid]
    if missing:
        raise RuntimeError(f"perf counter(s) not available: {', '.join(missing)}")
    by_id = {cid[n]: n for n in names}
    nsamp = max(1, min(180, int(minutes * 3)))
    out = {}
    for i in range(0, len(entities), 25):
        specs = [vim.PerformanceManager.QuerySpec(
            entity=e, intervalId=20, maxSample=nsamp, format="normal",
            metricId=[vim.PerformanceManager.MetricId(counterId=cid[n], instance=instance) for n in names])
            for e in entities[i:i + 25]]
        for em in call_ro(pm, "QueryPerf", querySpec=specs) or []:
            d = out.setdefault(mid(em.entity), {})
            for s in em.value:
                vals = [float(v) for v in s.value if v is not None and v >= 0]
                d.setdefault(by_id[s.id.counterId], {})[s.id.instance] = vals
    return out


def avg(v):
    return sum(v) / len(v) if v else None


def gather_vm_perf(si, ctx):
    vms = ctx.d.get("vms")
    if vms is None:
        raise RuntimeError("vm data missing")
    on = [v for v in vms if v["power"] == "poweredOn" and not v["template"]]
    refs = [vim.VirtualMachine(v["id"], si._stub) for v in on]
    res = perf_query(si, refs, ["cpu.ready.summation", "cpu.usage.average"], ctx.args.perf_minutes, "")
    out = {}
    for v in on:
        m = res.get(v["id"], {})
        ready, usage = (m.get("cpu.ready.summation", {}).get("") or []), (m.get("cpu.usage.average", {}).get("") or [])
        if ready:   # ready is ms summed over the vCPUs per 20 s sample
            out[v["id"]] = {"ready_pct_per_vcpu": round(avg(ready) / 20000 * 100 / max(1, v["vcpu"] or 1), 2),
                            "cpu_usage_pct": round(avg(usage) / 100, 1) if usage else None, "samples": len(ready)}
    return out


def gather_ds_perf(si, ctx):
    hosts = ctx.d.get("hosts")
    if hosts is None:
        raise RuntimeError("host data missing")
    live = [h for h in hosts if h["connection_state"] == "connected" and not h["maintenance"]]
    refs = [vim.HostSystem(h["id"], si._stub) for h in live]
    res = perf_query(si, refs, ["datastore.totalReadLatency.average", "datastore.totalWriteLatency.average"],
                     ctx.args.perf_minutes, "*")
    out = []
    for h in live:
        m = res.get(h["id"], {})
        rd, wr = m.get("datastore.totalReadLatency.average", {}), m.get("datastore.totalWriteLatency.average", {})
        for inst in sorted(set(rd) | set(wr)):
            if inst:
                out.append({"host": h["name"], "instance": inst, "read_ms": round(avg(rd.get(inst) or []) or 0, 1),
                            "write_ms": round(avg(wr.get(inst) or []) or 0, 1)})
    return out


def gather_vcenter(vc, args):
    """Connect and run every collection stage (each isolated). Unreachable -> ctx.d['unreachable']."""
    ctx = Ctx(vc, args)
    try:
        cm = vmlib.connect(vc)
        si = cm.__enter__()
    except SystemExit as e:
        ctx.d["unreachable"] = str(e)
        return ctx
    except Exception as e:  # noqa: BLE001
        ctx.d["unreachable"] = err_text(e)
        return ctx
    try:
        about = si.content.about
        ctx.d["about"] = {"version": about.version, "build": about.build, "full_name": about.fullName}

        def stage(name, fn):
            try:
                ctx.d[name] = fn()
            except Exception as e:  # noqa: BLE001 - one failing stage must not abort the run
                ctx.errors[name] = err_text(e)
        stage("gather", lambda: vsphere.gather(si))
        stage("alarms", lambda: vsphere.alarm_rows(si))
        stage("storage", lambda: vsphere_storage.gather(si))
        stage("hosts", lambda: [host_row(o) for o in collect(si, vim.HostSystem, HOST_PROPS)])
        stage("clusters", lambda: [cluster_row(o) for o in collect(si, vim.ClusterComputeResource, ["name", "host", "configurationEx"])])
        stage("vms", lambda: [vm_row(o) for o in collect(si, vim.VirtualMachine, VM_PROPS)])
        stage("dsmounts", lambda: [ds_mount_row(o) for o in collect(si, vim.Datastore, ["name", "summary", "host"])])
        stage("vm_perf", lambda: gather_vm_perf(si, ctx))
        stage("ds_perf", lambda: gather_ds_perf(si, ctx))
    finally:
        cm.__exit__(None, None, None)
    return ctx


# --------------------------------------------------------------------------- checks
CHECKS = []   # (item ids, function(ctx, add))


def check(*ids):
    def deco(fn):
        CHECKS.append((ids, fn))
        return fn
    return deco


def audit_findings(ctx):
    """Run vsphere_audit.analyze() once per vCenter (cached) on data already gathered."""
    if "audit" not in ctx.d:
        gather, alarms = ctx.need("gather", "alarms")
        db = vmlib.open_db()
        known = {r["instance_uuid"]: dict(r) for r in db.execute("SELECT instance_uuid, primary_ip FROM machines")}
        db.close()
        a = Namespace(snapshot_days=TH["snapshot_warn_days"], min_hw=f"vmx-{int(TH['min_hw'])}", datastore_free_pct=15)
        r = {"vcenter": ctx.name, "data": gather, "snapshots": [], "datastores": [], "alarms": alarms}
        ctx.d["audit"] = vsphere_audit.analyze(r, a, known, set())
    return ctx.d["audit"]


@check("A02")
def c_alarms(ctx, add):
    for x in (x for x in audit_findings(ctx) if x["check"] == "alarm"):
        add("A02", x["severity"], x["target"], x["detail"], x["suggestion"])


@check("A03")
def c_drift(ctx, add):
    gather, = ctx.need("gather")
    db = vmlib.open_db()
    vid = ctx.vc["id"]
    dbvms = [dict(r) for r in db.execute("SELECT name, instance_uuid FROM machines WHERE vcenter_id=? AND status='active'", (vid,))]
    dbhosts = [dict(r) for r in db.execute("SELECT hostname FROM esxi_hosts WHERE vcenter_id=? AND status='active'", (vid,))]
    dball = {r["instance_uuid"] for r in db.execute("SELECT instance_uuid FROM machines")}
    db.close()
    live = {v["instance_uuid"]: v for v in gather["vms"]}
    for r in dbvms:
        if r["instance_uuid"] not in live:
            add("A03", "INFO", r["name"], "VM is active in the inventory DB but no longer exists in vCenter",
                "Run `cfn vsphere discover` to mark it decommissioned (or confirm it was removed on purpose)")
    for u, v in live.items():
        if u not in dball and not v["is_template"]:
            add("A03", "INFO", v["name"], "VM exists in vCenter but not in the inventory DB", "Run `cfn vsphere discover` to record it")
    livehosts = {h["hostname"] for h in gather["hosts"]}
    dbh = {r["hostname"] for r in dbhosts}
    for h in sorted(dbh - livehosts):
        add("A03", "INFO", h, "ESXi host is active in the inventory DB but not in vCenter",
            "Run `cfn vsphere discover` to refresh, or confirm the host was removed")
    for h in sorted(livehosts - dbh):
        add("A03", "INFO", h, "ESXi host exists in vCenter but not in the inventory DB", "Run `cfn vsphere discover` to record it")


@check("B04", "B05")
def c_cluster_cfg(ctx, add):
    clusters, = ctx.need("clusters")
    for c in clusters:
        if not c["ha_enabled"]:
            add("B04", "WARN", c["name"], "vSphere HA is disabled", "Enable HA so VMs restart after a host failure")
        elif not c["admission_control"]:
            add("B04", "WARN", c["name"], "HA enabled but admission control is off",
                "Enable admission control so failover capacity is reserved")
        if not c["drs_enabled"]:
            add("B05", "WARN", c["name"], "DRS is disabled", "Enable DRS to balance load across hosts")
        elif c["drs_behavior"] == "manual":
            add("B05", "WARN", c["name"], "DRS automation level is manual", "Use partially/fully automated unless manual is intended")
        elif c["drs_behavior"] == "partiallyAutomated":
            add("B05", "INFO", c["name"], "DRS automation level is partially automated", "Fully automated is typical; confirm intent")


@check("B06", "B07")
def c_cluster_capacity(ctx, add):
    clusters, hosts = ctx.need("clusters", "hosts")
    hmap = {h["id"]: h for h in hosts}
    for c in clusters:
        hs = [hmap[i] for i in c["host_ids"] if i in hmap and hmap[i]["connection_state"] == "connected" and not hmap[i]["maintenance"]]
        if not hs:
            continue
        cpu_t, mem_t = sum(h["cpu_total_mhz"] for h in hs), sum(h["mem_total_mb"] for h in hs)
        cpu_u, mem_u = sum(h["cpu_used_mhz"] or 0 for h in hs), sum(h["mem_used_mb"] or 0 for h in hs)
        for label, u, t, unit in (("CPU", cpu_u, cpu_t, "MHz"), ("memory", mem_u, mem_t, "MB")):
            p = pct(u, t)
            s = sev_of((TH["cluster_use_warn"], TH["cluster_use_crit"]), p) if p is not None else None
            if s:
                add("B06", s, c["name"], f"cluster {label} usage {p}% ({u} of {t} {unit})",
                    "Add host capacity or rebalance/right-size VMs")
        if len(hs) < 2:
            add("B07", "WARN", c["name"], "fewer than 2 usable hosts: no failover capacity", "Add a host or accept the risk")
            continue
        big_c, big_m = max(h["cpu_total_mhz"] for h in hs), max(h["mem_total_mb"] for h in hs)
        if mem_u > mem_t - big_m:
            add("B07", "CRIT", c["name"], f"memory demand {mem_u} MB exceeds capacity {mem_t - big_m} MB if the largest host fails",
                "Add memory capacity or reduce memory demand to keep N+1")
        if cpu_u > cpu_t - big_c:
            add("B07", "WARN", c["name"], f"CPU demand {cpu_u} MHz exceeds capacity {cpu_t - big_c} MHz if the largest host fails",
                "Add CPU capacity or reduce demand to keep N+1")


@check("B08", "C09", "E30", "E35c")
def c_audit_mapped(ctx, add):
    m = {"esxi_build": "B08", "host_state": "C09", "vmware_tools": "E30", "hw_version": "E35c"}
    for x in audit_findings(ctx):
        if x["check"] in m:
            add(m[x["check"]], x["severity"], x["target"], x["detail"], x["suggestion"])


@check("C09", "C10", "C11", "C13", "C14")
def c_host_basic(ctx, add):
    hosts, = ctx.need("hosts")
    for h in hosts:
        n = h["name"]
        if h["power_state"] not in ("poweredOn", "None"):
            add("C09", "CRIT", n, f"host power state {h['power_state']}", "Check the host hardware/BMC")
        if h["overall_status"] in ("red", "yellow"):
            add("C10", "CRIT" if h["overall_status"] == "red" else "WARN", n, f"overallStatus {h['overall_status']}",
                "Check the host's alarms and hardware status in vCenter")
        for label, u, t in (("CPU", h["cpu_used_mhz"], h["cpu_total_mhz"]), ("memory", h["mem_used_mb"], h["mem_total_mb"])):
            p = pct(u or 0, t)
            s = sev_of((TH["host_use_warn"], TH["host_use_crit"]), p) if p is not None and u is not None else None
            if s:
                add("C11", s, n, f"{label} usage {p}%", "Rebalance VMs (DRS) or add capacity")
        if h["reboot_required"]:
            add("C13", "WARN", n, "reboot required (pending patch/config)", "Schedule a reboot in a maintenance window")
        if h["uptime_s"] and h["uptime_s"] / 86400 > TH["uptime_warn_days"]:
            add("C14", "WARN", n, f"uptime {int(h['uptime_s'] / 86400)} days", "Patch and reboot the host (long uptime means missed updates)")


@check("C12")
def c_sensors(ctx, add):
    hosts, = ctx.need("hosts")
    for h in hosts:
        for state, sev in (("red", "CRIT"), ("yellow", "WARN")):
            bad = [s["name"] for s in h["sensors"] if s["state"] == state]
            if bad:
                add("C12", sev, h["name"], f"{len(bad)} sensor(s) {state}: {', '.join(bad[:6])}{' ...' if len(bad) > 6 else ''}",
                    "Check the host hardware (BMC/iDRAC/iLO) and replace the failing component")


@check("C15", "C16", "C17", "C18", "C19", "C20")
def c_host_config(ctx, add):
    hosts, = ctx.need("hosts")
    now = datetime.now(UTC)
    for h in hosts:
        n = h["name"]
        if h["connection_state"] != "connected":
            continue   # config.* is not readable on disconnected hosts (reported by C09)
        if not h["ntp_servers"]:
            add("C15", "WARN", n, "no NTP servers configured", "Configure NTP servers and start ntpd")
        elif not h["services"].get("ntpd"):
            add("C15", "WARN", n, f"NTP servers set ({', '.join(h['ntp_servers'])}) but ntpd is not running", "Start the NTP service")
        for svc, label in (("TSM-SSH", "SSH"), ("TSM", "ESXi Shell")):
            if h["services"].get(svc):
                add("C16", "WARN", n, f"{label} service ({svc}) is running", "Stop it when not needed (use a time-limited session)")
        if h["lockdown"] in ("lockdownDisabled", None):
            add("C17", "INFO", n, "lockdown mode is off", "Consider normal lockdown so the host is only managed via vCenter")
        if h["cert_expires"]:
            days = (datetime.fromisoformat(h["cert_expires"]) - now).days
            s = "CRIT" if days < TH["cert_crit_days"] else "WARN" if days < TH["cert_warn_days"] else None
            if s:
                add("C18", s, n, f"certificate {'expired' if days < 0 else 'expires'} {h['cert_expires'][:10]} ({days} days)",
                    "Renew/replace the ESXi host certificate (vCenter: Certificates > Renew)")
        for lun in h["luns"]:
            dead, off = lun["states"].get("dead", 0), lun["states"].get("disabled", 0)
            if dead or off:
                add("C19", "CRIT" if dead == lun["paths"] else "WARN", f"{n} / {lun['id']}",
                    f"{dead} dead, {off} disabled of {lun['paths']} path(s)", "Check the SAN fabric, cabling and HBA; rescan after fixing")
        for sw in h["switches"]:
            ups = [h["pnics"][k] for k in sw["pnics"] if k in h["pnics"]]
            down = [p["device"] for p in ups if not p["up"]]
            if down:
                add("C20", "CRIT" if len(down) == len(ups) else "WARN", f"{n} / {sw['name']}",
                    f"uplink(s) link down: {', '.join(down)} ({len(ups) - len(down)} of {len(ups)} up)",
                    "Check the cable/SFP and the upstream switch port")


@check("C21")
def c_cpu_ready(ctx, add):
    perf, hosts, vms = ctx.need("vm_perf", "hosts", "vms")
    hmap = {h["id"]: h for h in hosts}
    agg, rows = defaultdict(lambda: [0.0, 0]), []
    for v in vms:
        p = perf.get(v["id"])
        if not p:
            continue
        w = v["vcpu"] or 1
        a = agg[v["host_id"]]
        a[0] += p["ready_pct_per_vcpu"] * w
        a[1] += w
        rows.append((p["ready_pct_per_vcpu"], v))
    for hid, (tot, w) in agg.items():
        r = round(tot / w, 2) if w else 0
        s = "CRIT" if r > TH["ready_crit"] else "WARN" if r > TH["ready_warn"] else None
        if s and hid in hmap:
            add("C21", s, hmap[hid]["name"], f"avg CPU ready {r}% per vCPU over {ctx.args.perf_minutes:g} min",
                "Reduce vCPU overcommit: right-size VMs or move some to other hosts")
    rows.sort(key=lambda t: -t[0])
    ctx.rankings["cpu_ready_vms"] = [{"vcenter": ctx.name, "vm": v["name"], "ready_pct_per_vcpu": r, "vcpu": v["vcpu"],
                                      "host": hmap.get(v["host_id"], {}).get("name")} for r, v in rows[:TH["rank_top"]]]
    for r, v in rows[:TH["rank_top"]]:
        s = "CRIT" if r > TH["ready_crit"] else "WARN" if r > TH["ready_warn"] else "INFO"
        if s != "INFO" or r >= 1:
            add("C21", s, v["name"], f"VM CPU ready {r}% per vCPU ({v['vcpu']} vCPU) on {hmap.get(v['host_id'], {}).get('name')}",
                "Reduce the VM's vCPU count or relieve the host")


def ds_args():
    return Namespace(ds_free_crit=TH["ds_free_crit"], ds_free_warn=TH["ds_free_warn"], overcommit_warn=TH["overcommit_warn"],
                     overcommit_crit=TH["overcommit_crit"], guest_free_crit=TH["guest_free_crit"],
                     guest_free_warn=TH["guest_free_warn"], snapshot_days=TH["snapshot_warn_days"],
                     snapshot_crit_days=TH["snapshot_crit_days"], snapshot_max_gb=TH["snapshot_crit_gb"],
                     snapshot_disk_pct=1e9)   # snapshot size only trips the absolute GB limit


@check("D22", "D23", "D24")
def c_datastores(ctx, add):
    (st,) = ctx.need("storage")
    m = {"free_pct": "D23", "overcommit_pct": "D24", "thin_headroom": "D24", "accessible": "D22",
         "maintenance_mode": "D22", "overall_status": "D22"}
    for d in st[0]:
        for x in vsphere_storage.ds_findings(ctx.name, d, ds_args()):
            add(m[x["metric"]], x["severity"], x["object"], x["detail"], x["suggestion"])


@check("D25")
def c_ds_mounts(ctx, add):
    mounts, clusters, hosts = ctx.need("dsmounts", "clusters", "hosts")
    hname = {h["id"]: h["name"] for h in hosts}
    for ds in mounts:
        if not ds["multiple_host_access"]:
            continue
        mounted = {m["host_id"] for m in ds["mounts"] if m["mounted"]}
        for c in clusters:
            ids = set(c["host_ids"])
            if mounted & ids and ids - mounted:
                missing = sorted(hname.get(i, i) for i in ids - mounted)
                add("D25", "WARN", ds["name"], f"mounted on {len(mounted & ids)} of {len(ids)} hosts in cluster {c['name']}; "
                    f"missing: {', '.join(missing[:6])}{' ...' if len(missing) > 6 else ''}",
                    "Mount the datastore on all cluster hosts (otherwise vMotion/HA to those hosts fails)")
        bad = [hname.get(m["host_id"], m["host_id"]) for m in ds["mounts"] if m["mounted"] and not m["accessible"]]
        if bad:
            add("D25", "CRIT", ds["name"], f"mounted but not accessible from: {', '.join(bad[:6])}", "Check storage paths on those hosts")


@check("D26")
def c_ds_latency(ctx, add):
    perf, mounts = ctx.need("ds_perf", "dsmounts")
    names = {d["uuid"]: d["name"] for d in mounts}
    for r in perf:
        worst = max(r["read_ms"], r["write_ms"])
        s = "CRIT" if worst > TH["latency_crit_ms"] else "WARN" if worst > TH["latency_warn_ms"] else None
        if s:
            add("D26", s, f"{r['host']} / {names.get(r['instance'], r['instance'])}",
                f"avg latency read {r['read_ms']} ms, write {r['write_ms']} ms over {ctx.args.perf_minutes:g} min",
                "Check storage array load, queue depths and paths; move busy VMs")


def os_key(s):
    s = re.sub(r"\(?\d+-bit\)?", "", (s or "").lower())
    for fam, rx in OS_FAMILIES:
        m = re.search(rx, s)
        if m:
            return fam, m.group(1)
    return None


@check("E27", "E28", "E29")
def c_os(ctx, add):
    vms, = ctx.need("vms")
    for v in vms:
        if v["template"]:
            continue
        name = (v["tools_os"] or v["config_os"] or "").strip()
        if name:
            low = re.sub(r"\(?\d+-bit\)?", "", name.lower())
            for label, rx, maxv in EOL_RULES:
                m = re.search(rx, low)
                if m and (maxv is None or int(m.group(1)) <= maxv):
                    add("E27", "CRIT", v["name"], f"{name} is out of support ({label}); VM {v['power']}",
                        "Upgrade or migrate to a supported OS; isolate it until then")
                    break
        t, c = os_key(v["tools_os"]), os_key(v["config_os"])
        if t and c:
            later = "or later" in (v["config_os"] or "").lower()
            diff = t[0] != c[0]
            if not diff and t[1] and c[1] and t[1] != c[1]:
                diff = not (later and t[1].isdigit() and c[1].isdigit() and int(t[1]) >= int(c[1]))
            if diff:
                add("E28", "WARN", v["name"], f"Tools reports '{v['tools_os']}' but configured OS is '{v['config_os']}'",
                    "Set the VM's guest OS type to match (some changes need a power-off)")
        if v["guest_id"] in OTHER_GUEST_IDS or not name or name.lower().startswith("other"):
            add("E29", "WARN", v["name"], f"guest OS unknown/Other ({name or v['guest_id'] or 'none'})",
                "Set the correct guest OS type and keep VMware Tools running so it is detected")


@check("E31", "E32")
def c_vm_net(ctx, add):
    gather, = ctx.need("gather")
    pgs = {(p["switch_type"], p["name"]): p["vlan_id"] for p in gather["port_groups"]}
    for v in gather["vms"]:
        if v["is_template"]:
            continue
        if v["power_state"] == "poweredOn" and (not v["primary_ip"] or not v["guest_hostname"]):
            miss = " and ".join(x for x, y in (("IP", v["primary_ip"]), ("hostname", v["guest_hostname"])) if not y)
            add("E31", "WARN", v["name"], f"powered on but reports no {miss} (Tools: {v['tools_status']})",
                "Start/repair VMware Tools; confirm the VM is alive")
        vlans = set()
        for n in v["nics"]:
            if n["network"] and EXPOSURE_RE.search(n["network"]):
                add("E32", "INFO", v["name"], f"NIC {n['label']} on exposed-looking network '{n['network']}'",
                    "Confirm the VM belongs on this network and is hardened")
            vl = pgs.get((n["pg_type"], n["network"]))
            if vl and vl.isdigit() and int(vl) > 0:
                vlans.add(int(vl))
        if len(vlans) >= 2:
            add("E32", "WARN", v["name"], f"NICs in {len(vlans)} VLANs: {', '.join(str(x) for x in sorted(vlans))}",
                "Multi-homed VMs bridge network zones; confirm it is intended and firewalled")


@check("E33", "E34", "E35b")
def c_vm_settings(ctx, add):
    vms, = ctx.need("vms")
    for v in vms:
        n = v["name"]
        if v["connection_state"] in ("orphaned", "inaccessible", "invalid", "disconnected"):
            add("E34", "CRIT", n, f"connection state {v['connection_state']}", "Check the VM's host/datastore; re-register or remove if orphaned")
        if v["question"]:
            add("E34", "CRIT", n, f"VM is waiting on a question: {v['question']}", "Answer the question in vCenter (the VM is stalled)")
        if v["consolidation_needed"]:
            add("E34", "WARN", n, "disk consolidation needed", "Run 'Consolidate' in vCenter after checking datastore space")
        if v["overall_status"] in ("red", "yellow"):
            add("E34", "CRIT" if v["overall_status"] == "red" else "WARN", n, f"overallStatus {v['overall_status']}",
                "Check the VM's alarms/events in vCenter")
        if v["template"] or v["power"] == "poweredOff":
            add("E35b", "INFO", n, "template" if v["template"] else "powered off", "Confirm it is still needed; archive or remove if not")
        if v["template"] or v["connection_state"] in ("orphaned", "inaccessible", "invalid"):
            continue
        notset = [k.split(".")[2] for k, val in v["isolation"].items() if (val or "").upper() != "TRUE"]
        if notset:
            add("E33", "INFO", n, f"copy/paste/drag-drop isolation not disabled: {', '.join(notset)}",
                "Set isolation.tools.<copy|paste|dnd>.disable=TRUE for sensitive VMs")
        if v["serial_ports"]:
            add("E33", "WARN", n, f"serial/parallel port present: {', '.join(v['serial_ports'])}", "Remove unused serial/parallel ports")
        if v["cdroms"]:
            add("E33", "WARN", n, f"CD-ROM connected: {', '.join(v['cdroms'])}", "Disconnect the ISO/host device when not needed")


@check("E35", "G50")
def c_vm_storage(ctx, add):
    (st,) = ctx.need("storage")
    for v in st[1]:
        for x in vsphere_storage.vm_findings(ctx.name, v, {}, {}, ds_args()):
            if x["metric"] in ("snapshot_age", "snapshot_size"):
                add("E35", x["severity"], x["object"], x["detail"], x["suggestion"])
            elif x["metric"] == "guest_free" and v["power"] == "poweredOn":
                add("G50", x["severity"], x["object"], x["detail"], x["suggestion"])


def vm_usage(ctx):
    vms, hosts = ctx.need("vms", "hosts")
    hmhz = {h["id"]: h["cpu_mhz"] for h in hosts}
    out = []
    for v in vms:
        if v["template"] or v["power"] != "poweredOn":
            continue
        alloc = (v["vcpu"] or 0) * hmhz.get(v["host_id"], 0)
        out.append({**v, "cpu_pct": pct(v["cpu_used_mhz"] or 0, alloc) if alloc and v["cpu_used_mhz"] is not None else None,
                    "mem_pct": pct(v["mem_active_mb"] or 0, v["mem_mb"]) if v["mem_mb"] and v["mem_active_mb"] is not None else None})
    return out


@check("F45", "F46", "F47")
def c_vm_use(ctx, add):
    for v in vm_usage(ctx):
        n = v["name"]
        if v["cpu_pct"] is not None and v["cpu_pct"] > TH["vm_cpu_warn"]:
            add("F45", "WARN", n, f"CPU {v['cpu_pct']}% of allocation ({v['cpu_used_mhz']} MHz, {v['vcpu']} vCPU)",
                "Add vCPUs or investigate the workload")
        if v["mem_pct"] is not None and v["mem_pct"] > TH["vm_mem_warn"]:
            add("F46", "WARN", n, f"guest active memory {v['mem_pct']}% of {v['mem_mb']} MB", "Add memory or investigate the workload")
        parts = [f"{lbl} {val}" for lbl, val in (("ballooned MB", v["ballooned_mb"]), ("swapped MB", v["swapped_mb"]),
                                                  ("compressed KB", v["compressed_kb"])) if val]
        if parts:
            add("F47", "WARN", n, ", ".join(parts), "Host memory pressure: add host memory, remove reservations/limits or move VMs")


@check("F48")
def c_oversized(ctx, add):
    perf = ctx.d.get("vm_perf") or {}
    for v in vm_usage(ctx):
        big = (v["vcpu"] or 0) >= TH["oversize_vcpu"] or (v["mem_mb"] or 0) / 1024 >= TH["oversize_mem_gb"]
        cpu = (perf.get(v["id"]) or {}).get("cpu_usage_pct")
        cpu = cpu if cpu is not None else v["cpu_pct"]
        if big and cpu is not None and v["mem_pct"] is not None and cpu < TH["oversize_cpu_max"] and v["mem_pct"] < TH["oversize_mem_max"]:
            add("F48", "INFO", v["name"], f"{v['vcpu']} vCPU / {round(v['mem_mb'] / 1024)} GB but CPU {cpu}% and memory {v['mem_pct']}% used",
                "Right-size the VM after confirming peak demand with the owner")


@check("F49")
def c_rankings(ctx, add):
    gather, = ctx.need("gather")
    use, top = vm_usage(ctx), TH["rank_top"]
    disk = {v["moref"]: v["disk_gb"] for v in gather["vms"]}
    ctx.rankings["top_cpu"] = [{"vcenter": ctx.name, "vm": v["name"], "cpu_mhz": v["cpu_used_mhz"], "cpu_pct": v["cpu_pct"],
                                "vcpu": v["vcpu"]} for v in sorted(use, key=lambda v: -(v["cpu_used_mhz"] or 0))[:top]]
    ctx.rankings["top_memory"] = [{"vcenter": ctx.name, "vm": v["name"], "mem_active_mb": v["mem_active_mb"],
                                   "mem_pct": v["mem_pct"], "mem_mb": v["mem_mb"]}
                                  for v in sorted(use, key=lambda v: -(v["mem_active_mb"] or 0))[:top]]
    alld = [v for v in ctx.d["vms"] if not v["template"]]
    ctx.rankings["top_disk"] = [{"vcenter": ctx.name, "vm": v["name"], "disk_gb": disk.get(v["id"]), "power": v["power"]}
                                for v in sorted(alld, key=lambda v: -(disk.get(v["id"]) or 0))[:top]]


def rank_findings(rankings):
    """F49 findings from the merged rankings (top N across all vCenters)."""
    out = []
    spec = [("top_cpu", "cpu_mhz", lambda r: f"CPU {r['cpu_mhz']} MHz ({r['cpu_pct']}% of allocation)"),
            ("top_memory", "mem_active_mb", lambda r: f"active memory {r['mem_active_mb']} MB of {r['mem_mb']} MB"),
            ("top_disk", "disk_gb", lambda r: f"provisioned disk {r['disk_gb']} GB")]
    for key, sk, fmt in spec:
        for i, r in enumerate(sorted(rankings.get(key, []), key=lambda r: -(r[sk] or 0))[:TH["rank_top"]], 1):
            out.append({"target": r["vm"], "vcenter": r["vcenter"], "severity": "INFO",
                        "detail": f"{key.replace('top_', 'top ')} #{i}: {fmt(r)}", "suggestion": "Review for right-sizing/capacity planning"})
    return out


# --------------------------------------------------------------------------- Veeam (H51/H52)
CONTAINER_KEYS = {"cluster": "cluster", "host": "host", "datacenter": "datacenter", "folder": "folder",
                  "resourcepool": "resource_pool", "datastore": "datastores"}


def include_rows(items):
    """Normalise a job's includes/excludes entries -> [{type, name, object_id, host}]."""
    rows = []
    for it in aslist(items):
        if not isinstance(it, dict):
            continue
        inv = it.get("inventoryObject") if isinstance(it.get("inventoryObject"), dict) else {}
        rows.append({"type": str(inv.get("type") or it.get("type") or "").lower(),
                     "name": str(inv.get("name") or it.get("name") or ""),
                     "object_id": str(inv.get("objectId") or it.get("objectId") or ""),
                     "host": str(inv.get("hostName") or it.get("hostName") or "")})
    return rows


def veeam_matches(vm, inc):
    """True when an include/exclude entry covers this VM (by moref, name, or container name)."""
    ids = re.findall(r"(?:^|[.:])((?:vm|vapp)-\d+)$", inc["object_id"].lower())
    if ids and ids[0] == vm["moref"].lower():
        return True
    n, t = inc["name"].lower(), inc["type"]
    if "virtualmachine" in t or t in ("vm", ""):
        return n == vm["name"].lower()
    for k, attr in CONTAINER_KEYS.items():
        if k in t:
            val = vm.get(attr)
            vals = [str(x).lower() for x in (val if isinstance(val, list) else [val]) if x]
            if k == "folder":
                vals = [p.lower() for p in re.split(r"[/\\]", str(vm.get("folder") or "")) if p]
            return n in vals
    return False


def veeam_skip(res, why, raw=None):
    for r in res.values():
        r["skip"] = why
    return res, raw


def check_veeam(args, ctxs):
    """H51/H52 from the Veeam job config + job states (GET only) -> ({id: {findings, skip, reason}}, raw)."""
    res = {i: {"findings": [], "skip": None, "reason": None} for i in ("H51", "H52")}
    if not args.veeam_host:
        return veeam_skip(res, "no --veeam-host given")
    cfg = Namespace(cred=args.veeam_cred, port=veeam_api.DEFAULT_PORT, api_version=veeam_api.DEFAULT_API_VERSION,
                    verify_ssl=False, timeout=30, hours=24)
    try:
        veeam_api.check_host(args.veeam_host)
        raw, errs = veeam_api.fetch_host(cfg, args.veeam_host, ["jobs", "jobs_states"])
    except veeam_api.ApiError as e:
        return veeam_skip(res, f"Veeam {e.kind}: {e}")
    except SystemExit as e:
        return veeam_skip(res, str(e))
    except Exception as e:  # noqa: BLE001
        return veeam_skip(res, f"Veeam: {err_text(e)}")
    if "jobs" in errs:
        return veeam_skip(res, f"Veeam jobs not readable: {errs['jobs']}", {"errors": errs})
    states = {s.get("id"): s for s in veeam_api.data_of(raw.get("jobs_states"))}
    jobs = []
    for j in veeam_api.data_of(raw.get("jobs")):
        vmx = j.get("virtualMachines")
        if not isinstance(vmx, dict):
            continue
        s = states.get(j.get("id"), {})
        jobs.append({"name": j.get("name"), "type": j.get("type"),
                     "disabled": bool(j.get("isDisabled")) or s.get("status") == "disabled",
                     "last_result": s.get("lastResult"), "last_run": s.get("lastRun"), "status": s.get("status"),
                     "includes": include_rows(vmx.get("includes")), "excludes": include_rows(vmx.get("excludes"))})
    rawout = {"jobs": jobs, "errors": errs}
    if not jobs:
        return veeam_skip(res, "Veeam returned no VM-level jobs", rawout)
    now, notes, evaluated = datetime.now(UTC), [], 0
    tagged = sorted({j["name"] for j in jobs for i in j["includes"] if "tag" in i["type"]})
    if tagged:
        notes.append(f"tag-based includes cannot be resolved (jobs: {', '.join(tagged)})")
    for ctx in ctxs:
        if "unreachable" in ctx.d:
            continue
        try:
            gather, storage = ctx.need("gather", "storage")
        except Skip as e:
            notes.append(f"{ctx.name}: {e}")
            continue
        vcn = {ctx.name.lower(), str(ctx.vc.get("host") or "").lower()}
        vcn |= {x.split(".")[0] for x in vcn if x and not x.replace(".", "").isdigit()}
        dsby = {v["id"]: v["datastores"] for v in storage[1]}
        jobs_vc = [j for j in jobs if any(i["host"].lower() in vcn or i["host"].lower().split(".")[0] in vcn for i in j["includes"])]
        if not jobs_vc:   # backed up elsewhere (another Veeam server) or not at all: not this server's coverage gap
            notes.append(f"{ctx.name}: not backed up by this Veeam server (no job references it) - not evaluated")
            continue
        evaluated += 1
        for v in gather["vms"]:
            if v["is_template"] or v["power_state"] != "poweredOn":
                continue
            vm = {**v, "datastores": dsby.get(v["moref"], [])}
            cover = [j for j in jobs_vc if any(veeam_matches(vm, i) for i in j["includes"])
                     and not any(veeam_matches(vm, i) for i in j["excludes"])]
            on = [j for j in cover if not j["disabled"]]
            if not on:
                why = f"only in disabled job(s): {', '.join(j['name'] for j in cover)}" if cover else "not in any Veeam job"
                res["H51"]["findings"].append({"target": v["name"], "vcenter": ctx.name, "severity": "WARN", "detail": why,
                                               "suggestion": "Add the VM to a backup job (or document why it is excluded)"})
                continue
            problems = []
            for j in on:
                lr, ld = (j["last_result"] or "").lower(), veeam_api.parse_ts(j["last_run"])
                when = veeam_api.fmt_ts(j["last_run"])
                if lr == "failed":
                    problems.append(("WARN", f"job '{j['name']}' last result Failed ({when})"))
                elif lr == "warning":
                    problems.append(("WARN", f"job '{j['name']}' last result Warning ({when})"))
                elif ld is None or now - ld > timedelta(hours=TH["veeam_stale_hours"]):
                    problems.append(("WARN", f"job '{j['name']}' has not run in over {TH['veeam_stale_hours']:g}h (last {when})"))
                else:
                    problems = []   # one healthy covering job is enough
                    break
            if problems:
                res["H52"]["findings"].append({
                    "target": v["name"], "vcenter": ctx.name, "severity": max((p[0] for p in problems), key=SEV_RANK.get),
                    "detail": "; ".join(p[1] for p in problems),
                    "suggestion": "Check the job's last session in Veeam and re-run after fixing the cause"})
    if not evaluated:
        return veeam_skip(res, "; ".join(notes) or "no vCenter evaluated", rawout)
    if notes:
        for r in res.values():
            r["reason"] = "; ".join(notes)
    return res, rawout


# --------------------------------------------------------------------------- guest_security merge (E36-E44)
def load_guest(args):
    """-> (items {id: item}, source info, skip reason or None)."""
    path = None
    if args.guest_results:
        p = Path(args.guest_results)
        path = p / "summary.json" if p.is_dir() else p
        if not path.is_file():
            return {}, None, f"guest results not found: {path}"
    else:
        cands = sorted((ROOT / "reports" / "guest_security").glob("*/summary.json"), key=lambda f: f.stat().st_mtime)
        if cands and datetime.now().timestamp() - cands[-1].stat().st_mtime < 86400:
            path = cands[-1]
        if not path:
            return {}, None, "guest credentials/run missing"
    try:
        data = json.loads(path.read_text())
        items = {i["id"]: i for i in data.get("items", []) if isinstance(i, dict) and "id" in i}
    except (OSError, ValueError) as e:
        return {}, None, f"guest results unreadable ({path}): {err_text(e)}"
    return items, {"source": str(path), "generated": data.get("generated")}, None


# --------------------------------------------------------------------------- assemble and report
def run_vcenter_checks(ctx):
    if "unreachable" in ctx.d:
        return
    a = ctx.d["about"]
    ctx.findings.append(("A01", {"target": ctx.name, "vcenter": ctx.name, "severity": "INFO",
                                 "detail": f"reachable, {a['full_name']} (version {a['version']}, build {a['build']})",
                                 "suggestion": "Keep vCenter on a supported, patched build"}))
    ctx.ran.add("A01")
    for ids, fn in CHECKS:
        rows = []

        def add(item, sev, target, detail, suggestion, rows=rows):
            rows.append((item, {"target": str(target), "vcenter": ctx.name, "severity": sev, "detail": detail,
                                "suggestion": suggestion}))
        try:
            fn(ctx, add)
        except Skip as e:
            ctx.skips.update({i: str(e) for i in ids})
            continue
        except Exception as e:  # noqa: BLE001 - an erroring item becomes skip, never a traceback
            ctx.skips.update({i: f"check error: {err_text(e)}" for i in ids})
            continue
        ctx.findings += rows
        ctx.ran.update(ids)


def assemble(ctxs, veeam, guest_items, guest_skip):
    reach = [c for c in ctxs if "unreachable" not in c.d]
    unreach = [c for c in ctxs if "unreachable" in c.d]
    items, rankings = [], {}
    for c in ctxs:
        for k, v in c.rankings.items():
            rankings.setdefault(k, []).extend(v)
    if "cpu_ready_vms" in rankings:
        rankings["cpu_ready_vms"] = sorted(rankings["cpu_ready_vms"], key=lambda r: -r["ready_pct_per_vcpu"])[:TH["rank_top"]]
    for iid, section, title in ITEMS:
        f, skip, reason = [], None, None
        if iid == "A01":
            f = [x for c in ctxs for i, x in c.findings if i == iid]
            f += [{"target": c.name, "vcenter": c.name, "severity": "CRIT",
                   "detail": f"unreachable or login failed: {c.d['unreachable']}",
                   "suggestion": "Check the vCenter address, credentials (credential_ref) and network path"} for c in unreach]
        elif iid in GUEST_IDS:
            gi = guest_items.get(iid)
            if guest_skip:
                skip = guest_skip
            elif not gi:
                skip = "item not present in the guest_security results"
            elif gi.get("status") == "skip":
                skip = gi.get("reason") or "skipped by guest_security"
            else:
                f = [{"target": str(x.get("target")), "vcenter": x.get("vcenter") or "", "severity": x.get("severity", "INFO"),
                      "detail": x.get("detail", ""), "suggestion": x.get("suggestion", "")} for x in gi.get("findings", [])]
                reason = gi.get("reason")
        elif iid in ("H51", "H52"):
            skip, reason, f = veeam[iid]["skip"], veeam[iid]["reason"], veeam[iid]["findings"]
        else:
            ok = [c for c in reach if iid in c.ran]
            bad = {c.name: c.skips[iid] for c in reach if iid in c.skips}
            f = rank_findings(rankings) if iid == "F49" and ok else [x for c in reach for i, x in c.findings if i == iid]
            if not ok:
                skip = "; ".join(f"{k}: {v}" for k, v in bad.items()) or "no reachable vCenter"
            else:
                notes = [f"{k}: {v}" for k, v in bad.items()]
                if unreach:
                    notes.append("not evaluated on unreachable vCenter(s): " + ", ".join(c.name for c in unreach))
                reason = "; ".join(notes) or None
        if skip:
            status, reason, f = "skip", skip, []
        else:
            worst = max((SEV_RANK[x["severity"]] for x in f), default=None)
            status = "pass" if worst is None else {0: "info", 1: "warn", 2: "crit"}[worst]
        f.sort(key=lambda x: (-SEV_RANK[x["severity"]], x["vcenter"], x["target"]))
        items.append({"id": iid, "section": section, "title": title, "status": status, "reason": reason, "findings": f})
    counts = {k: sum(1 for i in items if i["status"] == k) for k in ("pass", "info", "warn", "crit", "skip")}
    counts["findings"] = dict(Counter(x["severity"] for i in items for x in i["findings"]))
    return items, rankings, counts


def md_table(rows, head):
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]


# ranking key -> (sort field, table header, row function)
RANK_TABLES = {
    "top_cpu": ("cpu_mhz", ["VM", "vCenter", "CPU MHz", "CPU % of alloc", "vCPU"],
                lambda r: (r["vm"], r["vcenter"], r["cpu_mhz"], r["cpu_pct"], r["vcpu"])),
    "top_memory": ("mem_active_mb", ["VM", "vCenter", "Active MB", "Active %", "Configured MB"],
                   lambda r: (r["vm"], r["vcenter"], r["mem_active_mb"], r["mem_pct"], r["mem_mb"])),
    "top_disk": ("disk_gb", ["VM", "vCenter", "Provisioned GB", "Power"],
                 lambda r: (r["vm"], r["vcenter"], r["disk_gb"], r["power"])),
    "cpu_ready_vms": ("ready_pct_per_vcpu", ["VM", "vCenter", "Ready % per vCPU", "vCPU", "Host"],
                      lambda r: (r["vm"], r["vcenter"], r["ready_pct_per_vcpu"], r["vcpu"], r["host"])),
}


def ranked(rankings, key):
    sk = RANK_TABLES[key][0]
    return sorted(rankings.get(key, []), key=lambda r: -(r[sk] or 0))[:TH["rank_top"]]


def write_outputs(out, summary, ctxs, veeam_raw, guest_info):
    items, counts = summary["items"], summary["counts"]
    sc, fc = summary["scope"], counts["findings"]
    L = [f"# vSphere checklist - {summary['generated']}", "",
         f"Scope: {', '.join(sc['vcenters']) or 'none'}" + (f" (unreachable: {', '.join(sc['unreachable'])})" if sc["unreachable"] else ""), "",
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
    L += ["", "## Rankings (F49, C21)", ""]
    for key, (_, head, fn) in RANK_TABLES.items():
        L += [f"### {key}", ""] + md_table([fn(r) for r in ranked(summary["rankings"], key)], head) + [""]
    (out / "checklist.md").write_text("\n".join(L) + "\n")
    with open(out / "findings.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["item_id", "section", "title", "status", "severity", "vcenter", "target", "detail", "suggestion"])
        for it in items:
            for x in it["findings"]:
                w.writerow([it["id"], it["section"], it["title"], it["status"], x["severity"], x["vcenter"], x["target"],
                            x["detail"], x["suggestion"]])
    raw = out / "raw"
    for c in ctxs:
        d = {k: v for k, v in c.d.items() if k != "audit"}
        d["errors"] = c.errors
        (raw / f"{safe(c.name)}.json").write_text(json.dumps(d, indent=2, default=str))
    if veeam_raw:
        (raw / "veeam.json").write_text(json.dumps(veeam_raw, indent=2, default=str))
    if guest_info:
        (raw / "guest_security.json").write_text(json.dumps(guest_info, indent=2, default=str))


def print_tables(rankings):
    for key, (sk, head, fn) in RANK_TABLES.items():
        rows = ranked(rankings, key)
        if rows:
            print(f"\n{key}:")
            for r in rows:
                print("  " + "  ".join(str(x) for x in fn(r)))


def parse_thresholds(pairs):
    for p in pairs or []:
        k, _, v = p.partition("=")
        if k not in TH:
            sys.exit(f"unknown threshold {k!r}; known: {', '.join(sorted(TH))}")
        try:
            TH[k] = float(v)
        except ValueError:
            sys.exit(f"threshold {k} needs a number, got {v!r}")


def pick_vcenters(names):
    """Active vCenters (default) plus any explicitly named one of another status (e.g. auth_failed), so it shows in A01."""
    vcs = vmlib.select_vcenters(names)
    missing = {n.lower() for n in names or []} - {v["name"].lower() for v in vcs}
    if missing:
        db = vmlib.open_db()
        for r in db.execute("SELECT * FROM vcenters ORDER BY name"):
            if r["name"].lower() in missing:
                vcs.append(dict(r))
                missing.discard(r["name"].lower())
        db.close()
    for n in sorted(missing):
        print(f"warning: unknown vcenter: {n}", file=sys.stderr)
    return vcs


def main():
    ap = argparse.ArgumentParser(description="Read-only comprehensive vSphere health and security checklist")
    ap.add_argument("--vcenter", action="append", help="vcenter name (repeatable); default all active")
    ap.add_argument("--veeam-host", help="Veeam B&R server (hostname/IP) for backup coverage H51/H52; without it H is skipped")
    ap.add_argument("--veeam-cred", default=veeam_api.DEFAULT_CRED, help="Veeam credential REF (default VEEAM)")
    ap.add_argument("--guest-results", metavar="DIR", help="reports/guest_security/<ts>/ dir to merge as E36-E44")
    ap.add_argument("--perf-minutes", type=float, default=30, help="realtime performance window for C21/D26 (max 60)")
    ap.add_argument("--out", help="output dir (default reports/checklist/vsphere/<timestamp>)")
    ap.add_argument("--workers", type=int, default=4, help="vCenters collected concurrently")
    ap.add_argument("--threshold", action="append", metavar="KEY=VALUE", help="override a threshold constant (repeatable)")
    ap.add_argument("--json", action="store_true", help="print summary.json to stdout instead of the console summary")
    args = ap.parse_args()
    parse_thresholds(args.threshold)

    started = datetime.now()
    out = Path(args.out) if args.out else ROOT / "reports" / "checklist" / "vsphere" / started.strftime("%Y%m%d-%H%M%S")
    vcs = pick_vcenters(args.vcenter)
    if not vcs:
        sys.exit("no active vcenters (see: cfn vsphere add-vcenter)")
    (out / "raw").mkdir(parents=True, exist_ok=True)
    print(f"vSphere checklist (read-only) on {len(vcs)} vCenter(s), out={out}", file=sys.stderr if args.json else sys.stdout)

    with ThreadPoolExecutor(max(1, min(args.workers, len(vcs)))) as ex:
        ctxs = list(ex.map(lambda vc: gather_vcenter(vc, args), vcs))
    for c in ctxs:
        run_vcenter_checks(c)
        if "unreachable" in c.d:
            print(f"UNREACHABLE {c.name}: {c.d['unreachable']}", file=sys.stderr)
    veeam, veeam_raw = check_veeam(args, ctxs)
    guest_items, guest_info, guest_skip = load_guest(args)

    items, rankings, counts = assemble(ctxs, veeam, guest_items, guest_skip)
    summary = {"generated": started.isoformat(timespec="seconds"),
               "scope": {"vcenters": [c.name for c in ctxs if "unreachable" not in c.d],
                         "unreachable": [c.name for c in ctxs if "unreachable" in c.d],
                         "veeam_host": args.veeam_host, "guest_results": (guest_info or {}).get("source"),
                         "perf_minutes": args.perf_minutes, "thresholds": TH},
               "items": items, "rankings": rankings, "counts": counts}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    write_outputs(out, summary, ctxs, veeam_raw, guest_info)

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
        return
    fc = counts["findings"]
    print(f"Items: pass={counts['pass']} info={counts['info']} warn={counts['warn']} crit={counts['crit']} skip={counts['skip']}"
          f" | findings CRIT={fc.get('CRIT', 0)} WARN={fc.get('WARN', 0)} INFO={fc.get('INFO', 0)}")
    for st in ("crit", "warn", "skip"):
        for it in items:
            if it["status"] == st:
                extra = f": {(it['reason'] or '')[:100]}" if st == "skip" else f" ({len(it['findings'])})"
                print(f"  {st.upper():4} {it['id']:5} {it['title']}{extra}")
    print_tables(rankings)
    print(f"\nReport: {out / 'checklist.md'}\nJSON:   {out / 'summary.json'}")


if __name__ == "__main__":
    main()
