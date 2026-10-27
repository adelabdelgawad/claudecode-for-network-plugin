"""READ-ONLY vSphere storage-risk report for VMs and datastores (pyvmomi + inventory).

Usage:
    cfn vsphere-storage [--vcenter NAME ...] [--out DIR]
        [--ds-free-crit 10] [--ds-free-warn 20] [--overcommit-warn 100] [--overcommit-crit 150]
        [--guest-free-crit 10] [--guest-free-warn 15] [--snapshot-days 3] [--snapshot-crit-days 30]
        [--snapshot-max-gb 100] [--snapshot-disk-pct 50]

One PropertyCollector pass per object type (datastores, VMs); property reads only. Suggestions are text only.
Outputs under --out (default reports/vsphere_storage/<ts>): summary.json, report.md, vm_storage.csv, raw/*.json
"""
import argparse
import csv
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import vmlib
from pyVmomi import vim
from vmlib import ROOT, aslist, mid

GB = 1024 ** 3
RANK = {"INFO": 0, "WARN": 1, "CRIT": 2}
DELTA_RE = re.compile(r"-\d{6}(-delta|-sesparse)?\.vmdk$", re.I)
PSEUDO = ("/snap/", "/run", "/dev", "/sys", "/proc")
LOCAL_RE = re.compile(r"^datastore\d*( \(\d+\))?$", re.I)


def gb(b):
    return round((b or 0) / GB, 1)


def pct(a, b):
    return round(100 * a / b, 1) if b else None


def F(vc, sev, obj, metric, detail, sug, kind="datastore"):
    return {"vcenter": vc, "severity": sev, "object": obj, "kind": kind, "metric": metric, "detail": detail,
            "suggestion": sug}


def ds_name(fn):
    m = re.match(r"\[([^\]]*)\]", fn or "")
    return m.group(1) if m else None


def snap_walk(nodes, now, out):
    for n in aslist(nodes):
        out.append({"name": n.name, "age_days": round((now - n.createTime).total_seconds() / 86400, 1),
                    "created": n.createTime.isoformat(timespec="seconds"), "state": str(n.state)})
        snap_walk(n.childSnapshotList, now, out)
    return out


def gather(si):
    """Two PropertyCollector round-trips (datastores, VMs) -> plain dict rows."""
    now = datetime.now(timezone.utc)
    dsr, dsid = [], {}
    for o in vmlib.collect(si, vim.Datastore, ["name", "summary", "overallStatus", "host", "vm"]):
        s = o["summary"]
        cap, free, unc = s.capacity or 0, s.freeSpace or 0, s.uncommitted or 0
        multi = bool(s.multipleHostAccess)
        prov = cap - free + unc
        d = {"name": o["name"], "id": o["_id"], "type": s.type, "capacity_gb": gb(cap), "free_gb": gb(free),
             "uncommitted_gb": gb(unc), "capacity": cap, "free": free, "uncommitted": unc,
             "used_pct": pct(cap - free, cap), "free_pct": pct(free, cap), "provisioned_gb": gb(prov),
             "overcommit_pct": pct(prov, cap), "accessible": bool(s.accessible), "maintenance_mode": s.maintenanceMode,
             "multiple_host_access": multi, "overall_status": str(o.get("overallStatus")),
             "host_count": len(aslist(o.get("host"))), "vm_count": len(aslist(o.get("vm"))),
             "vms": sorted(mid(v) for v in aslist(o.get("vm"))), "local": (not multi) or bool(LOCAL_RE.match(o["name"]))}
        dsr.append(d)
        dsid[d["id"]] = d["name"]
    vmr = []
    props = ["name", "config.template", "runtime.powerState", "runtime.consolidationNeeded", "snapshot", "layoutEx.file",
             "config.hardware.device", "storage.perDatastoreUsage", "guest.disk", "guest.toolsRunningStatus"]
    for o in vmlib.collect(si, vim.VirtualMachine, props):
        if o.get("config.template"):
            continue
        disks = []
        for dev in aslist(o.get("config.hardware.device")):
            if isinstance(dev, vim.vm.device.VirtualDisk):
                b = dev.backing
                dsref = getattr(b, "datastore", None)
                fn = getattr(b, "fileName", None)
                disks.append({"label": dev.deviceInfo.label if dev.deviceInfo else None,
                              "capacity_kb": dev.capacityInKB, "capacity_gb": gb((dev.capacityInKB or 0) * 1024),
                              "file": fn, "datastore": dsid.get(mid(dsref)) or ds_name(fn),
                              "thin": getattr(b, "thinProvisioned", None), "mode": getattr(b, "diskMode", None)})
        files = aslist(o.get("layoutEx.file"))
        snap_bytes = sum(f.size or 0 for f in files if f.type in ("snapshotData", "snapshotMemory", "snapshotList")
                         or (f.type == "diskExtent" and DELTA_RE.search(f.name or "")))
        swap_bytes = sum(f.size or 0 for f in files if f.type == "swap")
        snaps = snap_walk(getattr(o.get("snapshot"), "rootSnapshotList", None), now, [])
        usage = [{"datastore": dsid.get(mid(u.datastore)) or mid(u.datastore), "committed_gb": gb(u.committed),
                  "uncommitted_gb": gb(u.uncommitted)} for u in aslist(o.get("storage.perDatastoreUsage"))]
        gdisks = [{"path": g.diskPath, "capacity_gb": round((g.capacity or 0) / GB, 2),
                   "free_gb": round((g.freeSpace or 0) / GB, 2), "capacity": g.capacity or 0, "free": g.freeSpace or 0,
                   "free_pct": pct(g.freeSpace or 0, g.capacity)} for g in aslist(o.get("guest.disk"))]
        vmr.append({"name": o.get("name"), "id": o["_id"], "power": str(o.get("runtime.powerState")),
                    "consolidation_needed": bool(o.get("runtime.consolidationNeeded")),
                    "tools": str(o.get("guest.toolsRunningStatus")), "disks": disks,
                    "disk_total_gb": round(sum(d["capacity_gb"] for d in disks), 1),
                    "datastores": sorted({d["datastore"] for d in disks if d["datastore"]}),
                    "snapshots": snaps, "snapshot_count": len(snaps),
                    "snapshot_oldest_days": max((s["age_days"] for s in snaps), default=None),
                    "snapshot_data_gb": gb(snap_bytes), "swap_gb": gb(swap_bytes), "per_datastore_usage": usage,
                    "guest_disks": gdisks})
    return dsr, vmr


def ds_findings(vc, d, a):
    f, n = [], d["name"]
    fp = d["free_pct"]
    if fp is not None and fp < a.ds_free_warn:
        sev = "CRIT" if fp < a.ds_free_crit else "WARN"
        f.append(F(vc, sev, n, "free_pct", f"{fp}% free ({d['free_gb']} of {d['capacity_gb']} GB)",
                   "Free space (old snapshots, orphaned VMDKs, unused VMs), migrate VMs, or expand the datastore"))
    oc = d["overcommit_pct"]
    if oc is not None and oc > a.overcommit_warn:
        f.append(F(vc, "CRIT" if oc > a.overcommit_crit else "WARN", n, "overcommit_pct",
                   f"provisioned {d['provisioned_gb']} GB = {oc}% of {d['capacity_gb']} GB (uncommitted {d['uncommitted_gb']} GB)",
                   "Reduce thin-provisioned growth risk: add capacity, move VMs, or reclaim space"))
    short = d["uncommitted"] - d["free"]
    if short > 0 and d["uncommitted"]:
        f.append(F(vc, "CRIT", n, "thin_headroom",
                   f"if all thin disks grew to full, free space would go negative by {gb(short)} GB "
                   f"(free {d['free_gb']} GB < uncommitted {d['uncommitted_gb']} GB)",
                   "Add at least the shortfall in capacity or migrate thin VMs; monitor growth and set datastore alarms"))
    if not d["accessible"]:
        f.append(F(vc, "CRIT", n, "accessible", "datastore not accessible", "Check storage paths/connectivity from the hosts"))
    if d["maintenance_mode"] not in (None, "normal"):
        f.append(F(vc, "WARN", n, "maintenance_mode", f"maintenance mode: {d['maintenance_mode']}",
                   "Exit maintenance mode when work is complete"))
    if d["overall_status"] in ("red", "yellow"):
        f.append(F(vc, "CRIT" if d["overall_status"] == "red" else "WARN", n, "overall_status",
                   f"overallStatus {d['overall_status']}", "Check datastore alarms/events in vCenter"))
    return f


def vm_findings(vc, v, dsmap, dsworst, a):
    f, n, on = [], v["name"], v["power"] == "poweredOn"
    mk = lambda sev, m, det, sug: f.append(F(vc, sev, n, m, det, sug, "vm"))  # noqa: E731
    vols = []
    for g in v["guest_disks"]:
        p = g["path"] or ""
        if g["capacity"] < GB or p.startswith(PSEUDO):
            continue
        vols.append(g)
        fp, fg, cg = g["free_pct"], g["free_gb"], g["capacity_gb"]
        if (fp is not None and fp < a.guest_free_crit) or (fg < 2 and cg >= 20):
            mk("CRIT", "guest_free", f"{p}: {fp}% free ({fg} of {cg} GB)",
               "Extend the guest volume/virtual disk or clean up data inside the guest")
        elif fp is not None and fp < a.guest_free_warn:
            mk("WARN", "guest_free", f"{p}: {fp}% free ({fg} of {cg} GB)",
               "Plan to extend the guest volume/virtual disk or clean up data")
    v["_worst_vol"] = min(vols, key=lambda g: g["free_pct"] if g["free_pct"] is not None else 101, default=None)
    if on and not v["guest_disks"]:
        mk("INFO", "guest_blind", f"can't see inside guest (tools: {v['tools']})",
           "Install/start VMware Tools so guest filesystem usage is visible")
    sn = v["snapshots"]
    if sn:
        old = v["snapshot_oldest_days"]
        names = ", ".join(s["name"] for s in sn[:5])
        if old > a.snapshot_days:
            mk("CRIT" if old > a.snapshot_crit_days else "WARN", "snapshot_age",
               f"{len(sn)} snapshot(s), oldest {old} days ({names}), snapshot data {v['snapshot_data_gb']} GB",
               "Confirm with the VM owner, then consolidate/delete old snapshots")
        dt, sd = v["disk_total_gb"], v["snapshot_data_gb"]
        if sd > a.snapshot_max_gb or (dt and sd > dt * a.snapshot_disk_pct / 100):
            mk("CRIT", "snapshot_size", f"snapshot data {sd} GB = {pct(sd, dt)}% of {dt} GB disks",
               "Delete/consolidate snapshots after confirming; large deltas risk filling the datastore")
    if v["consolidation_needed"]:
        mk("CRIT", "consolidation", "disk consolidation needed", "Run 'Consolidate' in vCenter after checking datastore space")
    loc = [d for d in v["datastores"] if dsmap.get(d, {}).get("local")]
    if on and loc:
        mk("INFO", "local_datastore", f"disks on local datastore: {', '.join(loc)}", "No HA/vMotion; consider shared storage")
    for d in v["disks"]:
        if d["mode"] and d["mode"] != "persistent":
            mk("INFO", "disk_mode", f"{d['label']} mode {d['mode']} ({d['datastore']})",
               "Independent/nonpersistent disks are excluded from snapshots/backups; confirm intended")
    for dn in v["datastores"]:
        s = dsworst.get(dn)
        if s:
            mk(s, "datastore_exposure", f"disks on {dn} which is {s}",
               "Resolve the datastore risk (see datastore findings)")
    return f


def table(rows, head):
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]


def write_outputs(out, started, args, results, findings):
    sev = Counter(x["severity"] for x in findings)
    L = [f"# vSphere storage-risk report - {started:%Y-%m-%d %H:%M}", "",
         f"Findings: CRIT={sev['CRIT']} WARN={sev['WARN']} INFO={sev['INFO']} (read-only; suggestions are text only)", ""]
    dsw = {}
    for x in findings:
        if x["kind"] == "datastore":
            k = (x["vcenter"], x["object"])
            dsw[k] = max(dsw.get(k, -1), RANK[x["severity"]])
    inv = {0: "INFO", 1: "WARN", 2: "CRIT", -1: "ok"}
    rows = []
    for r in results:
        for d in r.get("datastores", []):
            rows.append((-dsw.get((r["vcenter"], d["name"]), -1), d["free_pct"] if d["free_pct"] is not None else 101, r, d))
    rows.sort(key=lambda t: t[:2])
    L += ["## Datastores (by risk)", ""] + table(
        [(inv[-w], r["vcenter"], d["name"], d["type"], "local" if d["local"] else "shared", d["capacity_gb"], d["free_gb"],
          d["used_pct"], d["provisioned_gb"], d["overcommit_pct"], d["vm_count"]) for w, _, r, d in rows],
        ["Risk", "vCenter", "Datastore", "Type", "Access", "Cap GB", "Free GB", "Used %", "Prov GB", "Overcommit %", "VMs"])
    vrows = []
    for r in results:
        for v in r.get("vms", []):
            vf = [x for x in findings if x["kind"] == "vm" and x["object"] == v["name"] and x["vcenter"] == r["vcenter"]
                  and x["severity"] != "INFO"]
            if vf:
                vrows.append((max(RANK[x["severity"]] for x in vf), r["vcenter"], v, len(vf)))
    vrows.sort(key=lambda t: (-t[0], t[2]["name"]))
    vt = []
    for w, vc, v, nf in vrows:
        g = v.get("_worst_vol")
        vt.append((inv[w], vc, v["name"], v["power"], f"{g['path']} {g['free_pct']}% ({g['free_gb']} GB)" if g else "n/a",
                   f"{v['snapshot_oldest_days']}d x{v['snapshot_count']} / {v['snapshot_data_gb']} GB" if v["snapshot_count"] else "-",
                   ", ".join(v["datastores"]), nf))
    L += ["", f"## At-risk VMs ({len(vt)})", ""] + table(
        vt, ["Risk", "vCenter", "VM", "Power", "Worst guest volume (free)", "Snapshots (oldest/data)", "Datastores", "Findings"])
    for s in ("CRIT", "WARN", "INFO"):
        items = sorted((x for x in findings if x["severity"] == s), key=lambda x: (x["vcenter"], x["kind"], x["object"], x["metric"]))
        L += ["", f"## {s} ({len(items)})", ""] + table(
            [(x["vcenter"], x["kind"], x["object"], x["metric"], x["detail"], x["suggestion"]) for x in items],
            ["vCenter", "Kind", "Object", "Metric", "Detail", "Suggestion"])
    (out / "report.md").write_text("\n".join(L) + "\n")
    with open(out / "vm_storage.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["vcenter", "vm", "power", "tools", "guest_path", "guest_capacity_gb", "guest_free_gb", "guest_free_pct",
                    "datastores", "disk_total_gb", "thin_disks", "snapshot_count", "snapshot_oldest_days", "snapshot_data_gb",
                    "swap_gb", "consolidation_needed"])
        for r in results:
            for v in r.get("vms", []):
                base = [r["vcenter"], v["name"], v["power"], v["tools"]]
                tail = [";".join(v["datastores"]), v["disk_total_gb"], sum(1 for d in v["disks"] if d["thin"]),
                        v["snapshot_count"], v["snapshot_oldest_days"], v["snapshot_data_gb"], v["swap_gb"],
                        v["consolidation_needed"]]
                for g in v["guest_disks"] or [None]:
                    w.writerow(base + ([g["path"], g["capacity_gb"], g["free_gb"], g["free_pct"]] if g else ["", "", "", ""]) + tail)


def main():
    ap = argparse.ArgumentParser(description="Read-only vSphere storage-risk report")
    ap.add_argument("--vcenter", action="append", help="vcenter name (repeatable); default all active")
    ap.add_argument("--out", help="output dir (default reports/vsphere_storage/<timestamp>)")
    for name, dflt in (("ds-free-crit", 10), ("ds-free-warn", 20), ("overcommit-warn", 100), ("overcommit-crit", 150),
                       ("guest-free-crit", 10), ("guest-free-warn", 15), ("snapshot-days", 3), ("snapshot-crit-days", 30),
                       ("snapshot-max-gb", 100), ("snapshot-disk-pct", 50)):
        ap.add_argument(f"--{name}", type=float, default=dflt)
    a = ap.parse_args()
    started = datetime.now()
    out = Path(a.out) if a.out else ROOT / "reports" / "vsphere_storage" / started.strftime("%Y%m%d-%H%M%S")
    vcs = vmlib.select_vcenters(a.vcenter)
    if not vcs:
        sys.exit("no active vcenters (see: vsphere.py add-vcenter)")
    (out / "raw").mkdir(parents=True, exist_ok=True)
    results, findings = [], []
    for vc in vcs:
        r = {"vcenter": vc["name"], "error": None}
        try:
            with vmlib.connect(vc) as si:
                r["datastores"], r["vms"] = gather(si)
        except SystemExit as e:
            r["error"] = str(e)
        except Exception as e:  # noqa: BLE001
            r["error"] = f"{type(e).__name__}: {str(e).splitlines()[0][:120] if str(e) else ''}"
        results.append(r)
        if r["error"]:
            print(f"UNREACHABLE {vc['name']}: {r['error']}", file=sys.stderr)
            continue
        dsmap = {d["name"]: d for d in r["datastores"]}
        for d in r["datastores"]:
            findings += ds_findings(vc["name"], d, a)
        dsworst = {}
        for x in findings:
            if x["vcenter"] == vc["name"] and x["kind"] == "datastore" and x["severity"] in ("CRIT", "WARN"):
                if RANK[x["severity"]] > RANK.get(dsworst.get(x["object"]), -1):
                    dsworst[x["object"]] = x["severity"]
        for v in r["vms"]:
            findings += vm_findings(vc["name"], v, dsmap, dsworst, a)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", vc["name"])
        for k in ("datastores", "vms"):
            rows = [{kk: vv for kk, vv in x.items() if not kk.startswith("_")} for x in r[k]]
            (out / "raw" / f"{safe}_{k}.json").write_text(json.dumps(rows, indent=2, default=str))
    clean = [{**r, "vms": [{k: v for k, v in x.items() if not k.startswith("_")} for x in r.get("vms", [])]} for r in results]
    summary = {"generated": started.isoformat(timespec="seconds"), "read_only": True,
               "thresholds": {k: v for k, v in vars(a).items() if k not in ("vcenter", "out")},
               "counts": dict(Counter(x["severity"] for x in findings)), "vcenters": clean, "findings": findings}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    write_outputs(out, started, a, results, findings)
    sev = Counter(x["severity"] for x in findings)
    print(f"Findings: CRIT={sev['CRIT']} WARN={sev['WARN']} INFO={sev['INFO']}")
    top = sorted(findings, key=lambda x: (-RANK[x["severity"]], x["kind"] != "datastore"))[:10]
    for x in top:
        print(f"  {x['severity']:4} {x['vcenter']} {x['object']} [{x['metric']}] {x['detail'][:110]}")
    print(f"Report: {out / 'report.md'}")


if __name__ == "__main__":
    main()
