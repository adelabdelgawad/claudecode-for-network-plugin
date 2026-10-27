"""READ-ONLY VMware vSphere audit across active vCenters (pyvmomi + inventory).

Usage:
    cfn vsphere-audit [--vcenter NAME ...] [--snapshot-days 3] [--min-hw vmx-15]
        [--datastore-free-pct 15] [--switch-vlans DIR_OR_FILE] [--workers 4] [--out DIR]

Only property reads are performed. Suggestions in the report are text only, never executed.
--switch-vlans: a directory (or file) of saved `show vlan brief` output (e.g. from `scripts/show.py --out`);
port groups whose VLAN ID exists on none of those switches are flagged.

Outputs under --out (default reports/vsphere_audit/<YYYYmmdd-HHMMSS>):
    raw/<vcenter>.json   gathered live data (no credentials)
    summary.json         machine-readable findings
    report.md            findings by severity and check, unreachable vCenters
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import vmlib
import vsphere
from vmlib import ROOT

SEV_RANK = {"INFO": 0, "WARN": 1, "CRIT": 2}
VLAN_RE = re.compile(r"^(\d{1,4})\s+\S+\s+(?:active|act/\S+|sus\S*)\b", re.M | re.I)


def finding(vc, check, sev, target, detail, suggestion):
    return {"vcenter": vc, "check": check, "severity": sev, "target": target, "detail": detail, "suggestion": suggestion}


def parse_switch_vlans(path):
    """Return ({vlan ids}, switch_file_count) from saved `show vlan brief` output; tolerant of junk."""
    p = Path(path)
    files = [f for f in (sorted(p.rglob("*")) if p.is_dir() else [p]) if f.is_file()]
    ids, n = set(), 0
    for f in files:
        try:
            found = {int(x) for x in VLAN_RE.findall(f.read_text(errors="replace"))}
        except OSError:
            continue
        if found:
            ids |= found
            n += 1
    return ids, n


def vlan_ids(vlan):
    """Numeric VLAN IDs (>0) a port group VLAN string refers to; trunks/pvlans/0 yield nothing to check."""
    return [int(vlan)] if vlan and vlan.isdigit() and int(vlan) > 0 else []


def hw_num(v):
    m = re.search(r"(\d+)", v or "")
    return int(m.group(1)) if m else None


def collect_vcenter(vc, args):
    try:
        with vmlib.connect(vc) as si:
            return {"vcenter": vc["name"], "data": vsphere.gather(si), "snapshots": vsphere.snapshot_rows(si),
                    "datastores": vsphere.datastore_rows(si), "alarms": vsphere.alarm_rows(si), "error": None}
    except SystemExit as e:
        err = str(e)
    except Exception as e:  # noqa: BLE001
        err = f"{type(e).__name__}: {str(e).splitlines()[0][:120] if str(e) else ''}"
    return {"vcenter": vc["name"], "error": err}


def analyze(r, args, known, vlans):
    vc, d, f = r["vcenter"], r["data"], []
    pgs = {(p["switch_type"], p["name"]): p for p in d["port_groups"]}
    vms = [v for v in d["vms"] if not v["is_template"]]
    for v in vms:
        on = v["power_state"] == "poweredOn"
        if on and v["tools_status"] in ("toolsNotInstalled", "toolsNotRunning", "toolsOld", None):
            s = v["tools_status"] or "unknown"
            sev = "INFO" if s == "toolsOld" else "WARN"
            f.append(finding(vc, "vmware_tools", sev, v["name"], f"VMware Tools: {s}",
                             "Install/upgrade VMware Tools (open-vm-tools on Linux) and ensure the service is running"
                             if s != "toolsOld" else "Schedule a VMware Tools upgrade"))
        if v["power_state"] == "poweredOff":
            f.append(finding(vc, "powered_off", "INFO", v["name"], "VM is powered off",
                             "Confirm it is still needed; decommission or archive if not"))
        h = hw_num(v["hw_version"])
        if h is not None and h < hw_num(args.min_hw):
            f.append(finding(vc, "hw_version", "INFO", v["name"], f"hardware version {v['hw_version']} < {args.min_hw}",
                             "Plan a VM hardware upgrade in a maintenance window (after a snapshot/backup)"))
        if on:
            for n in v["nics"]:
                if not n["connected"]:
                    f.append(finding(vc, "nic_disconnected", "WARN", f"{v['name']} / {n['label']}",
                                     f"NIC disconnected (network {n['network']})",
                                     "Verify the adapter should be connected; reconnect it if the VM needs this network"))
                pg = pgs.get((n["pg_type"], n["network"]))
                if pg and pg["vlan_id"] and (pg["vlan_id"] == "0" or pg["vlan_id"].startswith("trunk")):
                    f.append(finding(vc, "nic_vlan_info", "INFO", f"{v['name']} / {n['label']}",
                                     f"port group {n['network']} VLAN {pg['vlan_id']}",
                                     "VLAN 0 = untagged, trunk = guest tags VLANs; confirm this is intended"))
        row = known.get(v["instance_uuid"])
        if not row:
            f.append(finding(vc, "inventory_drift", "INFO", v["name"], "VM not in the inventory DB",
                             "Run `vsphere.py discover` to record it"))
        elif v["primary_ip"] and row["primary_ip"] != v["primary_ip"]:
            f.append(finding(vc, "inventory_drift", "INFO", v["name"],
                             f"guest IP {v['primary_ip']} differs from DB ({row['primary_ip']})",
                             "Run `vsphere.py discover` to refresh the inventory"))
    for s in r["snapshots"]:
        if s["age_days"] > args.snapshot_days:
            f.append(finding(vc, "snapshot_old", "CRIT" if s["age_days"] > 14 else "WARN", s["vm"],
                             f"snapshot '{s['snapshot']}' is {s['age_days']} days old"
                             + (f", ~{s['vm_snap_size_gb']} GB" if s["vm_snap_size_gb"] else ""),
                             "Confirm with the VM owner, then consolidate/delete the snapshot (old snapshots slow I/O and grow)"))
    for ds in r["datastores"]:
        if ds["free_pct"] is not None and ds["free_pct"] < args.datastore_free_pct:
            f.append(finding(vc, "datastore_free", "CRIT" if ds["free_pct"] < args.datastore_free_pct / 3 else "WARN",
                             ds["name"], f"{ds['free_pct']}% free ({ds['free_gb']} of {ds['capacity_gb']} GB)",
                             "Free space or expand the datastore; check for old snapshots and orphaned VMDKs"))
        if not ds["accessible"]:
            f.append(finding(vc, "datastore_inaccessible", "CRIT", ds["name"], "datastore not accessible",
                             "Check storage connectivity/paths from the hosts"))
    by_cluster = defaultdict(list)
    for h in d["hosts"]:
        if h["connection_state"] != "connected":
            f.append(finding(vc, "host_state", "CRIT", h["hostname"], f"host {h['connection_state']}",
                             "Check management network, hostd/vpxa services and vCenter connectivity"))
        if h["maintenance_mode"]:
            f.append(finding(vc, "host_state", "WARN", h["hostname"], "host in maintenance mode",
                             "Exit maintenance mode if work is complete"))
        by_cluster[h["cluster"] or f"(standalone) {h['hostname']}"].append(h)
    for cl, hs in by_cluster.items():
        builds = Counter(h["esxi_build"] for h in hs)
        if len(hs) < 2 or len(builds) < 2:
            continue
        (b1, c1), (_, c2) = builds.most_common(2)
        if c1 == c2:
            f.append(finding(vc, "esxi_build", "INFO", cl, f"no majority ESXi build: {dict(builds)}",
                             "Standardise cluster hosts on one build (e.g. via lifecycle manager)"))
            continue
        for h in hs:
            if h["esxi_build"] != b1:
                f.append(finding(vc, "esxi_build", "WARN", h["hostname"],
                                 f"ESXi build {h['esxi_build']} differs from cluster {cl} majority {b1}",
                                 "Patch/upgrade this host to match the cluster (use lifecycle manager)"))
    for a in r["alarms"]:
        if not a["acknowledged"]:
            f.append(finding(vc, "alarm", "CRIT" if a["status"] == "red" else "WARN", a["entity"],
                             f"{a['alarm']} ({a['status']}) since {a['time']}",
                             "Investigate the alarm in vCenter; acknowledge or resolve it"))
    if vlans:
        for p in d["port_groups"]:
            if any(i not in vlans for i in vlan_ids(p["vlan_id"])):
                f.append(finding(vc, "vlan_missing_on_switches", "WARN", f"{p['name']} ({p['switch_name']})",
                                 f"VLAN {p['vlan_id']} not found on any scanned switch",
                                 "Verify the VLAN exists/is trunked on the upstream switches, or the port group is stale"))
    return f


def write_report(out, started, args, results, findings, extra):
    sev = Counter(x["severity"] for x in findings)
    L = [f"# vSphere read-only audit - {started:%Y-%m-%d %H:%M}", "",
         f"vCenters: {len(results)} ({sum(1 for r in results if r['error'])} unreachable). "
         f"Findings: CRIT={sev['CRIT']} WARN={sev['WARN']} INFO={sev['INFO']}. Suggestions are text only, never executed.", "",
         f"Thresholds: snapshots > {args.snapshot_days}d, hw >= {args.min_hw}, datastore free >= {args.datastore_free_pct}%", ""]
    L += extra
    for r in results:
        if r["error"]:
            L.append(f"- UNREACHABLE {r['vcenter']}: {r['error']}")
    for chk in sorted({x["check"] for x in findings}):
        items = sorted((x for x in findings if x["check"] == chk), key=lambda x: (-SEV_RANK[x["severity"]], x["vcenter"], x["target"]))
        L += ["", f"## {chk} ({len(items)})", "", f"Suggestion: {items[0]['suggestion']}", "",
              "| Sev | vCenter | Target | Detail |", "|---|---|---|---|"]
        L += [f"| {x['severity']} | {x['vcenter']} | {x['target']} | {x['detail']} |" for x in items]
    (out / "report.md").write_text("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Read-only vSphere audit")
    ap.add_argument("--vcenter", action="append", help="vcenter name (repeatable); default all active")
    ap.add_argument("--snapshot-days", type=int, default=3)
    ap.add_argument("--min-hw", default="vmx-15")
    ap.add_argument("--datastore-free-pct", type=float, default=15)
    ap.add_argument("--switch-vlans", metavar="PATH", help="dir/file of saved `show vlan brief` outputs")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", help="output dir (default reports/vsphere_audit/<timestamp>)")
    args = ap.parse_args()

    started = datetime.now()
    out = Path(args.out) if args.out else ROOT / "reports" / "vsphere_audit" / started.strftime("%Y%m%d-%H%M%S")
    vcs = vmlib.select_vcenters(args.vcenter)
    if not vcs:
        sys.exit("no active vcenters (see: vsphere.py add-vcenter)")
    (out / "raw").mkdir(parents=True, exist_ok=True)
    print(f"Auditing {len(vcs)} vCenter(s) read-only, out={out}")

    extra, vlans = [], set()
    if args.switch_vlans:
        vlans, n = parse_switch_vlans(args.switch_vlans)
        if vlans:
            extra += [f"VLAN cross-check: {len(vlans)} VLAN IDs parsed from {n} switch file(s).", ""]
        else:
            print("warning: no VLANs parsed from --switch-vlans; skipping the cross-check", file=sys.stderr)
            extra += ["VLAN cross-check skipped: no VLANs parsed from the given path.", ""]

    with ThreadPoolExecutor(max(1, min(args.workers, len(vcs)))) as ex:
        results = list(ex.map(lambda vc: collect_vcenter(vc, args), vcs))
    db = vmlib.open_db()
    known = {r["instance_uuid"]: dict(r) for r in db.execute("SELECT instance_uuid, primary_ip FROM machines")}
    db.close()
    findings = []
    for r in results:
        (out / "raw" / f"{re.sub(r'[^A-Za-z0-9._-]', '_', r['vcenter'])}.json").write_text(
            json.dumps({k: v for k, v in r.items()}, indent=2, default=str))
        if not r["error"]:
            findings += analyze(r, args, known, vlans)
    summary = {"generated": started.isoformat(timespec="seconds"), "read_only": True,
               "vcenters": [{"name": r["vcenter"], "error": r["error"]} for r in results],
               "counts": dict(Counter(x["severity"] for x in findings)), "findings": findings}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    write_report(out, started, args, results, findings, extra)

    sev = Counter(x["severity"] for x in findings)
    print(f"Findings: CRIT={sev['CRIT']} WARN={sev['WARN']} INFO={sev['INFO']}")
    for chk, c in sorted(Counter((x["check"]) for x in findings).items()):
        print(f"  {chk:26} {c}")
    for r in results:
        if r["error"]:
            print(f"  UNREACHABLE {r['vcenter']}: {r['error'][:80]}")
    print(f"Report: {out / 'report.md'}\nJSON:   {out / 'summary.json'}")


if __name__ == "__main__":
    main()
