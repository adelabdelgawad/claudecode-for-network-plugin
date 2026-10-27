"""READ-ONLY VMware vSphere inventory + views (pyvmomi). Never changes anything in vCenter/ESXi.

Usage:
    cfn vsphere add-vcenter NAME HOST [--port 443] [--no-verify-ssl] [--cred VCENTER] [--site NAME]
    cfn vsphere discover [VCENTER ...] [--workers 4]
    cfn vsphere show {snapshots|datastores|alarms|host-nics|vm} [--vcenter NAME ...] [--json] [--out]
        snapshots [--older-days N] | host-nics [--host GLOB] | vm NAME

`discover` upserts vcenters/esxi_hosts/port_groups/machines/machine_nics in the inventory. User-owned columns
(role, environment, owner, site_id, notes, status, credential_ref once set) are never overwritten; VMs that
vanished from vCenter are marked 'decommissioned', not deleted. Credentials: NET_<credential_ref>_USERNAME/_PASSWORD.
"""
import argparse
import fnmatch
import json
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timezone

from pyVmomi import vim

import vmlib
from vmlib import ROOT, aslist, call_ro, collect, mid, server_time

GB = 1024 ** 3
NOTE_GONE = "vsphere: not found in vCenter, marked decommissioned"


def gb(n, nd=1):
    return round(n / GB, nd) if n is not None else None


def short(t):
    return type(t).__name__.split(".")[-1]


# --------------------------------------------------------------------------- gathering (read-only)
class Tree:
    """moref -> (name, parent) for folders/datacenters/compute resources/pools, resolved in memory."""

    def __init__(self, si):
        self.nodes, self.dcs, self.clusters = {}, set(), set()
        for t in (vim.Folder, vim.Datacenter, vim.ComputeResource, vim.ResourcePool):
            for o in collect(si, t, ["name", "parent"]):
                self.nodes[o["_id"]] = (o.get("name"), mid(o.get("parent")))
                if t is vim.Datacenter:
                    self.dcs.add(o["_id"])
        self.clusters = {o["_id"] for o in collect(si, vim.ClusterComputeResource, ["name"])}

    def name(self, ref):
        return self.nodes.get(mid(ref), (None,))[0]

    def chain(self, ref):
        out, cur = [], mid(ref)
        while cur in self.nodes and len(out) < 50:
            out.append(cur)
            cur = self.nodes[cur][1]
        return out

    def datacenter(self, ref):
        return next((self.nodes[i][0] for i in self.chain(ref) if i in self.dcs), None)

    def cluster(self, ref):
        return next((self.nodes[i][0] for i in self.chain(ref) if i in self.clusters), None)

    def folder_path(self, ref):
        names = []
        for i in self.chain(ref):
            if i in self.dcs:
                break
            names.append(self.nodes[i][0])
        return "/" + "/".join(reversed(names[:-1] if names else names))  # drop the datacenter's top 'vm' folder


def vlan_text(v):
    n = short(v) if v is not None else ""
    if n == "VlanIdSpec":
        return str(v.vlanId)
    if n == "TrunkVlanSpec":
        return "trunk:" + ",".join(f"{r.start}-{r.end}" if r.start != r.end else str(r.start) for r in aslist(v.vlanId))
    if n == "PvlanSpec":
        return f"pvlan:{v.pvlanId}"
    return None


def host_record(o, tree):
    hw = o.get("summary.hardware")
    sysinfo = o.get("hardware.systemInfo")
    serial = getattr(sysinfo, "serialNumber", None)
    if not serial and sysinfo is not None:
        serial = next((i.identifierValue for i in aslist(sysinfo.otherIdentifyingInfo)
                       if getattr(i.identifierType, "key", "") == "ServiceTag"), None)
    vnics = aslist(o.get("config.network.vnic"))
    ips = {v.device: v.spec.ip.ipAddress for v in vnics if getattr(getattr(v.spec, "ip", None), "ipAddress", None)}
    vendor = re.sub(r"[^a-z0-9 ]", "", (getattr(hw, "vendor", "") or "").lower()).split()
    prod = o.get("summary.config.product")
    return {"hostname": o["name"], "moref": o["_id"], "mgmt_ip": ips.get("vmk0") or next(iter(ips.values()), None),
            "datacenter": tree.datacenter(o.get("parent")), "cluster": tree.cluster(o.get("parent")),
            "vendor": vendor[0] if vendor else None, "model": getattr(hw, "model", None), "serial": serial,
            "esxi_version": getattr(prod, "version", None), "esxi_build": getattr(prod, "build", None),
            "cpu_model": getattr(hw, "cpuModel", None), "cpu_sockets": getattr(hw, "numCpuPkgs", None),
            "cpu_cores": getattr(hw, "numCpuCores", None), "memory_gb": gb(getattr(hw, "memorySize", None)),
            "connection_state": str(o.get("runtime.connectionState")),
            "maintenance_mode": int(bool(o.get("runtime.inMaintenanceMode")))}


HOST_PROPS = ["name", "parent", "runtime.connectionState", "runtime.inMaintenanceMode", "summary.hardware",
              "summary.config.product", "hardware.systemInfo", "config.network.vnic", "config.network.portgroup"]
VM_PROPS = ["name", "parent", "resourcePool", "runtime.host", "runtime.powerState", "config.instanceUuid",
            "config.uuid", "config.template", "config.guestId", "config.guestFullName", "config.version",
            "config.hardware.numCPU", "config.hardware.memoryMB", "config.hardware.device", "guest.guestFullName",
            "guest.guestFamily", "guest.hostName", "guest.ipAddress", "guest.net", "guest.toolsStatus",
            "guest.toolsRunningStatus", "guest.toolsVersionStatus2", "guest.toolsVersion"]


def tools_status(o):
    s, run, v2 = o.get("guest.toolsStatus"), o.get("guest.toolsRunningStatus"), o.get("guest.toolsVersionStatus2")
    s, run, v2 = (str(x) if x else None for x in (s, run, v2))
    if not s:
        s = {"guestToolsRunning": "toolsOk", "guestToolsExecutingScripts": "toolsOk",
             "guestToolsNotRunning": "toolsNotRunning"}.get(run)
    if s == "toolsOk" and v2 in ("guestToolsNeedUpgrade", "guestToolsSupportedOld", "guestToolsTooOld"):
        s = "toolsOld"
    return s


def vm_record(o, tree, hosts_by_moref, dvpg_names):
    devs = aslist(o.get("config.hardware.device"))
    gnics = {(n.macAddress or "").lower(): [a for a in aslist(n.ipAddress) if not a.lower().startswith("fe80")]
             for n in aslist(o.get("guest.net"))}
    nics, disks = [], []
    for d in devs:
        if isinstance(d, vim.vm.device.VirtualEthernetCard):
            b = d.backing
            if hasattr(b, "port") and getattr(b.port, "portgroupKey", None):
                net, pgt = dvpg_names.get(b.port.portgroupKey, b.port.portgroupKey), "distributed"
            else:
                net, pgt = getattr(b, "deviceName", None), "standard"
            mac = (d.macAddress or "").lower() or None
            nics.append({"label": d.deviceInfo.label if d.deviceInfo else None, "mac": mac,
                         "adapter_type": short(d).replace("Virtual", "", 1).lower(), "network": net,
                         "pg_type": pgt, "connected": int(bool(d.connectable and d.connectable.connected)),
                         "ip_addresses": ",".join(gnics.get(mac or "", [])) or None})
        elif isinstance(d, vim.vm.device.VirtualDisk):
            kb = d.capacityInKB or (d.capacityInBytes or 0) // 1024
            disks.append({"label": d.deviceInfo.label if d.deviceInfo else None, "size_gb": round(kb / 1024 ** 2, 1),
                          "file": getattr(d.backing, "fileName", None),
                          "thin": getattr(d.backing, "thinProvisioned", None)})
    gid = o.get("config.guestId")
    fam = str(o.get("guest.guestFamily") or "")
    osf = {"windowsGuest": "windows", "linuxGuest": "linux"}.get(fam) or (
        "windows" if "windows" in (gid or "").lower() else "linux" if fam == "" and "linux" in (gid or "").lower() else "other")
    mem = o.get("config.hardware.memoryMB")
    hid = mid(o.get("runtime.host"))
    return {"name": o["name"], "instance_uuid": o.get("config.instanceUuid"), "bios_uuid": o.get("config.uuid"),
            "moref": o["_id"], "host_moref": hid, "host": hosts_by_moref.get(hid, (None, None))[0],
            "datacenter": tree.datacenter(o.get("parent")), "cluster": hosts_by_moref.get(hid, (None, None))[1],
            "folder": tree.folder_path(o.get("parent")), "resource_pool": tree.name(o.get("resourcePool")),
            "is_template": int(bool(o.get("config.template"))), "guest_os_id": gid,
            "guest_os": o.get("config.guestFullName") or o.get("guest.guestFullName"), "os_family": osf,
            "guest_hostname": o.get("guest.hostName"), "primary_ip": o.get("guest.ipAddress"),
            "vcpu": o.get("config.hardware.numCPU"), "memory_gb": round(mem / 1024, 2) if mem else None,
            "disk_gb": round(sum(d["size_gb"] for d in disks), 1), "power_state": str(o.get("runtime.powerState")),
            "tools_status": tools_status(o), "tools_version": o.get("guest.toolsVersion"),
            "hw_version": o.get("config.version"), "nics": nics, "disks": disks}


def gather(si):
    """One read-only sweep of a vCenter -> plain dicts (about, hosts, port_groups, vms)."""
    about = si.content.about
    tree = Tree(si)
    hrows = collect(si, vim.HostSystem, HOST_PROPS)
    hosts = [host_record(o, tree) for o in hrows]
    pgs = {}
    for o in hrows:
        for p in aslist(o.get("config.network.portgroup")):
            s = p.spec
            pgs.setdefault(("standard", s.vswitchName, s.name), {
                "name": s.name, "switch_name": s.vswitchName, "switch_type": "standard", "vlan_id": str(s.vlanId)})
    dvs = {o["_id"]: o.get("name") for o in collect(si, vim.DistributedVirtualSwitch, ["name"])}
    dvpg_names = {}
    for o in collect(si, vim.dvs.DistributedVirtualPortgroup, ["name", "key", "config"]):
        c = o.get("config")
        dvpg_names[o.get("key")] = o["name"]
        if getattr(c, "uplink", False):
            continue
        sw = dvs.get(mid(getattr(c, "distributedVirtualSwitch", None)))
        vlan = vlan_text(getattr(getattr(c, "defaultPortConfig", None), "vlan", None))
        pgs[("distributed", sw, o["name"])] = {"name": o["name"], "switch_name": sw, "switch_type": "distributed",
                                               "vlan_id": vlan}
    hosts_by_moref = {h["moref"]: (h["hostname"], h["cluster"]) for h in hosts}
    vms = [vm_record(o, tree, hosts_by_moref, dvpg_names) for o in collect(si, vim.VirtualMachine, VM_PROPS)]
    return {"about": {"version": about.version, "build": about.build, "full_name": about.fullName},
            "hosts": hosts, "port_groups": list(pgs.values()), "vms": [v for v in vms if v["instance_uuid"]]}


# --------------------------------------------------------------------------- inventory writes
def upsert(db, table, where, vals, ins=None):
    """Insert or update; returns (id, 'new'|'updated'|'unchanged'). None values never overwrite stored data."""
    vals = {k: v for k, v in vals.items() if v is not None}
    cond = " AND ".join(f"{k} IS ?" for k in where)
    row = db.execute(f"SELECT * FROM {table} WHERE {cond}", tuple(where.values())).fetchone()
    if row:
        diff = {k: v for k, v in vals.items() if row[k] != v}
        if diff:
            db.execute(f"UPDATE {table} SET {', '.join(f'{k}=?' for k in diff)} WHERE id=?", (*diff.values(), row["id"]))
        return row["id"], "updated" if diff else "unchanged"
    allv = {**where, **(ins or {}), **vals}
    cur = db.execute(f"INSERT INTO {table} ({', '.join(allv)}) VALUES ({', '.join('?' * len(allv))})", tuple(allv.values()))
    return cur.lastrowid, "new"


def apply_vcenter(db, vc, data):
    """Write one vCenter's gathered data; returns {table: Counter(state)}."""
    st = {t: Counter() for t in ("vcenters", "esxi_hosts", "port_groups", "machines", "machine_nics")}
    vid = vc["id"]
    a = data["about"]
    st["vcenters"][upsert(db, "vcenters", {"id": vid}, {"version": a["version"], "build": a["build"]})[1]] += 1

    host_ids = {}
    for h in data["hosts"]:
        ip = h["mgmt_ip"]
        if ip and db.execute("SELECT 1 FROM esxi_hosts WHERE mgmt_ip=? AND hostname!=?", (ip, h["hostname"])).fetchone():
            h = {**h, "mgmt_ip": None}
        hid, s = upsert(db, "esxi_hosts", {"hostname": h["hostname"]}, {**h, "vcenter_id": vid},
                        {"site_id": vc.get("site_id")} if vc.get("site_id") else None)
        host_ids[h["moref"]] = hid
        st["esxi_hosts"][s] += 1

    pg_ids = {}
    for p in data["port_groups"]:
        pid, s = upsert(db, "port_groups", {"vcenter_id": vid, "switch_name": p["switch_name"], "name": p["name"]},
                        {"switch_type": p["switch_type"], "vlan_id": p["vlan_id"]})
        pg_ids.setdefault((p["switch_type"], p["name"]), pid)
        st["port_groups"][s] += 1

    seen = set()
    for v in data["vms"]:
        seen.add(v["instance_uuid"])
        cols = {k: v[k] for k in ("name", "bios_uuid", "moref", "datacenter", "cluster", "folder", "resource_pool",
                                  "is_template", "guest_os_id", "guest_os", "os_family", "guest_hostname",
                                  "primary_ip", "vcpu", "memory_gb", "disk_gb", "power_state", "tools_status",
                                  "tools_version", "hw_version")}
        cols.update(vcenter_id=vid, esxi_host_id=host_ids.get(v["host_moref"]))
        old = db.execute("SELECT id, mgmt_protocol, credential_ref, status, notes FROM machines WHERE instance_uuid=?",
                         (v["instance_uuid"],)).fetchone()
        if old and old["status"] == "decommissioned" and NOTE_GONE in (old["notes"] or ""):
            cols["status"] = "active"
            cols["notes"] = f"{old['notes']}\n{date.today()} vsphere: reappeared in vCenter, reactivated"
        if not old or not old["mgmt_protocol"]:
            proto = {"windows": ("winrm", 5985, "WINDOWS"), "linux": ("ssh", 22, "LINUX")}.get(v["os_family"])
            if proto:
                cols.update(zip(("mgmt_protocol", "port"), proto[:2]))
                if not (old and old["credential_ref"]):
                    cols["credential_ref"] = proto[2]
        mid_, s = upsert(db, "machines", {"instance_uuid": v["instance_uuid"]}, cols,
                         {"site_id": vc["site_id"]} if vc.get("site_id") else None)
        st["machines"][s] += 1
        macs = set()
        for n in v["nics"]:
            if not n["mac"]:
                continue
            macs.add(n["mac"])
            _, s = upsert(db, "machine_nics", {"machine_id": mid_, "mac": n["mac"]},
                          {"label": n["label"], "adapter_type": n["adapter_type"], "network": n["network"],
                           "port_group_id": pg_ids.get((n["pg_type"], n["network"])), "connected": n["connected"],
                           "ip_addresses": n["ip_addresses"]})
            st["machine_nics"][s] += 1
        stale = [r[0] for r in db.execute("SELECT id FROM machine_nics WHERE machine_id=? AND mac NOT IN (%s)"
                                          % ",".join("?" * len(macs)), (mid_, *macs))] if macs else []
        for i in stale:
            db.execute("DELETE FROM machine_nics WHERE id=?", (i,))
            st["machine_nics"]["removed"] += 1

    gone = [r for r in db.execute("SELECT id, instance_uuid FROM machines WHERE vcenter_id=? AND status!='decommissioned'", (vid,))
            if r["instance_uuid"] not in seen]
    if gone and not seen:
        print(f"  warning: {vc['name']}: vCenter returned 0 VMs but {len(gone)} are in the DB; skipping decommission "
              "(check the account's read permissions)")
        gone = []
    for r in gone:
        db.execute("UPDATE machines SET status='decommissioned', notes=COALESCE(notes || char(10), '') || ? WHERE id=?",
                   (f"{date.today()} {NOTE_GONE}", r["id"]))
        st["machines"]["decommissioned"] += 1
    return st


def gather_vcenter(vc):
    try:
        with vmlib.connect(vc) as si:
            return vc, gather(si), None
    except SystemExit as e:
        return vc, None, ("creds", str(e))
    except vim.fault.InvalidLogin:
        return vc, None, ("auth", "login failed (InvalidLogin)")
    except Exception as e:  # noqa: BLE001 - one bad vCenter must not stop the others
        return vc, None, ("error", f"{type(e).__name__}: {str(e).splitlines()[0][:120] if str(e) else ''}")


def cmd_discover(args):
    vcs = vmlib.select_vcenters(args.names)
    if not vcs:
        sys.exit("no active vcenters (see: vsphere.py add-vcenter)")
    print(f"Discovering {len(vcs)} vCenter(s) read-only")
    with ThreadPoolExecutor(max(1, min(args.workers, len(vcs)))) as ex:
        results = list(ex.map(gather_vcenter, vcs))
    db = vmlib.open_db()
    with db:
        for vc, data, err in results:
            if err:
                print(f"  {vc['name']}: {err[0].upper()} {err[1]}")
                if err[0] == "auth":
                    db.execute("UPDATE vcenters SET status='auth_failed' WHERE id=?", (vc["id"],))
                continue
            st = apply_vcenter(db, vc, data)
            print(f"  {vc['name']} ({data['about']['version']} build {data['about']['build']})")
            for t, c in st.items():
                if t != "vcenters":
                    print(f"    {t:13} " + ", ".join(f"{k}={v}" for k, v in sorted(c.items())))
    db.close()


def cmd_add_vcenter(args):
    db = vmlib.open_db()
    site = None
    if args.site:
        r = db.execute("SELECT id FROM sites WHERE name=?", (args.site,)).fetchone()
        if not r:
            sys.exit(f"unknown site {args.site!r}")
        site = r["id"]
    with db:
        vals = {"host": args.host, "port": args.port, "verify_ssl": args.verify_ssl, "credential_ref": args.cred,
                "site_id": site}
        _, s = upsert(db, "vcenters", {"name": args.name}, vals, {"port": 443})
    print(f"vcenter {args.name}: {s}")
    db.close()


# --------------------------------------------------------------------------- show views (live, read-only)
def snapshot_rows(si, older_days=None, names=None):
    now = server_time(si)
    vms = collect(si, vim.VirtualMachine, ["name", "snapshot.rootSnapshotList"])
    vms = [v for v in vms if v.get("snapshot.rootSnapshotList") and (not names or v["name"] in names)]
    sizes = {}
    if vms:
        pat = re.compile(r"-\d{6}-(delta|sesparse)\.vmdk$")
        for o in collect(si, vim.VirtualMachine, ["layoutEx.file"], objs=[v["_obj"] for v in vms]):
            sizes[o["_id"]] = sum(f.size or 0 for f in aslist(o.get("layoutEx.file")) if str(f.type) in (
                "snapshotData", "snapshotMemory", "snapshotList") or (str(f.type) == "diskExtent" and pat.search(f.name or "")))
    rows = []

    def walk(vm, nodes):
        for n in nodes:
            ct = n.createTime if n.createTime.tzinfo else n.createTime.replace(tzinfo=timezone.utc)
            age = (now - ct).days
            if older_days is None or age >= older_days:
                rows.append({"vm": vm["name"], "snapshot": n.name, "created": ct.strftime("%Y-%m-%d %H:%M"),
                             "age_days": age, "vm_snap_size_gb": gb(sizes[vm["_id"]], 2) if vm["_id"] in sizes else None})
            walk(vm, aslist(n.childSnapshotList))
    for v in vms:
        walk(v, aslist(v["snapshot.rootSnapshotList"]))
    return sorted(rows, key=lambda r: -r["age_days"])


def datastore_rows(si):
    rows = []
    for o in collect(si, vim.Datastore, ["name", "summary", "vm"]):
        s = o["summary"]
        cap, free = s.capacity or 0, s.freeSpace or 0
        rows.append({"name": o["name"], "type": s.type, "capacity_gb": gb(cap), "free_gb": gb(free),
                     "free_pct": round(100 * free / cap, 1) if cap else None, "accessible": bool(s.accessible),
                     "vms": len(aslist(o.get("vm")))})
    return sorted(rows, key=lambda r: (r["free_pct"] is None, r["free_pct"]))


def alarm_rows(si):
    root = si.content.rootFolder
    states = []
    for o in collect(si, vim.Folder, ["triggeredAlarmState"], objs=[root]):
        states += aslist(o.get("triggeredAlarmState"))
    if not states:
        return []
    anames = {o["_id"]: o.get("info.name") for o in collect(si, vim.alarm.Alarm, ["info.name"], objs=list({s.alarm for s in states}))}
    ents = {}
    for s in states:
        ents.setdefault(type(s.entity), {})[mid(s.entity)] = s.entity
    enames = {}
    for t, refs in ents.items():
        enames.update({o["_id"]: o.get("name") for o in collect(si, t, ["name"], objs=list(refs.values()))})
    return [{"entity": enames.get(mid(s.entity)) or mid(s.entity), "entity_type": short(s.entity),
             "alarm": anames.get(mid(s.alarm)) or mid(s.alarm), "status": str(s.overallStatus),
             "time": s.time.strftime("%Y-%m-%d %H:%M") if s.time else None, "acknowledged": bool(s.acknowledged)}
            for s in states]


def host_nic_rows(si, host_glob=None, workers=8):
    hosts = collect(si, vim.HostSystem, ["name", "runtime.connectionState", "config.network.pnic",
                                         "config.network.vswitch", "config.network.proxySwitch",
                                         "configManager.networkSystem"])
    hosts = [h for h in hosts if not host_glob or fnmatch.fnmatch(h["name"].lower(), host_glob.lower())]

    def one(h):
        pnics = aslist(h.get("config.network.pnic"))
        sw = {}
        for s in aslist(h.get("config.network.vswitch")):
            for k in aslist(s.pnic):
                sw[k.split("-")[-1]] = s.name
        for s in aslist(h.get("config.network.proxySwitch")):
            for k in aslist(s.pnic):
                sw[k.split("-")[-1]] = s.dvsName
        hints = {}
        if str(h.get("runtime.connectionState")) == "connected" and h.get("configManager.networkSystem") and pnics:
            try:
                for x in aslist(call_ro(h["configManager.networkSystem"], "QueryNetworkHint", device=[p.device for p in pnics])):
                    hints[x.device] = x
            except Exception as e:  # noqa: BLE001
                print(f"  warning: {h['name']}: QueryNetworkHint failed ({type(e).__name__})", file=sys.stderr)
        out = []
        for p in pnics:
            x = hints.get(p.device)
            cdp, lldp = getattr(x, "connectedSwitchPort", None), getattr(x, "lldpInfo", None)
            lp = {kv.key: kv.value for kv in aslist(getattr(lldp, "parameter", None))}
            out.append({"host": h["name"], "vmnic": p.device, "mac": p.mac,
                        "speed_mb": getattr(p.linkSpeed, "speedMb", None), "driver": p.driver,
                        "vswitch": sw.get(p.device),
                        "cdp_device": getattr(cdp, "devId", None), "cdp_port": getattr(cdp, "portId", None),
                        "cdp_mgmt": getattr(cdp, "mgmtAddr", None) or getattr(cdp, "address", None),
                        "cdp_vlan": getattr(cdp, "vlan", None),
                        "lldp_chassis": getattr(lldp, "chassisId", None), "lldp_port": getattr(lldp, "portId", None),
                        "lldp_system": lp.get("System Name")})
        return out
    with ThreadPoolExecutor(max(1, workers)) as ex:
        rows = [r for part in ex.map(one, hosts) for r in part]
    return sorted(rows, key=lambda r: (r["host"], r["vmnic"]))


def vm_rows(si, name):
    data = gather(si)
    pat = name.lower()
    vms = [v for v in data["vms"] if v["name"].lower() == pat] or \
          [v for v in data["vms"] if fnmatch.fnmatch(v["name"].lower(), pat)]
    snaps = snapshot_rows(si, names={v["name"] for v in vms}) if vms else []
    return [{**v, "snapshots": [s for s in snaps if s["vm"] == v["name"]]} for v in vms]


VIEWS = {
    "snapshots": (lambda si, a: snapshot_rows(si, a.older_days),
                  ["vcenter", "vm", "snapshot", "created", "age_days", "vm_snap_size_gb"]),
    "datastores": (lambda si, a: datastore_rows(si),
                   ["vcenter", "name", "type", "capacity_gb", "free_gb", "free_pct", "accessible", "vms"]),
    "alarms": (lambda si, a: alarm_rows(si),
               ["vcenter", "entity", "entity_type", "alarm", "status", "time", "acknowledged"]),
    "host-nics": (lambda si, a: host_nic_rows(si, a.host),
                  ["vcenter", "host", "vmnic", "mac", "speed_mb", "driver", "vswitch", "cdp_device", "cdp_port",
                   "cdp_mgmt", "cdp_vlan", "lldp_chassis", "lldp_port", "lldp_system"]),
    "vm": (lambda si, a: vm_rows(si, a.name), None),
}


def table(rows, cols):
    if not rows:
        return "(no rows)"
    cell = lambda v: "" if v is None else ("yes" if v is True else "no" if v is False else str(v))  # noqa: E731
    w = [max(len(c), *(len(cell(r.get(c))) for r in rows)) for c in cols]
    line = lambda vals: "  ".join(v.ljust(n) for v, n in zip(vals, w)).rstrip()  # noqa: E731
    return "\n".join([line(cols), line(["-" * n for n in w])] + [line([cell(r.get(c)) for c in cols]) for r in rows])


def render_vm(v):
    out = [f"{v['name']}  [{v['vcenter']}]  {v['power_state']}  host={v['host']}  cluster={v['cluster']}  folder={v['folder']}",
           f"  os={v['guest_os']} ({v['os_family']})  hostname={v['guest_hostname']}  ip={v['primary_ip']}",
           f"  vcpu={v['vcpu']}  mem_gb={v['memory_gb']}  disk_gb={v['disk_gb']}  hw={v['hw_version']}  "
           f"tools={v['tools_status']} {v['tools_version'] or ''}".rstrip(), "  NICs:"]
    out += ["    " + l for l in table(v["nics"], ["label", "mac", "adapter_type", "network", "pg_type", "connected", "ip_addresses"]).splitlines()]
    out += ["  Disks:"] + ["    " + l for l in table(v["disks"], ["label", "size_gb", "thin", "file"]).splitlines()]
    out += ["  Snapshots:"] + ["    " + l for l in table(v["snapshots"], ["snapshot", "created", "age_days", "vm_snap_size_gb"]).splitlines()]
    return "\n".join(out)


def cmd_show(args):
    vcs = vmlib.select_vcenters(args.vcenter)
    if not vcs:
        sys.exit("no active vcenters (see: vsphere.py add-vcenter)")
    fn, cols = VIEWS[args.view]

    def run(vc):
        try:
            with vmlib.connect(vc) as si:
                return vc, [{"vcenter": vc["name"], **r} for r in fn(si, args)], None
        except SystemExit as e:
            return vc, [], str(e)
        except Exception as e:  # noqa: BLE001
            return vc, [], f"{type(e).__name__}: {str(e).splitlines()[0][:120] if str(e) else ''}"
    with ThreadPoolExecutor(max(1, min(4, len(vcs)))) as ex:
        results = list(ex.map(run, vcs))
    rows = [r for _, part, _ in results for r in part]
    for vc, _, err in results:
        if err:
            print(f"error: {vc['name']}: {err}", file=sys.stderr)
    text = "\n\n".join(render_vm(r) for r in rows) if cols is None else table(rows, cols)
    if args.view == "vm" and not rows and not any(e for _, _, e in results):
        text = f"no VM matching {args.name!r}"
    payload = json.dumps(rows, indent=2, default=str)
    print(payload if args.json else text)
    if args.out:
        d = ROOT / "outputs" / vmlib.timestamp()
        d.mkdir(parents=True, exist_ok=True)
        (d / f"vsphere-{args.view}.json").write_text(payload)
        (d / f"vsphere-{args.view}.txt").write_text(text + "\n")
        print(f"saved to {d}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Read-only VMware vSphere inventory and views")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("add-vcenter", help="record a vCenter in the inventory (no network access)")
    p.add_argument("name")
    p.add_argument("host", help="vCenter FQDN or IP")
    p.add_argument("--port", type=int)
    p.add_argument("--no-verify-ssl", dest="verify_ssl", action="store_const", const=0, help="self-signed certificate")
    p.add_argument("--verify-ssl", dest="verify_ssl", action="store_const", const=1)
    p.add_argument("--cred", help="credential_ref (default VCENTER -> NET_VCENTER_USERNAME/_PASSWORD)")
    p.add_argument("--site", help="site name from the sites table")
    p.set_defaults(fn=cmd_add_vcenter)

    p = sub.add_parser("discover", help="upsert hosts, port groups, VMs and NICs into the inventory")
    p.add_argument("names", nargs="*", metavar="VCENTER", help="default: all active vcenters")
    p.add_argument("--workers", type=int, default=4)
    p.set_defaults(fn=cmd_discover)

    p = sub.add_parser("show", help="live read-only views")
    vs = p.add_subparsers(dest="view", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--vcenter", action="append", help="vcenter name (repeatable; default all active)")
    common.add_argument("--json", action="store_true", help="print JSON instead of a table")
    common.add_argument("--out", action="store_true", help="also save to outputs/<timestamp>/vsphere-<view>.json/.txt")
    for v, h in (("snapshots", "VM snapshots with age"), ("datastores", "datastore capacity"),
                 ("alarms", "triggered alarms"), ("host-nics", "ESXi pNICs with CDP/LLDP neighbours"),
                 ("vm", "live details of one VM")):
        q = vs.add_parser(v, parents=[common], help=h)
        if v == "snapshots":
            q.add_argument("--older-days", type=int, metavar="N")
        if v == "host-nics":
            q.add_argument("--host", metavar="GLOB")
        if v == "vm":
            q.add_argument("name", help="exact VM name, or a glob")
    p.set_defaults(fn=cmd_show)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
