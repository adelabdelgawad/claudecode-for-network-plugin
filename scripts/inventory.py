"""Read-only queries against the device inventory.

Usage: cfn inventory list [HOSTS...] [--match SW-*] [--role R] [--status active|any|...] [--json]
       cfn inventory get HOST_OR_IP
       cfn inventory counts
         (get also prints the firewall_details row for device_type='firewall')
       cfn inventory vms [NAMES...] [--match GLOB] [--os windows|linux|other] [--cluster C]
                [--host ESXI_HOSTNAME] [--power poweredOn|poweredOff|suspended] [--status active|any|...]
                [--templates] [--json]
       cfn inventory vm NAME_OR_IP
       cfn inventory esxi [--match GLOB] [--cluster C] [--status ...] [--json]
       cfn inventory vcenters [--json]
"""
import argparse
import fnmatch
import json
import sqlite3

import netlib

COLS = ["hostname", "mgmt_ip", "role", "model", "os_type", "os_version", "status", "credential_ref"]
VM_COLS = ["name", "primary_ip", "os_family", "guest_os", "vcpu", "memory_gb", "power_state", "cluster",
           "host", "role", "status"]
ESXI_COLS = ["hostname", "mgmt_ip", "cluster", "model", "esxi_version", "connection_state",
             "maintenance_mode", "vms", "status"]
VC_COLS = ["name", "host", "version", "build", "site", "status", "verify_ssl", "credential_ref"]


def cmd_list(args):
    if args.targets or args.match or args.role or args.all:
        rows = netlib.select_devices(args, allow_any_status=True)
        for t in args.targets:
            rows += [r for r in netlib._query("WHERE hostname=? OR mgmt_ip=?", (t, t))
                     if args.status in ("any", r["status"])]
    else:
        rows = netlib._query("" if args.status == "any" else "WHERE status=?",
                             () if args.status == "any" else (args.status,))
    seen = {r["id"]: r for r in rows}
    rows = sorted(seen.values(), key=lambda r: r["hostname"] or "")
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return
    table = [[str(r[c] if r[c] is not None else "-") for c in COLS] for r in rows]
    widths = [max(len(c), *(len(x[i]) for x in table)) if table else len(c) for i, c in enumerate(COLS)]
    print("  ".join(c.ljust(w) for c, w in zip(COLS, widths)))
    for x in table:
        print("  ".join(v.ljust(w) for v, w in zip(x, widths)))
    print(f"{len(rows)} devices")


def cmd_get(args):
    rows = netlib._query("WHERE hostname=? OR mgmt_ip=?", (args.target, args.target))
    if not rows:
        raise SystemExit(f"{args.target!r} not in the inventory")
    for r in rows:
        for k, v in r.items():
            print(f"{k:15} {v}")
        if r.get("device_type") == "firewall":
            _print_firewall_details(r["id"])
        print()


def _print_firewall_details(device_id):
    try:
        rows = _q("SELECT * FROM firewall_details WHERE device_id=?", (device_id,))
    except sqlite3.OperationalError:  # table not applied yet
        return
    print("firewall_details:" + ("" if rows else " (no row; defaults apply)"))
    for r in rows:
        for k, v in r.items():
            if k != "device_id":
                print(f"  {k:17} {v}")


def _q(sql, params=()):
    db = netlib.open_db()
    db.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in db.execute(sql, params)]
    finally:
        db.close()


def _print_rows(rows, cols, label, as_json):
    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return
    table = [[str(r[c] if r[c] is not None else "-") for c in cols] for r in rows]
    widths = [max(len(c), *(len(x[i]) for x in table)) if table else len(c) for i, c in enumerate(cols)]
    print("  ".join(c.ljust(w) for c, w in zip(cols, widths)))
    for x in table:
        print("  ".join(v.ljust(w) for v, w in zip(x, widths)))
    print(f"{len(rows)} {label}")



VM_SELECT = ("SELECT m.*, h.hostname AS host FROM machines m "
             "LEFT JOIN esxi_hosts h ON h.id = m.esxi_host_id")


def cmd_vms(args):
    where, params = [], []
    if not args.templates:
        where.append("m.is_template = 0")
    if args.status != "any":
        where.append("m.status = ?")
        params.append(args.status)
    if args.os:
        where.append("m.os_family = ?")
        params.append(args.os)
    if args.cluster:
        where.append("m.cluster = ?")
        params.append(args.cluster)
    if args.host:
        where.append("h.hostname = ?")
        params.append(args.host)
    if args.power:
        where.append("m.power_state = ?")
        params.append(args.power)
    rows = _q(f"{VM_SELECT} {'WHERE ' + ' AND '.join(where) if where else ''} ORDER BY m.name", params)
    if args.match:
        rows = [r for r in rows if any(fnmatch.fnmatch(r["name"] or "", g) for g in args.match)]
    if args.names:
        rows = [r for r in rows if any(n in (r["name"], r["guest_hostname"], r["primary_ip"]) for n in args.names)]
    _print_rows(rows, VM_COLS, "VMs", args.json)


def cmd_vm(args):
    rows = _q(f"{VM_SELECT} WHERE m.name=? OR m.guest_hostname=? OR m.primary_ip=? ORDER BY m.name",
              (args.target,) * 3)
    if not rows:
        raise SystemExit(f"{args.target!r} not in the inventory")
    for r in rows:
        for k, v in r.items():
            print(f"{k:15} {v}")
        nics = _q("SELECT n.label, n.mac, n.adapter_type, n.network, n.connected, n.ip_addresses, "
                  "p.name AS port_group, p.vlan_id, p.switch_name FROM machine_nics n "
                  "LEFT JOIN port_groups p ON p.id = n.port_group_id WHERE n.machine_id=? ORDER BY n.id",
                  (r["id"],))
        print(f"NICs ({len(nics)}):")
        for n in nics:
            print("  " + "  ".join(f"{k}={'-' if v is None else v}" for k, v in n.items()))
        print()


def cmd_esxi(args):
    where, params = [], []
    if args.status != "any":
        where.append("h.status = ?")
        params.append(args.status)
    if args.cluster:
        where.append("h.cluster = ?")
        params.append(args.cluster)
    rows = _q("SELECT h.*, (SELECT COUNT(*) FROM machines m WHERE m.esxi_host_id = h.id "
              "AND m.is_template = 0) AS vms FROM esxi_hosts h "
              f"{'WHERE ' + ' AND '.join(where) if where else ''} ORDER BY h.hostname", params)
    if args.match:
        rows = [r for r in rows if any(fnmatch.fnmatch(r["hostname"] or "", g) for g in args.match)]
    _print_rows(rows, ESXI_COLS, "ESXi hosts", args.json)


def cmd_vcenters(args):
    rows = _q("SELECT v.*, s.name AS site FROM vcenters v LEFT JOIN sites s ON s.id = v.site_id ORDER BY v.name")
    _print_rows(rows, VC_COLS, "vCenters", args.json)


def _vsphere_counts(db):
    for title, sql in (
        ("VM os_family", "SELECT os_family, COUNT(*) FROM machines GROUP BY os_family ORDER BY 2 DESC"),
        ("VM guest_os", "SELECT guest_os, COUNT(*) FROM machines GROUP BY guest_os ORDER BY 2 DESC"),
        ("VM power_state", "SELECT power_state, COUNT(*) FROM machines GROUP BY power_state ORDER BY 2 DESC"),
        ("ESXi esxi_version", "SELECT esxi_version, COUNT(*) FROM esxi_hosts GROUP BY esxi_version ORDER BY 2 DESC"),
    ):
        try:
            rows = db.execute(sql).fetchall()
        except sqlite3.OperationalError:  # table not present
            continue
        if rows:
            print(f"By {title}:")
            for val, n in rows:
                print(f"  {str(val or '-'):30} {n}")


def cmd_counts(args):
    db = netlib.open_db()
    for title, col in (("status", "status"), ("model", "model")):
        print(f"By {title}:")
        for val, n in db.execute(f"SELECT {col}, COUNT(*) FROM devices GROUP BY {col} ORDER BY 2 DESC"):
            print(f"  {str(val or '-'):30} {n}")
    _vsphere_counts(db)
    db.close()


def main():
    ap = argparse.ArgumentParser(description="Read-only inventory queries")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("list")
    netlib.add_target_args(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_list)
    p = sub.add_parser("get")
    p.add_argument("target", metavar="HOST_OR_IP")
    p.set_defaults(fn=cmd_get)
    p = sub.add_parser("counts")
    p.set_defaults(fn=cmd_counts)
    p = sub.add_parser("vms")
    p.add_argument("names", nargs="*", metavar="NAMES", help="VM name, guest hostname or primary IP")
    p.add_argument("--match", action="append", default=[], metavar="GLOB", help="fnmatch glob on VM name (repeatable)")
    p.add_argument("--os", choices=["windows", "linux", "other"])
    p.add_argument("--cluster")
    p.add_argument("--host", metavar="ESXI_HOSTNAME")
    p.add_argument("--power", choices=["poweredOn", "poweredOff", "suspended"])
    p.add_argument("--status", default="active", help="inventory status (default: active; 'any' for all)")
    p.add_argument("--templates", action="store_true", help="include templates")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_vms)
    p = sub.add_parser("vm")
    p.add_argument("target", metavar="NAME_OR_IP")
    p.set_defaults(fn=cmd_vm)
    p = sub.add_parser("esxi")
    p.add_argument("--match", action="append", default=[], metavar="GLOB", help="fnmatch glob on hostname (repeatable)")
    p.add_argument("--cluster")
    p.add_argument("--status", default="active", help="inventory status (default: active; 'any' for all)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_esxi)
    p = sub.add_parser("vcenters")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_vcenters)
    args = ap.parse_args()
    try:
        args.fn(args)
    except sqlite3.Error as e:
        raise SystemExit(f"database error: {e}")


if __name__ == "__main__":
    main()
