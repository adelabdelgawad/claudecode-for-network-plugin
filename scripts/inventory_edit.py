"""Record user-supplied device facts in the site's inventory/inventory.db (the sanctioned way to write it).

Usage: cfn inventory_edit add HOSTNAME MGMT_IP --type TYPE [--vendor V] [--os-type T] [--role R] [--site NAME]
                [--notes TEXT] [--cred REF] [--port N] [--status S] [--dry-run]
                [firewall: --ha-mode standalone|active-passive|active-active --ha-role primary|auxiliary
                 --ha-peer HOST --api-port N --verify-ssl --api-cred REF]
       cfn inventory_edit set HOST_OR_IP [--ip IP] [--hostname H] [--role R] [--site NAME] [--notes TEXT]
                [--status S] [--cred REF] [--port N] [firewall options as above] [--dry-run]
         (--type firewall --vendor sophos defaults: os_type sophos_sfos, credential_ref SOPHOS, a firewall_details row)

Every real write needs the user to type `APPROVE INV-EDIT` (valid 15 min); --dry-run writes nothing and needs no
approval. Parameterized SQL, one transaction per command. Only the local inventory/inventory.db is touched.
"""
import argparse
import sqlite3
import sys

import netlib

NEEDS_APPROVAL = "inventory write needs the user to type `APPROVE INV-EDIT` (valid 15 min)"
FW_FIELDS = {"ha_mode": "ha_mode", "ha_role": "ha_role", "api_port": "api_port",
             "verify_ssl": "verify_ssl", "api_cred": "api_credential_ref"}
DEV_SET = {"ip": "mgmt_ip", "hostname": "hostname", "role": "role", "notes": "notes",
           "status": "status", "cred": "credential_ref", "port": "port"}


def fail(msg, code=1):
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def add_fw_args(ap):
    ap.add_argument("--ha-mode", choices=["standalone", "active-passive", "active-active"])
    ap.add_argument("--ha-role", choices=["primary", "auxiliary"])
    ap.add_argument("--ha-peer", help="hostname of the HA peer (must be in the inventory)")
    ap.add_argument("--api-port", type=int)
    ap.add_argument("--verify-ssl", action="store_true", default=None)
    ap.add_argument("--api-cred", help="credential_ref for the XML API (NET_<REF>_*)")
    ap.add_argument("--dry-run", action="store_true", help="print what would be written; write nothing")


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add", help="add a device")
    a.add_argument("hostname")
    a.add_argument("mgmt_ip")
    a.add_argument("--type", required=True, dest="device_type")
    a.add_argument("--vendor")
    a.add_argument("--os-type")
    a.add_argument("--role")
    a.add_argument("--site")
    a.add_argument("--notes")
    a.add_argument("--cred")
    a.add_argument("--port", type=int)
    a.add_argument("--status")
    add_fw_args(a)
    s = sub.add_parser("set", help="change fields of an existing device")
    s.add_argument("target", help="hostname or mgmt_ip")
    s.add_argument("--ip")
    s.add_argument("--hostname")
    s.add_argument("--role")
    s.add_argument("--site")
    s.add_argument("--notes")
    s.add_argument("--status")
    s.add_argument("--cred")
    s.add_argument("--port", type=int)
    add_fw_args(s)
    return ap


def connect():
    db = netlib.open_db(readonly=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def find_device(db, key):
    return db.execute("SELECT * FROM devices WHERE hostname=? OR mgmt_ip=?", (key, key)).fetchone()


def check_unique(db, hostname, ip, exclude_id=None):
    for col, val in (("hostname", hostname), ("mgmt_ip", ip)):
        if val is None:
            continue
        row = db.execute(f"SELECT id, hostname FROM devices WHERE {col}=?", (val,)).fetchone()
        if row and row["id"] != exclude_id:
            fail(f"{col} {val!r} already belongs to device {row['hostname']!r}; refusing.")


def site_id_for(db, name):
    """Id of site `name`, creating the row if missing; None when no site was given."""
    if not name:
        return None
    row = db.execute("SELECT id FROM sites WHERE name=?", (name,)).fetchone()
    if row:
        return row["id"]
    return db.execute("INSERT INTO sites(name) VALUES (?)", (name,)).lastrowid


def peer_id(db, host):
    row = db.execute("SELECT id FROM devices WHERE hostname=? OR mgmt_ip=?", (host, host)).fetchone()
    if not row:
        fail(f"HA peer {host!r} is not in the inventory.")
    return row["id"]


def fw_values(args, db):
    """firewall_details columns given on the command line (column -> value)."""
    vals = {col: getattr(args, opt) for opt, col in FW_FIELDS.items() if getattr(args, opt, None) is not None}
    if "verify_ssl" in vals:
        vals["verify_ssl"] = 1
    if args.ha_peer is not None:
        vals["ha_peer_id"] = peer_id(db, args.ha_peer)
    return vals


def device_values(args):
    """devices columns for `add`, with the Sophos firewall defaults applied."""
    vals = {"hostname": args.hostname, "mgmt_ip": args.mgmt_ip, "device_type": args.device_type,
            "vendor": args.vendor, "os_type": args.os_type, "role": args.role, "notes": args.notes,
            "credential_ref": args.cred, "port": args.port, "status": args.status}
    if args.device_type == "firewall" and (args.vendor or "").lower() == "sophos":
        vals["os_type"] = vals["os_type"] or "sophos_sfos"
        vals["credential_ref"] = vals["credential_ref"] or "SOPHOS"
    return {k: v for k, v in vals.items() if v is not None}


def insert_row(db, table, vals):
    cols = ", ".join(vals)
    marks = ", ".join("?" for _ in vals)
    return db.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(vals.values())).lastrowid


def upsert_fw(db, device_id, vals):
    exists = db.execute("SELECT 1 FROM firewall_details WHERE device_id=?", (device_id,)).fetchone()
    if not exists:
        insert_row(db, "firewall_details", {"device_id": device_id, **vals})
    elif vals:
        sets = ", ".join(f"{c}=?" for c in vals)
        db.execute(f"UPDATE firewall_details SET {sets} WHERE device_id=?", (*vals.values(), device_id))


def show_rows(db, device_id):
    d = db.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    print("devices:")
    for k, v in dict(d).items():
        print(f"  {k:15} {v}")
    fw = db.execute("SELECT * FROM firewall_details WHERE device_id=?", (device_id,)).fetchone()
    if fw:
        print("firewall_details:")
        for k, v in dict(fw).items():
            if k != "device_id":
                print(f"  {k:18} {v}")


def require_approval(dry):
    if not dry and not netlib.inv_edit_approved():
        fail(NEEDS_APPROVAL, 2)


def finish(db, plan, dry, device_id):
    """Dry-run: print the plan and roll back. Real run: commit the one transaction, print the rows."""
    if dry:
        print("DRY RUN (nothing written):")
        for line in plan:
            print(f"  {line}")
        db.rollback()
        return
    db.commit()
    show_rows(db, device_id)


def cmd_add(args):
    db = connect()
    try:
        if find_device(db, args.hostname) or find_device(db, args.mgmt_ip):
            fail(f"{args.hostname!r} / {args.mgmt_ip!r} is already in the inventory; use `set`.")
        dev = device_values(args)
        is_fw = args.device_type == "firewall"
        fw = {"ha_mode": "standalone", **fw_values(args, db)} if is_fw else {}
        plan = [f"INSERT devices {dev}"]
        if args.site:
            plan.append(f"site {args.site!r} (created if missing)")
        if is_fw:
            plan.append(f"INSERT firewall_details {fw}")
        require_approval(args.dry_run)
        site_id = site_id_for(db, args.site)
        did = insert_row(db, "devices", {**dev, **({"site_id": site_id} if site_id else {})})
        if is_fw:
            upsert_fw(db, did, fw)
        finish(db, plan, args.dry_run, did)
    finally:
        db.close()


def cmd_set(args):
    db = connect()
    try:
        dev = find_device(db, args.target)
        if not dev:
            fail(f"{args.target!r} is not in the inventory.")
        vals = {col: getattr(args, opt) for opt, col in DEV_SET.items() if getattr(args, opt) is not None}
        check_unique(db, vals.get("hostname"), vals.get("mgmt_ip"), exclude_id=dev["id"])
        fw = fw_values(args, db)
        if fw and dev["device_type"] != "firewall":
            fail(f"{dev['hostname']!r} is not a firewall; firewall options do not apply.")
        if not vals and not fw and not args.site:
            fail("nothing to change: give at least one field option.")
        plan = [f"UPDATE devices {vals} (site={args.site!r}) WHERE id={dev['id']}"]
        if fw:
            plan.append(f"UPSERT firewall_details {fw}")
        require_approval(args.dry_run)
        if args.site:
            vals["site_id"] = site_id_for(db, args.site)
        if vals:
            sets = ", ".join(f"{c}=?" for c in vals)
            db.execute(f"UPDATE devices SET {sets}, updated_at=datetime('now') WHERE id=?",
                       (*vals.values(), dev["id"]))
        if fw:
            upsert_fw(db, dev["id"], fw)
        finish(db, plan, args.dry_run, dev["id"])
    finally:
        db.close()


def main():
    args = build_parser().parse_args()
    {"add": cmd_add, "set": cmd_set}[args.cmd](args)


if __name__ == "__main__":
    main()
