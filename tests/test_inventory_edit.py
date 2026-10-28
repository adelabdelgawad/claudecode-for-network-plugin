"""Selftest for scripts/inventory_edit.py: approval gate, add/set rules, firewall defaults, --dry-run.

No device contact; every case runs the script as a subprocess against a throwaway site.
Run: .venv/bin/python tests/test_inventory_edit.py   (needs the venv python for python-dotenv)
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "inventory_edit.py"
SCHEMA = REPO / "inventory" / "schema.sql"
FW = ["add", "FW-EDGE-01", "192.0.2.10", "--type", "firewall", "--vendor", "sophos", "--site", "SITE-A"]


def make_site():
    site = Path(tempfile.mkdtemp()).resolve()
    (site / ".claude-for-network").write_text("{}")
    (site / "inventory").mkdir()
    db = sqlite3.connect(site / "inventory" / "inventory.db")
    db.executescript(SCHEMA.read_text())
    db.close()
    return site


def approve(site, status="approved", age_min=0):
    when = datetime.now(timezone.utc) - timedelta(minutes=age_min)  # noqa: UP017
    d = site / ".claude" / "approvals"
    d.mkdir(parents=True, exist_ok=True)
    (d / "INV-EDIT.json").write_text(json.dumps({"status": status, "approved_at": when.isoformat()}))


def run(site, *args):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"),
           "CLAUDE_PROJECT_DIR": str(site)}
    p = subprocess.run([sys.executable, str(SCRIPT), *args], env=env, capture_output=True, text=True, check=False)
    return p.returncode, p.stdout + p.stderr


def rows(site, sql):
    db = sqlite3.connect(site / "inventory" / "inventory.db")
    db.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in db.execute(sql)]
    finally:
        db.close()


def check_refusals(fails):
    for label, kw in (("no approval", None), ("expired approval", {"age_min": 20}),
                      ("rejected approval", {"status": "rejected"})):
        site = make_site()
        if kw:
            approve(site, **kw)
        rc, out = run(site, *FW)
        if rc != 2 or "APPROVE INV-EDIT" not in out:
            fails.append(f"{label}: expected exit 2 + message, got {rc}: {out!r}")
        if rows(site, "SELECT * FROM devices") or rows(site, "SELECT * FROM sites"):
            fails.append(f"{label}: DB was changed")


def check_add(fails):
    site = make_site()
    approve(site)
    rc, out = run(site, *FW)
    dev = rows(site, "SELECT d.*, s.name AS site FROM devices d JOIN sites s ON s.id=d.site_id")
    fw = rows(site, "SELECT * FROM firewall_details")
    if rc != 0 or len(dev) != 1:
        fails.append(f"add sophos firewall failed: {rc} {out!r}")
        return
    d = dev[0]
    if (d["site"], d["os_type"], d["credential_ref"], d["device_type"]) != ("SITE-A", "sophos_sfos", "SOPHOS", "firewall"):
        fails.append(f"add: wrong device defaults {d}")
    if len(fw) != 1 or fw[0]["ha_mode"] != "standalone" or fw[0]["api_port"] != 4444 or fw[0]["device_id"] != d["id"]:
        fails.append(f"add: wrong firewall_details {fw}")
    if "FW-EDGE-01" not in out or "firewall_details" not in out:
        fails.append("add: resulting rows not printed")
    rc, out = run(site, "add", "FW-EDGE-02", "192.0.2.10", "--type", "switch")
    if rc != 1 or "already" not in out or len(rows(site, "SELECT * FROM devices")) != 1:
        fails.append(f"duplicate IP not refused: {rc} {out!r}")
    rc, out = run(site, "add", "FW-EDGE-01", "192.0.2.11", "--type", "switch")
    if rc != 1 or len(rows(site, "SELECT * FROM devices")) != 1:
        fails.append(f"duplicate hostname not refused: {rc} {out!r}")
    return site


def check_set(fails, site):
    rc, out = run(site, "add", "SW-ACCESS-01", "192.0.2.20", "--type", "switch")
    if rc != 0:
        fails.append(f"add switch failed: {rc} {out!r}")
    rc, out = run(site, "set", "FW-EDGE-01", "--ip", "192.0.2.20")
    if rc != 1 or "already" not in out:
        fails.append(f"set to another device's IP not refused: {rc} {out!r}")
    rc, out = run(site, "set", "FW-EDGE-01", "--ip", "192.0.2.30", "--role", "edge", "--api-port", "8443")
    d = rows(site, "SELECT * FROM devices WHERE hostname='FW-EDGE-01'")[0]
    fw = rows(site, f"SELECT * FROM firewall_details WHERE device_id={d['id']}")[0]
    if rc != 0 or d["mgmt_ip"] != "192.0.2.30" or d["role"] != "edge" or fw["api_port"] != 8443:
        fails.append(f"set --ip failed: {rc} {out!r} {d} {fw}")
    before = rows(site, "SELECT * FROM devices ORDER BY id")
    rc, out = run(site, "set", "SW-ACCESS-01", "--role", "access", "--dry-run")
    if rc != 0 or "DRY RUN" not in out or rows(site, "SELECT * FROM devices ORDER BY id") != before:
        fails.append(f"set --dry-run wrote or failed: {rc} {out!r}")


def check_dry_run(fails):
    site = make_site()  # no approval on purpose
    rc, out = run(site, *FW, "--dry-run")
    if rc != 0 or "DRY RUN" not in out:
        fails.append(f"add --dry-run failed without approval: {rc} {out!r}")
    if rows(site, "SELECT * FROM devices") or rows(site, "SELECT * FROM sites") \
            or rows(site, "SELECT * FROM firewall_details"):
        fails.append("add --dry-run wrote to the DB")


def main():
    fails = []
    check_refusals(fails)
    site = check_add(fails)
    if site:
        check_set(fails, site)
    check_dry_run(fails)
    for f in fails:
        print("FAIL:", f)
    print("test_inventory_edit: " + ("FAILED" if fails else "all passed"))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
