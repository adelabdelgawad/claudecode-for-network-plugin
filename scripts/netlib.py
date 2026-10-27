"""Shared helpers for the network scripts (inventory targeting, Netmiko params, backups)."""
import fnmatch
import os
import re
import sqlite3
from datetime import datetime

import paths
from dotenv import load_dotenv

ROOT = paths.site_root()
load_dotenv(ROOT / ".env")
DB = ROOT / os.getenv("INVENTORY_DB", "inventory/inventory.db")

READONLY_PREFIXES = ("show ", "display ", "get ", "ping ", "traceroute ", "more ")
_BAD_PIPE = re.compile(r"\|\s*(redirect|tee|append)\b", re.IGNORECASE)


def timestamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def readonly_problem(cmd):
    """Return why `cmd` is not an allowed read-only command, or None if it is fine."""
    c = cmd.strip().lower()
    if not c:
        return "empty command"
    if any(ch in cmd for ch in ("\n", "\r", ";", ">")):
        return "contains newline, ';' or '>'"
    if _BAD_PIPE.search(c):
        return "pipes into redirect/tee/append"
    if c == "dir" or c.startswith("dir ") or c.startswith(READONLY_PREFIXES):
        return None
    return "not in the read-only allowlist (show/display/get/ping/traceroute/dir/more)"


def require_readonly(commands, what="command"):
    bad = [f"  {c!r}: {p}" for c in commands if (p := readonly_problem(c))]
    if bad:
        raise SystemExit(f"Rejected {what}(s):\n" + "\n".join(bad))


def add_target_args(ap):
    ap.add_argument("targets", nargs="*", help="hostnames or mgmt IPs from the inventory")
    ap.add_argument("--match", action="append", default=[], metavar="GLOB",
                    help="fnmatch glob on hostname (repeatable)")
    ap.add_argument("--role", help="select devices with this role")
    ap.add_argument("--all", action="store_true", help="all devices with the selected status")
    ap.add_argument("--status", default="active", help="inventory status to target (default: active)")


def open_db(readonly=True):
    if readonly:
        return sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    return sqlite3.connect(DB)


def _query(where, params):
    db = open_db()
    db.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in db.execute(f"SELECT * FROM devices {where} ORDER BY hostname", params)]
    finally:
        db.close()


def select_devices(args, allow_any_status=False):
    """Devices matching the shared filters (no 'nothing matched' check)."""
    rows = _query("", ())
    if not (allow_any_status and args.status == "any"):
        rows = [r for r in rows if r["status"] == args.status]
    selected = {}
    for r in rows:
        if args.all:
            selected[r["id"]] = r
        if args.role and r["role"] == args.role:
            selected[r["id"]] = r
        if any(fnmatch.fnmatch(r["hostname"] or "", g) for g in args.match):
            selected[r["id"]] = r
    return list(selected.values())


def resolve_targets(args):
    if not (args.targets or args.match or args.role or args.all):
        raise SystemExit("Specify targets, --match, --role or --all")
    allrows = _query("", ())
    by_key = {}
    for r in allrows:
        by_key[r["hostname"]] = r
        by_key[r["mgmt_ip"]] = r
    chosen = {}
    for t in args.targets:
        r = by_key.get(t)
        if not r:
            raise SystemExit(f"Target {t!r} is not in the inventory")
        if r["status"] != args.status:
            raise SystemExit(f"Target {t!r} has status {r['status']!r}, not {args.status!r}")
        chosen[r["id"]] = r
    for r in select_devices(args):
        chosen[r["id"]] = r
    if not chosen:
        raise SystemExit("No devices matched the given filters")
    return sorted(chosen.values(), key=lambda r: r["hostname"] or "")


def conn_params(dev):
    ref = dev.get("credential_ref") or "DEFAULT"
    user = os.getenv(f"NET_{ref}_USERNAME")
    pw = os.getenv(f"NET_{ref}_PASSWORD")
    for name, val in ((f"NET_{ref}_USERNAME", user), (f"NET_{ref}_PASSWORD", pw)):
        if not val:
            raise RuntimeError(f"missing credential env var {name}")
    return {
        "device_type": dev.get("os_type") or "cisco_ios",
        "host": dev["mgmt_ip"],
        "port": dev.get("port") or 22,
        "username": user,
        "password": pw,
        "secret": os.getenv(f"NET_{ref}_ENABLE") or "",
        "conn_timeout": 15,
        "auth_timeout": 20,
    }


def save_running_config(conn, hostname):
    conn.enable()
    cfg = conn.send_command("show running-config")
    path = ROOT / "backups" / hostname / f"{timestamp()}.cfg"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(cfg)
    return path


def err_text(e):
    msg = str(e).splitlines()[0][:120] if str(e) else ""
    return f"{type(e).__name__}: {msg}"
