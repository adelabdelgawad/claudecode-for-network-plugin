"""Plan, review and apply device configuration changes (the only sanctioned path).

Usage: cfn change plan --title TEXT (-c CMD ... | --commands-file FILE) [--verify "show ..."] [--rollback-file FILE] [--save] [--continue-on-error] TARGETS...
       cfn change show ID | list
       cfn change apply ID

`apply` only runs after the USER has typed `APPROVE <ID>` (captured by the UserPromptSubmit hook
into .claude/approvals/<ID>.json). Approval is bound to the plan's sha256, single use, valid 60 min.
"""
import argparse
import hashlib
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from netmiko import ConnectHandler

import netlib
from netlib import ROOT

CHANGES = ROOT / "changes"
APPROVALS = ROOT / ".claude" / "approvals"
APPROVAL_TTL_MIN = 60


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_lines(path):
    return [ln.rstrip() for ln in Path(path).read_text().splitlines() if ln.strip()]


def load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def plan_path(cid):
    return CHANGES / cid / "plan.json"


def summary(plan, digest):
    t = plan["targets"]
    lines = [
        f"ID:      {plan['id']}",
        f"Title:   {plan['title']}",
        f"Targets: {len(t)}",
        *[f"  - {d['hostname']} ({d['mgmt_ip']})" for d in t],
        "Config commands (exact):",
        *[f"  {c}" for c in plan["commands"]],
        "Verify:  " + (", ".join(plan["verify"]) if plan["verify"] else "none"),
        "Rollback commands:" + ("" if plan["rollback"] else " none"),
        *[f"  {c}" for c in plan["rollback"]],
        f"Save config (write memory): {'yes' if plan['save'] else 'no'}",
        f"Stop on error: {'yes' if plan['stop_on_error'] else 'no'}",
        f"Plan sha256: {digest}",
        "",
        f"To approve, the USER must type exactly:  APPROVE {plan['id']}",
        f"(or REJECT {plan['id']} to cancel)",
    ]
    return "\n".join(lines)


def cmd_plan(args):
    commands = list(args.commands or [])
    if args.commands_file:
        commands += read_lines(args.commands_file)
    commands = [c.rstrip() for c in commands if c.strip()]
    if not commands:
        raise SystemExit("No config commands given (-c or --commands-file)")
    verify = [v.strip() for v in args.verify]
    netlib.require_readonly(verify, "verify command")
    rollback = read_lines(args.rollback_file) if args.rollback_file else []
    devs = netlib.resolve_targets(args)

    cid = f"CHG-{netlib.timestamp()}-{secrets.token_hex(2)}"
    plan = {
        "id": cid,
        "title": args.title,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "targets": [{k: d[k] for k in ("id", "hostname", "mgmt_ip", "os_type", "credential_ref")} for d in devs],
        "commands": commands,
        "verify": verify,
        "rollback": rollback,
        "save": bool(args.save),
        "stop_on_error": not args.continue_on_error,
    }
    path = plan_path(cid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan, indent=2, sort_keys=True))
    print(summary(plan, sha256_file(path)))


def load_plan(cid):
    path = plan_path(cid)
    if not path.is_file():
        raise SystemExit(f"No such plan: {cid}")
    return json.loads(path.read_text()), sha256_file(path)


def cmd_show(args):
    plan, digest = load_plan(args.id)
    print(summary(plan, digest))


def status_of(cid):
    result = load_json(CHANGES / cid / "result.json")
    if result:
        return result.get("status", "applied")
    appr = load_json(APPROVALS / f"{cid}.json")
    if appr:
        return appr.get("status", "pending")
    return "pending"


def cmd_list(args):
    for p in sorted(CHANGES.glob("CHG-*/plan.json")):
        plan = load_json(p) or {}
        print(f"{p.parent.name}  {status_of(p.parent.name):9}  {plan.get('title', '')}")


def refuse(msg):
    print(f"NOT APPROVED — {msg}", file=sys.stderr)
    sys.exit(3)


def check_approval(cid, digest):
    ask = f"ask the user to type: APPROVE {cid}"
    path = APPROVALS / f"{cid}.json"
    appr = load_json(path)
    if not appr or appr.get("status") != "approved":
        refuse(ask)
    if appr.get("plan_sha256") != digest:
        refuse(f"plan changed after approval — re-plan and re-approve ({ask})")
    if appr.get("consumed"):
        refuse(f"approval already used (single use); {ask}")
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(appr["approved_at"])
    except (KeyError, ValueError):
        refuse(f"approval has no valid timestamp; {ask}")
    if age.total_seconds() > APPROVAL_TTL_MIN * 60:
        refuse(f"approval older than {APPROVAL_TTL_MIN} minutes; {ask}")
    appr["consumed"] = True
    appr["consumed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    path.write_text(json.dumps(appr, indent=2, sort_keys=True))


def log_change(db, dev_id, action, details, cid):
    db.execute(
        "INSERT INTO change_log (device_id, action, details, performed_by) VALUES (?, ?, ?, ?)",
        (dev_id, action, json.dumps(details), f"claude-code; approved by user via APPROVE {cid}"),
    )
    db.commit()


def apply_one(dev, plan, db):
    entry = {"hostname": dev["hostname"], "mgmt_ip": dev["mgmt_ip"], "status": "failed",
             "backup": None, "output": "", "verify_output": {}, "error": None}
    try:
        with ConnectHandler(**netlib.conn_params(dev)) as conn:
            conn.enable()
            entry["backup"] = str(netlib.save_running_config(conn, dev["hostname"]))
            entry["output"] = conn.send_config_set(plan["commands"])
            if plan["save"]:
                entry["output"] += "\n" + conn.save_config()
            for v in plan["verify"]:
                entry["verify_output"][v] = conn.send_command(v)
        entry["status"] = "ok"
    except Exception as e:  # noqa: BLE001 - record any failure per host
        entry["error"] = netlib.err_text(e)
    ok = entry["status"] == "ok"
    log_change(db, dev["id"], plan["title"] if ok else f"FAILED: {plan['title']}", {
        "change_id": plan["id"], "commands": plan["commands"], "backup": entry["backup"],
        "saved": ok and plan["save"], "output": entry["output"][-4000:], "error": entry["error"],
    }, plan["id"])
    return entry


def cmd_apply(args):
    plan, digest = load_plan(args.id)
    check_approval(args.id, digest)
    db = netlib.open_db(readonly=False)
    results = []
    for dev in plan["targets"]:
        entry = apply_one(dev, plan, db)
        results.append(entry)
        print(f"{'OK  ' if entry['status'] == 'ok' else 'FAIL'} {dev['hostname']:30} {dev['mgmt_ip']:15} "
              f"{entry['error'] or 'backup ' + str(entry['backup'])}")
        if entry["status"] != "ok" and plan["stop_on_error"]:
            print("Stopping: error on a target and --continue-on-error was not set")
            break
    db.close()
    skipped = [d["hostname"] for d in plan["targets"][len(results):]]
    status = "applied" if len(results) == len(plan["targets"]) and all(r["status"] == "ok" for r in results) else "failed"
    (CHANGES / args.id / "result.json").write_text(json.dumps({
        "id": args.id, "status": status, "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "results": results, "not_attempted": skipped}, indent=2, sort_keys=True))
    print(f"{args.id}: {status} ({sum(r['status'] == 'ok' for r in results)}/{len(plan['targets'])} ok)")
    for v in results:
        for cmd, out in v["verify_output"].items():
            print(f"===== {v['hostname']} :: {cmd} =====\n{out}")
    sys.exit(0 if status == "applied" else 1)


def main():
    ap = argparse.ArgumentParser(description="Plan and apply approved device changes")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan", help="create a change plan (does not connect to devices)")
    p.add_argument("--title", required=True)
    p.add_argument("-c", "--command", action="append", dest="commands", metavar="CMD")
    p.add_argument("--commands-file")
    p.add_argument("--verify", action="append", default=[], metavar="SHOW_CMD")
    p.add_argument("--rollback-file")
    p.add_argument("--save", action="store_true", help="save config after applying")
    p.add_argument("--continue-on-error", action="store_true")
    netlib.add_target_args(p)
    p.set_defaults(fn=cmd_plan)
    for name, fn in (("show", cmd_show), ("apply", cmd_apply)):
        p = sub.add_parser(name)
        p.add_argument("id")
        p.set_defaults(fn=fn)
    p = sub.add_parser("list")
    p.set_defaults(fn=cmd_list)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
