"""Plan, review and apply device configuration changes (the only sanctioned path).

Usage: cfn change plan --title TEXT (-c CMD ... | --commands-file FILE) [--verify "show ..."] [--rollback-file FILE] [--save] [--continue-on-error] TARGETS...
       cfn change plan --title TEXT --rename-rules-file FILE FIREWALL      (Sophos: FILE lines "old name => new name")
       cfn change plan --title TEXT --sophos-steps FILE.json TARGETS...   (Sophos: FILE is a list of {resource, vars})
       cfn change show ID | list
       cfn change apply ID

Sophos plans (kind sophos_xml) are lists of template steps: each step is {resource, vars} from resources/sophos/
(scripts/sophos_xml.py). The plan stores the steps AND the exact XML each step renders to (password masked), so the
sha256 the user approves covers the requests; fields a step does not list are carried over from the live record when
it runs. Applying backs the firewall up, then runs the steps in order through sophos_xml.submit, re-reads the entity
after each step, verifies the intended effect and stops at the first failure.
The rename plan (kind sophos_rename_rule) is a generated step sequence: SFOS cannot rename a rule in place, so per rule
add_copy -> verify -> rule-group update -> delete -> verify; the original is never deleted before the copy is verified.

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
import sophos_api
import sophos_xml
from netlib import ROOT

CHANGES = ROOT / "changes"
APPROVALS = ROOT / ".claude" / "approvals"
APPROVAL_TTL_MIN = 60
SOPHOS_RENAME = "sophos_rename_rule"  # plan["kind"]: a rename, generated as sophos_xml steps
SOPHOS_XML = "sophos_xml"  # plan["kind"]: steps from resources/sophos; absent kind = classic netmiko config plan
SOPHOS_KINDS = (SOPHOS_RENAME, SOPHOS_XML)


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


METHOD = ("Method:  Sophos XML API, one template step at a time (resources/sophos). Backup first; after each step the entity\n"
          "         is re-read and the intended effect verified; stops at the first failure. A rename is add_copy -> verify ->\n"
          "         group update -> delete -> verify and never deletes the original before the copy is verified.")


def sophos_request_lines(plan):
    """The exact XML each step renders to, per target (password masked); [] for non-Sophos plans."""
    if plan.get("kind") not in SOPHOS_KINDS:
        return []
    lines = ["Requests (exact XML, password masked; fields a step does not list come from the live record when it runs):"]
    for host, reqs in plan["requests"].items():
        for n, r in enumerate(reqs, 1):
            lines += [f"  [{host}] step {n}: {r['resource']}", f"    {r['xml']}"]
    return lines


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
        *sophos_request_lines(plan),
        (METHOD
         if plan.get("kind") in SOPHOS_KINDS else
         f"Save config (write memory): {'yes' if plan['save'] else 'no'}"),
        f"Stop on error: {'yes' if plan['stop_on_error'] else 'no'}",
        f"Plan sha256: {digest}",
        "",
        f"To approve, the USER must type exactly:  APPROVE {plan['id']}",
        f"(or REJECT {plan['id']} to cancel)",
    ]
    return "\n".join(lines)


def new_plan(args, devs, commands, verify, rollback, **extra):
    cid = f"CHG-{netlib.timestamp()}-{secrets.token_hex(2)}"
    return {
        "id": cid,
        "title": args.title,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "targets": [{k: d[k] for k in ("id", "hostname", "mgmt_ip", "os_type", "credential_ref")} for d in devs],
        "commands": commands,
        "verify": verify,
        "rollback": rollback,
        "save": bool(args.save),
        "stop_on_error": not args.continue_on_error,
        **extra,
    }


def save_plan(plan):
    path = plan_path(plan["id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan, indent=2, sort_keys=True))
    print(summary(plan, sha256_file(path)))


def read_renames(path):
    """Parse 'old => new' lines (blank lines and #comments skipped); check_renames rejects anything ambiguous."""
    pairs = []
    for ln in read_lines(path):
        if ln.lstrip().startswith("#"):
            continue
        old, sep, new = ln.partition(" => ")
        if not sep:
            raise SystemExit(f"bad line (expected 'old name => new name'): {ln!r}")
        pairs.append((old.strip(), new.strip()))
    return check_renames(pairs)


def check_renames(pairs):
    """Reject empty lists, illegal or identical names and ambiguous sets of (old, new) pairs; return them."""
    for old, new in pairs:
        try:
            sophos_api.check_rule_name(old)
            sophos_api.check_rule_name(new)
        except ValueError as e:
            raise SystemExit(str(e))
        if old == new:
            raise SystemExit(f"old and new names are identical: {old!r}")
    olds, news = [o for o, _ in pairs], [n for _, n in pairs]
    if not pairs:
        raise SystemExit("no renames given")
    if len(set(olds)) != len(olds) or len(set(news)) != len(news) or set(olds) & set(news):
        raise SystemExit("renames must have unique old names, unique new names, and no new name equal to an old name")
    return pairs


def resolve_sophos_targets(args, what):
    devs = netlib.resolve_targets(args)
    bad = [d["hostname"] for d in devs if not (d.get("vendor") == "sophos" and d.get("device_type") == "firewall")]
    if bad:
        raise SystemExit(f"{what} only apply to Sophos firewalls; not one: {', '.join(bad)}")
    return devs


def reject_mixed(args, flag):
    if args.commands or args.commands_file or args.verify or args.rollback_file or args.save:
        raise SystemExit(f"{flag} cannot be combined with -c/--commands-file/--verify/--rollback-file/--save")


STEP_KEYS = {"resource", "vars", "expect_current", "renamed"}


def check_steps(steps):
    """Validate a list of {resource, vars[, expect_current, renamed]}: every step must render; returns it."""
    if not isinstance(steps, list) or not steps:
        raise SystemExit("the steps must be a non-empty JSON list of {resource, vars}")
    for n, st in enumerate(steps, 1):
        if not isinstance(st, dict) or not set(st) <= STEP_KEYS or not isinstance(st.get("vars"), dict):
            raise SystemExit(f"step {n}: expected an object with resource and vars (optional: {sorted(STEP_KEYS - {'resource', 'vars'})})")
        try:
            sophos_xml.render(sophos_xml.load_resource(st.get("resource", "")), st["vars"])
        except (ValueError, KeyError) as e:
            raise SystemExit(f"step {n}: {e}")
    return steps


def describe_step(st):
    res = sophos_xml.load_resource(st["resource"])
    return f"{res.verb} {res.entity} via {res.name} {json.dumps(st['vars'], sort_keys=True)}"


def planned_requests(devs, steps):
    """{hostname: [{resource, xml}]}: what each step renders to from its own variables (password masked)."""
    reqs = []
    for st in steps:
        res = sophos_xml.load_resource(st["resource"])
        reqs.append({"resource": res.name, "xml": sophos_xml.build(res, st["vars"], sophos_xml.PREVIEW_USER, sophos_xml.MASK)})
    return {d["hostname"]: reqs for d in devs}


def plan_sophos_steps(args, devs, steps, rollback=(), kind=SOPHOS_XML, **extra):
    """Create and save a step plan; the sha256 the user approves covers the steps and their rendered XML."""
    steps = check_steps(steps)
    plan = new_plan(args, devs, [describe_step(s) for s in steps], [], list(rollback), kind=kind, steps=steps,
                    requests=planned_requests(devs, steps), **extra)
    save_plan(plan)
    return plan


def plan_sophos_xml(args):
    reject_mixed(args, "--sophos-steps")
    steps = load_json(args.sophos_steps)
    if steps is None:
        raise SystemExit(f"cannot read the steps file {args.sophos_steps}")
    return plan_sophos_steps(args, resolve_sophos_targets(args, "sophos steps"), steps)


def rename_steps(pairs, groups):
    """The step sequence of a rename (SFOS cannot rename in place): per rule add_copy, then the rule-group update if
    the rule is in a group, then delete of the original. Each step is verified by the executor before the next runs."""
    members = {(g.findtext("Name") or "").strip(): sophos_api.group_members(g) for g in groups}
    steps = []
    for old, new in pairs:
        steps.append({"resource": "firewall_rule.add_copy", "vars": {"old": old, "new": new}})
        gname = next((g for g, ms in members.items() if old in ms), None)
        if gname and new in members[gname]:   # an interrupted run already added the copy to the group
            members[gname] = [m for m in members[gname] if m != old]
        elif gname:
            cur = members[gname]
            at = cur.index(old) + 1
            target = cur[:at] + [new] + cur[at:]
            steps.append({"resource": "firewall_rule_group.update", "vars": {"name": gname, "members": target},
                          "expect_current": {"SecurityPolicyList": cur}})
            members[gname] = [m for m in target if m != old]
        steps.append({"resource": "firewall_rule.delete", "vars": {"name": old}, "renamed": [old, new]})
    return steps


def plan_sophos_rename(args, groups=None):
    """Plan a rename of rules by name. Reads the firewall's rule groups (read-only Get) unless `groups` is given."""
    reject_mixed(args, "--rename-rules-file")
    pairs = read_renames(args.rename_rules_file)
    devs = resolve_sophos_targets(args, "rule renames")
    if len(devs) != 1:
        raise SystemExit("a rename plan works on one firewall at a time (rule names and groups differ per firewall)")
    if groups is None:
        groups = read_entity(sophos_api.attach_details(devs)[0], "FirewallRuleGroup")

    def show(a, b):
        return f"RENAME FirewallRule {a!r} -> {b!r}"

    plan = plan_sophos_steps(args, devs, rename_steps(pairs, groups), [show(n, o) for o, n in pairs],
                             kind=SOPHOS_RENAME, renames=[list(p) for p in pairs])
    # Ready-made rollback input: a new plan (new approval) can undo it with --rename-rules-file.
    rb = CHANGES / plan["id"] / "rollback-renames.txt"
    rb.write_text("".join(f"{n} => {o}\n" for o, n in pairs))
    print(f"Rollback input for a new plan: {rb}")
    return plan


def cmd_plan(args):
    if args.rename_rules_file:
        return plan_sophos_rename(args)
    if args.sophos_steps:
        return plan_sophos_xml(args)
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
    save_plan(new_plan(args, devs, commands, verify, rollback))


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


def read_entity(dev, entity):
    """Records of one Sophos entity ([] when there are none); raises RuntimeError if it cannot be read."""
    r = sophos_api.fetch_entity(dev, entity)
    if r["state"] == "empty":
        return []
    if r["state"] != "ok":
        raise RuntimeError(f"could not read {entity} ({r['state']}: {r['status']})")
    return r["records"]


def rule_name(rec):
    return (rec.findtext("Name") or "").strip()


def group_named(groups, name):
    return next((g for g in groups if (g.findtext("Name") or "").strip() == name), None)


def group_holding(groups, rule):
    return next((g for g in groups if rule in sophos_api.group_members(g)), None)


def copy_follows(rules, old, new):
    """True when `new` is an identical copy sitting right after `old` (what an interrupted rename leaves)."""
    names = [rule_name(r) for r in rules]
    if names.count(new) != 1 or names.count(old) != 1 or names.index(new) != names.index(old) + 1:
        return False
    return sophos_api.rule_content(rules[names.index(new)]) == sophos_api.rule_content(rules[names.index(old)])


def sophos_preflight(d, steps):
    """Check every step that can be checked up front; RuntimeError before anything is sent."""
    rules = read_entity(d, "FirewallRule")
    names = [rule_name(r) for r in rules]
    deleted = {s["vars"]["name"] for s in steps if s["resource"] == "firewall_rule.delete"}
    linked = {(n.findtext("LinkedFirewallrule") or "").strip() for n in read_entity(d, "NATRule")} if deleted else set()
    for old in sorted(deleted & linked):
        raise RuntimeError(f"pre-check: a NAT rule is linked to {old!r}; deleting it would break that NAT rule")
    for s in steps:
        if s["resource"] != "firewall_rule.add_copy":
            continue
        old, new = s["vars"]["old"], s["vars"]["new"]
        if names.count(old) != 1:
            raise RuntimeError(f"pre-check: rule {old!r} found {names.count(old)} times (expected 1); nothing changed")
        if new in names and not copy_follows(rules, old, new):
            raise RuntimeError(f"pre-check: a rule named {new!r} already exists and is not an identical copy of "
                               f"{old!r} right after it; nothing changed")


def snapshot(d, res):
    return {e: read_entity(d, e) for e in sophos_xml.watched(res)}


def step_noop(res, v, before, record):
    """Why a step has nothing to do (an interrupted earlier run already did it), else None."""
    if res.name == "firewall_rule.add_copy" and copy_follows(before["FirewallRule"], v["old"], v["new"]):
        return f"copy {v['new']!r} already follows {v['old']!r} and is identical, reusing it"
    if res.verb == "Set update":
        if res.entity == "FirewallRuleGroup":
            done = sophos_api.group_members(record) == v["members"]
        else:
            done = sophos_xml.fields_match(res, v, record)
        return "already in the requested state" if done else None
    return None


def run_step(d, plan, step):
    """One step: read, skip if already done, send via sophos_xml.submit, re-read and verify. Returns the log text."""
    res = sophos_xml.load_resource(step["resource"])
    v = step["vars"]
    before = snapshot(d, res)
    record = sophos_xml.pick_record(res, v, before[res.entity])
    why = step_noop(res, v, before, record)
    if why:
        return f"{res.name}: {why}\n"
    if step.get("expect_current"):
        sophos_xml.check_expect(record, step["expect_current"])
    user, pw = sophos_api.api_credentials(d)
    text = sophos_xml.submit(d, sophos_xml.build(res, v, user, pw, record), plan)
    problems = sophos_xml.verify_step(res, v, before, snapshot(d, res))
    if problems:
        raise RuntimeError(f"{res.name} was sent ({text}) but verification failed: " + "; ".join(problems))
    return f"{res.name}: {text}\n"


def sophos_steps_run(dev, plan, entry):
    """Back up, pre-check, then run the plan's steps in order; the first failure stops the run."""
    d = sophos_api.attach_details([dev])[0]
    entry["backup"] = str(sophos_api.backup_device(d))
    steps = plan["steps"]
    sophos_preflight(d, steps)
    for n, step in enumerate(steps, 1):
        entry["stage"] = f"step {n}/{len(steps)}: {describe_step(step)}"
        entry["output"] += run_step(d, plan, step)
        if step.get("renamed"):
            entry.setdefault("renamed", []).append(step["renamed"])
    entry["stage"] = None
    if any(s["resource"].startswith("firewall_rule.") for s in steps):
        final = [rule_name(r) for r in read_entity(d, "FirewallRule")]
        entry["verify_output"]["FirewallRule names, in order"] = "\n".join(f"{i}. {n}" for i, n in enumerate(final, 1))


def apply_one(dev, plan, db):
    entry = {"hostname": dev["hostname"], "mgmt_ip": dev["mgmt_ip"], "status": "failed",
             "backup": None, "output": "", "verify_output": {}, "error": None}
    try:
        if plan.get("kind") in SOPHOS_KINDS:
            sophos_steps_run(dev, plan, entry)
        else:
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
        if entry.get("renamed"):
            entry["error"] += f" | renamed before the stop: {entry['renamed']}"
        if entry.get("stage"):
            entry["error"] += f" | stopped during: {entry['stage']}"
    ok = entry["status"] == "ok"
    log_change(db, dev["id"], plan["title"] if ok else f"FAILED: {plan['title']}", {
        "change_id": plan["id"], "commands": plan["commands"], "backup": entry["backup"],
        "saved": ok and plan["save"], "output": entry["output"][-4000:], "error": entry["error"],
    }, plan["id"])
    return entry


def cmd_apply(args):
    plan, digest = load_plan(args.id)
    check_approval(args.id, digest)
    plan = dict(plan, digest=digest)  # sophos_xml.submit re-checks the consumed approval against this digest
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
    p.add_argument("--rename-rules-file", metavar="FILE",
                   help="Sophos firewalls: rename firewall rules; lines 'old name => new name' (name only)")
    p.add_argument("--sophos-steps", metavar="FILE.json",
                   help="Sophos firewalls: JSON list of {resource, vars} steps from resources/sophos (cfn sophos-xml list)")
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
