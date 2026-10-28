"""Check, plan and verify Sophos firewall-rule renames: the before/after parts of the approval-gated flow.

Usage: cfn sophos-rename check  (--file FILE | --from-report REPORT.md) TARGETS...
       cfn sophos-rename plan   --title TEXT (--file FILE | --from-report REPORT.md) [--canary] FIREWALL
       cfn sophos-rename verify CHG-ID

SFOS cannot rename a firewall rule in place (the name is the key), so a rename is a copy + delete that
`cfn change apply` performs per rule (see the sophos-xg skill). This script runs everything around it, so
no model has to read raw XML:

  check   live pre-flight of every rename: old name present once, new name free (or an identical copy
          already follows: the rename resumes), rule group, status, NAT link. One table per firewall;
          exit 1 if anything blocks. Read-only.
  plan    check, then create the change plan(s). --canary makes plan 1 = one ungrouped + one grouped rule
          and plan 2 = the rest. Creating a plan does not touch the firewall.
  verify  after `cfn change apply`: compares the live firewall with the backup that apply took first
          (rule count, order, content, status, group membership, NAT rules) -> PASS/FAIL lines; exit 1 on FAIL.
          Read-only.

FILE holds lines `old name => new name`. REPORT is a markdown table with a `Recommended name` column and one
column per firewall named like a dash-separated part of its hostname (`FW-EDGE-01` -> `FW`); a cell
holds `#position` and the old rule name in backticks; rows without a backticked name are skipped.
"""
import argparse
import contextlib
import io
import re
import sys
from pathlib import Path

import change
import netlib
import sophos_api

ENTITIES = ("FirewallRule", "FirewallRuleGroup", "NATRule")


# --------------------------------------------------------------------------- input
def report_pairs(report, hostname):
    """(old, new) pairs for one firewall from the first markdown table that has a `Recommended name` column."""
    parts = [p.lower() for p in hostname.split("-")]
    in_table, name_col, col, pairs = False, None, None, []
    for line in Path(report).read_text().splitlines():
        if not line.lstrip().startswith("|"):
            if in_table:
                break
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not in_table:
            heads = [c.strip("* ").lower() for c in cells]
            if "recommended name" in heads:
                in_table, name_col = True, heads.index("recommended name")
                col = next((i for i, h in enumerate(heads) if h in parts), None)
                if col is None:
                    raise SystemExit(f"no column for {hostname!r} in the report table (headers: {heads})")
            continue
        if set("".join(cells)) <= set("-: ") or len(cells) <= max(col, name_col):
            continue
        m = re.search(r"`([^`]+)`", cells[col])
        if m:
            pairs.append((m.group(1), cells[name_col].strip("* ")))
    if not pairs:
        raise SystemExit(f"no renames for {hostname!r} found in {report}")
    return change.check_renames(pairs)


def pairs_for(args, hostname):
    return change.read_renames(args.file) if args.file else report_pairs(args.from_report, hostname)


def live_state(dev):
    """{entity: records} read live from one firewall (read-only)."""
    return {e: change.read_entity(dev, e) for e in ENTITIES}


# --------------------------------------------------------------------------- check
def assess(rules, groups, nat, pairs):
    """One row per rename: position, status, group and a verdict (ok / resume / BLOCK ...)."""
    names = [change.rule_name(r) for r in rules]
    linked = {(n.findtext("LinkedFirewallrule") or "").strip() for n in nat}
    rows = []
    for old, new in pairs:
        found, grp = names.count(old), change.group_holding(groups, old)
        if found != 1:
            verdict = f"BLOCK: old rule found {found} times (expected 1)"
        elif old in linked:
            verdict = "BLOCK: a NAT rule is linked to it"
        elif new not in names:
            verdict = "ok"
        elif change.copy_follows(rules, old, new):
            verdict = "resume: an identical copy already follows"
        else:
            verdict = "BLOCK: new name already used by a different rule"
        rule = rules[names.index(old)] if found == 1 else None
        rows.append({"old": old, "new": new, "verdict": verdict, "ok": not verdict.startswith("BLOCK"),
                     "pos": names.index(old) + 1 if found == 1 else "-",
                     "status": rule.findtext("Status") if rule is not None else "-",
                     "group": grp.findtext("Name") if grp is not None else ""})
    return rows


def render(hostname, rows):
    bad = sum(not r["ok"] for r in rows)
    resume = sum(r["verdict"].startswith("resume") for r in rows)
    head = (f"{hostname}: {len(rows)} renames | {len(rows) - bad - resume} ok, {resume} resume, {bad} blocked | "
            f"{sum(bool(r['group']) for r in rows)} grouped, {sum(r['status'] == 'Disable' for r in rows)} disabled")
    lines = [f"  #{r['pos']:<3} {r['status']:<7} [{r['group'] or '-'}] {r['old']!r} -> {r['new']!r}  {r['verdict']}"
             for r in rows]
    return "\n".join([head, *lines])


def check_firewall(args, dev):
    """(rows, error) for one firewall; error is a text when it could not be read."""
    try:
        st = live_state(dev)
        pairs = pairs_for(args, dev["hostname"])
        return assess(st["FirewallRule"], st["FirewallRuleGroup"], st["NATRule"], pairs), None
    except (sophos_api.ApiError, RuntimeError) as e:
        return None, str(e)


def cmd_check(args):
    blocked = False
    for dev in sophos_api.resolve_firewalls(args):
        rows, err = check_firewall(args, dev)
        print(f"{dev['hostname']}: ERROR {err}" if err else render(dev["hostname"], rows))
        blocked = blocked or err is not None or any(not r["ok"] for r in rows)
    return 1 if blocked else 0


# --------------------------------------------------------------------------- plan
def split_canary(rows):
    """(first, rest): the first stage holds one ungrouped and one grouped rule so both code paths get tested."""
    ungrouped, grouped = [r for r in rows if not r["group"]], [r for r in rows if r["group"]]
    first = ungrouped[:1] + grouped[:1]
    if len(first) < 2:
        first = (ungrouped + grouped)[:2]
    return first, [r for r in rows if r not in first]


def create_plan(dev, rows, title, label):
    """Write the stage's rename file and create its step plan (change.plan_sophos_rename: add_copy, group update,
    delete per rule, rendered from resources/sophos); returns (change id, file). Reads rule groups only."""
    path = change.CHANGES / f"{dev['hostname']}-rename-{netlib.timestamp()}-{label}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# generated by cfn sophos-rename plan\n" + "".join(f"{r['old']} => {r['new']}\n" for r in rows))
    ns = argparse.Namespace(title=title, commands=None, commands_file=None, verify=[], rollback_file=None, save=False,
                            continue_on_error=False, rename_rules_file=str(path), sophos_steps=None, targets=[dev["hostname"]],
                            match=[], role=None, all=False, status="active")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        change.plan_sophos_rename(ns)
    return re.search(r"ID:\s+(CHG-\S+)", out.getvalue()).group(1), path


def cmd_plan(args):
    devs = sophos_api.resolve_firewalls(args)
    if len(devs) != 1:
        raise SystemExit("plan works on one firewall at a time (rule names differ per firewall)")
    dev = devs[0]
    rows, err = check_firewall(args, dev)
    if err:
        raise SystemExit(f"{dev['hostname']}: ERROR {err}")
    print(render(dev["hostname"], rows))
    if any(not r["ok"] for r in rows):
        print("BLOCKED: fix the BLOCK rows above first; no plan was created")
        return 1
    stages = [s for s in (split_canary(rows) if args.canary else (rows,)) if s]
    for n, stage in enumerate(stages, 1):
        label = f"stage {n}: " if args.canary else ""
        title = f"{dev['hostname']} {label}rename {len(stage)} rule(s) by copy + verify + delete: {args.title}"
        cid, path = create_plan(dev, stage, title, f"stage{n}")
        print(f"PLAN {cid}: {len(stage)} rename(s) from {path.name} -> the user must type: APPROVE {cid}")
    return 0


# --------------------------------------------------------------------------- verify
def load_backup(path):
    """{entity: records} from a `cfn sophos-api backup` file (entities the firmware skipped are left out)."""
    _, secs = sophos_api.load_backup(path)
    return {name: recs for name, (state, recs) in secs.items() if state in ("ok", "empty")}


def _rule_lines(before, live, sub, complete):
    b, now = before["FirewallRule"], live["FirewallRule"]
    b_names, l_names = [change.rule_name(r) for r in b], [change.rule_name(r) for r in now]
    want = [sub.get(n, n) for n in b_names]
    missing, extra = [n for n in want if n not in l_names], [n for n in l_names if n not in want]
    out = [("PASS" if not missing else "FAIL", f"all {len(want)} expected rules present" if not missing
            else f"missing rules: {missing}")]
    if complete:
        out.append(("PASS" if not extra else "FAIL", "no extra rules" if not extra else f"extra rules: {extra}"))
    elif extra:
        out.append(("WARN", f"extra rules (an interrupted copy?): {extra}"))
    same = [n for n in l_names if n in want] == [n for n in want if n in l_names]
    out.append(("PASS" if same else "FAIL", "rule order unchanged" if same else "rule order differs"))
    orig = {sub.get(n, n): n for n in b_names}
    b_by, l_by = {change.rule_name(r): r for r in b}, {change.rule_name(r): r for r in now}
    differ = [n for n in want
              if n in l_by and sophos_api.rule_content(l_by[n]) != sophos_api.rule_content(b_by[orig[n]])]
    out.append(("PASS" if not differ else "FAIL", "every field but name/position identical" if not differ
                else f"content differs: {differ}"))
    stale = [o for o, n in sub.items() if o in l_names or n not in l_names]
    out.append(("PASS" if not stale else "FAIL", f"{len(sub)} renamed: old names gone, new names present"
                if not stale else f"rename not reflected for: {stale}"))
    return out, extra


def _group_lines(before, live, sub, complete, extra):
    if "FirewallRuleGroup" not in before:
        stale = [m for g in live["FirewallRuleGroup"] for m in sophos_api.group_members(g) if m in sub]
        return [("WARN", "the backup has no group snapshot (taken by an older tool)"),
                ("PASS" if not stale else "FAIL", "no group lists a removed name" if not stale
                 else f"groups still list: {stale}")]
    exp = {g.findtext("Name"): {sub.get(m, m) for m in sophos_api.group_members(g)}
           for g in before["FirewallRuleGroup"]}
    got = {g.findtext("Name"): set(sophos_api.group_members(g)) for g in live["FirewallRuleGroup"]}
    problems = [f"group {n} missing" for n in exp if n not in got]
    problems += [f"unexpected group {n}" for n in got if n not in exp]
    for name in exp.keys() & got.keys():
        gone, more = exp[name] - got[name], got[name] - exp[name]
        if gone or (more and (complete or not more <= set(extra))):
            problems.append(f"{name}: missing {sorted(gone)}, unexpected {sorted(more)}")
    return [("PASS" if not problems else "FAIL", f"group membership as expected ({len(exp)} groups)"
             if not problems else "; ".join(problems))]


def _nat_lines(before, live, sub):
    if "NATRule" not in before:
        return []

    def key(recs, mapped):
        links = [(n.findtext("LinkedFirewallrule") or "").strip() for n in recs]
        return sorted((n.findtext("Name"), sub.get(k, k) if mapped else k) for n, k in zip(recs, links))

    ok = key(before["NATRule"], True) == key(live["NATRule"], False)
    return [("PASS" if ok else "FAIL", "NAT rules unchanged" if ok else "NAT rules differ from the backup")]


def verify_state(before, live, renames, complete):
    """[(PASS|FAIL|WARN, text)]: the live firewall against the pre-change backup with `renames` applied."""
    sub = dict(renames)
    out, extra = _rule_lines(before, live, sub, complete)
    return out + _group_lines(before, live, sub, complete, extra) + _nat_lines(before, live, sub)


def cmd_verify(args):
    plan, _ = change.load_plan(args.id)
    result = change.load_json(change.CHANGES / args.id / "result.json")
    if plan.get("kind") != change.SOPHOS_RENAME or not result:
        raise SystemExit(f"{args.id} is not an applied Sophos rename plan")
    failed = False
    for entry in result["results"]:
        target = next(t for t in plan["targets"] if t["hostname"] == entry["hostname"])
        done = [tuple(p) for p in entry.get("renamed", [])]
        complete = result["status"] == "applied" and len(done) == len(plan["renames"])
        print(f"{entry['hostname']}: plan {result['status']}, {len(done)}/{len(plan['renames'])} renames done; "
              f"before = {Path(entry['backup']).name}")
        live = live_state(sophos_api.attach_details([target])[0])
        lines = verify_state(load_backup(entry["backup"]), live, done, complete)
        for level, text in lines:
            print(f"  {level} {text}")
        failed = failed or any(level == "FAIL" for level, _ in lines)
    print("RESULT: " + ("FAIL" if failed else "PASS"))
    return 1 if failed else 0


# --------------------------------------------------------------------------- cli
def source_args(p):
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="lines 'old name => new name'")
    src.add_argument("--from-report", help="markdown report with a 'Recommended name' table")


def main():
    ap = argparse.ArgumentParser(description="Check, plan and verify Sophos firewall-rule renames")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("check", help="live pre-flight of the renames (read-only)")
    source_args(p)
    netlib.add_target_args(p)
    p.set_defaults(fn=cmd_check)
    p = sub.add_parser("plan", help="check, then create the change plan(s); nothing is sent to the firewall")
    p.add_argument("--title", required=True)
    p.add_argument("--canary", action="store_true", help="plan 1: one ungrouped + one grouped rule; plan 2: the rest")
    source_args(p)
    netlib.add_target_args(p)
    p.set_defaults(fn=cmd_plan)
    p = sub.add_parser("verify", help="compare the live firewall with the backup `apply` took (read-only)")
    p.add_argument("id")
    p.set_defaults(fn=cmd_verify)
    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
