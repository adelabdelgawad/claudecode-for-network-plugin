"""Offline selftest for scripts/sophos_rename.py: report parsing, pre-flight verdicts, canary split, post-change verify.

No device contact; the firewall states are built in memory with the helpers of tests/test_sophos_rename.py.
Run: .venv/bin/python tests/test_sophos_rename_flow.py   (needs the venv python for netmiko)
"""
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "scripts"))

import test_sophos_rename as base  # sets up the throwaway site environment and the shared record helpers

# isort: split
import sophos_rename

REPORT = """# Report
Some text.

## 1. Common to all
| Recommended name | Purpose | SITE1 | SITE2 |
|---|---|---|---|
| **Allow-A** | a | #3 `old a` | #5 `Old A2` |
| **Allow-B** | b | #4 `old b` **(disabled)** | - |
| **Allow-C** | c | #9 `old c` | #6 `old c2` |

## 2. Another table
| Recommended name | Purpose | SITE1 | SITE2 |
|---|---|---|---|
| **Other** | x | #1 `ignored` | #1 `ignored` |
"""


def nat_rec(name, link="None"):
    n = ET.Element("NATRule")
    ET.SubElement(n, "Name").text = name
    ET.SubElement(n, "LinkedFirewallrule").text = link
    return n


def state(names, groups=None, nat=(("nat", "None"),), actions=None, disabled=()):
    actions = actions or {}
    rules = [base.rec(n, actions.get(n, "Accept"), names[i - 1] if i else None, "After" if i else "Top",
                      status="Disable" if n in disabled else "Enable") for i, n in enumerate(names)]
    return {"FirewallRule": rules, "FirewallRuleGroup": [base.grp(g, m) for g, m in (groups or {}).items()],
            "NATRule": [nat_rec(n, link) for n, link in nat]}


def check_report(fails):
    f = Path(tempfile.mkdtemp()) / "report.md"
    f.write_text(REPORT)
    want1 = [("old a", "Allow-A"), ("old b", "Allow-B"), ("old c", "Allow-C")]
    if sophos_rename.report_pairs(f, "SITE1-FW") != want1:
        fails.append("report_pairs: wrong pairs for the first firewall column (or a second table was read)")
    if sophos_rename.report_pairs(f, "site2-edge") != [("Old A2", "Allow-A"), ("old c2", "Allow-C")]:
        fails.append("report_pairs: wrong pairs for the second firewall column / a '-' cell was not skipped")
    if not base.raises(SystemExit, sophos_rename.report_pairs, f, "OTHER-FW"):
        fails.append("report_pairs must refuse a firewall that has no column")
    f.write_text("no table here\n")
    if not base.raises(SystemExit, sophos_rename.report_pairs, f, "SITE1-FW"):
        fails.append("report_pairs must refuse a report without the table")


def check_assess(fails):
    st = state(["r1", "old a", "old b", "old c", "taken"], groups={"G": ["old a", "old c"]},
               nat=(("nat", "old c"),), disabled=("old b",))
    rows = sophos_rename.assess(st["FirewallRule"], st["FirewallRuleGroup"], st["NATRule"],
                                [("old a", "A"), ("old b", "B"), ("old c", "C"), ("gone", "G2"), ("r1", "taken")])
    got = {r["old"]: r for r in rows}
    if not (got["old a"]["ok"] and got["old a"]["group"] == "G" and got["old a"]["pos"] == 2):
        fails.append(f"assess: a plain grouped rename must be ok with its group and position: {got['old a']}")
    if not (got["old b"]["ok"] and got["old b"]["status"] == "Disable" and got["old b"]["group"] == ""):
        fails.append(f"assess: a disabled ungrouped rule: {got['old b']}")
    if got["old c"]["ok"] or "NAT" not in got["old c"]["verdict"]:
        fails.append("assess: a rule a NAT rule links to must be blocked")
    if got["gone"]["ok"] or got["r1"]["ok"]:
        fails.append("assess: a missing old rule and a taken new name must be blocked")
    st = state(["x", "old a", "old a2"])  # an identical copy already follows -> resume
    rows = sophos_rename.assess(st["FirewallRule"], [], st["NATRule"], [("old a", "old a2")])
    if not (rows[0]["ok"] and rows[0]["verdict"].startswith("resume")):
        fails.append(f"assess: an identical copy right after the original must resume: {rows[0]}")
    if "1 resume" not in sophos_rename.render("FW", rows):
        fails.append("render: the header must count resumes")


def mk(name, group):
    return {"old": name, "group": group}


def check_canary(fails):
    rows =[mk("g1", "G"), mk("g2", "G"), mk("u1", ""), mk("u2", "")]
    first, rest = sophos_rename.split_canary(rows)
    if [r["old"] for r in first] != ["u1", "g1"] or [r["old"] for r in rest] != ["g2", "u2"]:
        fails.append(f"split_canary: one ungrouped + one grouped first, the rest in order: {first} {rest}")
    first, rest = sophos_rename.split_canary([mk("g1", "G"), mk("g2", "G"), mk("g3", "G")])
    if [r["old"] for r in first] != ["g1", "g2"] or [r["old"] for r in rest] != ["g3"]:
        fails.append("split_canary: with only grouped rules the first two go first")
    first, rest = sophos_rename.split_canary([mk("g1", "G")])
    if len(first) != 1 or rest:
        fails.append("split_canary: a single rule is a single stage")


def levels(lines):
    return [lv for lv, _ in lines]


def check_verify(fails):
    groups = {"G": ["a", "c"]}
    before = state(["a", "b", "c"], groups)
    ren = [("a", "A"), ("c", "C")]
    live = state(["A", "b", "C"], {"G": ["A", "C"]})
    if set(levels(sophos_rename.verify_state(before, live, ren, True))) != {"PASS"}:
        fails.append(f"verify: a correct full rename must be all PASS: {sophos_rename.verify_state(before, live, ren, True)}")
    # list members in another order are not a difference
    live["FirewallRule"][0] = base.rec("A", rev=True, prev=None, pos="Top")
    if "FAIL" in levels(sophos_rename.verify_state(before, live, ren, True)):
        fails.append("verify: reordered list members must not FAIL")
    cases = {
        "content changed": (state(["A", "b", "C"], {"G": ["A", "C"]}, actions={"b": "Drop"}), True),
        "order changed": (state(["b", "A", "C"], {"G": ["A", "C"]}), True),
        "group lost the new rule": (state(["A", "b", "C"], {"G": ["A"]}), True),
        "old name still present": (state(["a", "A", "b", "C"], {"G": ["A", "C"]}), True),
        "extra rule on a complete run": (state(["A", "b", "C", "zz"], {"G": ["A", "C"]}), True),
        "NAT changed": (state(["A", "b", "C"], {"G": ["A", "C"]}, nat=(("nat", "A"),)), True),
    }
    for label, (lv, complete) in cases.items():
        if "FAIL" not in levels(sophos_rename.verify_state(before, lv, ren, complete)):
            fails.append(f"verify must FAIL when: {label}")
    # an interrupted run: only 'a' renamed, its copy 'C' sits next to the original 'c' -> WARN, not FAIL
    partial = state(["A", "b", "c", "C"], {"G": ["A", "c", "C"]})
    res = sophos_rename.verify_state(before, partial, [("a", "A")], False)
    if "FAIL" in levels(res) or "WARN" not in levels(res):
        fails.append(f"verify: an in-flight copy of a partial run is a WARN, not a FAIL: {res}")
    # a resumed rename: the copy 'N' already followed 'o' before the run; afterwards only 'N' remains
    rb = state(["x", "o", "N", "y"], {"G": ["o", "N"]})
    rl = state(["x", "N", "y"], {"G": ["N"]})
    res = sophos_rename.verify_state(rb, rl, [("o", "N")], True)
    if set(levels(res)) != {"PASS"}:
        fails.append(f"verify: a resumed rename (copy existed before the run) must be all PASS: {res}")
    old_backup = {k: v for k, v in before.items() if k != "FirewallRuleGroup"}
    res = sophos_rename.verify_state(old_backup, live, ren, True)
    if "WARN" not in levels(res) or "FAIL" in levels(res):
        fails.append("verify: a backup without groups must WARN and still check that no group lists an old name")


def check_create_plan(fails):
    """sophos_rename plan -> step plan via the change module (add_copy, group update, delete per rule), nothing sent."""
    fw = base.FakeFirewall(["A", "old a", "old b"], groups={"G": ["A", "old a"]}).install()
    try:
        cid, path = sophos_rename.create_plan(dict(base.DEV), [{"old": "old a", "new": "Allow-A"}], "t", "stage1")
        plan, _ = base.change.load_plan(cid)
    finally:
        fw.uninstall()
    got = [s["resource"] for s in plan["steps"]]
    if plan["kind"] != "sophos_rename_rule" or got != ["firewall_rule.add_copy", "firewall_rule_group.update",
                                                       "firewall_rule.delete"]:
        fails.append(f"create_plan: wrong plan kind or step sequence: {plan['kind']} {got}")
    if fw.sent or not path.is_file():
        fails.append("create_plan must not send anything and must write the rename file")


def check_grouped_move_refused(fails):
    """firewall_rule.move on a rule in a rule group is refused at plan time (SFOS ignores the position there)."""
    groups = [base.grp("G", ["in-group"])]
    move = [{"resource": "firewall_rule.move", "vars": {"name": "in-group", "position": "Top"}}]
    if not base.raises(SystemExit, base.change.refuse_grouped_moves, [dict(base.DEV)], move, read=lambda d, e: groups):
        fails.append("refuse_grouped_moves must refuse moving a grouped rule")
    loose = [{"resource": "firewall_rule.move", "vars": {"name": "loose", "position": "Top"}}]
    if base.raises(SystemExit, base.change.refuse_grouped_moves, [dict(base.DEV)], loose, read=lambda d, e: groups):
        fails.append("refuse_grouped_moves must allow moving an ungrouped rule")


def check_canary_plans_only_first(fails):
    """--canary creates ONE plan (the canary) and saves the rest to a file; the rest is planned after the canary."""
    fw = base.FakeFirewall(["u1", "g1", "g2"], groups={"G": ["g1", "g2"]}).install()
    import argparse
    import contextlib
    import io
    ns = argparse.Namespace(targets=[base.DEV["hostname"]], match=[], role=None, all=False, status="active",
                            canary=True, title="t", file=None, from_report=None)
    rows = [{"old": o, "new": n, "group": g, "ok": True, "verdict": "ok", "pos": i + 1, "status": "Enable"}
            for i, (o, n, g) in enumerate([("u1", "U1", ""), ("g1", "G1", "G"), ("g2", "G2", "G")])]
    real = (sophos_rename.sophos_api.resolve_firewalls, sophos_rename.check_firewall)
    sophos_rename.sophos_api.resolve_firewalls = lambda a: [dict(base.DEV)]
    sophos_rename.check_firewall = lambda a, d: (rows, None)
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            sophos_rename.cmd_plan(ns)
    finally:
        sophos_rename.sophos_api.resolve_firewalls, sophos_rename.check_firewall = real
        fw.uninstall()
    text = out.getvalue()
    if text.count("PLAN CHG-") != 1 or "REST: 1 rename(s)" not in text:
        fails.append(f"--canary must create only the canary plan and save the rest: {text}")


def main():
    fails = []
    for fn in (check_report, check_assess, check_canary, check_verify, check_create_plan, check_grouped_move_refused,
               check_canary_plans_only_first):
        fn(fails)
    for f in fails:
        print("FAIL", f)
    print("sophos rename flow selftest:", "FAILED" if fails else "ok")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
