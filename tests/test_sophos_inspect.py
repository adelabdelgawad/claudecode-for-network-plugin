"""Offline selftest for scripts/sophos_inspect.py: rule lines, find, usage, diff, and loading offline sources.

No device contact; states are built in memory (helpers of the rename tests) or from temporary XML files.
Run: .venv/bin/python tests/test_sophos_inspect.py   (needs the venv python for netmiko)
"""
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "scripts"))

import test_sophos_rename_flow as flow  # sets up the throwaway site environment and the record helpers

# isort: split
import sophos_inspect

base = flow.base


def host(name, address):
    h = ET.Element("IPHost")
    ET.SubElement(h, "Name").text = name
    ET.SubElement(h, "IPAddress").text = address
    return h


def kinds(lines):
    return [k for k, _ in lines]


def check_lines_and_lookups(fails):
    st = flow.state(["r1", "Allow web"], {"G": ["Allow web"]}, nat=(("n1", "Allow web"),))
    st["IPHost"] = [host("Host-1", "192.0.2.10")]
    st["IPHostGroup"] = [base.grp("HG", ["Host-1"])]
    line = sophos_inspect.rule_line(2, st["FirewallRule"][1], "G")
    for want in ("#2", "E", "'Allow web'", "[G]", "Accept", "LAN>-", "dst=N1,N2,N3"):
        if want not in line:
            fails.append(f"rule_line misses {want!r}: {line}")
    if " D " not in sophos_inspect.rule_line(1, base.rec("x", status="Disable"), ""):
        fails.append("rule_line must mark a disabled rule D")
    hits = sophos_inspect.find_hits(st, "host-1")
    if not any("IPHost" in h and "192.0.2.10" in h for h in hits) or not any("member of IPHostGroup" in h for h in hits):
        fails.append(f"find_hits: the host and its group membership must be found: {hits}")
    if sophos_inspect.find_hits(st, "ALLOW")[0].split()[:2] != ["FOUND", "FirewallRule"]:
        fails.append("find_hits: a rule is found by a case-insensitive substring")
    if not sophos_inspect.find_hits(st, "nope")[0].startswith("NOT FOUND"):
        fails.append("find_hits: a missing name is reported NOT FOUND")
    use = sophos_inspect.usage_hits(st, "Allow web")
    if not (any(h.startswith("FirewallRuleGroup 'G'") for h in use) and any(h.startswith("NATRule 'n1'") for h in use)):
        fails.append(f"usage_hits: a rule referenced by a group and a NAT rule: {use}")
    if len(sophos_inspect.usage_hits(st, "N2")) != 2 or "nothing" not in sophos_inspect.usage_hits(st, "zzz")[0]:
        fails.append("usage_hits: a network used by both rules, and an unused name")


def check_diff(fails):
    before = flow.state(["a", "b", "c", "d"], {"G": ["a", "b"]}, nat=(("n", "None"),))
    if sophos_inspect.diff_states(before, before):
        fails.append("diff: identical states must have no differences")
    after = flow.state(["A", "b", "c", "e"], {"G": ["A", "b", "e"]}, nat=(("n", "A"),), actions={"c": "Drop"})
    after["FirewallRule"][3] = base.rec("e", action="Reject", prev="c")  # 'd' removed, a different rule 'e' added
    lines = sophos_inspect.diff_states(before, after)
    text = " | ".join(f"{k} {t}" for k, t in lines)
    for want in ("RENAMED 'a' -> 'A'", "ADDED 'e'", "REMOVED 'd'", "CHANGED 'c': NetworkPolicy", "GROUP 'G': +['e']",
                 "NAT 'n' changed"):
        if want not in text:
            fails.append(f"diff misses {want!r}: {text}")
    if "ORDER" in kinds(lines):
        fails.append("diff: renamed rules in the same place must not be reported as a reorder")
    moved = flow.state(["b", "a", "c", "d"], {"G": ["a", "b"]}, nat=(("n", "None"),))
    if "ORDER" not in kinds(sophos_inspect.diff_states(before, moved)):
        fails.append("diff: a reorder must be reported")


def check_offline_sources(fails):
    d = Path(tempfile.mkdtemp())
    backup = d / "b.xml"
    root = ET.Element("SophosBackup", host="FW-X")
    sec = ET.SubElement(root, "Entity", name="FirewallRule", status="ok", records="2")
    for r in flow.state(["a", "b"])["FirewallRule"]:
        sec.append(r)
    ET.SubElement(root, "Entity", name="FirewallRuleGroup", status="skipped", records="0")
    ET.ElementTree(root).write(backup)
    label, st = sophos_inspect.load_state(str(backup), ("FirewallRule", "FirewallRuleGroup", "NATRule"))
    if "FW-X" not in label or [sophos_inspect.rname(r) for r in st["FirewallRule"]] != ["a", "b"] or st["NATRule"]:
        fails.append(f"load_state(backup): {label} {st}")
    out = d / "outputs"
    out.mkdir()
    resp = ET.Element("Response")
    for r in flow.state(["x"])["FirewallRule"]:
        resp.append(r)
    ET.ElementTree(resp).write(out / "FirewallRule.xml")
    label, st = sophos_inspect.load_state(str(out), ("FirewallRule", "FirewallRuleGroup"))
    if [sophos_inspect.rname(r) for r in st["FirewallRule"]] != ["x"] or st["FirewallRuleGroup"]:
        fails.append(f"load_state(outputs dir): {st}")


def main():
    fails = []
    for fn in (check_lines_and_lookups, check_diff, check_offline_sources):
        fn(fails)
    for f in fails:
        print("FAIL", f)
    print("sophos inspect selftest:", "FAILED" if fails else "ok")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
