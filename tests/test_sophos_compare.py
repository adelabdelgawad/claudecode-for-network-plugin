"""Offline selftest for scripts/sophos_compare.py: matching by purpose, groups, pins, recommended names, rule order.

Synthetic firewalls FW-A, FW-B, FW-C only; no device contact. The report/groups files go to a temporary directory.
Run: .venv/bin/python tests/test_sophos_compare.py   (needs the venv python for netmiko)
"""
import json
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "scripts"))

import test_sophos_rename as base  # sets up the throwaway site environment

# isort: split
import sophos_api
import sophos_compare as sc

LAB = ["FW-A", "FW-B", "FW-C"]


def rec(name, action="Accept", sz=("LAN",), dz=("WAN",), src=(), dst=(), svc=(), wf="None", status="Enable",
        identity=()):
    e = ET.Element("FirewallRule", transactionid="")
    ET.SubElement(e, "Name").text = name
    ET.SubElement(e, "Status").text = status
    ET.SubElement(e, "PolicyType").text = "Network"
    pol = ET.SubElement(e, "NetworkPolicy")
    ET.SubElement(pol, "Action").text = action
    for tag, item, vals in (("SourceZones", "Zone", sz), ("DestinationZones", "Zone", dz),
                            ("SourceNetworks", "Network", src), ("DestinationNetworks", "Network", dst),
                            ("Services", "Service", svc), ("Identity", "Member", identity)):
        if vals:
            parent = ET.SubElement(pol, tag)
            for v in vals:
                ET.SubElement(parent, item).text = v
    ET.SubElement(pol, "WebFilter").text = wf
    return e


def feats(recs):
    return [sc.features(i, r) for i, r in enumerate(recs, 1)]


def fw(**by_label):
    return {lb: feats(by_label[lb.replace("-", "_")]) for lb in LAB}


def membership(items):
    return {frozenset((lb, r["name"]) for lb, r in g["members"]) for g in items}


def run(rules, **kw):
    return sc.compare(LAB, rules, kw.pop("min_score", 0.6), kw.pop("pins", None))


MS = ("Mail-Hosts", "Cloud-Suite")


def check_matching(fails):
    rules = fw(
        FW_A=[rec("Microsoft Services", dst=MS), rec("DC to DNS IPs", dst=("8.8.8.8", "1.1.1.1"), svc=("DNS",)),
              rec("Only on A", dst=("Special-Host",))],
        FW_B=[rec("MicrosoftServices", dst=MS), rec("DC To Dns", dst=("8.8.8.8", "1.1.1.1"), svc=("DNS",))],
        FW_C=[rec("Microsoft Servcies", dst=MS), rec("Domain Controllers DNS", dst=("8.8.8.8", "1.1.1.1"),
                                                      svc=("DNS",))])
    items, _ = run(rules)
    got = membership(items)
    ms = {("FW-A", "Microsoft Services"), ("FW-B", "MicrosoftServices"), ("FW-C", "Microsoft Servcies")}
    dns = {("FW-A", "DC to DNS IPs"), ("FW-B", "DC To Dns"), ("FW-C", "Domain Controllers DNS")}
    if ms not in got:
        fails.append(f"typo/spacing names with the same destinations must be one group: {got}")
    if dns not in got:
        fails.append(f"different names with the same purpose must be one group: {got}")
    if {("FW-A", "Only on A")} not in got:
        fails.append("a rule on one firewall must be a specific group of one")


def check_action_not_matched(fails):
    rules = fw(FW_A=[rec("Startpage", action="Accept", dst=("Site-X",))],
               FW_B=[rec("Startpage", action="Drop", dst=("Site-X",))], FW_C=[])
    items, _ = run(rules)
    if any(len(g["members"]) > 1 for g in items):
        fails.append("same name but allow vs block must not match")
    rules = fw(FW_A=[rec("Startpage", action="Drop", dst=("Site-X",))],
               FW_B=[rec("Startpage", action="Reject", dst=("Site-X",))], FW_C=[])
    if len(run(rules)[0]) != 1:
        fails.append("Drop and Reject are both block and must match")
    rules = fw(FW_A=[rec("Web", sz=("WAN",), dz=("LAN",), dst=("Pub",))], FW_B=[rec("Web", dst=("Pub",))], FW_C=[])
    if any(len(g["members"]) > 1 for g in run(rules)[0]):
        fails.append("an inbound rule must not match an outbound one")


def check_missing_and_report(fails):
    rules = fw(FW_A=[rec("VPN Access", sz=("LAN", "VPN"), dz=("LAN",)), rec("Zoom", dst=("Zoom-Hosts",))],
               FW_B=[rec("VPN Access", sz=("LAN", "VPN"), dz=("LAN",), status="Disable")],
               FW_C=[rec("Zoom", dst=("Zoom-Hosts",)), rec("Zoom Mini", dst=("Other",))])
    items, problems = run(rules)
    text = sc.render(LAB, rules, items, problems, 0.6)
    if "— missing" not in text or "**(disabled)**" not in text:
        fails.append("a rule common to two shows '— missing' and a disabled rule is flagged")
    for head in ("## 1. Common to all", "## 2. Common to some", "## 3. Site-specific", "## 4. Rule-order problems"):
        if head not in text:
            fails.append(f"report misses section {head!r}")
    scopes = {g["scope"] for g in sc.to_json(LAB, items, problems)["groups"]}
    if scopes != {"some", "specific"}:
        fails.append(f"groups.json scopes: {scopes}")


def check_pins(fails):
    rules = fw(FW_A=[rec("Alpha", dst=("H1",))], FW_B=[rec("Zebra", dst=("H9",))], FW_C=[])
    if len(run(rules)[0]) != 2:
        fails.append("setup: unrelated rules must not match without a pin")
    f = Path(tempfile.mkdtemp()) / "pins.json"
    f.write_text(json.dumps([{"FW-A": "alpha", "FW-B": "Zebra"}]))
    items, _ = run(rules, pins=str(f))
    if membership(items) != {frozenset({("FW-A", "Alpha"), ("FW-B", "Zebra")})}:
        fails.append("a pinned group must be kept (name match is case-insensitive)")
    f.write_text(json.dumps([{"FW-A": "Nope", "FW-B": "Zebra"}]))
    if not base.raises(SystemExit, lambda: run(rules, pins=str(f))):
        fails.append("a pin naming an unknown rule must be refused")


def check_order(fails):
    rs = feats([rec("Servers", action="Reject", src=("Servers",)),
                rec("Servers to Updates", src=("Servers",), dst=("Upd",)),
                rec("Disabled early", status="Disable"), rec("Desktop"),
                rec("Laptops", src=("192.0.2.0/24",), dst=("X",))])
    txt = " | ".join(t for _, _, t in sc.order_problems("FW-A", rs))
    if "#2 `Servers to Updates` never matches" not in txt or "#1 `Servers`" not in txt:
        fails.append(f"a full shadow must be reported: {txt}")
    if "#5 `Laptops` never matches (shadowed by #4 `Desktop`)" not in txt:
        fails.append(f"any-covers-everything shadow: {txt}")
    if "Disabled early" in txt:
        fails.append("a disabled rule is never reported and never shadows")
    part = feats([rec("Servers", action="Reject", src=("Servers",)), rec("Updates", dst=("Upd",)),
                  rec("Other", src=("Lab",))])
    txt = " | ".join(t for _, _, t in sc.order_problems("FW-A", part))
    if "#2 `Updates`" not in txt or "blocked for the sources of #1 `Servers`" not in txt or "#3" in txt:
        fails.append(f"partial block (B's source any) must be reported, disjoint sources not: {txt}")
    ident = feats([rec("Staff", identity=("user@example.test",)), rec("Next")])
    if sc.order_problems("FW-A", ident):
        fails.append("a rule with an identity restriction must not shadow")


def check_names(fails):
    cases = [([rec("Insrance Domains"), rec("Insurance Domains"), rec("Insurance Domains")], "Allow-Insurance-Domains"),
             ([rec("Drop site.example", action="Drop")], "Block-Site-Example"),
             ([rec("Web Publish", sz=("WAN",), dz=("LAN",))], "Publish-Web"),
             ([rec("Servers To all Internet"), rec("allowed servers To Internet")], "Allow-Servers-Internet")]
    for recs, want in cases:
        got = sc.recommend_name(feats(recs))
        if got != want:
            fails.append(f"recommended name {got!r}, wanted {want!r}")
        try:
            sophos_api.check_rule_name(got)
        except ValueError as e:
            fails.append(str(e))
    long = sc.recommend_name(feats([rec("word " * 30)]))
    if len(long) > sophos_api.RULE_NAME_MAX:
        fails.append("a long name must be shortened to the SFOS limit")


def main():
    fails = []
    for fn in (check_matching, check_action_not_matched, check_missing_and_report, check_pins, check_order,
               check_names):
        fn(fails)
    for f in fails:
        print("FAIL", f)
    print("sophos compare selftest:", "FAILED" if fails else "ok")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
