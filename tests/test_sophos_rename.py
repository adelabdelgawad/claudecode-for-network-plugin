"""Offline selftest for renaming Sophos firewall rules: the generated step plan and its template-driven apply.

No device contact: FakeFirewall answers the Gets and parses every write request the executor posts (it replaces
sophos_xml.post), so the real templates, the approval check and the verification all run.
Run: .venv/bin/python tests/test_sophos_rename.py   (needs the venv python for netmiko)
"""
import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
_SITE = tempfile.mkdtemp(prefix="cfn-test-site-")
Path(_SITE, ".claude-for-network").write_text("{}")
os.environ["CLAUDE_PROJECT_DIR"] = _SITE
os.environ.update({"NET_DEFAULT_USERNAME": "u", "NET_DEFAULT_PASSWORD": "p"})

import change
import netlib
import sophos_api
import sophos_xml

DEV = {"id": 1, "hostname": "FW-EDGE-01", "mgmt_ip": "192.0.2.1", "os_type": "sfos", "credential_ref": "DEFAULT",
       "vendor": "sophos", "device_type": "firewall", "api_credential_ref": "DEFAULT"}


netlib.resolve_targets = lambda args: [dict(DEV)]  # no inventory DB in the throwaway site: one fake firewall


def raises(exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc:
        return True
    except Exception:  # noqa: BLE001
        return False
    return False


def rec(name, action="Accept", prev=None, pos="After", status="Enable", rev=False, nets=("N1", "N2", "N3")):
    e = ET.Element("FirewallRule", transactionid="")
    ET.SubElement(e, "Name").text = name
    ET.SubElement(e, "Status").text = status
    ET.SubElement(e, "Position").text = pos
    ET.SubElement(e, "PolicyType").text = "Network"
    if prev:
        ET.SubElement(ET.SubElement(e, "After"), "Name").text = prev
    np = ET.SubElement(e, "NetworkPolicy")
    ET.SubElement(np, "Action").text = action
    ET.SubElement(ET.SubElement(np, "SourceZones"), "Zone").text = "LAN"
    dest = ET.SubElement(np, "DestinationNetworks")
    for n in (reversed(nets) if rev else nets):  # a set to SFOS: the order it lists them in is not meaningful
        ET.SubElement(dest, "Network").text = n
    return e


def grp(name, members):
    g = ET.Element("FirewallRuleGroup", transactionid="")
    ET.SubElement(g, "Name").text = name
    ET.SubElement(g, "Description")
    lst = ET.SubElement(g, "SecurityPolicyList")
    for m in members:
        ET.SubElement(lst, "SecurityPolicy").text = m
    ET.SubElement(g, "Policytype").text = "Any"
    return g


def response(entity, code="200", text="Configuration applied successfully."):
    return ET.fromstring(f'<Response><Login><status>Authentication Successful</status></Login>'
                         f'<{entity} transactionid=""><Status code="{code}">{text}</Status></{entity}></Response>')


class FakeFirewall:
    """Rules in order, rule groups and NAT links. It answers Gets and applies the write requests that
    sophos_xml.post receives. modes: refuse_add (True or a rule name), misplace, mutate, auto_join, group_noop,
    remove_noop, reorder."""

    def __init__(self, names, groups=None, nat_links=(), **modes):
        self.names, self.action = list(names), {n: "Accept" for n in names}
        self.groups = {g: list(m) for g, m in (groups or {}).items()}
        self.nat, self.modes, self.calls, self.sent, self.reordered = list(nat_links), modes, [], [], set()
        self.saved, self.reads = {}, 0  # reads = Get requests answered (one per fetch call, however many entities)

    def read(self, entities):
        self.reads += 1
        return {e: self.fetch_entity(e) for e in entities}

    # -- install: route the module-level seams of sophos_api / sophos_xml / netlib to this fake
    def install(self):
        for mod, attr, fn in ((sophos_api, "attach_details", lambda devs: devs),
                              (sophos_api, "backup_device", lambda dev: Path("/tmp/fake-backup.xml")),
                              (sophos_api, "fetch_entity", lambda dev, e, timeout=30: self.read([e])[e]),
                              (sophos_api, "fetch_entities", lambda dev, es, timeout=30: self.read(es)),
                              (sophos_api, "api_credentials", lambda dev: ("u", "p")),
                              (sophos_xml, "post", lambda dev, xml, timeout=30: self.post(xml)),
                              (netlib, "resolve_targets", lambda args: [dict(DEV)])):
            self.saved[(mod, attr)] = getattr(mod, attr)
            setattr(mod, attr, fn)
        return self

    def uninstall(self):
        for (mod, attr), fn in self.saved.items():
            setattr(mod, attr, fn)

    def group_records(self):
        return [grp(g, m) for g, m in self.groups.items()]

    def fetch_entity(self, entity):
        if entity == "FirewallRule":
            recs = [rec(n, self.action[n], self.names[i - 1] if i else None, "After" if i else "Top",
                        rev=n in self.reordered) for i, n in enumerate(self.names)]
        elif entity == "FirewallRuleGroup":
            recs = self.group_records()
        else:
            recs = []
            for link in ["None"] + self.nat:
                n = ET.Element("NATRule")
                ET.SubElement(n, "Name").text = "nat"
                ET.SubElement(n, "LinkedFirewallrule").text = link
                recs.append(n)
        return {"state": "ok" if recs else "empty", "status": None, "records": recs}

    def post(self, xml):
        root = ET.fromstring(xml)
        verb = root[1]
        ent = verb[0]
        name = ent.findtext("Name")
        self.sent.append(xml)
        if verb.tag == "Remove":
            self.calls.append(("remove", name))
            if not self.modes.get("remove_noop"):
                self.names.remove(name)
                self.action.pop(name)
                for m in self.groups.values():
                    if name in m:
                        m.remove(name)
        elif ent.tag == "FirewallRuleGroup":
            self.calls.append(("group", name))
            if not self.modes.get("group_noop"):
                self.groups[name] = [e.text for e in ent.findall("SecurityPolicyList/SecurityPolicy")]
        elif verb.attrib == {"operation": "add"}:
            old = ent.findtext("After/Name")
            self.calls.append(("add", old, name))
            if self.modes.get("refuse_add") in (True, old):
                return response("FirewallRule", "500", "Operation failed.")
            i = self.names.index(old)
            self.names.insert(len(self.names) if self.modes.get("misplace") else i + 1, name)
            self.action[name] = "Drop" if self.modes.get("mutate") else ent.findtext("NetworkPolicy/Action")
            if self.modes.get("reorder"):
                self.reordered.add(name)
            if self.modes.get("auto_join"):
                for m in self.groups.values():
                    if old in m:
                        m.insert(m.index(old) + 1, name)
        else:
            raise AssertionError(f"the fake firewall does not know this write: {xml}")
        return response(ent.tag)


def plan_dict(args_title="t"):
    return argparse.Namespace(title=args_title, commands=None, commands_file=None, verify=[], rollback_file=None,
                              save=False, continue_on_error=False, rename_rules_file=None, sophos_steps=None,
                              targets=[DEV["hostname"]], match=[], role=None, all=False, status="active")


def quiet(fn, *a, **kw):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **kw)


def make_rename_plan(fw, pairs):
    """Create a rename step plan (as `cfn change plan --rename-rules-file`) and return (plan, digest)."""
    f = Path(tempfile.mkdtemp()) / "r.txt"
    f.write_text("".join(f"{o} => {n}\n" for o, n in pairs))
    ns = plan_dict()
    ns.rename_rules_file = str(f)
    plan = quiet(change.plan_sophos_rename, ns, fw.group_records())
    return change.load_plan(plan["id"])


def make_steps_plan(steps):
    f = Path(tempfile.mkdtemp()) / "steps.json"
    f.write_text(json.dumps(steps))
    ns = plan_dict()
    ns.sophos_steps = str(f)
    return change.load_plan(quiet(change.plan_sophos_xml, ns)["id"])


def approve(plan, digest, consume=True):
    """What the UserPromptSubmit hook writes after the user types APPROVE, then what `apply` does first."""
    change.APPROVALS.mkdir(parents=True, exist_ok=True)
    (change.APPROVALS / f"{plan['id']}.json").write_text(json.dumps({
        "status": "approved", "plan_sha256": digest, "approved_at": datetime.now(timezone.utc).isoformat()}))
    if consume:
        change.check_approval(plan["id"], digest)
    return dict(plan, digest=digest)


def run_plan(fw, plan, digest):
    entry = {"hostname": DEV["hostname"], "mgmt_ip": DEV["mgmt_ip"], "output": "", "verify_output": {}, "backup": None}
    try:
        change.sophos_steps_run(dict(DEV), approve(plan, digest), entry)
        return None, entry
    except Exception as e:  # noqa: BLE001
        return str(e), entry


def run_rename(fw, pairs):
    plan, digest = make_rename_plan(fw, pairs)
    return run_plan(fw, plan, digest)


def kinds(fw):
    return [c[0] for c in fw.calls]


def check_read_renames(fails):
    d = Path(tempfile.mkdtemp())
    f = d / "r.txt"
    f.write_text("# comment\nA => B\n\nC d => E f\n")
    if change.read_renames(f) != [("A", "B"), ("C d", "E f")]:
        fails.append("read_renames: wrong parse")
    for text in ("A -> B\n", "A => A\n", "A => B\nA => C\n", "A => B\nC => B\n", "A => B\nB => C\n", "\n# only\n"):
        f.write_text(text)
        if not raises(SystemExit, change.read_renames, f):
            fails.append(f"read_renames accepted {text!r}")
    for bad in ("", " x", "a,b", "x" * 61, "a\nb"):
        if not raises(ValueError, sophos_api.check_rule_name, bad):
            fails.append(f"check_rule_name must refuse {bad!r}")
    if sophos_api.rule_content(rec("X")) != sophos_api.rule_content(rec("Y", rev=True)):
        fails.append("rule_content must ignore the order of list members (networks, zones, ...)")
    if sophos_api.rule_content(rec("X")) == sophos_api.rule_content(rec("Y", nets=("N1", "N2"))):
        fails.append("rule_content must notice a different member set")


def check_rename_steps(fails):
    steps = change.rename_steps([("Zoom", "Allow-Zoom"), ("Lap", "Allow-Lap"), ("Mail", "Allow-Mail")],
                                [grp("Biz", ["A", "Zoom", "Lap"])])
    res = [s["resource"] for s in steps]
    want = ["firewall_rule.add_copy", "firewall_rule_group.update", "firewall_rule.delete"] * 2 + \
           ["firewall_rule.add_copy", "firewall_rule.delete"]
    if res != want:
        fails.append(f"rename_steps: wrong sequence (copy, group update when grouped, delete): {res}")
    g1, g2 = steps[1], steps[4]
    if g1["vars"]["members"] != ["A", "Zoom", "Allow-Zoom", "Lap"] or g1["expect_current"] != {
            "SecurityPolicyList": ["A", "Zoom", "Lap"]}:
        fails.append(f"rename_steps: first group step must insert the copy after the original: {g1}")
    if g2["expect_current"]["SecurityPolicyList"] != ["A", "Allow-Zoom", "Lap"] or \
            g2["vars"]["members"] != ["A", "Allow-Zoom", "Lap", "Allow-Lap"]:
        fails.append(f"rename_steps: the second group step must start from the state after the first delete: {g2}")
    if steps[2].get("renamed") != ["Zoom", "Allow-Zoom"]:
        fails.append("rename_steps: the delete step must carry the rename it completes")

    fw = FakeFirewall(["A", "Zoom"], groups={"Biz": ["A", "Zoom"]}).install()
    try:
        plan, digest = make_rename_plan(fw, [("Zoom", "Allow-Zoom")])
        if plan["kind"] != change.SOPHOS_RENAME or plan["renames"] != [["Zoom", "Allow-Zoom"]] or len(plan["steps"]) != 3:
            fails.append("rename plan: kind, renames or steps missing")
        reqs = plan["requests"][DEV["hostname"]]
        if [r["resource"] for r in reqs] != [s["resource"] for s in plan["steps"]] or "********" not in reqs[0]["xml"] \
                or "<Password>p</Password>" in json.dumps(plan):
            fails.append("rename plan: rendered requests must list every step, with the password masked")
        text = change.summary(plan, digest)
        if "Requests (exact XML" not in text or "firewall_rule.add_copy" not in text or "<Name>Allow-Zoom</Name>" not in text:
            fails.append("summary must show the exact requests")
        if not raises(SystemExit, make_rename_plan, FakeFirewall(["A"]), [("A", "B"), ("A", "C")]):
            fails.append("a rename plan with ambiguous pairs must be refused")
    finally:
        fw.uninstall()


def run(fw, pairs):
    fw.install()
    try:
        return run_rename(fw, pairs)
    finally:
        fw.uninstall()


def check_apply(fails):
    # ungrouped rule: create, then delete
    fw = FakeFirewall(["DNAT", "Laptop", "Desktop"])
    err, entry = run(fw, [("Laptop", "Allow-Laptops")])
    if err or fw.names != ["DNAT", "Allow-Laptops", "Desktop"] or kinds(fw) != ["add", "remove"]:
        fails.append(f"ungrouped ok-path: {err} {fw.names} {fw.calls}")
    if entry.get("renamed") != [["Laptop", "Allow-Laptops"]] or "2. Allow-Laptops" not in \
            entry["verify_output"].get("FirewallRule names, in order", ""):
        fails.append("ungrouped ok-path: renamed list or final listing missing")

    # grouped rule that does not join its group by itself: create, group update, delete
    fw = FakeFirewall(["A", "Zoom", "B"], groups={"Biz": ["A", "Zoom"]})
    err, _ = run(fw, [("Zoom", "Allow-Zoom")])
    if err or kinds(fw) != ["add", "group", "remove"] or fw.groups["Biz"] != ["A", "Allow-Zoom"]:
        fails.append(f"grouped ok-path: {err} {fw.calls} {fw.groups}")

    # grouped rule whose copy joins the group automatically: the group step is skipped as already done
    fw = FakeFirewall(["A", "Zoom", "B"], groups={"Biz": ["A", "Zoom"]}, auto_join=True)
    err, entry = run(fw, [("Zoom", "Allow-Zoom")])
    if err or kinds(fw) != ["add", "remove"] or fw.groups["Biz"] != ["A", "Allow-Zoom"] or \
            "already in the requested state" not in entry["output"]:
        fails.append(f"auto-join ok-path: {err} {fw.calls} {fw.groups}")

    # the firewall lists the copy's networks in another order (what stopped ANC stage 2): still fine
    fw = FakeFirewall(["A", "Zoom", "B"], reorder=True)
    err, _ = run(fw, [("Zoom", "Allow-Zoom")])
    if err or kinds(fw) != ["add", "remove"] or fw.names != ["A", "Allow-Zoom", "B"]:
        fails.append(f"a copy with reordered list members must be accepted: {err} {fw.calls}")

    # two renames in the same group: the second group step starts from the state after the first delete
    fw = FakeFirewall(["A", "Zoom", "Lap", "B"], groups={"Biz": ["A", "Zoom", "Lap"]})
    err, entry = run(fw, [("Zoom", "Allow-Zoom"), ("Lap", "Allow-Lap")])
    if err or fw.groups["Biz"] != ["A", "Allow-Zoom", "Allow-Lap"] or len(entry["renamed"]) != 2:
        fails.append(f"two renames in one group: {err} {fw.groups}")



def check_apply_resume(fails):
    # resume: an interrupted run left an identical copy right after the original -> reuse it, no second create
    fw = FakeFirewall(["A", "Zoom", "Allow-Zoom", "B"], groups={"Biz": ["A", "Zoom", "Allow-Zoom"]})
    fw.reordered.add("Allow-Zoom")
    err, entry = run(fw, [("Zoom", "Allow-Zoom")])
    if err or kinds(fw) != ["remove"] or fw.names != ["A", "Allow-Zoom", "B"] or fw.groups["Biz"] != ["A", "Allow-Zoom"]:
        fails.append(f"resume ok-path: {err} {fw.calls} {fw.names} {fw.groups}")
    # resume must refuse a same-named rule that is not an identical copy right after the original
    for label, fw in (("differs", FakeFirewall(["A", "Zoom", "Allow-Zoom"])),
                      ("not adjacent", FakeFirewall(["Zoom", "A", "Allow-Zoom"]))):
        if label == "differs":
            fw.action["Allow-Zoom"] = "Drop"
        err, _ = run(fw, [("Zoom", "Allow-Zoom")])
        if not err or fw.calls:
            fails.append(f"resume must refuse an existing rule that {label}: {err} {fw.calls}")

    # pre-checks: no write at all
    taken = FakeFirewall(["A", "B"])
    taken.action["B"] = "Drop"  # a different rule that already has the new name (an identical neighbour = resume)
    for label, fw, pairs in (
        ("missing old rule", FakeFirewall(["A"]), [("Nope", "X")]),
        ("new name taken", taken, [("A", "B")]),
        ("NAT linked", FakeFirewall(["A", "B"], nat_links=["A"]), [("A", "A2")]),
    ):
        err, _ = run(fw, pairs)
        if not err or fw.calls:
            fails.append(f"pre-check '{label}' must stop before any write: {err} {fw.calls}")



def check_apply_stops(fails):
    # every misbehaviour must stop BEFORE the delete: the copy is verified before the original is touched
    for label, kw, groups in (
        ("create refused", {"refuse_add": True}, None),
        ("copy misplaced", {"misplace": True}, None),
        ("copy differs from the original", {"mutate": True}, None),
        ("group update ignored", {"group_noop": True}, {"Biz": ["A", "Zoom"]}),
    ):
        fw = FakeFirewall(["A", "Zoom", "B"], groups=groups, **kw)
        err, entry = run(fw, [("Zoom", "Allow-Zoom")])
        if not err or "remove" in kinds(fw) or entry.get("renamed"):
            fails.append(f"'{label}' must stop before deleting the original: {err} {fw.calls}")

    # a delete that does nothing is caught afterwards
    fw = FakeFirewall(["A", "Zoom"], remove_noop=True)
    err, _ = run(fw, [("Zoom", "Allow-Zoom")])
    if not err or kinds(fw) != ["add", "remove"]:
        fails.append(f"a delete that changes nothing must be reported: {err}")

    # the second rename fails: the first stays done and is reported, the second original is untouched
    fw = FakeFirewall(["A", "B"], refuse_add="B")
    err, entry = run(fw, [("A", "A2"), ("B", "B2")])
    if not err or entry.get("renamed") != [["A", "A2"]] or fw.names != ["A2", "B"]:
        fails.append(f"partial run: {err} {entry.get('renamed')} {fw.names}")

    # drift: the group changed after planning -> stop before sending anything for that step
    fw = FakeFirewall(["A", "Zoom"], groups={"Biz": ["A", "Zoom"]}).install()
    try:
        plan, digest = make_rename_plan(fw, [("Zoom", "Allow-Zoom")])
        fw.groups["Biz"].insert(0, "Intruder")
        err, _ = run_plan(fw, plan, digest)
    finally:
        fw.uninstall()
    if not err or "re-plan" not in err or kinds(fw) != ["add"]:
        fails.append(f"a group that changed after planning must stop the run at its step: {err} {fw.calls}")


def main():
    fails = []
    for fn in (check_read_renames, check_rename_steps, check_apply, check_apply_resume, check_apply_stops):
        fn(fails)
    for f in fails:
        print("FAIL", f)
    print("sophos rename selftest:", "FAILED" if fails else "ok")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
