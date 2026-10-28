"""Offline selftest for scripts/sophos_xml.py (template-driven Sophos executor) and the Get-only guarantee of sophos_api.

No device contact: sophos_xml.post (the one HTTP send) and the Get seams are replaced by in-memory fakes.
Run: .venv/bin/python tests/test_sophos_xml.py   (needs the venv python for netmiko)
"""
import contextlib
import io
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "scripts"))

import test_sophos_rename as base  # sets up the throwaway site environment, fakes and plan helpers

# isort: split
import change
import sophos_api
import sophos_xml

EXPECTED = ["firewall_rule.add_copy", "firewall_rule.delete", "firewall_rule.move", "firewall_rule_group.update",
            "fqdnhost.add", "fqdnhost.delete", "fqdnhost.update", "iphost.add", "iphost.delete", "iphost.update",
            "service.add", "service.delete", "service.update"]
SAMPLE = {
    "firewall_rule.add_copy": {"old": "Laptop", "new": "Allow-Laptops"},
    "firewall_rule.move": {"name": "R1", "position": "After", "after": "R0"},
    "firewall_rule.delete": {"name": "Old Rule"},
    "firewall_rule_group.update": {"name": "Biz", "members": ["A", "B"]},
    "iphost.add": {"name": "HOST-1", "host_type": "Network", "ip_address": "192.0.2.0", "subnet": "255.255.255.0"},
    "iphost.update": {"name": "HOST-1", "ip_address": "192.0.2.9"},
    "iphost.delete": {"name": "HOST-1"},
    "fqdnhost.add": {"name": "FQ-1", "fqdn": "example.com"},
    "fqdnhost.update": {"name": "FQ-1", "fqdn": "example.org"},
    "fqdnhost.delete": {"name": "FQ-1"},
    "service.add": {"name": "SVC-1", "protocol": "TCP", "dst_port": "8443"},
    "service.update": {"name": "SVC-1", "protocol": "UDP", "src_port": "1:65535", "dst_port": "5060"},
    "service.delete": {"name": "SVC-1"},
}
INJECT = "x</Name><Remove><FirewallRule><Name>victim</Name></FirewallRule></Remove><Name>"


def res(name):
    return sophos_xml.load_resource(name)


def build(name, vars_, record=None):
    return sophos_xml.build(res(name), vars_, "admin", "pw", record)


def check_resources(fails):
    if [r.name for r in sophos_xml.list_resources()] != EXPECTED:
        fails.append(f"resource set differs: {[r.name for r in sophos_xml.list_resources()]}")
    for name, vars_ in SAMPLE.items():
        try:
            xml = build(name, vars_)
            sophos_xml.assert_request_shape(xml, res(name))
            root = ET.fromstring(xml)
            r = res(name)
            if [c.tag for c in root] != ["Login", r.tag] or root[1].attrib != r.attrib or root[1][0].tag != r.entity:
                fails.append(f"{name}: wrong verb/entity in the rendered request")
            if r.verb == "Remove" and [c.tag for c in root[1][0]] != ["Name"]:
                fails.append(f"{name}: a Remove must hold only the Name")
        except Exception as e:  # noqa: BLE001
            fails.append(f"{name}: does not render / pass assert_request_shape: {e}")
    for bad in ("../x.y", "iphost", "iphost.nope", "IPHOST.add", "iphost.add/../x"):
        if not base.raises(ValueError, sophos_xml.load_resource, bad):
            fails.append(f"load_resource must refuse {bad!r}")


def check_injection(fails):
    for name, key in (("iphost.add", "name"), ("fqdnhost.add", "fqdn"), ("service.add", "name"), ("iphost.delete", "name")):
        xml = build(name, dict(SAMPLE[name], **{key: INJECT}))
        root = ET.fromstring(xml)
        ent = root[1][0]
        if [c.tag for c in root] != ["Login", root[1].tag] or len(root.findall(".//Remove")) != (1 if name == "iphost.delete" else 0):
            fails.append(f"{name}: an injected </Name><Remove> became markup")
        if INJECT not in {e.text for e in ent.iter()}:
            fails.append(f"{name}: the injected text must survive as plain text")
    for bad in ("</Name><Remove>", 'a" onload="x'):
        if not base.raises(ValueError, build, "firewall_rule.delete", {"name": bad}) and \
                ET.fromstring(build("firewall_rule.delete", {"name": bad}))[1][0][0].text != bad:
            fails.append(f"rule name {bad!r}: neither refused nor kept as text")
    root = ET.fromstring(sophos_xml.wrap_login(ET.fromstring("<Remove><IPHost><Name>n</Name></IPHost></Remove>"),
                                               "u</Username>", "p</Password><Remove>&"))
    if root.find("Login/Password").text != "p</Password><Remove>&" or [c.tag for c in root] != ["Login", "Remove"]:
        fails.append("login credentials must be escaped, not interpreted")
    if "pw" in sophos_xml.mask_password(build("iphost.delete", SAMPLE["iphost.delete"])):
        fails.append("mask_password left the password in")


def check_vars(fails):
    cases = {
        "unknown variable": ("iphost.delete", {"name": "n", "extra": "x"}),
        "missing required": ("fqdnhost.add", {"name": "n"}),
        "control character": ("fqdnhost.add", {"name": "n", "fqdn": "a\nb"}),
        "bad choice": ("service.add", {"name": "n", "protocol": "ICMP", "dst_port": "1"}),
        "host_type needs its fields": ("iphost.add", {"name": "n", "host_type": "Network", "ip_address": "192.0.2.0"}),
        "IP host must not carry a subnet": ("iphost.add", {"name": "n", "host_type": "IP", "ip_address": "192.0.2.1",
                                                           "subnet": "255.255.255.0"}),
        "list given as text": ("firewall_rule_group.update", {"name": "G", "members": "A"}),
        "text given as list": ("iphost.delete", {"name": ["n"]}),
        "overlong rule name": ("firewall_rule.delete", {"name": "x" * 61}),
        "after without anchor": ("firewall_rule.move", {"name": "R", "position": "After"}),
        "top with an anchor": ("firewall_rule.move", {"name": "R", "position": "Top", "after": "X"}),
        "bad position": ("firewall_rule.move", {"name": "R", "position": "Middle"}),
        "same old and new": None,
    }
    for label, case in cases.items():
        if case and not base.raises(ValueError, build, *case):
            fails.append(f"vars: must refuse {label}")
    x = ET.fromstring(build("iphost.add", {"name": "n", "host_type": "IP", "ip_address": "192.0.2.1"}))[1][0]
    if x.findtext("IPFamily") != "IPv4" or x.find("Subnet") is not None or x.find("StartIPAddress") is not None:
        fails.append("iphost.add: defaults must apply and empty optional fields must be pruned")


def check_move_and_merge(fails):
    def rule(name, **kw):
        return base.rec(name, **kw)

    ent = ET.fromstring(build("firewall_rule.move", {"name": "R1", "position": "After", "after": "R0"}))[1][0]
    if ent.findtext("Position") != "After" or ent.findtext("After/Name") != "R0" or ent.find("Before") is not None:
        fails.append("move After: Position/After wrong or a stray Before present")
    ent = ET.fromstring(build("firewall_rule.move", {"name": "R1", "position": "Before", "before": "R2"}))[1][0]
    if ent.findtext("Position") != "Before" or ent.findtext("Before/Name") != "R2" or ent.find("After") is not None:
        fails.append("move Before: Position/Before wrong or a stray After present")
    # merged with the live record: the old After block must not survive a move to Top, other fields are kept
    cur = rule("R1", prev="R0", action="Drop")
    ent = ET.fromstring(build("firewall_rule.move", {"name": "R1", "position": "Top"}, cur))[1][0]
    if ent.findtext("Position") != "Top" or ent.find("After") is not None or ent.find("Before") is not None:
        fails.append("move Top: stale After/Before of the current record leaked into the request")
    if ent.findtext("NetworkPolicy/Action") != "Drop" or ent.findtext("Status") != "Enable":
        fails.append("move: the rest of the current record must be sent unchanged (full object)")
    ent = ET.fromstring(build("firewall_rule.move", {"name": "R1", "position": "Before", "before": "R5"}, cur))[1][0]
    if ent.findtext("Before/Name") != "R5" or ent.find("After") is not None or ent.findtext("Position") != "Before":
        fails.append("move Before merged: After of the record must be dropped")
    if not base.raises(ValueError, build, "firewall_rule.move", {"name": "Other", "position": "Top"}, cur):
        fails.append("an update must refuse a record that is not the named one")

    old = rule("Laptop", prev="DC", pos="After")
    root = ET.fromstring(build("firewall_rule.add_copy", {"old": "Laptop", "new": "Allow-Laptops"}, old))
    ent = root[1][0]
    if root[1].attrib != {"operation": "add"} or ent.findtext("Name") != "Allow-Laptops" or ent.findtext("After/Name") != "Laptop":
        fails.append("add_copy: must add the copy named new, right After the original")
    if sophos_api.rule_content(ent) != sophos_api.rule_content(old):
        fails.append("add_copy: the copy must equal the original except name and position")
    top = rule("T", pos="Top")
    if ET.fromstring(build("firewall_rule.add_copy", {"old": "T", "new": "N"}, top))[1][0].findtext("After/Name") != "T":
        fails.append("add_copy: an original at Top must still give 'After original'")

    host = ET.Element("IPHost", transactionid="7")
    for tag, text in (("Name", "H"), ("IPFamily", "IPv4"), ("HostType", "IP"), ("IPAddress", "192.0.2.1"),
                      ("Description", "keep me")):
        ET.SubElement(host, tag).text = text
    ent = ET.fromstring(build("iphost.update", {"name": "H", "ip_address": "192.0.2.9"}, host))[1][0]
    got = {c.tag: c.text for c in ent}
    if got != {"Name": "H", "IPFamily": "IPv4", "HostType": "IP", "IPAddress": "192.0.2.9", "Description": "keep me"}:
        fails.append(f"iphost.update must send the whole record with only the given fields changed: {got}")
    if ent.attrib != {"transactionid": ""}:
        fails.append("a merged record must carry an empty transactionid")


def check_merge_records(fails):
    svc = ET.fromstring("<Services><Name>S</Name><Type>ICMP</Type></Services>")
    if not base.raises(ValueError, build, "service.update", dict(SAMPLE["service.update"], name="S"), svc):
        fails.append("service.update must refuse a non TCPorUDP service")
    grp = ET.fromstring(build("firewall_rule_group.update", {"name": "G", "members": ["a", "b"]}, base.grp("G", ["a"])))[1][0]
    if sophos_api.group_members(grp) != ["a", "b"] or grp.findtext("Policytype") != "Any":
        fails.append("group update: members replaced, other group fields kept")


def check_shape(fails):
    r = res("firewall_rule.delete")
    good = build("firewall_rule.delete", {"name": "x"})
    tampered = {
        "two verbs": good.replace("</Remove>", "</Remove><Remove><FirewallRule><Name>y</Name></FirewallRule></Remove>"),
        "second entity": good.replace("</Remove>", "<IPHost><Name>y</Name></IPHost></Remove>"),
        "extra field in a remove": good.replace("</Name>", "</Name><Position>Top</Position>"),
        "wrong verb": good.replace("Remove>", "Set>").replace("<Remove", "<Set"),
        "login missing": good.replace("<Login><Username>admin</Username><Password>pw</Password></Login>", ""),
        "dtd": '<!DOCTYPE x [<!ENTITY a "b">]>' + good,
        "nested verb": good.replace("<Name>x</Name>", "<Name>x</Name><Get/>"),
        "no name": good.replace("<Name>x</Name>", ""),
    }
    for label, bad in tampered.items():
        if not base.raises(sophos_xml.ShapeError, sophos_xml.assert_request_shape, bad, r):
            fails.append(f"assert_request_shape accepted: {label}")
    add = res("iphost.add")
    x = build("iphost.add", SAMPLE["iphost.add"])
    if not base.raises(sophos_xml.ShapeError, sophos_xml.assert_request_shape, x.replace('operation="add"', 'operation="update"'), add):
        fails.append("assert_request_shape accepted a changed operation attribute")
    if not base.raises(sophos_xml.ShapeError, sophos_xml.assert_request_shape, x.replace("<IPFamily>", "<Set><IPFamily>")
                       .replace("</IPFamily>", "</IPFamily></Set>"), add):
        fails.append("assert_request_shape accepted a verb element inside the entity")


def check_status(fails):
    def resp(code, text, entity="IPHost"):
        return ET.fromstring(f'<Response><{entity}><Status code="{code}">{text}</Status></{entity}></Response>')

    if sophos_xml.parse_status(resp("200", "Configuration applied successfully."), "IPHost") != "Configuration applied successfully.":
        fails.append("status 200 must be ok")
    if sophos_xml.parse_status(resp("201", "Created"), "IPHost") != "Created":
        fails.append("any 2xx must be ok")
    top = ET.fromstring('<Response><Status code="200">fine</Status></Response>')
    if sophos_xml.parse_status(top, "IPHost") != "fine":
        fails.append("a top-level <Status code> must be read too")
    for label, root, kind, word in (
            ("534", resp("534", "Not allowed"), "api", "allowed API"),
            ("532", resp("532", "API disabled"), "api", "disabled"),
            ("auth failure", ET.fromstring("<Response><Status code=\"200\">Authentication Failure</Status></Response>"), "auth",
             "Authentication Failure"),
            ("500", resp("500", "Operation failed. Entity has dependents."), "api", "Entity has dependents"),
            ("no status", ET.fromstring("<Response><IPHost/></Response>"), "proto", "no <Status>")):
        try:
            sophos_xml.parse_status(root, "IPHost")
            fails.append(f"status {label}: must raise")
        except sophos_api.ApiError as e:
            if e.kind != kind or word not in str(e):
                fails.append(f"status {label}: wrong error kind/text: {e.kind} {e}")


def check_submit(fails):
    posted = []
    orig = sophos_xml.post
    sophos_xml.post = lambda dev, xml, timeout=30: posted.append(xml) or base.response("IPHost")
    try:
        dev = dict(base.DEV)
        plan, digest = base.make_steps_plan([{"resource": "iphost.add", "vars": SAMPLE["iphost.add"]}])
        xml = build("iphost.add", SAMPLE["iphost.add"])
        other = build("iphost.add", dict(SAMPLE["iphost.add"], name="OTHER"))
        verb = build("iphost.delete", SAMPLE["iphost.delete"])
        refusals = {
            "no plan": {},
            "no digest": dict(plan),
            "not yet approved": dict(plan, digest=digest),
        }
        for label, p in refusals.items():
            if not base.raises(sophos_xml.NotApproved, sophos_xml.submit, dev, xml, p):
                fails.append(f"submit must refuse: {label}")
        base.approve(plan, digest, consume=False)  # approved by the user but `apply` has not consumed it yet
        if not base.raises(sophos_xml.NotApproved, sophos_xml.submit, dev, xml, dict(plan, digest=digest)):
            fails.append("submit must refuse an approval that check_approval has not consumed")
        approved = base.approve(plan, digest)
        for label, req in (("another record name", other), ("another verb", verb)):
            if not base.raises(sophos_xml.NotApproved, sophos_xml.submit, dev, req, approved):
                fails.append(f"submit must refuse a request that is not in the plan: {label}")
        if not base.raises(sophos_xml.NotApproved, sophos_xml.submit, dict(dev, hostname="OTHER-FW"), xml, approved):
            fails.append("submit must refuse a host the plan does not name")
        if posted:
            fails.append("nothing may be posted by a refused submit")
        if sophos_xml.submit(dev, xml, approved) != "Configuration applied successfully." or len(posted) != 1:
            fails.append("submit of an approved, planned request must post once and return the status text")
        # the plan file changes after approval: the digest no longer matches
        path = change.plan_path(plan["id"])
        data = json.loads(path.read_text())
        data["steps"][0]["vars"]["name"] = "CHANGED"
        path.write_text(json.dumps(data, indent=2, sort_keys=True))
        if change.sha256_file(path) == digest or not base.raises(sophos_xml.NotApproved, sophos_xml.submit, dev, xml, approved):
            fails.append("plan sha must change with any step, and submit must refuse a plan changed after approval")
        if not base.raises(SystemExit, change.check_approval, plan["id"], change.sha256_file(path)):
            fails.append("check_approval must refuse the changed plan")
    finally:
        sophos_xml.post = orig


def check_submit_status(fails):
    orig = sophos_xml.post
    dev, xml = dict(base.DEV), build("iphost.add", SAMPLE["iphost.add"])
    try:
        plan2, digest2 = base.make_steps_plan([{"resource": "iphost.add", "vars": SAMPLE["iphost.add"]}])
        ap2 = base.approve(plan2, digest2)
        for code, text, kind in (("534", "x", "api"), ("532", "x", "api"), ("500", "boom", "api"),
                                 ("200", "Authentication Failure", "auth")):
            sophos_xml.post = lambda dev, x, timeout=30, c=code, t=text: base.response("IPHost", c, t)
            try:
                sophos_xml.submit(dev, xml, ap2)
                fails.append(f"submit: status {code} {text} must raise")
            except sophos_api.ApiError as e:
                if e.kind != kind:
                    fails.append(f"submit: status {code} -> kind {e.kind}, wanted {kind}")
    finally:
        sophos_xml.post = orig


def check_plan_steps(fails):
    for bad in ([], {}, [{"resource": "nope.add", "vars": {}}], [{"resource": "iphost.delete"}],
                [{"resource": "iphost.delete", "vars": {}}], [{"resource": "iphost.delete", "vars": {"name": "n"}, "x": 1}]):
        if not base.raises(SystemExit, change.check_steps, bad):
            fails.append(f"check_steps accepted {bad!r}")
    plan, digest = base.make_steps_plan([{"resource": "iphost.add", "vars": SAMPLE["iphost.add"]},
                                         {"resource": "service.add", "vars": SAMPLE["service.add"]}])
    if plan["kind"] != change.SOPHOS_XML or len(plan["requests"][base.DEV["hostname"]]) != 2:
        fails.append("steps plan: kind or rendered requests missing")
    if "pw" in json.dumps(plan) or "********" not in json.dumps(plan):
        fails.append("steps plan: the password must be masked in the stored requests")
    text = change.summary(plan, digest)
    if "<Name>HOST-1</Name>" not in text or "<DestinationPort>8443</DestinationPort>" not in text:
        fails.append("steps plan: the summary must show the exact rendered XML of every step")


class GenericFake:
    """Stores records per entity; applies add/update/remove posted through sophos_xml.post. fail: names that get a 500."""

    def __init__(self, seed=(), fail=()):
        self.db, self.fail, self.sent, self.saved = {}, set(fail), [], {}
        for rec in seed:
            self.db.setdefault(rec.tag, {})[rec.findtext("Name")] = rec

    def install(self):
        fw = base.FakeFirewall([])
        fw.fetch_entity = self.fetch_entity
        fw.post = self.post
        self.fw = fw.install()
        return self

    def uninstall(self):
        self.fw.uninstall()

    def fetch_entity(self, entity):
        recs = [ET.fromstring(ET.tostring(r)) for r in self.db.get(entity, {}).values()]
        return {"state": "ok" if recs else "empty", "status": None, "records": recs}

    def post(self, xml):
        verb = ET.fromstring(xml)[1]
        ent = verb[0]
        name = ent.findtext("Name")
        self.sent.append((verb.tag, verb.attrib.get("operation"), ent.tag, name))
        if name in self.fail:
            return base.response(ent.tag, "500", "Operation failed.")
        if verb.tag == "Remove":
            self.db.get(ent.tag, {}).pop(name, None)
        else:
            self.db.setdefault(ent.tag, {})[name] = ent
        return base.response(ent.tag)


def check_generic_apply(fails):
    host = ET.fromstring("<FQDNHost><Name>FQ-1</Name><FQDN>old.example.com</FQDN><Description>keep me</Description></FQDNHost>")
    steps = [{"resource": "fqdnhost.update", "vars": {"name": "FQ-1", "fqdn": "new.example.com"}},
             {"resource": "iphost.add", "vars": SAMPLE["iphost.add"]},
             {"resource": "service.add", "vars": SAMPLE["service.add"]},
             {"resource": "iphost.update", "vars": {"name": "HOST-1", "ip_address": "192.0.2.77"}},
             {"resource": "service.delete", "vars": SAMPLE["service.delete"] | {"name": "SVC-1"}}]
    gf = GenericFake([host]).install()
    try:
        plan, digest = base.make_steps_plan(steps)
        err, entry = base.run_plan(gf, plan, digest)
    finally:
        gf.uninstall()
    fq = gf.db["FQDNHost"]["FQ-1"]
    if err or fq.findtext("FQDN") != "new.example.com" or fq.findtext("Description") != "keep me":
        fails.append(f"generic apply: update must change the field and keep the rest of the record: {err}")
    if gf.db["IPHost"]["HOST-1"].findtext("IPAddress") != "192.0.2.77" or "SVC-1" in gf.db.get("Services", {}):
        fails.append("generic apply: iphost update or service delete did not take effect")
    if [s[0] + ":" + (s[1] or "") for s in gf.sent] != ["Set:update", "Set:add", "Set:add", "Set:update", "Remove:"]:
        fails.append(f"generic apply: steps must be sent in order: {gf.sent}")
    if not entry["backup"]:
        fails.append("generic apply: a backup must be taken first")



def check_generic_stops(fails):
    host = ET.fromstring("<FQDNHost><Name>FQ-1</Name><FQDN>old.example.com</FQDN><Description>keep me</Description></FQDNHost>")
    # stops at the first failing step: nothing after it is sent
    steps = [{"resource": "fqdnhost.add", "vars": {"name": "A", "fqdn": "a.example.com"}},
             {"resource": "iphost.add", "vars": SAMPLE["iphost.add"]},
             {"resource": "fqdnhost.delete", "vars": {"name": "A"}}]
    gf = GenericFake(fail=["HOST-1"]).install()
    try:
        plan, digest = base.make_steps_plan(steps)
        err, entry = base.run_plan(gf, plan, digest)
    finally:
        gf.uninstall()
    if not err or "500" not in err or len(gf.sent) != 2 or "A" not in gf.db["FQDNHost"]:
        fails.append(f"generic apply: must stop at the first failing step and never run the later delete: {err} {gf.sent}")
    # an update whose record is missing, and an update that did not take effect
    gf = GenericFake().install()
    try:
        plan, digest = base.make_steps_plan([{"resource": "fqdnhost.update", "vars": {"name": "Z", "fqdn": "z.example.com"}}])
        err, _ = base.run_plan(gf, plan, digest)
    finally:
        gf.uninstall()
    if not err or gf.sent:
        fails.append(f"an update of a record that does not exist must stop before sending: {err}")
    gf = GenericFake([host])
    gf.post = None
    gf.install()
    gf.fw.post = lambda xml: base.response("FQDNHost")  # claims success, changes nothing
    try:
        plan, digest = base.make_steps_plan([{"resource": "fqdnhost.update", "vars": {"name": "FQ-1", "fqdn": "q.example.com"}}])
        err, _ = base.run_plan(gf, plan, digest)
    finally:
        gf.uninstall()
    if not err or "verification failed" not in err:
        fails.append(f"a write that changes nothing must fail verification: {err}")


def check_cli(fails):
    def boom(*a, **k):
        raise AssertionError("render/list must never send")

    orig = sophos_xml.post
    sophos_xml.post = boom
    try:
        for argv, want in ((["list"], ["iphost.add", "firewall_rule.move", "Set update", "service.delete"]),
                           (["render", "iphost.add", "--var", "name=H", "--var", "host_type=IP", "--var", "ip_address=192.0.2.1"],
                            ["<Name>H</Name>", "********", "Set"]),
                           (["render", "firewall_rule_group.update", "--var", "name=G", "--var", "members=a", "--var", "members=b"],
                            ["<SecurityPolicy>a</SecurityPolicy>", "<SecurityPolicy>b</SecurityPolicy>"])):
            out, old = io.StringIO(), sys.argv
            sys.argv = ["sophos_xml.py", *argv]
            try:
                with contextlib.redirect_stdout(out):
                    sophos_xml.main()
            finally:
                sys.argv = old
            missing = [w for w in want if w not in out.getvalue()]
            if missing or "admin" in out.getvalue() or ">pw<" in out.getvalue():
                fails.append(f"cli {argv[0]}: output lacks {missing} or leaks credentials")
        # render --host: a read-only Get supplies the current record and the update shows the merged object
        seen = []
        saved = (sophos_api.resolve_firewalls, sophos_api.fetch_entity)
        sophos_api.resolve_firewalls = lambda ns: [dict(base.DEV)]
        sophos_api.fetch_entity = lambda dev, e: seen.append(e) or {
            "records": [ET.fromstring("<FQDNHost><Name>FQ-1</Name><FQDN>o.example.com</FQDN><Description>d</Description></FQDNHost>")]}
        out, old = io.StringIO(), sys.argv
        sys.argv = ["sophos_xml.py", "render", "fqdnhost.update", "--var", "name=FQ-1", "--var", "fqdn=n.example.com",
                    "--host", "FW-EDGE-01"]
        try:
            with contextlib.redirect_stdout(out):
                sophos_xml.main()
        finally:
            sys.argv = old
            sophos_api.resolve_firewalls, sophos_api.fetch_entity = saved
        if seen != ["FQDNHost"] or "<Description>d</Description>" not in out.getvalue() or "n.example.com" not in out.getvalue():
            fails.append(f"render --host must Get the record and show the merged update: {seen}")
    finally:
        sophos_xml.post = orig


def check_get_only(fails):
    """Every sophos_api CLI path sends only Login + Get; no write builder exists there any more."""
    for gone in ("build_add_rule_request", "build_remove_rule_request", "build_group_update_request",
                 "assert_add_rule_only", "assert_remove_rule_only", "assert_group_update_only", "_write",
                 "add_rule_clone", "add_rule_to_group", "remove_firewall_rule"):
        if hasattr(sophos_api, gone):
            fails.append(f"sophos_api.{gone} must be gone (writes live only in sophos_xml)")
    sent = []
    orig = sophos_api._post_xml
    sophos_api._post_xml = lambda dev, xml, timeout=30: sent.append(xml) or ET.fromstring(
        '<Response APIVersion="2000.1"><Login><status>Authentication Successful</status></Login><DNS><Name>d</Name></DNS></Response>')
    dev = dict(base.DEV, api_port=4444, verify_ssl=0)
    try:
        sophos_api.api_call(dev, ["FirewallRule", "IPHost"])
        sophos_api.fetch_entity(dev, "Services")
        sophos_api.run_get(dev, ["FQDNHost"], 5)
        sophos_api.backup_xml(dev, 5, ["FirewallRule", "FirewallRuleGroup"])
        sophos_api.backup_device(dev)
    finally:
        sophos_api._post_xml = orig
    if len(sent) < 7:
        fails.append(f"get-only: expected every CLI path to send, saw {len(sent)} requests")
    for x in sent:
        try:
            sophos_api.assert_get_only(x)
        except AssertionError as e:
            fails.append(f"get-only: a sophos_api verb sent a non-Get request: {e}")
        if any(w in x for w in ("<Set", "<Remove")):
            fails.append("get-only: a Set/Remove reached the wire from sophos_api")
    for xml in (build(n, v) for n, v in SAMPLE.items()):
        if not base.raises(AssertionError, sophos_api.assert_get_only, xml):
            fails.append("assert_get_only must reject every rendered write request")
    for e in ("Set", "Remove", "IPHost><Remove", "a b"):
        if not base.raises(ValueError, sophos_api.build_get_request, "u", "p", [e]):
            fails.append(f"build_get_request must refuse entity {e!r}")


def main():
    fails = []
    for fn in (check_resources, check_injection, check_vars, check_move_and_merge, check_merge_records, check_shape, check_status,
               check_submit, check_submit_status, check_plan_steps, check_generic_apply, check_generic_stops, check_cli, check_get_only):
        try:
            fn(fails)
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            fails.append(f"{fn.__name__} crashed: {type(e).__name__}: {e}")
    for f in fails:
        print("FAIL", f)
    print("sophos xml selftest:", "FAILED" if fails else "ok")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
