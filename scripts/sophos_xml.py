"""Template-driven Sophos Firewall (SFOS) XML executor: the ONLY place a Sophos write request is built or sent.

Usage: cfn sophos-xml list
       cfn sophos-xml render RESOURCE [--var k=v ...] [--host FIREWALL]

Design (inspired by the Apache-2.0 sophos/sophos-firewall-sdk: one XML template per action and one submit
function), stdlib only. Each resources/sophos/<entity>.<action>.xml holds a header comment declaring its verb
(`Set add` | `Set update` | `Remove`), entity and variables, then the XML with `$var` placeholders. Placeholders
may stand only in element text (checked at load) and every value is XML-escaped, so a value can never add an
element or attribute. An update or copy template lists just the fields it sets; the rest of the full record
is carried over from a live Get (the SDK's update() also sends the whole object).

Safety: build() re-parses what it rendered and refuses unless it is exactly <Login> + one declared verb holding one
declared entity. submit() refuses unless `cfn change apply` has consumed the user's APPROVE for the plan that lists
this request (change.check_approval ran; the plan file still hashes to the approved digest).
`list` and `render` never send a write; `render --host` only does a read-only <Get> (password masked).
"""
import argparse
import copy
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from xml.sax.saxutils import escape

import sophos_api
from sophos_api import ApiError, canon

RES_DIR = Path(__file__).resolve().parent.parent / "resources" / "sophos"
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
HEADER_RE = re.compile(r"\A\s*<!--\s*cfn-resource\n(.*?)-->", re.DOTALL)
PLACEHOLDER_RE = re.compile(r">\$([a-z][a-z0-9_]*)<")
VERBS = {"Set add": ("Set", {"operation": "add"}), "Set update": ("Set", {"operation": "update"}),
         "Remove": ("Remove", {})}
VERB_TAGS = {"set", "remove", "get", "login", "request", "add", "update", "delete"}
MASK = "********"
PREVIEW_USER = "API_USER"
MAX_VALUE = 1024
APPROVAL_FRESH_MIN = 60
WATCH = {"FirewallRule": ("FirewallRule", "FirewallRuleGroup"), "FirewallRuleGroup": ("FirewallRule", "FirewallRuleGroup")}


class ShapeError(ValueError):
    """A rendered request is not exactly the declared verb + entity."""


class NotApproved(Exception):
    """submit() was called without a consumed approval for a plan that lists the request."""


# --------------------------------------------------------------------------- resources
class Resource:
    """One parsed template: manifest fields plus the XML body."""

    def __init__(self, name, meta, body):
        self.name, self.body = name, body
        self.verb = meta.get("verb", "")
        if self.verb not in VERBS:
            raise ValueError(f"{name}: verb must be one of {sorted(VERBS)}")
        self.tag, self.attrib = VERBS[self.verb][0], dict(VERBS[self.verb][1])
        self.entity, self.key = meta.get("entity", ""), meta.get("key", "")
        self.required, self.optional = meta.get("vars", "").split(), meta.get("optional", "").split()
        self.defaults = dict(p.split("=", 1) for p in meta.get("defaults", "").split())
        self.lists = dict(p.split("=", 1) for p in meta.get("lists", "").split())
        self.prune, self.drop = meta.get("prune", "").split(), meta.get("drop", "").split()
        self.choices = {p.split("=", 1)[0]: p.split("=", 1)[1].split("|") for p in meta.get("choices", "").split()}
        self.record_from, self.rulenames = meta.get("record_from", ""), meta.get("rulenames", "").split()
        self.record_must = dict(p.split("=", 1) for p in meta.get("record_must", "").split())
        self.requires = parse_requires(meta.get("requires", ""))
        self.check_body()

    @property
    def variables(self):
        return self.required + self.optional

    def check_body(self):
        found = PLACEHOLDER_RE.findall(self.body)
        if self.body.count("$") != len(found):
            raise ValueError(f"{self.name}: a $placeholder stands outside element text")
        if set(found) != set(self.variables) or self.key not in self.variables:
            raise ValueError(f"{self.name}: placeholders {sorted(set(found))} differ from the declared vars")
        root = ET.fromstring(self.body)
        if (root.tag, root.attrib) != (self.tag, self.attrib) or [c.tag for c in root] != [self.entity]:
            raise ValueError(f"{self.name}: body does not match the declared verb/entity")


def parse_requires(text):
    """'position After:after Before:before Top:' -> (var, {value: [required vars]}), or None."""
    parts = text.split()
    if not parts:
        return None
    return parts[0], {p.split(":", 1)[0]: [x for x in p.split(":", 1)[1].split(",") if x] for p in parts[1:]}


def load_resource(name):
    """Load and validate resources/sophos/<name>.xml (name is entity.action; no paths)."""
    if not NAME_RE.match(name):
        raise ValueError(f"invalid resource name {name!r}")
    path = RES_DIR / f"{name}.xml"
    if not path.is_file():
        raise ValueError(f"unknown resource {name!r} (try: cfn sophos-xml list)")
    text = path.read_text()
    m = HEADER_RE.match(text)
    if not m:
        raise ValueError(f"{name}: missing cfn-resource header comment")
    meta = {}
    for line in m.group(1).splitlines():
        if line.strip():
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return Resource(name, meta, text[m.end():].strip())


def list_resources():
    return [load_resource(p.stem) for p in sorted(RES_DIR.glob("*.xml"))]


# --------------------------------------------------------------------------- rendering
def _check_text(key, s):
    if not isinstance(s, str) or len(s) > MAX_VALUE or any(ord(c) < 32 for c in s):
        raise ValueError(f"variable {key}: must be text of at most {MAX_VALUE} characters, no control characters")


def check_vars(res, given):
    """Defaults + given values, validated against the manifest; returns {var: str | [str]}."""
    unknown = set(given) - set(res.variables)
    if unknown:
        raise ValueError(f"{res.name}: unknown variable(s) {sorted(unknown)}")
    vals = {k: ([] if k in res.lists else "") for k in res.variables}
    vals.update(res.defaults)
    vals.update({k: v for k, v in given.items() if v not in ("", None, [])})
    for k in res.variables:
        v = vals[k]
        if (k in res.lists) != isinstance(v, list):
            raise ValueError(f"variable {k}: expected {'a list' if k in res.lists else 'text'}")
        for s in (v if isinstance(v, list) else [v]):
            _check_text(k, s)
        if k in res.required and not v:
            raise ValueError(f"{res.name}: required variable {k} is missing")
        if k in res.choices and v and v not in res.choices[k]:
            raise ValueError(f"variable {k}: must be one of {res.choices[k]}")
        if k in res.rulenames:
            for s in (v if isinstance(v, list) else [v] if v else []):
                sophos_api.check_rule_name(s)
    _check_requires(res, vals)
    return vals


def _check_requires(res, vals):
    if not res.requires:
        return
    var, table = res.requires
    needed = table.get(vals[var], [])
    for g in {x for xs in table.values() for x in xs}:
        if (g in needed) != bool(vals[g]):
            raise ValueError(f"{res.name}: with {var}={vals[var]} {g} must be {'given' if g in needed else 'empty'}")


def _expand(tag, items):
    return "".join(f"<{tag}>{escape(s)}</{tag}>" for s in items)


def _prune(parent, tags):
    """Remove (bottom-up) elements named in `tags` that hold no text anywhere inside."""
    for child in list(parent):
        _prune(child, tags)
        if child.tag in tags and not any((e.text or "").strip() for e in child.iter()):
            parent.remove(child)


def _merge(verb, res, record, vals):
    """Replace `verb`'s entity by the live record with the template's fields laid over it."""
    ent = verb[0]
    if record.tag != ent.tag:
        raise ValueError(f"record is a {record.tag}, expected {ent.tag}")
    for tag, text in res.record_must.items():
        if (record.findtext(tag) or "").strip() != text:
            raise ValueError(f"{res.name}: the current record's {tag} is not {text!r}")
    base = copy.deepcopy(record)
    base.attrib.clear()
    base.set("transactionid", "")
    if res.verb == "Set update" and (base.findtext("Name") or "").strip() != vals[res.key]:
        raise ValueError("the current record is not the one named in the request")
    for tag in res.drop:
        for e in base.findall(tag):
            base.remove(e)
    prev = None
    for new in list(ent):
        olds = base.findall(new.tag)
        if olds:
            at = list(base).index(olds[0])
            for o in olds:
                base.remove(o)
        else:
            prevs = base.findall(prev) if prev else []
            at = list(base).index(prevs[-1]) + 1 if prevs else len(base)
        base.insert(at, new)
        prev = new.tag
    verb.remove(ent)
    verb.append(base)


def render(res, given, record=None):
    """The verb element (<Set ..>/<Remove>) for `given` vars; with `record`, the full merged object."""
    vals = check_vars(res, given)
    mapping = {k: _expand(res.lists[k], v) if k in res.lists else escape(v) for k, v in vals.items()}
    verb = ET.fromstring(Template(res.body).substitute(mapping))
    _prune(verb, res.prune)
    if record is not None and res.verb != "Remove":
        _merge(verb, res, record, vals)
    return verb


def wrap_login(verb, user, password):
    req = ET.Element("Request")
    login = ET.SubElement(req, "Login")
    ET.SubElement(login, "Username").text = user      # ElementTree escapes the text
    ET.SubElement(login, "Password").text = password
    req.append(verb)
    return ET.tostring(req, encoding="unicode")


def _need(ok, msg):
    if not ok:
        raise ShapeError(msg)


def assert_request_shape(xml, res):
    """Re-parse `xml` and require exactly Login + one declared verb holding one declared entity, nothing else."""
    _need("<!" not in xml, "DTD/entity/comment markup is not allowed")
    root = ET.fromstring(xml)
    _need(root.tag == "Request" and [c.tag for c in root] == ["Login", res.tag], f"expected Login then {res.tag}")
    login, op = root
    _need([c.tag for c in login] == ["Username", "Password"], "unexpected <Login> content")
    _need(op.attrib == res.attrib and [c.tag for c in op] == [res.entity], f"expected exactly one {res.entity}")
    ent = op[0]
    _need(set(ent.attrib) <= {"transactionid"}, "unexpected attributes on the entity")
    names = ent.findall("Name")
    _need(len(names) == 1 and (names[0].text or "").strip(), "the entity needs exactly one non-empty Name")
    _need(res.verb != "Remove" or [c.tag for c in ent] == ["Name"], "a Remove may name one record and nothing else")
    for e in ent.iter():
        _need(e.tag.lower() not in VERB_TAGS, f"element <{e.tag}> inside the entity")


def build(res, given, user, password, record=None):
    """Render + wrap Login + assert shape. Returns the request XML string (does not send)."""
    xml = wrap_login(render(res, given, record), user, password)
    assert_request_shape(xml, res)
    return xml


def mask_password(xml):
    root = ET.fromstring(xml)
    root.find("Login/Password").text = MASK
    return ET.tostring(root, encoding="unicode")


# --------------------------------------------------------------------------- approval + sending
def covers(planned, xml):
    """True when `xml` has the planned verb/entity and every field the plan listed (merged extras allowed)."""
    p, x = ET.fromstring(planned), ET.fromstring(xml)
    pv, xv = p[1], x[1]
    if (pv.tag, pv.attrib, [c.tag for c in pv]) != (xv.tag, xv.attrib, [c.tag for c in xv]):
        return False
    return all(canon(c) in [canon(e) for e in xv[0].findall(c.tag)] for c in pv[0])


def _require_approved(plan):
    import change   # lazy: change imports this module
    cid, digest = plan.get("id"), plan.get("digest")
    if not cid or not digest:
        raise NotApproved("no approved plan given")
    path = change.plan_path(cid)
    if not path.is_file() or change.sha256_file(path) != digest:
        raise NotApproved(f"{cid}: the plan file is missing or changed since it was approved")
    appr = change.load_json(change.APPROVALS / f"{cid}.json") or {}
    if appr.get("status") != "approved" or appr.get("plan_sha256") != digest or not appr.get("consumed"):
        raise NotApproved(f"{cid}: no consumed approval for this plan (the user must type APPROVE {cid})")
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(appr["consumed_at"])
    except (KeyError, ValueError):
        raise NotApproved(f"{cid}: approval record has no valid consumed_at")
    if age.total_seconds() > APPROVAL_FRESH_MIN * 60:
        raise NotApproved(f"{cid}: the approval was consumed more than {APPROVAL_FRESH_MIN} minutes ago")


def post(dev, xml, timeout=30):
    """The one HTTP send (tests replace it). Transport + login check live in sophos_api."""
    return sophos_api._post_xml(dev, xml, timeout)


def parse_status(root, entity, what="request"):
    """API status text for a write response; raises ApiError on anything but a 2xx code."""
    st = root.find(f"{entity}/Status")
    if st is None:
        st = next((e for e in root.findall("Status") if "code" in e.attrib), None)
    if st is None:
        raise ApiError("proto", f"no <Status> in the response to: {what}")
    code, text = st.get("code", ""), (st.text or "").strip()
    if "authentication failure" in text.lower():
        raise ApiError("auth", f"{what}: Authentication Failure (bad credentials)")
    if code == "532":
        raise ApiError("api", f"{what}: API is disabled on the firewall (532) {text[:100]}".rstrip())
    if code == "534":
        raise ApiError("api", f"{what}: this host's IP is not in the firewall's allowed API addresses (534) {text[:100]}".rstrip())
    if not (code.isdigit() and 200 <= int(code) < 300):
        raise ApiError("api", f"{what} refused: {code or '?'} {text[:150]}")
    return text


def submit(dev, xml, approved_plan, timeout=30):
    """Send one request that the approved plan lists. Returns the status text; raises NotApproved / ApiError."""
    _require_approved(approved_plan)
    for item in approved_plan.get("requests", {}).get(dev["hostname"], []):
        res = load_resource(item["resource"])
        try:
            assert_request_shape(xml, res)
        except ShapeError:
            continue
        if covers(item["xml"], xml):
            return parse_status(post(dev, xml, timeout), res.entity, res.name)
    raise NotApproved("this request is not one of the requests in the approved plan")


# --------------------------------------------------------------------------- reading + verification
def name_of(rec):
    return (rec.findtext("Name") or "").strip()


def pick_record(res, vals, records):
    """The live record a template merges into / acts on (None for a plain add); RuntimeError if it is missing."""
    want = vals.get(res.record_from) if res.record_from else (vals.get(res.key) if res.verb == "Remove" else None)
    if want is None:
        return None
    found = [r for r in records if name_of(r) == want]
    if len(found) != 1:
        raise RuntimeError(f"{res.entity} {want!r} found {len(found)} times on the firewall (expected 1)")
    return found[0]


def watched(res):
    return WATCH.get(res.entity, (res.entity,))


def fields_match(res, vals, rec):
    """True when `rec` already holds every field the template would set (an update would change nothing)."""
    skel = render(res, vals)[0]
    return all(sorted(canon(c) for c in skel.findall(t.tag)) == sorted(canon(c) for c in rec.findall(t.tag))
               for t in skel)


def check_expect(rec, expect):
    """Raise RuntimeError unless the live record has the values the plan was made against."""
    for tag, want in expect.items():
        e = rec.find(tag)
        got = [(c.text or "").strip() for c in e] if isinstance(want, list) and e is not None else \
            (e.text or "").strip() if e is not None else None
        if got != want:
            raise RuntimeError(f"{name_of(rec)!r}: {tag} is {got!r} now, the plan was made against {want!r}; re-plan")


def _moved(pairs, vals):
    """Rule (name, content) pairs after `name` moves per position/after/before."""
    name = vals["name"]
    item = next(p for p in pairs if p[0] == name)
    rest = [p for p in pairs if p[0] != name]
    names = [p[0] for p in rest]
    pos = vals["position"]
    anchor = vals.get("after") if pos == "After" else vals.get("before")
    if pos in ("After", "Before") and anchor not in names:
        raise RuntimeError(f"move anchor {anchor!r} is not another rule on the firewall")
    at = {"Top": 0, "Bottom": len(rest)}.get(pos)
    if at is None:
        at = names.index(anchor) + (1 if pos == "After" else 0)
    return rest[:at] + [item] + rest[at:]


def _rule_pairs(recs):
    return [(name_of(r), sophos_api.rule_content(r)) for r in recs]


def _rule_problems(res, vals, before, after):
    pairs = _rule_pairs(before["FirewallRule"])
    action = res.name.split(".")[1]
    if action == "add_copy":
        i = [p[0] for p in pairs].index(vals["old"])
        want = pairs[:i + 1] + [(vals["new"], pairs[i][1])] + pairs[i + 1:]
    elif action == "delete":
        want = [p for p in pairs if p[0] != vals["name"]]
    else:
        want = _moved(pairs, vals)
    got = _rule_pairs(after["FirewallRule"])
    if [p[0] for p in got] != [p[0] for p in want]:
        return [f"rule list is not as expected: {[p[0] for p in got]} (wanted {[p[0] for p in want]})"]
    return [] if got == want else ["some rule's content differs from what was expected"]


def _members(recs):
    return {name_of(g): sophos_api.group_members(g) for g in recs}


def _group_problems(res, vals, before, after):
    b, a = _members(before["FirewallRuleGroup"]), _members(after["FirewallRuleGroup"])
    action = res.name.split(".")[1]
    if action == "delete":
        want = {g: [m for m in ms if m != vals["name"]] for g, ms in b.items()}
    elif action == "add_copy":   # a copy may join its original's group by itself
        joined = {g: ms[:ms.index(vals["old"]) + 1] + [vals["new"]] + ms[ms.index(vals["old"]) + 1:] if vals["old"] in ms
                  else ms for g, ms in b.items()}
        return [] if a in (b, joined) else ["rule group membership changed unexpectedly after the copy"]
    else:
        want = b
    return [] if a == want else [f"rule group membership differs: {a} (wanted {want})"]


def _plain_problems(res, vals, before, after):
    key = vals[res.key]
    b, a = {name_of(r): r for r in before}, {name_of(r): r for r in after}
    probs = []
    if res.verb == "Remove":
        probs += [f"{res.entity} {key!r} is still present"] if key in a else []
    elif key not in a:
        return [f"{res.entity} {key!r} is not present after the {res.verb}"]
    elif not fields_match(res, vals, a[key]):
        probs.append(f"{res.entity} {key!r} does not hold the requested field values")
    if sorted(n for n in b if n != key) != sorted(n for n in a if n != key):
        probs.append(f"the set of other {res.entity} records changed")
    elif any(canon(a[n]) != canon(b[n]) for n in b if n != key):
        probs.append(f"another {res.entity} record changed")
    return probs


def verify_step(res, vals, before, after):
    """Problems (list of text; empty = verified) between the entity snapshots taken before and after one step."""
    if res.entity == "FirewallRule":
        return _rule_problems(res, vals, before, after) + _group_problems(res, vals, before, after)
    probs = _plain_problems(res, vals, before[res.entity], after[res.entity])
    if res.entity == "FirewallRuleGroup":
        got = _members(after["FirewallRuleGroup"]).get(vals["name"])
        probs += [] if got == vals["members"] else [f"group lists {got}, wanted {vals['members']}"]
    return probs


# --------------------------------------------------------------------------- CLI
def parse_var_args(res, pairs):
    out = {}
    for p in pairs:
        k, sep, v = p.partition("=")
        if not sep:
            raise SystemExit(f"bad --var {p!r} (expected key=value)")
        out[k] = out.get(k, []) + [v] if k in res.lists else v
    return out


def cmd_list(args):
    for r in list_resources():
        req = " ".join(r.required)
        opt = " ".join(f"[{o}]" for o in r.optional)
        print(f"{r.name:30} {r.verb:11} {r.entity:17} vars: {req} {opt}".rstrip())


def _live_record(args, res, vals):
    ns = argparse.Namespace(targets=[args.host], match=[], role=None, all=False, status="active")
    dev = sophos_api.resolve_firewalls(ns)[0]
    return pick_record(res, vals, sophos_api.fetch_entity(dev, res.entity)["records"]) if res.record_from else None


def cmd_render(args):
    res = load_resource(args.resource)
    vals = parse_var_args(res, args.var)
    record = _live_record(args, res, check_vars(res, vals)) if args.host else None
    xml = build(res, vals, PREVIEW_USER, MASK, record)
    print(f"# {res.name}: {res.verb} {res.entity}" + (" (merged with the live record, read-only Get)" if record is not None
          else " (template fields only; unlisted fields are carried over from the live record at apply)"))
    root = ET.fromstring(xml)
    ET.indent(root)
    print(ET.tostring(root, encoding="unicode"))


def main():
    ap = argparse.ArgumentParser(description="Sophos XML resource library: list and preview (never writes)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="resources with verb, entity and variables").set_defaults(fn=cmd_list)
    p = sub.add_parser("render", help="preview the request a resource renders to (password masked)")
    p.add_argument("resource")
    p.add_argument("--var", action="append", default=[], metavar="k=v", help="repeat for list variables")
    p.add_argument("--host", help="firewall to Get the current record from, to show the merged update (read-only)")
    p.set_defaults(fn=cmd_render)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
