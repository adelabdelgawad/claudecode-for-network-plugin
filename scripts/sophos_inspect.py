"""Read-only Sophos inspection: list rules, look names up, see what uses an object, diff two snapshots.

Usage: cfn sophos-inspect rules SOURCE... [--name GLOB] [--group NAME] [--disabled]
       cfn sophos-inspect find  SOURCE... --name TEXT [--name TEXT ...]
       cfn sophos-inspect usage SOURCE... --object NAME
       cfn sophos-inspect diff  BEFORE AFTER

SOURCE is one of: a firewall hostname or IP from the inventory (read live, XML API `<Get>` only), a
`cfn sophos-api backup` file (.xml), or a directory written by `cfn sophos-api get ... --out`
(outputs/<ts>/<hostname>/). Nothing is ever written to a firewall.

  rules   one line per firewall rule: position, status, name, group, action, zones, networks, services
  find    where a name (substring, any case) exists: rules, NAT rules, hosts, FQDN hosts, groups, services,
          web filters, and as a member of any group; NOT FOUND otherwise
  usage   every rule, group and NAT rule that references an object (exact name)
  diff    what changed between two snapshots: renamed (same content, new name), added, removed, changed
          (which fields), rule order, rule-group membership, NAT rules
"""
import argparse
import fnmatch
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import change
import sophos_api

RULE_SET = ("FirewallRule", "FirewallRuleGroup", "NATRule")
OBJECTS = ("IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "Services", "ServiceGroup", "WebFilterPolicy")
GROUPS = ("FirewallRuleGroup", "IPHostGroup", "FQDNHostGroup", "ServiceGroup")
POLICIES = ("NetworkPolicy", "UserPolicy", "HTTPBasedPolicy")
DETAIL = {"IPHost": "IPAddress", "FQDNHost": "FQDN"}
NAME_TAGS = ("Name", "Description")


# --------------------------------------------------------------------------- sources
def _dir_records(d, entity):
    f = d / f"{entity}.xml"
    return sophos_api.entity_records(ET.parse(f).getroot(), entity)[0] if f.is_file() else []


def load_state(spec, entities):
    """(label, {entity: records}) for a hostname (live, read-only), a backup file or an outputs directory."""
    p = Path(spec)
    if p.is_file():
        meta, secs = sophos_api.load_backup(p)
        return f"{meta.get('host', '?')} ({p.name})", {e: secs.get(e, ("skipped", []))[1] for e in entities}
    if p.is_dir():
        return str(p), {e: _dir_records(p, e) for e in entities}
    ns = argparse.Namespace(targets=[spec], match=[], role=None, all=False, status="active")
    dev = sophos_api.resolve_firewalls(ns)[0]
    return dev["hostname"], {e: change.read_entity(dev, e) for e in entities}


def leaf_texts(rec):
    """[(tag, text)] of every leaf element of a record, except names and descriptions."""
    return [(e.tag, (e.text or "").strip()) for e in rec.iter()
            if e is not rec and len(e) == 0 and (e.text or "").strip() and e.tag not in NAME_TAGS]


def rname(rec):
    return (rec.findtext("Name") or "").strip()


# --------------------------------------------------------------------------- rules
def short(items, n=3):
    return ",".join(items[:n]) + (f"+{len(items) - n}" if len(items) > n else "") if items else "-"


def rule_line(pos, rec, group):
    pol = next((rec.find(t) for t in POLICIES if rec.find(t) is not None), None)

    def listed(path):
        return [(e.text or "").strip() for e in pol.findall(path)] if pol is not None else []

    return (f"#{pos:<3} {'E' if rec.findtext('Status') == 'Enable' else 'D'} {rname(rec)!r} [{group or '-'}] "
            f"{(pol.findtext('Action') if pol is not None else None) or '-'} "
            f"{short(listed('SourceZones/Zone'))}>{short(listed('DestinationZones/Zone'))} "
            f"src={short(listed('SourceNetworks/Network'))} dst={short(listed('DestinationNetworks/Network'))} "
            f"svc={short(listed('Services/Service'))}")


def cmd_rules(args):
    for spec in args.sources:
        label, st = load_state(spec, ("FirewallRule", "FirewallRuleGroup"))
        shown = []
        for pos, rec in enumerate(st["FirewallRule"], 1):
            grp = change.group_holding(st["FirewallRuleGroup"], rname(rec))
            gname = grp.findtext("Name") if grp is not None else ""
            if args.name and not fnmatch.fnmatch(rname(rec).lower(), args.name.lower()):
                continue
            if (args.group and gname != args.group) or (args.disabled and rec.findtext("Status") == "Enable"):
                continue
            shown.append(rule_line(pos, rec, gname))
        print(f"== {label}: {len(st['FirewallRule'])} rules, {len(shown)} shown")
        print("\n".join(f"  {s}" for s in shown))
    return 0


# --------------------------------------------------------------------------- find / usage
def find_hits(st, text):
    """Lines describing every place the (substring) `text` exists in the state."""
    low, hits = text.lower(), []
    for entity in ("FirewallRule", "NATRule", "FirewallRuleGroup", *OBJECTS):
        for pos, rec in enumerate(st.get(entity, []), 1):
            if low in rname(rec).lower():
                extra = rec.findtext(DETAIL[entity]) if entity in DETAIL else None
                where = f"#{pos} {rec.findtext('Status')}" if entity == "FirewallRule" else (extra or "")
                hits.append(f"FOUND {entity} {rname(rec)!r} {where}".rstrip())
    for entity in GROUPS:
        for rec in st.get(entity, []):
            hits += [f"FOUND member of {entity} {rname(rec)!r}: {t!r}" for _, t in leaf_texts(rec) if low in t.lower()]
    return hits or [f"NOT FOUND {text!r}"]


def cmd_find(args):
    for spec in args.sources:
        label, st = load_state(spec, ("FirewallRule", "NATRule", "FirewallRuleGroup", *OBJECTS))
        print(f"== {label}")
        for text in args.name:
            print("\n".join(f"  {h}" for h in find_hits(st, text)))
    return 0


def usage_hits(st, obj):
    """Lines for every rule, group and NAT rule that references the object `obj` (exact name, any case)."""
    low, hits = obj.lower(), []
    for pos, rec in enumerate(st.get("FirewallRule", []), 1):
        tags = sorted({t for t, x in leaf_texts(rec) if x.lower() == low})
        hits += [f"rule #{pos} {rname(rec)!r} ({', '.join(tags)})"] if tags else []
    for entity in (*GROUPS, "NATRule"):
        for rec in st.get(entity, []):
            tags = sorted({t for t, x in leaf_texts(rec) if x.lower() == low})
            hits += [f"{entity} {rname(rec)!r} ({', '.join(tags)})"] if tags else []
    return hits or [f"nothing references {obj!r}"]


def cmd_usage(args):
    for spec in args.sources:
        label, st = load_state(spec, ("FirewallRule", "NATRule", *GROUPS))
        print(f"== {label}")
        print("\n".join(f"  {h}" for h in usage_hits(st, args.object)))
    return 0


# --------------------------------------------------------------------------- diff
def _renames(b, a):
    """{old name: new name} for removed rules that reappear under another name with identical content."""
    renames = {}
    for old in (n for n in b if n not in a):
        new = next((n for n in a if n not in b and n not in renames.values()
                    and sophos_api.rule_content(a[n]) == sophos_api.rule_content(b[old])), None)
        if new:
            renames[old] = new
    return renames


def _by_field(rec):
    return {c.tag: sophos_api.canon(c) for c in rec if c.tag not in sophos_api.RULE_POSITION_TAGS}


def _changed_fields(old, new):
    o, n = _by_field(old), _by_field(new)
    return sorted(t for t in o.keys() | n.keys() if o.get(t) != n.get(t))


def _rule_diff(before, after):
    b, a = ({rname(r): r for r in st.get("FirewallRule", [])} for st in (before, after))
    renames = _renames(b, a)
    out = [("RENAMED", f"{o!r} -> {n!r}") for o, n in renames.items()]
    out += [("ADDED", repr(n)) for n in a if n not in b and n not in renames.values()]
    out += [("REMOVED", repr(n)) for n in b if n not in a and n not in renames]
    out += [("CHANGED", f"{n!r}: {', '.join(_changed_fields(b[n], a[n]))}")
            for n in b if n in a and sophos_api.rule_content(b[n]) != sophos_api.rule_content(a[n])]
    old_order = [renames.get(n, n) for n in b if n in a or n in renames]
    if old_order != [n for n in a if n in old_order]:
        out.append(("ORDER", "the order of the common rules differs"))
    return out, renames


def _group_diff(before, after, renames):
    b = {rname(g): {renames.get(m, m) for m in sophos_api.group_members(g)} for g in before.get("FirewallRuleGroup", [])}
    a = {rname(g): set(sophos_api.group_members(g)) for g in after.get("FirewallRuleGroup", [])}
    out = [("GROUP+", repr(n)) for n in a if n not in b] + [("GROUP-", repr(n)) for n in b if n not in a]
    for n in b.keys() & a.keys():
        if b[n] != a[n]:
            out.append(("GROUP", f"{n!r}: +{sorted(a[n] - b[n])} -{sorted(b[n] - a[n])}"))
    return out


def _nat_diff(before, after):
    b, a = ({rname(r): sophos_api.canon(r) for r in st.get("NATRule", [])} for st in (before, after))
    return ([("NAT+", repr(n)) for n in a if n not in b] + [("NAT-", repr(n)) for n in b if n not in a]
            + [("NAT", f"{n!r} changed") for n in b if n in a and a[n] != b[n]])


def diff_states(before, after):
    """[(kind, text)]: differences in rules, rule groups and NAT rules (renames are recognised, not reported twice)."""
    rules, renames = _rule_diff(before, after)
    return rules + _group_diff(before, after, renames) + _nat_diff(before, after)


def cmd_diff(args):
    (lb, before), (la, after) = (load_state(s, RULE_SET) for s in (args.before, args.after))
    lines = diff_states(before, after)
    print(f"== {lb}  ->  {la}")
    print("\n".join(f"  {k:8} {t}" for k, t in lines) if lines else "  no differences")
    return 0


# --------------------------------------------------------------------------- cli
def main():
    ap = argparse.ArgumentParser(description="Read-only Sophos inspection")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("rules", help="list firewall rules")
    p.add_argument("sources", nargs="+", metavar="SOURCE")
    p.add_argument("--name", help="glob on the rule name (case-insensitive)")
    p.add_argument("--group", help="only rules in this rule group")
    p.add_argument("--disabled", action="store_true", help="only disabled rules")
    p.set_defaults(fn=cmd_rules)
    p = sub.add_parser("find", help="where do these names exist")
    p.add_argument("sources", nargs="+", metavar="SOURCE")
    p.add_argument("--name", action="append", required=True, metavar="TEXT")
    p.set_defaults(fn=cmd_find)
    p = sub.add_parser("usage", help="what references an object")
    p.add_argument("sources", nargs="+", metavar="SOURCE")
    p.add_argument("--object", required=True)
    p.set_defaults(fn=cmd_usage)
    p = sub.add_parser("diff", help="differences between two snapshots")
    p.add_argument("before")
    p.add_argument("after")
    p.set_defaults(fn=cmd_diff)
    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
