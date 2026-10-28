"""Read-only comparison of firewall rules across several Sophos XG firewalls.

Usage: cfn sophos_compare SOURCE SOURCE [SOURCE ...] [--min-score 0.6] [--groups FILE] [--out DIR]

SOURCE is what `cfn sophos-inspect` takes: a firewall hostname/IP from the inventory (read live, <Get> only), a
`cfn sophos-api backup` file (.xml) or an outputs directory with FirewallRule.xml. Nothing is written to a firewall.

Rules are matched by PURPOSE, not by literal name: a pair scores from normalized-name similarity (typos, spacing,
word order) and content similarity (same action class and traffic direction are required; destinations, services
and web filter are compared). Groups hold at most one rule per firewall. Output goes to
reports/sophos_compare/<timestamp>/report.md (common to all, common to some, site-specific, rule-order problems)
and groups.json. `--groups FILE` is a JSON list of {firewall_label: rule_name} that pins groups before matching.
Recommended names are proposals only; renaming or reordering is a firewall change and needs a change plan.
"""
import argparse
import difflib
import itertools
import json
import re
import sys
from collections import Counter
from pathlib import Path

import netlib
import sophos_api
import sophos_inspect
from sophos_inspect import POLICIES, rname

NAME_W, CONTENT_W = 0.6, 0.4
DISJOINT_FACTOR = 0.8  # both name destinations and share none: the rules are probably site-specific
DST_W = 2  # destinations say most about a rule's purpose
SUBSET_SCORE = 0.85  # one name's words all appear in the other ("Dental" in "Dental Desktops")
STOP = {"to", "all", "allowed", "the", "for", "of", "and", "a", "from", "by"}
VERBS = {"allow", "block", "drop", "deny", "reject", "publish", "accept"}
ANY = {"", "any"}
OBJ_NOISE = re.compile(r"(fqdnhostgroup|iphostgroup|fqdnhost|iphost|fqdn|host|group|ips?)")


# --------------------------------------------------------------------------- features
def _policy(rec):
    return next((rec.find(t) for t in POLICIES if rec.find(t) is not None), None)


def _listed(pol, path):
    return [(e.text or "").strip() for e in pol.findall(path) if (e.text or "").strip()] if pol is not None else []


def action_class(action):
    return "allow" if action == "Accept" else "block" if action in ("Drop", "Reject") else (action or "?").lower()


def direction(src_zones, dst_zones):
    """inbound (from WAN only), outbound (to WAN, not from WAN) or other."""
    src, dst = {z.upper() for z in src_zones}, {z.upper() for z in dst_zones}
    if src == {"WAN"} and "WAN" not in dst:
        return "inbound"
    if ("WAN" in dst or not dst) and "WAN" not in src:
        return "outbound"
    return "other"


def features(pos, rec):
    pol = _policy(rec)
    sz, dz = _listed(pol, "SourceZones/Zone"), _listed(pol, "DestinationZones/Zone")
    wf = (pol.findtext("WebFilter") or "") if pol is not None else ""
    return {"name": rname(rec), "pos": pos, "enabled": rec.findtext("Status") == "Enable",
            "action": (pol.findtext("Action") if pol is not None else None) or "",
            "cls": action_class(pol.findtext("Action") if pol is not None else None),
            "dir": direction(sz, dz), "src_zones": sz, "dst_zones": dz,
            "src": _listed(pol, "SourceNetworks/Network"), "dst": _listed(pol, "DestinationNetworks/Network"),
            "svc": _listed(pol, "Services/Service"),
            "identity": bool(_listed(pol, "Identity/Member")),
            "webfilter": "" if wf.lower() in ("none", "") else wf}


def is_any(items):
    return not items or any(i.lower() == "any" for i in items)


# --------------------------------------------------------------------------- similarity
def split_words(text):
    """Lowercase words of a name, splitting camelCase, digits-kept, punctuation removed."""
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    return re.findall(r"[a-z0-9]+", text.lower())


def name_words(name):
    return [w for w in split_words(name) if w not in STOP]


def _near(w, words):
    return any(difflib.SequenceMatcher(None, w, o).ratio() >= 0.8 for o in words)


def name_similarity(a, b):
    wa, wb = name_words(a), name_words(b)
    small, big = sorted((wa, wb), key=len)
    if small and len(small) < len(big) and all(_near(w, big) for w in small):
        return max(SUBSET_SCORE, name_similarity_chars(wa, wb))
    return name_similarity_chars(wa, wb)


def name_similarity_chars(wa, wb):
    plain = difflib.SequenceMatcher(None, "".join(wa), "".join(wb)).ratio()
    ordered = difflib.SequenceMatcher(None, " ".join(sorted(wa)), " ".join(sorted(wb))).ratio()
    return max(plain, ordered)


def norm_obj(obj):
    o = re.sub(r"[^a-z0-9.*]", "", obj.lower())
    return OBJ_NOISE.sub("", o) or o


def jaccard(a, b):
    a, b = set(a), set(b)
    return len(a & b) / len(a | b) if a | b else 1.0


def obj_words(items):
    return {w for x in items for w in split_words(OBJ_NOISE.sub(" ", x.lower())) if len(w) > 2}


def list_similarity(a, b, normalize=norm_obj, words=True):
    """1 for any vs any, 0 for any vs a named list, else Jaccard of the normalized members (or of their words)."""
    if is_any(a) or is_any(b):
        return 1.0 if is_any(a) and is_any(b) else 0.0
    exact = jaccard([normalize(x) for x in a], [normalize(x) for x in b])
    return max(exact, jaccard(obj_words(a), obj_words(b))) if words and normalize is norm_obj else exact


def same_filter(a, b):
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio() >= 0.85


def content_similarity(a, b):
    """Destinations (by object, or by shared words except for inbound publishes), services, web filter."""
    words = a["dir"] != "inbound"
    parts = [(DST_W, list_similarity(a["dst"], b["dst"], words=words)), (1, list_similarity(a["svc"], b["svc"], str.lower))]
    if a["webfilter"] or b["webfilter"]:
        parts.append((1, 1.0 if same_filter(a["webfilter"], b["webfilter"]) else 0.0))
    return sum(w * v for w, v in parts) / sum(w for w, _ in parts)


def compatible(a, b):
    return a["cls"] == b["cls"] and a["dir"] == b["dir"]


def pair_score(a, b):
    if not compatible(a, b):
        return 0.0
    score = NAME_W * name_similarity(a["name"], b["name"]) + CONTENT_W * content_similarity(a, b)
    disjoint = not is_any(a["dst"]) and not is_any(b["dst"]) and list_similarity(a["dst"], b["dst"], words=a["dir"] != "inbound") == 0
    return score * DISJOINT_FACTOR if disjoint else score


# --------------------------------------------------------------------------- grouping
def group_score(g1, g2, scores):
    """Average pair score between two groups; 0 when they share a firewall or any pair is far below par."""
    if {fw for fw, _ in g1} & {fw for fw, _ in g2}:
        return 0.0
    vals = [scores.get((m1, m2), scores.get((m2, m1), 0.0)) for m1 in g1 for m2 in g2]
    return sum(vals) / len(vals) if min(vals) > 0 else 0.0


def all_scores(rules):
    """{((fw, i), (fw2, j)): score} for rules of different firewalls."""
    out = {}
    for (fa, ra), (fb, rb) in itertools.combinations(rules.items(), 2):
        for i, a in enumerate(ra):
            for j, b in enumerate(rb):
                out[((fa, i), (fb, j))] = pair_score(a, b)
    return out


def best_merge(groups, scores, floor):
    best = (floor, None)
    for g1, g2 in itertools.combinations(groups, 2):
        s = group_score(g1, g2, scores)
        if s > best[0] or (s == best[0] and best[1] is None and s > 0 and s >= floor):
            best = (s, (g1, g2))
    return best[1]


def auto_groups(rules, taken, min_score):
    """Greedy average-linkage clustering of the not-yet-pinned rules, one rule per firewall per group."""
    scores = all_scores(rules)
    groups = [[(fw, i)] for fw, rs in rules.items() for i in range(len(rs)) if (fw, i) not in taken]
    while True:
        pick = best_merge(groups, scores, min_score)
        if not pick:
            return groups
        groups.remove(pick[0])
        groups.remove(pick[1])
        groups.append(pick[0] + pick[1])


def load_pins(path, rules, labels):
    """[[(fw, index)...]] from a JSON list of {label: rule name}; SystemExit for an unknown label or rule."""
    data = json.loads(Path(path).read_text())
    if not isinstance(data, list):
        sys.exit("--groups: the file must be a JSON list of {firewall_label: rule_name}")
    pins, seen = [], set()
    low = {lb.lower(): lb for lb in labels}
    for entry in data:
        grp = []
        for label, name in entry.items():
            fw = low.get(label.lower())
            idx = next((i for i, r in enumerate(rules.get(fw, [])) if r["name"].lower() == str(name).lower()), None)
            if fw is None or idx is None:
                sys.exit(f"--groups: no rule {name!r} on firewall {label!r} (labels: {', '.join(labels)})")
            if (fw, idx) in seen:
                sys.exit(f"--groups: rule {name!r} on {label!r} is pinned twice")
            seen.add((fw, idx))
            grp.append((fw, idx))
        if len({fw for fw, _ in grp}) != len(grp):
            sys.exit("--groups: a pinned group may hold one rule per firewall")
        pins.append(grp)
    return pins


def build_groups(rules, min_score, pins=()):
    taken = {m for g in pins for m in g}
    groups = [list(g) for g in pins] + auto_groups(rules, taken, min_score)
    order = {fw: n for n, fw in enumerate(rules)}
    for g in groups:
        g.sort(key=lambda m: order[m[0]])
    return sorted(groups, key=lambda g: (-len(g), order[g[0][0]], g[0][1]))


# --------------------------------------------------------------------------- recommended names
def _canon_words(names):
    """{word: spelling} mapping each word to the most common spelling of its fuzzy cluster."""
    words = Counter(w for n in names for w in set(name_words(n)))
    reps, canon = [], {}
    for w, _ in words.most_common():
        near = next((r for r in reps if difflib.SequenceMatcher(None, w, r).ratio() >= 0.8), None)
        if near is None:
            reps.append(w)
        canon[w] = near or w
    return canon


def _case(word, originals):
    orig = Counter(o for n in originals for o in re.findall(r"[A-Za-z0-9]+", n) if o.lower() == word).most_common(1)
    form = orig[0][0] if orig else word
    return form if form.isupper() and len(form) <= 4 else word.capitalize()


def consensus_words(names):
    canon = _canon_words(names)
    votes = Counter(canon[w] for n in names for w in set(name_words(n)))
    keep = {w for w, c in votes.items() if c * 2 > len(names)} or set(votes)
    best = max(names, key=lambda n: sum(votes[canon[w]] for w in name_words(n)))
    out = []
    for w in name_words(best):
        if canon[w] in keep and canon[w] not in [canon[o] for o in out]:
            out.append(w)
    return [canon[w] for w in out]


def recommend_name(rules):
    """Verb-Words for a group of rule feature dicts (consensus spelling, valid per check_rule_name)."""
    names = [r["name"] for r in rules]
    verb = "Block" if rules[0]["cls"] == "block" else "Publish" if rules[0]["dir"] == "inbound" else "Allow"
    words = [w for w in consensus_words(names) if w not in VERBS] or ["Rule"]
    parts = [verb] + [_case(w, names) for w in words]
    name = "-".join(parts)
    while len(name) > sophos_api.RULE_NAME_MAX and len(parts) > 2:
        parts.pop()
        name = "-".join(parts)
    sophos_api.check_rule_name(name)
    return name


# --------------------------------------------------------------------------- rule order
def covers(a_items, b_items, key=str):
    """True when A's list covers B's: empty/any covers all, otherwise a superset by object name."""
    if is_any(a_items):
        return True
    return not is_any(b_items) and {key(x).lower() for x in b_items} <= {key(x).lower() for x in a_items}


def zones_cover(a, b):
    """Return 'full', 'source' (A's source zones only overlap B's any) or None."""
    if not covers(a["dst_zones"], b["dst_zones"]):
        return None
    if covers(a["src_zones"], b["src_zones"]):
        return "full"
    return "source" if is_any(b["src_zones"]) and not is_any(a["src_zones"]) else None


def shadow(a, b):
    """(where, A) when the earlier rule A hides B ("" = fully, else a zone note), or None."""
    if a["identity"] or not (covers(a["src"], b["src"]) and covers(a["dst"], b["dst"]) and covers(a["svc"], b["svc"])):
        return None
    z = zones_cover(a, b)
    if z is None:
        return None
    return "" if z == "full" else f" for traffic from {','.join(a['src_zones'])}"


def overlaps(a, b):
    return is_any(b["src"]) or bool({x.lower() for x in a["src"]} & {x.lower() for x in b["src"]})


def partial_block(a, b):
    """True when the earlier block rule A (named sources) blocks B's traffic for A's sources."""
    return (a["cls"] == "block" and not a["identity"] and not is_any(a["src"]) and overlaps(a, b)
            and covers(a["dst"], b["dst"]) and covers(a["svc"], b["svc"])
            and zones_cover(a, b) is not None)


def order_problems(label, rs):
    """[(firewall, position, text)] for rules shadowed (or partly blocked) by an earlier enabled rule."""
    out, blocked = [], {}
    live = [r for r in rs if r["enabled"]]
    for j, b in enumerate(live):
        hits = [(a, shadow(a, b)) for a in live[:j] if shadow(a, b) is not None]
        if hits:
            by = ", ".join(f"#{a['pos']} `{a['name']}`" for a, _ in hits)
            out.append((label, b["pos"], f"#{b['pos']} `{b['name']}` never matches{hits[0][1]} (shadowed by {by})"))
            continue
        for a in live[:j]:
            if partial_block(a, b):
                blocked.setdefault(a["pos"], (a, []))[1].append(b)
    for a, bs in blocked.values():
        listed = ", ".join(f"#{b['pos']} `{b['name']}`" for b in bs)
        text = (f"{listed}: blocked for the sources of #{a['pos']} `{a['name']}` "
                f"({_short(a['src'])}), which sits above")
        out.append((label, a["pos"], text))
    return out


# --------------------------------------------------------------------------- report
def _short(items, n=3):
    return ",".join(items[:n]) + (f"+{len(items) - n}" if len(items) > n else "") if items else "any"


def cell(r):
    return f"#{r['pos']} `{r['name']}`" + ("" if r["enabled"] else " **(disabled)**")


def differs(members):
    rs = [r for _, r in members]
    out = [lbl for lbl, key in (("source", "src"), ("destinations", "dst"), ("services", "svc"),
                                ("web filter", "webfilter"), ("action", "action"), ("status", "enabled"))
           if len({tuple(sorted(x.lower() for x in r[key])) if isinstance(r[key], list) else r[key]
                   for r in rs}) > 1]
    return ", ".join(out) or "-"


def what_it_does(r):
    base = (f"{r['action'] or '?'} {r['dir']}; src {_short(r['src'])}; dst {_short(r['dst'])}; svc {_short(r['svc'])}")
    return base + (f"; web filter {r['webfilter']}" if r["webfilter"] else "")


def label_of(spec, label):
    p = Path(spec)
    if p.is_dir():
        return p.name
    return label.split(" (")[0] if p.is_file() else label


def unique(labels):
    seen, out = Counter(), []
    for lb in labels:
        seen[lb] += 1
        out.append(lb if labels.count(lb) == 1 else f"{lb}#{seen[lb]}")
    return out


def named_groups(groups, rules):
    """[{'members': [(label, feat)], 'recommended': name}] in report order."""
    out = []
    for g in groups:
        feats = [(fw, rules[fw][i]) for fw, i in g]
        out.append({"members": feats, "recommended": recommend_name([f for _, f in feats])})
    return out


def table_all(items, labels):
    lines = ["| Recommended name | " + " | ".join(labels) + " | Differs in |", "|---" * (len(labels) + 2) + "|"]
    for g in items:
        by = dict(g["members"])
        lines.append(f"| **{g['recommended']}** | " + " | ".join(cell(by[lb]) if lb in by else "— missing"
                                                                   for lb in labels) + f" | {differs(g['members'])} |")
    return lines


def section_specific(items, labels):
    lines = []
    for lb in labels:
        mine = [g for g in items if g["members"][0][0] == lb]
        lines += [f"### {lb} ({len(mine)})", ""]
        if mine:
            lines += ["| Current | Recommended | What it does |", "|---|---|---|"]
            lines += [f"| {cell(g['members'][0][1])} | **{g['recommended']}** | "
                      f"{what_it_does(g['members'][0][1])} |" for g in mine]
        else:
            lines.append("No site-specific rules.")
        lines.append("")
    return lines


def render(labels, rules, items, problems, min_score):
    both = [g for g in items if len(g["members"]) == len(labels)]
    some = [g for g in items if 1 < len(g["members"]) < len(labels)]
    spec = [g for g in items if len(g["members"]) == 1]
    counts = ", ".join(f"{lb} {len(rules[lb])}" for lb in labels)
    intro = (f"Sources: {counts} rules. Matched by purpose (name + action + direction + destinations/services), "
             f"min score {min_score}. `#n` = position (top = 1).")
    lines = ["# Firewall rule comparison", "", intro, "", f"## 1. Common to all ({len(both)})", ""]
    lines += table_all(both, labels) if both else ["None."]
    lines += ["", f"## 2. Common to some ({len(some)})", ""]
    lines += table_all(some, labels) if some else ["None."]
    lines += ["", f"## 3. Site-specific ({len(spec)})", ""] + section_specific(spec, labels)
    lines += [f"## 4. Rule-order problems ({len(problems)})", ""]
    lines += (["| Firewall | Problem |", "|---|---|"] + [f"| {fw} | {t} |" for fw, _, t in problems]
              if problems else ["None found."])
    note = ("Recommended names are proposals only; renaming or reordering is a firewall change and goes through "
            "a change plan.")
    lines += ["", note]
    return "\n".join(lines) + "\n"


def to_json(labels, items, problems):
    def scope(g):
        return "all" if len(g["members"]) == len(labels) else "some" if len(g["members"]) > 1 else "specific"

    return {"firewalls": labels,
            "groups": [{"scope": scope(g), "recommended": g["recommended"],
                        "rules": {lb: {"position": r["pos"], "name": r["name"], "enabled": r["enabled"]}
                                  for lb, r in g["members"]}} for g in items],
            "order_problems": [{"firewall": fw, "position": p, "text": t} for fw, p, t in problems]}


# --------------------------------------------------------------------------- main
def load_rules(sources):
    labels, rules = [], {}
    for spec in sources:
        label, st = sophos_inspect.load_state(spec, ("FirewallRule",))
        labels.append(label_of(spec, label))
        rules[spec] = [features(i, r) for i, r in enumerate(st["FirewallRule"], 1)]
    labels = unique(labels)
    return labels, {lb: rules[s] for lb, s in zip(labels, sources)}


def compare(labels, rules, min_score, pins_file=None):
    pins = load_pins(pins_file, rules, labels) if pins_file else []
    items = named_groups(build_groups(rules, min_score, pins), rules)
    problems = [p for lb in labels for p in order_problems(lb, rules[lb])]
    return items, problems


def main():
    ap = argparse.ArgumentParser(description="Read-only comparison of firewall rules across Sophos firewalls")
    ap.add_argument("sources", nargs="+", metavar="SOURCE")
    ap.add_argument("--min-score", type=float, default=0.6, help="minimum match score 0-1 (default 0.6)")
    ap.add_argument("--groups", help="JSON list of {firewall_label: rule_name} pinning groups by hand")
    ap.add_argument("--out", help="output directory (default reports/sophos_compare/<timestamp>)")
    args = ap.parse_args()
    if len(args.sources) < 2:
        ap.error("give at least two SOURCEs")
    labels, rules = load_rules(args.sources)
    items, problems = compare(labels, rules, args.min_score, args.groups)
    out = Path(args.out) if args.out else netlib.ROOT / "reports" / "sophos_compare" / netlib.timestamp()
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(render(labels, rules, items, problems, args.min_score))
    (out / "groups.json").write_text(json.dumps(to_json(labels, items, problems), indent=2) + "\n")
    n = len(labels)
    print(f"{len(labels)} firewalls: " + ", ".join(f"{lb} {len(rules[lb])} rules" for lb in labels))
    print(f"common to all: {sum(len(g['members']) == n for g in items)}, common to some: "
          f"{sum(1 < len(g['members']) < n for g in items)}, specific: {sum(len(g['members']) == 1 for g in items)}, "
          f"order problems: {len(problems)}")
    print(f"report: {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
