"""READ-ONLY Sophos Firewall (SFOS) XML API client: get, backup, facts, audit.

Usage: cfn sophos-api get ENTITY [ENTITY ...] [--host H ...] [--match GLOB] [--role R] [--all] [--out] [--quiet] [--workers 8]
       cfn sophos-api backup [TARGETS...] [--match GLOB] [--all] [--workers 4]
       cfn sophos-api facts  [TARGETS...] [--match GLOB] [--all] [--update-inventory]
       cfn sophos-api audit  [TARGETS...] [--match GLOB] [--all] [--offline | --live] [--out DIR]

Transport: POST of form field `reqxml` to https://<mgmt_ip>:<api_port>/webconsole/APIController
with <Request><Login>..</Login><Get>..</Get></Request>.

READ-ONLY GUARANTEE: every command-line verb here (get, backup, facts, audit) sends only
build_get_request(); it can emit <Login> and <Get> and nothing else, and assert_get_only()
re-parses the serialized XML and asserts that before every send.
This module builds NO write request: Set add / Set update / Remove live only in scripts/sophos_xml.py
(template-driven, sent only after the approval gate consumed the user's APPROVE). Kept here: the shared
transport (_post_xml), credentials, entity reading and the record helpers (rule_content, group_members, ...).

Targets: standard netlib selectors, restricted to vendor='sophos' AND device_type='firewall'.
Per-firewall options come from the firewall_details table (missing row -> defaults; missing table
-> clear error). API credentials: NET_<api_credential_ref>_USERNAME / _PASSWORD (default SOPHOSAPI).
"""
import argparse
import copy
import json
import os
import re
import sqlite3
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import netlib
from netlib import ROOT

# Curated entity set for `backup`. Edit freely; names are the <Get> entity tags from
# https://docs.sophos.com/nsg/sophos-firewall/latest/API/ (an entity the firmware does not
# support is recorded as skipped, never fatal).
BACKUP_ENTITIES = [
    "FirewallRule", "FirewallRuleGroup", "NATRule", "IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup",
    "Services", "ServiceGroup", "Interface", "VLAN", "Alias", "Zone", "UnicastRoute",
    "DNS", "DHCPServer", "AdminSettings", "AdministrationProfile", "AuthenticationServer",
    "VPNIPSecConnection", "SSLVPNPolicy", "WebFilterPolicy", "IPSPolicy",
    "ApplicationFilterPolicy", "Notification", "SNMPCommunity", "SyslogServers", "Time",
]
ENTITIES_PER_REQUEST = 4   # SFOS pays ~3-5 s of login per request, so batch; 28 in one request times out
BACKUP_PARALLEL = 4        # chunks in flight at once per firewall
BACKUP_MIN_TIMEOUT = 120   # a 4-entity request can take far longer than a one-entity one
FACTS_PROBE_ENTITY = "DNS"  # any entity works: Response root attributes come back regardless

ENTITY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
# Names that would turn a <Get> child into something other than a read. Defence in depth only:
# the builder never emits these as verbs, and assert_get_only() rejects nested structure.
FORBIDDEN_ENTITY = {"login", "get", "set", "remove", "add", "update", "delete", "request"}

FW_DEFAULTS = {"api_port": 4444, "api_enabled": 0, "verify_ssl": 0, "api_credential_ref": "SOPHOSAPI",
               "ha_mode": None, "ha_role": None, "ha_peer_id": None, "license_expiry": None,
               "fw_notes": None}


class ApiError(Exception):
    """Fatal per-device problem (transport, login, API access). kind: conn|auth|api|proto."""

    def __init__(self, kind, msg):
        super().__init__(msg)
        self.kind = kind


# --------------------------------------------------------------------------- request building
def build_get_request(username, password, entities):
    """Serialize <Request><Login>..</Login><Get><Entity/>..</Get></Request>. Nothing else is possible."""
    if not entities:
        raise ValueError("no entities requested")
    req = ET.Element("Request")
    login = ET.SubElement(req, "Login")
    ET.SubElement(login, "Username").text = username   # ElementTree escapes the text
    ET.SubElement(login, "Password").text = password
    get = ET.SubElement(req, "Get")
    for e in entities:
        if not ENTITY_RE.match(e) or e.lower() in FORBIDDEN_ENTITY:
            raise ValueError(f"invalid entity name {e!r}")
        ET.SubElement(get, e)
    xml = ET.tostring(req, encoding="unicode")
    assert_get_only(xml)
    return xml


def assert_get_only(xml):
    """Re-parse the serialized request and assert it is exactly Login + Get(plain entities)."""
    root = ET.fromstring(xml)
    assert root.tag == "Request", "request root must be <Request>"
    assert [c.tag for c in root] == ["Login", "Get"], "request may contain only <Login> then <Get>"
    login, get = list(root)
    assert [c.tag for c in login] == ["Username", "Password"], "unexpected <Login> content"
    assert len(get) > 0, "empty <Get>"
    for ent in get:
        assert len(ent) == 0 and not ent.attrib, f"<Get> entity {ent.tag!r} must be a bare element"
        assert ent.tag.lower() not in FORBIDDEN_ENTITY, f"forbidden element {ent.tag!r} in <Get>"
    low = xml.lower()
    for bad in ("<set", "<remove", "<add>", "<update", "<delete"):
        assert bad not in low, f"write verb {bad!r} in request"


# --------------------------------------------------------------------------- record helpers (read side of rule renames)
RULE_NAME_MAX = 60  # SFOS limit: 60 UTF-8 characters, no commas


def check_rule_name(name):
    """Raise ValueError unless `name` is a legal, untrimmed SFOS firewall rule name."""
    if not isinstance(name, str) or not name or name != name.strip():
        raise ValueError(f"invalid rule name {name!r}: empty or has leading/trailing spaces")
    if len(name) > RULE_NAME_MAX or "," in name or any(ord(c) < 32 for c in name):
        raise ValueError(f"invalid rule name {name!r}: max {RULE_NAME_MAX} chars, no commas or control characters")


RULE_POSITION_TAGS = ("Name", "Position", "After", "Before")  # what differs between a rule and its renamed copy


def canon(e):
    """(tag, text, sorted children). Lists such as networks, zones or services are sets to SFOS, and a
    rule created from a copy can list their members in another order, so order must not matter."""
    return (e.tag, (e.text or "").strip(), tuple(sorted(canon(c) for c in e)))


def rule_content(rec):
    """Canonical content of a firewall rule record minus its name and position: what a rename must not change."""
    return sorted(canon(c) for c in rec if c.tag not in RULE_POSITION_TAGS)


def group_rest(grp):
    """Everything in a rule-group record except its member list."""
    return [(e.tag, (e.text or "").strip()) for child in grp if child.tag != "SecurityPolicyList"
            for e in child.iter()]


def group_members(grp):
    lst = grp.find("SecurityPolicyList")
    return [(e.text or "").strip() for e in lst] if lst is not None else []


# --------------------------------------------------------------------------- inventory helpers
def attach_details(devs):
    """Return copies of devs with firewall_details columns merged in (defaults if no row)."""
    db = netlib.open_db()
    db.row_factory = sqlite3.Row
    try:
        try:
            rows = {r["device_id"]: dict(r) for r in db.execute("SELECT * FROM firewall_details")}
        except sqlite3.OperationalError as e:
            if "no such table" in str(e):
                raise SystemExit("table firewall_details is missing from the inventory DB: apply "
                                 "inventory/schema.sql first (see CLAUDE.md, 'schema.sql' command)")
            raise
    finally:
        db.close()
    out = []
    for d in devs:
        m = dict(d)
        det = rows.get(d["id"], {})
        for k, default in FW_DEFAULTS.items():
            src = "notes" if k == "fw_notes" else k
            m[k] = det.get(src, default) if det.get(src) is not None else default
        out.append(m)
    return out


def resolve_firewalls(args):
    devs = netlib.resolve_targets(args)
    explicit = set(args.targets)
    bad = [d for d in devs if not (d.get("vendor") == "sophos" and d.get("device_type") == "firewall")]
    named = [d for d in bad if d["hostname"] in explicit or d["mgmt_ip"] in explicit]
    if named:
        raise SystemExit("Refusing non-Sophos-firewall target(s): " + ", ".join(
            f"{d['hostname']} (vendor={d.get('vendor')}, device_type={d.get('device_type')})" for d in named)
            + "; this tool only handles vendor='sophos' AND device_type='firewall'")
    devs = [d for d in devs if d not in bad]
    if bad:
        print(f"note: skipped {len(bad)} selected device(s) that are not Sophos firewalls", file=sys.stderr)
    if not devs:
        raise SystemExit("No Sophos firewalls (vendor='sophos', device_type='firewall') matched")
    return attach_details(devs)


def api_credentials(dev):
    ref = dev["api_credential_ref"] or "SOPHOSAPI"
    user, pw = os.getenv(f"NET_{ref}_USERNAME"), os.getenv(f"NET_{ref}_PASSWORD")
    for name, val in ((f"NET_{ref}_USERNAME", user), (f"NET_{ref}_PASSWORD", pw)):
        if not val:
            raise ApiError("auth", f"missing credential env var {name}")
    return user, pw


# --------------------------------------------------------------------------- transport
def _ssl_context(dev):
    if dev["verify_ssl"]:
        return ssl.create_default_context()
    return ssl._create_unverified_context()  # self-signed SFOS cert; only when verify_ssl=0


def api_call(dev, entities, timeout=30):
    """Send one read-only <Get> and return the parsed <Response> root. Raises ApiError."""
    user, pw = api_credentials(dev)
    return _post_xml(dev, build_get_request(user, pw, entities), timeout)


def _post_xml(dev, xml, timeout=30):
    """POST one request body that build_get_request() or sophos_xml.build() already asserted; return the parsed <Response> root."""
    url = f"https://{dev['mgmt_ip']}:{int(dev['api_port'])}/webconsole/APIController"
    body = urllib.parse.urlencode({"reqxml": xml}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context(dev)) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise ApiError("api", f"HTTP {e.code} from APIController (API not enabled, or this host not in the allowed IPs?)")
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise ApiError("conn", f"{type(reason).__name__}: {str(reason)[:100]}")
    text = raw.decode("utf-8", errors="replace")
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ApiError("proto", "response contains a DTD/entity declaration; refusing to parse")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise ApiError("api", "non-XML response (API not enabled on this port, or this host not in the allowed IPs?)")
    if root.tag != "Response":
        raise ApiError("proto", f"unexpected response root <{root.tag}>")
    check_login(root)
    return root


def check_login(root):
    st = root.find("Login/status")
    msg = (st.text or "").strip() if st is not None else ""
    low = msg.lower()
    if st is None:
        top = root.find("Status")  # some builds answer with a bare <Status> when API access is off
        if top is not None:
            raise ApiError("api", f"API refused: {(top.text or '').strip()[:100] or top.get('code', '?')}")
        return  # no Login block: assume session-less success; entity parse decides
    if "success" in low:
        return
    if any(w in low for w in ("not enabled", "not allowed", "access", "disabled")):
        raise ApiError("api", f"API access denied: {msg[:100]}")
    # SFOS answers 'Authentication Failure' for bad credentials; the docs do not say whether it
    # is also used when the caller IP is not in the API allowed list, so report both causes.
    raise ApiError("auth", f"login failed: {msg[:100] or 'no status'} (bad credentials, or API disabled/IP not allowed)")


# --------------------------------------------------------------------------- response parsing
def _is_api_status(e):
    """The API's own status element: tag Status carrying a code attribute (a rule's <Status>Enable is not)."""
    return e.tag == "Status" and "code" in e.attrib


def entity_records(parent, entity):
    """(records, api_status_text). Records are the elements named `entity` that hold real data.

    UNCERTAIN: SFOS returns multi-record entities as repeated sibling <Entity> elements and
    singleton settings (DNS, AdminSettings, Time...) as one <Entity>. Empty results come back as
    an <Entity> whose only child is <Status code="..."> (documented as 'No. of records Zero.').
    """
    recs, status = [], None
    for e in parent.findall(entity):
        kids = list(e)
        if kids and all(_is_api_status(k) for k in kids):
            status = "; ".join(f"{k.get('code')}: {(k.text or '').strip()}" for k in kids)
        else:
            recs.append(e)
    if not recs and status is None:
        top = [f"{k.get('code')}: {(k.text or '').strip()}" for k in parent if _is_api_status(k)]
        if top:
            status = "; ".join(top)
    return recs, status


def _entity_result(root, entity, scoped):
    """dict(state, records, status, root) for one entity of a response (`scoped` = the root kept in the result)."""
    recs, status = entity_records(root, entity)
    if recs:
        state = "ok"
    elif (root.find(entity) is not None and status is None) or (
            status is not None and ("zero" in status.lower() or "526" in status)):
        state = "empty"
    else:
        state = "skipped"
        status = status or f"no <{entity}> element in response (entity unsupported on this firmware?)"
    return {"state": state, "records": recs, "status": status, "root": scoped}


def _scoped_root(root, entity, entities):
    """The response reduced to one entity's elements (what a single-entity request would have returned)."""
    if len(entities) == 1:
        return root
    mine = ET.Element(root.tag, root.attrib)
    mine.extend(c for c in root if c.tag == entity or c.tag not in entities)
    return mine


def fetch_entities(dev, entities, timeout=30):
    """Fetch several entities with ONE <Get> request. Returns {entity: dict(state, records, status, root)}
    in the order given, each shaped like fetch_entity()'s result. Fatal -> ApiError."""
    entities = list(entities)
    root = api_call(dev, entities, timeout)
    return {e: _entity_result(root, e, _scoped_root(root, e, entities)) for e in entities}


def fetch_entity(dev, entity, timeout=30):
    """Fetch one entity. Returns dict(state, records, status, root). state: ok|empty|skipped. Fatal -> ApiError."""
    return fetch_entities(dev, [entity], timeout)[entity]


def chunks(items, size=ENTITIES_PER_REQUEST):
    items = list(items)
    return [items[i:i + size] for i in range(0, len(items), size)]


# --------------------------------------------------------------------------- get
def run_get(dev, entities, timeout):
    out = {}
    try:
        for chunk in chunks(entities):
            out.update(fetch_entities(dev, chunk, timeout))
    except ApiError as e:
        return dev, None, f"{e.kind}: {e}"
    except Exception as e:  # noqa: BLE001 - report any failure per host
        return dev, None, netlib.err_text(e)
    return dev, out, None


def cmd_get(args):
    for e in args.entities:
        if not ENTITY_RE.match(e) or e.lower() in FORBIDDEN_ENTITY:
            raise SystemExit(f"invalid entity name {e!r}")
    if args.quiet and not args.out:
        raise SystemExit("--quiet requires --out")
    args.targets = list(args.host)
    devs = resolve_firewalls(args)
    outdir = ROOT / "outputs" / netlib.timestamp() if args.out else None
    with ThreadPoolExecutor(min(args.workers, len(devs))) as ex:
        results = list(ex.map(lambda d: run_get(d, args.entities, args.timeout), devs))
    ok = 0
    for dev, res, err in results:
        host, ip = dev["hostname"], dev["mgmt_ip"]
        if err:
            print(f"FAIL {host:30} {ip:15} {err}")
            continue
        ok += 1
        counts = {e: (len(r["records"]) if r["state"] != "skipped" else "skipped") for e, r in res.items()}
        if outdir:
            d = outdir / host
            d.mkdir(parents=True, exist_ok=True)
            for e, r in res.items():
                (d / f"{e}.xml").write_text(ET.tostring(r["root"], encoding="unicode"))
        line = "  ".join(f"{e}={n}" for e, n in counts.items())
        print(f"OK   {host:30} {ip:15} {line}")
        if not args.quiet:
            for e, r in res.items():
                if r["status"]:
                    print(f"     {e}: {r['status']}")
    if outdir:
        print(f"saved to {outdir}")
    print(f"{ok} ok / {len(results) - ok} failed")


# --------------------------------------------------------------------------- backup
def _timed_out(err):
    return err.kind == "conn" and "timed out" in str(err).lower()


def _fetch_chunk(dev, names, timeout):
    """{entity: result dict | ApiError} for one chunk; a timed-out chunk is retried one entity per request."""
    try:
        return fetch_entities(dev, names, timeout)
    except ApiError as e:
        if len(names) == 1 or not _timed_out(e):
            return {n: e for n in names}
    out = {}
    for n in names:
        try:
            out[n] = fetch_entity(dev, n, timeout)
        except ApiError as e:
            out[n] = e
    return out


def _fetch_backup_set(dev, entities, timeout):
    """{entity: result | ApiError}: chunks of ENTITIES_PER_REQUEST, BACKUP_PARALLEL requests at a time.
    Raises the first error when no entity could be read at all (the device is unusable)."""
    parts = chunks(entities)
    with ThreadPoolExecutor(min(BACKUP_PARALLEL, len(parts))) as ex:
        got = list(ex.map(lambda c: _fetch_chunk(dev, c, max(timeout, BACKUP_MIN_TIMEOUT)), parts))
    merged = {n: r for part in got for n, r in part.items()}
    if all(isinstance(r, ApiError) and r.kind in ("conn", "auth", "api", "proto") for r in merged.values()):
        raise next(iter(merged.values()))
    return merged


def backup_xml(dev, timeout=30, entities=None):
    """Fetch the entity set and return (xml_text, per-entity summary dict). Raises ApiError if fatal."""
    entities = entities or BACKUP_ENTITIES
    stamp = datetime.now().isoformat(timespec="seconds")
    root = ET.Element("SophosBackup", host=dev["hostname"], ip=dev["mgmt_ip"], timestamp=stamp)
    summary, api_version = {}, None
    fetched = _fetch_backup_set(dev, entities, timeout)
    for name in entities:
        r = fetched[name]
        if isinstance(r, ApiError):
            ET.SubElement(root, "Entity", name=name, status="skipped", records="0", reason=str(r)[:200])
            summary[name] = "skipped"
            continue
        api_version = api_version or r["root"].get("APIVersion")
        sec = ET.SubElement(root, "Entity", name=name, status=r["state"], records=str(len(r["records"])))
        if r["status"] and r["state"] != "ok":
            sec.set("reason", r["status"][:200])
        for rec in r["records"]:
            sec.append(copy.deepcopy(rec))
        summary[name] = r["state"]
    if api_version:
        root.set("api_version", api_version)
    ET.indent(root)
    return ET.tostring(root, encoding="unicode", xml_declaration=False), summary


def backup_device(dev, timeout=30):
    """Back up one firewall to backups/<hostname>/<ts>.xml. Returns the path. Used by backup.py too."""
    if "api_port" not in dev:
        dev = attach_details([dev])[0]
    xml, _ = backup_xml(dev, timeout)
    path = ROOT / "backups" / dev["hostname"] / f"{netlib.timestamp()}.xml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('<?xml version="1.0" encoding="UTF-8"?>\n' + xml + "\n")
    os.chmod(path, 0o600)  # backups can hold PSKs / community strings
    return path


def cmd_backup(args):
    devs = resolve_firewalls(args)

    def one(d):
        try:
            xml, summ = backup_xml(d, args.timeout)
            path = ROOT / "backups" / d["hostname"] / f"{netlib.timestamp()}.xml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('<?xml version="1.0" encoding="UTF-8"?>\n' + xml + "\n")
            os.chmod(path, 0o600)
            return d, path, summ, None
        except ApiError as e:
            return d, None, None, f"{e.kind}: {e}"
        except Exception as e:  # noqa: BLE001
            return d, None, None, netlib.err_text(e)

    with ThreadPoolExecutor(min(args.workers, len(devs))) as ex:
        results = list(ex.map(one, devs))
    for dev, path, summ, err in results:
        if err:
            print(f"FAIL {dev['hostname']:30} {dev['mgmt_ip']:15} {err}")
        else:
            skipped = [k for k, v in summ.items() if v == "skipped"]
            extra = f"  (skipped: {', '.join(skipped)})" if skipped else ""
            print(f"OK   {dev['hostname']:30} {path}{extra}")


# --------------------------------------------------------------------------- facts
def cmd_facts(args):
    devs = resolve_firewalls(args)

    def one(d):
        try:
            return d, api_call(d, [FACTS_PROBE_ENTITY], args.timeout), None
        except ApiError as e:
            return d, None, f"{e.kind}: {e}"
        except Exception as e:  # noqa: BLE001
            return d, None, netlib.err_text(e)

    with ThreadPoolExecutor(min(args.workers, len(devs))) as ex:
        results = list(ex.map(one, devs))
    db = netlib.open_db(readonly=False) if args.update_inventory else None
    ok = 0
    for dev, root, err in results:
        if err:
            print(f"FAIL {dev['hostname']:30} {dev['mgmt_ip']:15} {err}")
            continue
        ok += 1
        attrs = dict(root.attrib)
        print(f"OK   {dev['hostname']:30} {dev['mgmt_ip']:15} " + "  ".join(f"{k}={v}" for k, v in attrs.items()))
        if db is not None and attrs.get("APIVersion"):
            # APIVersion is the API schema version (e.g. 2000.1), not the firmware string, so label it.
            with db:  # transaction scope, as in discover.py's single write pass
                db.execute("UPDATE devices SET os_version=? WHERE id=?", (f"API {attrs['APIVersion']}", dev["id"]))
                db.execute("INSERT OR IGNORE INTO firewall_details (device_id) VALUES (?)", (dev["id"],))
                db.execute("UPDATE firewall_details SET api_enabled=1 WHERE device_id=?", (dev["id"],))
    if db is not None:
        db.close()
        print("inventory updated (os_version, firewall_details.api_enabled); status/credential_ref untouched")
    print(f"{ok} ok / {len(results) - ok} failed")


# --------------------------------------------------------------------------- audit
# Tag names follow the Sophos API docs for FirewallRule / NATRule (SFOS 18-20). Versions differ, so
# every lookup is by descendant tag name and tolerant of absence. UNCERTAIN items are marked.
OBJECT_ENTITIES = ("IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "Services", "ServiceGroup")
NAT_REF_TAGS = ("OriginalSourceNetworks", "OriginalDestinationNetworks", "OriginalServices",
                "OriginalSource", "OriginalDestination", "OriginalService",
                "TranslatedSource", "TranslatedDestination", "TranslatedService")  # UNCERTAIN: varies by version
NAT_LITERALS = {"", "any", "original", "masq", "-", "none"}
ON = {"enable", "enabled", "on", "true", "1", "yes"}
OFF = {"disable", "disabled", "off", "false", "0", "no"}
BLOCK_ACTIONS = {"drop", "reject", "deny"}


def _t(e):
    return (e.text or "").strip() if e is not None else ""


def _leaves(e):
    """Text of leaf descendants (or of e itself when it is a leaf)."""
    if len(e) == 0:
        return [_t(e)] if _t(e) else []
    return [_t(x) for x in e.iter() if len(x) == 0 and _t(x)]


def _field(rec, tag):
    """First descendant named tag (not the API status element)."""
    for x in rec.iter(tag):
        if x is not rec and not _is_api_status(x):
            return x
    return None


def _values(rec, *tags):
    """(found_any_container, values) for the first of `tags` present in rec."""
    for tag in tags:
        e = _field(rec, tag)
        if e is not None:
            return True, _leaves(e)
    return False, []


def _is_any(found, vals):
    # In SFOS an empty selector means Any; an omitted element is treated the same way (UNCERTAIN).
    return (not found) or (not vals) or any(v.lower() == "any" for v in vals)


def load_backup(path):
    """-> (meta, {entity: (state, [records])})."""
    root = ET.parse(path).getroot()
    secs = {}
    for sec in root.findall("Entity"):
        name = sec.get("name")
        recs, _ = entity_records(sec, name)
        secs[name] = (sec.get("status", "ok"), recs)
    return dict(root.attrib), secs


def analyze(meta, secs):
    rules = secs.get("FirewallRule", ("skipped", []))[1]
    f = {k: [] for k in ("any_any_any", "logging_disabled", "disabled", "no_description", "wan_to_lan",
                         "unparsed")}
    for r in rules:
        name = _t(_field(r, "Name")) or "(unnamed)"
        st = _field(r, "Status")
        status = _t(st).lower() if st is not None else ""
        enabled = status not in OFF  # missing Status treated as enabled
        action = _t(_field(r, "Action")).lower()
        if not action and _field(r, "SourceZones") is None and _field(r, "SourceNetworks") is None:
            f["unparsed"].append(name)
            continue
        if not enabled:
            f["disabled"].append(name)
        if not _t(_field(r, "Description")):
            f["no_description"].append(name)
        if not enabled:
            continue
        log = _field(r, "LogTraffic")
        if log is not None and _t(log).lower() in OFF:
            f["logging_disabled"].append(name)
        if action in BLOCK_ACTIONS:
            continue
        src = _is_any(*_values(r, "SourceNetworks", "SourceNetwork"))
        dst = _is_any(*_values(r, "DestinationNetworks", "DestinationNetwork"))
        svc = _is_any(*_values(r, "Services", "Service"))
        if src and dst and svc:
            f["any_any_any"].append(name)
        _, sz = _values(r, "SourceZones", "SourceZone")
        _, dz = _values(r, "DestinationZones", "DestinationZone")
        if any(z.lower() == "wan" for z in sz) and any(z.lower() == "lan" for z in dz):
            f["wan_to_lan"].append(name)

    # object inventory and references
    defined = {}
    for ent in OBJECT_ENTITIES:
        for rec in secs.get(ent, ("skipped", []))[1]:
            n = _t(_field(rec, "Name"))
            if n:
                defined.setdefault(ent, set()).add(n)
    all_defined = set().union(*defined.values()) if defined else set()
    obj_evaluable = bool(all_defined)

    nat_missing = []
    if obj_evaluable:
        for r in secs.get("NATRule", ("skipped", []))[1]:
            miss = set()
            for tag in NAT_REF_TAGS:
                for e in r.iter(tag):
                    for v in _leaves(e):
                        if v.lower() not in NAT_LITERALS and v not in all_defined:
                            miss.add(v)
            if miss:
                nat_missing.append({"rule": _t(_field(r, "Name")) or "(unnamed)", "missing": sorted(miss)})

    refs = set()  # any leaf text outside <Name> elements = a potential reference
    for ent, (_, recs) in secs.items():
        for rec in recs:
            for x in rec.iter():
                if len(x) == 0 and x.tag != "Name" and not _is_api_status(x) and _t(x):
                    refs.add(_t(x))
    unused = {}
    for ent in ("IPHost", "Services"):
        # Built-in objects cannot be told apart from user objects here (UNCERTAIN), so expect noise.
        if ent in defined:
            unused[ent] = sorted(n for n in defined[ent] if n not in refs)

    counts = {e: len(v[1]) for e, v in secs.items()}
    return {
        "host": meta.get("host"), "backup_timestamp": meta.get("timestamp"), "api_version": meta.get("api_version"),
        "rule_count": len(rules), "nat_rule_count": counts.get("NATRule", 0),
        "findings": {k: v for k, v in f.items()},
        "nat_missing_objects": nat_missing if obj_evaluable else None,
        "unused_iphost": unused.get("IPHost"), "unused_services": unused.get("Services"),
        "entity_counts": counts,
        "skipped_entities": [e for e, v in secs.items() if v[0] == "skipped"],
    }


def newest_backup(hostname):
    d = ROOT / "backups" / hostname
    files = sorted(d.glob("*.xml")) if d.is_dir() else []
    return files[-1] if files else None


def write_report(out, results, started):
    L = [f"# Sophos firewall audit ({started:%Y-%m-%d %H:%M})", "",
         "Offline analysis of backup XML; read-only. Counts are candidates for review, not verdicts.", ""]
    L += ["| Firewall | Rules | Any-any-any | No logging | Disabled | No description | WAN->LAN | NAT missing obj | Unused hosts | Unused svc |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        if "error" in r:
            L.append(f"| {r['host']} | error: {r['error']} |||||||||")
            continue
        f = r["findings"]
        L.append(f"| {r['host']} | {r['rule_count']} | {len(f['any_any_any'])} | {len(f['logging_disabled'])} | "
                 f"{len(f['disabled'])} | {len(f['no_description'])} | {len(f['wan_to_lan'])} | "
                 f"{'n/a' if r['nat_missing_objects'] is None else len(r['nat_missing_objects'])} | "
                 f"{'n/a' if r['unused_iphost'] is None else len(r['unused_iphost'])} | "
                 f"{'n/a' if r['unused_services'] is None else len(r['unused_services'])} |")
    titles = {"any_any_any": "Enabled accept rules with any source, destination and service",
              "logging_disabled": "Enabled rules with logging disabled", "disabled": "Disabled rules",
              "no_description": "Rules with no description", "wan_to_lan": "Enabled accept rules WAN -> LAN",
              "unparsed": "Rules whose structure was not recognised (tag names differ?)"}
    for r in results:
        if "error" in r:
            continue
        L += ["", f"## {r['host']}", f"Backup: {r['backup_timestamp']}  API {r['api_version']}"]
        if r["skipped_entities"]:
            L.append(f"Skipped entities: {', '.join(r['skipped_entities'])}")
        for k, title in titles.items():
            names = r["findings"][k]
            if names:
                L += ["", f"### {title} ({len(names)})"] + [f"- {n}" for n in names[:50]]
                if len(names) > 50:
                    L.append(f"- ... {len(names) - 50} more (see summary.json)")
        if r["nat_missing_objects"]:
            L += ["", f"### NAT rules referencing undefined objects ({len(r['nat_missing_objects'])})"]
            L += [f"- {m['rule']}: {', '.join(m['missing'])}" for m in r["nat_missing_objects"][:50]]
        for key, label in (("unused_iphost", "IPHost"), ("unused_services", "Services")):
            if r[key]:
                L += ["", f"### Unreferenced {label} objects ({len(r[key])}; includes built-ins)"]
                L += [f"- {n}" for n in r[key][:50]]
    (out / "report.md").write_text("\n".join(L) + "\n")


def cmd_audit(args):
    devs = resolve_firewalls(args)
    started = datetime.now()
    out = (Path(args.out) if args.out else ROOT / "reports" / "sophos_audit" / started.strftime("%Y%m%d-%H%M%S"))
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for d in devs:
        host = d["hostname"]
        path = None if args.live else newest_backup(host)
        try:
            if path is None:
                if args.offline:
                    raise RuntimeError("no backup XML found (run `backup` first, or drop --offline)")
                path = backup_device(d, args.timeout)
            meta, secs = load_backup(path)
            res = analyze(meta, secs)
            res["backup_file"] = str(path)
            res["host"] = host
        except (ApiError, RuntimeError, ET.ParseError, OSError) as e:
            res = {"host": host, "error": f"{type(e).__name__}: {str(e)[:150]}"}
        results.append(res)
    summary = {"generated": started.isoformat(timespec="seconds"), "read_only": True,
               "device_count": len(results), "devices": results}
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    write_report(out, results, started)
    tot = {}
    for r in results:
        if "error" in r:
            print(f"FAIL {r['host']:30} {r['error']}")
            continue
        f = r["findings"]
        print(f"OK   {r['host']:30} rules={r['rule_count']} any_any_any={len(f['any_any_any'])} "
              f"no_log={len(f['logging_disabled'])} disabled={len(f['disabled'])} no_desc={len(f['no_description'])} "
              f"wan_lan={len(f['wan_to_lan'])} nat_missing={'n/a' if r['nat_missing_objects'] is None else len(r['nat_missing_objects'])}")
        for k, v in f.items():
            tot[k] = tot.get(k, 0) + len(v)
    print("Totals: " + ", ".join(f"{k}={v}" for k, v in tot.items()))
    print(f"Report: {out / 'report.md'}\nJSON:   {out / 'summary.json'}")


# --------------------------------------------------------------------------- CLI
def _common(p, positional=True):
    if positional:
        netlib.add_target_args(p)
    else:
        p.add_argument("--host", action="append", default=[], metavar="HOST", help="hostname or mgmt IP (repeatable)")
        p.add_argument("--match", action="append", default=[], metavar="GLOB", help="fnmatch glob on hostname (repeatable)")
        p.add_argument("--role", help="select devices with this role")
        p.add_argument("--all", action="store_true", help="all firewalls with the selected status")
        p.add_argument("--status", default="active", help="inventory status to target (default: active)")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--timeout", type=int, default=30, help="per-request timeout seconds")


def main():
    ap = argparse.ArgumentParser(description="Read-only Sophos XG/SFOS XML API client")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("get", help="fetch entities, print record counts")
    p.add_argument("entities", nargs="+", metavar="ENTITY")
    _common(p, positional=False)
    p.add_argument("--out", action="store_true", help="save raw XML to outputs/<ts>/<hostname>/<Entity>.xml")
    p.add_argument("--quiet", action="store_true", help="one line per device (requires --out)")
    p.set_defaults(fn=cmd_get)
    p = sub.add_parser("backup", help="curated entity set -> backups/<hostname>/<ts>.xml")
    _common(p)
    p.set_defaults(fn=cmd_backup, workers=4)
    p = sub.add_parser("facts", help="API version / root attributes")
    _common(p)
    p.add_argument("--update-inventory", action="store_true", help="write os_version and api_enabled to the inventory")
    p.set_defaults(fn=cmd_facts)
    p = sub.add_parser("audit", help="offline analysis of the newest backup XML")
    _common(p)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--offline", action="store_true", help="never contact the firewall (error if no backup exists)")
    g.add_argument("--live", action="store_true", help="take a fresh backup first, then analyse it")
    p.add_argument("--out", help="output dir (default reports/sophos_audit/<timestamp>)")
    p.set_defaults(fn=cmd_audit)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
