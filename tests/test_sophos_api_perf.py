"""Offline selftest for the Sophos request batching: fetch_entities, chunked/parallel backup, and the request
count of an apply (a grouped one-rule rename). Nothing contacts a device.
Run: .venv/bin/python tests/test_sophos_api_perf.py   (needs the venv python for netmiko)
"""
import math
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "scripts"))

import test_sophos_rename as base  # sets up the throwaway site environment and FakeFirewall

# isort: split
import sophos_api

DEV = dict(base.DEV, api_port=4444, verify_ssl=0)
OK_LOGIN = "<Login><status>Authentication Successful</status></Login>"


def requested(xml):
    return [e.tag for e in ET.fromstring(xml)[1]]


class FakeApi:
    """Stands in for sophos_api._post_xml: answers every requested entity with one record. fail(entities) may
    return an ApiError to raise instead."""

    def __init__(self, fail=None):
        self.requests, self.fail, self.timeouts = [], fail, []

    def __call__(self, dev, xml, timeout=30):
        ents = requested(xml)
        self.requests.append(ents)
        self.timeouts.append(timeout)
        err = self.fail(ents) if self.fail else None
        if err:
            raise err
        body = "".join(f"<{e}><Name>{e}-1</Name></{e}>" for e in ents)
        return ET.fromstring(f'<Response APIVersion="2000.1">{OK_LOGIN}{body}</Response>')

    def __enter__(self):
        self.orig = sophos_api._post_xml
        sophos_api._post_xml = self
        return self

    def __exit__(self, *exc):
        sophos_api._post_xml = self.orig


def check_fetch_entities(fails):
    with FakeApi() as api:
        got = sophos_api.fetch_entities(DEV, ["FirewallRule", "IPHost"])
        one = sophos_api.fetch_entity(DEV, "DNS")
    if len(api.requests) != 2 or api.requests[0] != ["FirewallRule", "IPHost"]:
        fails.append(f"fetch_entities must send ONE request for all entities: {api.requests}")
    if list(got) != ["FirewallRule", "IPHost"] or any(set(r) != set(one) for r in got.values()):
        fails.append("fetch_entities: wrong keys or result shape")
    if [c.tag for c in got["IPHost"]["root"] if c.tag != "Login"] != ["IPHost"]:
        fails.append("fetch_entities: each entity's root must hold only its own elements")
    if got["IPHost"]["records"][0].findtext("Name") != "IPHost-1" or one["state"] != "ok":
        fails.append("fetch_entities: records not parsed per entity")


def check_backup_requests(fails):
    for n in (1, 4, 5, 28):
        names = sophos_api.BACKUP_ENTITIES[:n]
        with FakeApi() as api:
            xml, summ = sophos_api.backup_xml(DEV, 30, names)
        if len(api.requests) != math.ceil(n / 4):
            fails.append(f"backup of {n} entities used {len(api.requests)} requests, want {math.ceil(n / 4)}")
        if list(summ) != names or [e.get("name") for e in ET.fromstring(xml)] != names:
            fails.append(f"backup of {n}: entity order changed")
        if min(api.timeouts) < 120:
            fails.append(f"backup per-request timeout must be >= 120s: {api.timeouts}")


def check_backup_failures(fails):
    refuse = lambda ents: sophos_api.ApiError("auth", "login failed")  # noqa: E731
    with FakeApi(refuse) as api:
        try:
            sophos_api.backup_xml(DEV, 30)
            fails.append("backup must raise when every chunk fails")
        except sophos_api.ApiError as e:
            if e.kind != "auth":
                fails.append(f"backup raised the wrong error: {e.kind}")
    # one chunk fails (not a timeout): its entities are skipped, the rest are kept
    bad = sophos_api.BACKUP_ENTITIES[4]
    with FakeApi(lambda ents: sophos_api.ApiError("api", "boom") if bad in ents else None):
        _, summ = sophos_api.backup_xml(DEV, 30)
    skipped = [k for k, v in summ.items() if v == "skipped"]
    if skipped != sophos_api.BACKUP_ENTITIES[4:8] or len(summ) != 28:
        fails.append(f"a failed chunk must record exactly its entities as skipped: {skipped}")
    # a timed-out chunk is retried one entity per request; only the entity that still fails is skipped
    slow = sophos_api.BACKUP_ENTITIES[5]
    tmo = sophos_api.ApiError("conn", "TimeoutError: timed out")
    with FakeApi(lambda ents: tmo if slow in ents else None) as api:
        _, summ = sophos_api.backup_xml(DEV, 30)
    skipped = [k for k, v in summ.items() if v == "skipped"]
    singles = [r for r in api.requests if len(r) == 1]
    if skipped != [slow] or len(singles) != 4:  # the chunk itself, then its 4 entities one by one
        fails.append(f"timed-out chunk: want only {slow} skipped after 4 single retries: {skipped} {singles}")


def check_get_chunks(fails):
    with FakeApi() as api:
        _, out, err = sophos_api.run_get(DEV, sophos_api.BACKUP_ENTITIES[:9], 30)
    if err or list(out) != sophos_api.BACKUP_ENTITIES[:9] or [len(r) for r in api.requests] != [4, 4, 1]:
        fails.append(f"run_get must use chunks of 4: {err} {[len(r) for r in api.requests]}")


def apply_count(fw, pairs):
    """Requests (Gets + writes) an apply sends after the backup."""
    err, entry = base.run_rename(fw, pairs)
    return err, entry, fw.reads + len(fw.sent)


def check_apply_requests(fails):
    fw = base.FakeFirewall(["A", "Zoom"], groups={"Biz": ["A", "Zoom"]}).install()
    try:
        err, entry, n = apply_count(fw, [("Zoom", "Allow-Zoom")])
    finally:
        fw.uninstall()
    if err or fw.names != ["A", "Allow-Zoom"] or fw.groups["Biz"] != ["A", "Allow-Zoom"]:
        fails.append(f"grouped rename did not complete: {err} {fw.names} {fw.groups}")
    if n > 7:
        fails.append(f"a 1-rule grouped rename sent {n} requests after the backup, want <= 7")
    print(f"grouped 1-rule rename: {n} requests after the backup ({fw.reads} reads + {len(fw.sent)} writes)")
    lines = entry["output"].splitlines()
    if len(lines) != 3 or not all(l.endswith("s)") and "(" in l for l in lines):
        fails.append(f"every step line must end with its elapsed seconds: {lines}")
    if "Allow-Zoom" not in entry["verify_output"].get("FirewallRule names, in order", ""):
        fails.append("final rule listing missing")


def main():
    fails = []
    for fn in (check_fetch_entities, check_backup_requests, check_backup_failures, check_get_chunks,
               check_apply_requests):
        fn(fails)
    for f in fails:
        print("FAIL", f)
    print("sophos api perf selftest:", "FAILED" if fails else "ok")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
