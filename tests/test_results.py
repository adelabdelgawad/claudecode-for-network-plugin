"""Regression test for scripts/results.py (read-only run-directory analysis).

Usage: python3 tests/test_results.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "results.py"


def run(args, cwd=None, env=None):
    e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"), **(env or {})}
    p = subprocess.run([sys.executable, str(SCRIPT), *args], cwd=cwd, env=e, capture_output=True, text=True, check=False)
    return p.returncode, p.stdout + p.stderr


def snapshot(d):
    return sorted((str(p.relative_to(d)), p.stat().st_mtime_ns, p.stat().st_size) for p in d.rglob("*"))


def make_audit(root):
    d = root / "reports" / "log_audit" / "20260101-000000"
    (d / "raw").mkdir(parents=True)
    devs = [
        {"hostname": "SW-ACCESS-01", "ip": "192.0.2.11", "os_version": "15.2", "elapsed": 3.5, "connect_error": None},
        {"hostname": "SW-ACCESS-02", "ip": "192.0.2.12", "os_version": "15.2", "elapsed": 9.0, "connect_error": None},
        {"hostname": "SW-CORE-01", "ip": "192.0.2.13", "os_version": "16.9", "connect_error": "TimeoutError: timed out"},
        {"hostname": "SW-CORE-02", "ip": "192.0.2.14", "os_version": "16.9", "error": "TimeoutError: timed out",
         "meta": {"site": "A"}},
    ]
    (d / "summary.json").write_text(json.dumps({"device_count": 4, "devices": devs}))
    (d / "raw" / "SW-ACCESS-01.txt").write_text("line one\n%LINK-3-UPDOWN: Gi1/0/1 down\nntp ok\n")
    (d / "raw" / "SW-ACCESS-02.txt").write_text("nothing\n%link-3-updown: Gi1/0/2 down\n")
    return d


def make_show(root):
    d = root / "outputs" / "20260202-000000"
    d.mkdir(parents=True)
    (d / "SW-ACCESS-01.txt").write_text("===== SW-ACCESS-01 (192.0.2.11) :: show vlan =====\nVLAN0010 users\nVLAN0020 voice\n")
    (d / "SW-CORE-01.txt").write_text("===== SW-CORE-01 (192.0.2.13) :: show vlan =====\nVLAN0010 users\n")
    return d


def make_xml(root):
    d = root / "outputs" / "20260303-000000"
    (d / "FW-EDGE-01").mkdir(parents=True)
    (d / "FW-EDGE-01" / "FirewallRule.xml").write_text("<Response><FirewallRule><Name>allow-dns</Name></FirewallRule></Response>")
    (d / "FW-EDGE-02").mkdir()
    (d / "FW-EDGE-02" / "FirewallRule.xml").write_text("<Response><FirewallRule><Name>deny-all</Name></FirewallRule></Response>")
    return d


def main():
    cases = []
    with tempfile.TemporaryDirectory() as td:
        t = Path(td).resolve()
        audit, show, xml = make_audit(t), make_show(t), make_xml(t)
        before = snapshot(t)

        rc, out = run([str(audit)])
        cases.append(("summary default: counts", "devices: 4  ok: 2  failed: 2" in out, True))
        cases.append(("summary groups errors", "2" in out and "TimeoutError" in out, True))
        cases.append(("summary lists slowest first", out.index("SW-ACCESS-02") < out.index("slowest:") + 40, True))
        rc, out = run([str(audit), "summary"])
        cases.append(("summary explicit exits 0", rc, 0))

        rc, out = run([str(audit), "failed"])
        cases.append(("failed lists both failed hosts", out.splitlines(),
                      ["SW-CORE-01\tTimeoutError: timed out", "SW-CORE-02\tTimeoutError: timed out"]))

        rc, out = run([str(audit), "field", "os_version"])
        cases.append(("field counts values", "15.2" in out and "16.9" in out, True))
        rc, out = run([str(audit), "field", "meta.site", "--top", "1"])
        cases.append(("field dotted path, top N", len(out.strip().splitlines()) == 2 and "<missing>" in out, True))

        rc, out = run([str(audit), "grep", "LINK-3"])
        cases.append(("grep raw layout is case-sensitive", out.strip(), "SW-ACCESS-01: %LINK-3-UPDOWN: Gi1/0/1 down"))
        rc, out = run([str(audit), "grep", "-i", "link-3", "--host", "SW-ACCESS-02"])
        cases.append(("grep -i with --host glob", out.strip(), "SW-ACCESS-02: %link-3-updown: Gi1/0/2 down"))
        rc, out = run([str(audit), "grep", "-i", "link-3", "--count"])
        cases.append(("grep --count per host", out.count("SW-ACCESS-0"), 2))
        rc, out = run([str(audit), "grep", "nomatch-xyz"])
        cases.append(("grep no match exits 1", rc, 1))
        rc, out = run([str(audit), "grep", "("])
        cases.append(("grep bad regex fails cleanly", rc != 0 and "bad regex" in out, True))

        rc, out = run([str(show), "grep", "VLAN0010"])
        cases.append(("show layout grep", sorted(out.splitlines()),
                      ["SW-ACCESS-01: VLAN0010 users", "SW-CORE-01: VLAN0010 users"]))
        rc, out = run([str(show)])
        cases.append(("show layout summary without summary.json", "2 host(s)" in out, True))

        rc, out = run([str(xml), "grep", "deny-all"])
        cases.append(("xml layout grep", out.strip(), "FW-EDGE-02/FirewallRule: <Response><FirewallRule><Name>deny-all</Name></FirewallRule></Response>"))
        rc, out = run([str(xml), "grep", "Name", "--host", "FW-EDGE-01", "--count"])
        cases.append(("xml layout --host --count", "FW-EDGE-01/FirewallRule" in out and "EDGE-02" not in out, True))

        cases.append(("nothing was written", snapshot(t) == before, True))

        site = t / "site"
        site.mkdir()
        (site / ".claude-for-network").write_text("{}")
        rc, out = run(["summary"], cwd=site, env={"CLAUDE_PROJECT_DIR": str(site)})
        cases.append(("no run dir under a site exits with a message", rc != 0 and "no run directory" in out, True))
        (site / "outputs").mkdir()
        shutil.copytree(show, site / "outputs" / "a")
        shutil.copytree(audit, site / "outputs" / "b")
        os.utime(site / "outputs" / "a", (1, 1))
        os.utime(site / "outputs" / "b", None)
        rc, out = run(["summary"], cwd=site, env={"CLAUDE_PROJECT_DIR": str(site)})
        cases.append(("default RUN_DIR picks the newest run", "devices: 4" in out, True))
        rc, out = run([str(t / "missing")])
        cases.append(("missing RUN_DIR fails", rc != 0, True))

    bad = [(n, got, want) for n, got, want in cases if got != want]
    for n, got, want in bad:
        print(f"FAIL {n}: got {got!r}, want {want!r}")
    print(f"{len(cases) - len(bad)}/{len(cases)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
