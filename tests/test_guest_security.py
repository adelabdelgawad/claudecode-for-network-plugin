"""Offline selftest for the guest_show `security` preset and guest_security.py (no VM or network contact).

Run: python3 tests/test_guest_security.py   (needs the venv python for paramiko/pyVmomi imports)
"""
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
# The scripts resolve a site root at import time; give them an empty throwaway site (the test reads no site data).
_SITE = tempfile.mkdtemp(prefix="cfn-test-site-")
Path(_SITE, ".claude-for-network").write_text("{}")
os.environ["CLAUDE_PROJECT_DIR"] = _SITE

import guest_security as gs  # noqa: E402
import guest_show as g  # noqa: E402

REJECT = {
    "windows": ["Set-MpPreference -DisableRealtimeMonitoring $true", "Stop-Service Spooler", "Remove-Item C:\\x",
                "Restart-Computer", "Get-Process; Stop-Process -Id 4", "Get-Service | Out-File C:\\o.txt",
                "net localgroup administrators evil /add", "net user evil /add", "w32tm /resync",
                "try { Stop-Service x } catch { 'e' }"],
    "linux": ["rm -rf /tmp/x", "apt update", "apt upgrade", "apt install nginx", "systemctl stop sshd",
              "systemctl restart sshd", "yum update", "dnf updateinfo list security", "yum -C install x",
              "lastb -f /var/log/btmp", "aa-status", "sudo cat /etc/os-release", "cat /etc/shadow"],
}


def main():
    fails = []
    # 1. every preset command passes the validator, and every Windows text passes the independent static vetting
    n = 0
    for osf, cmds in g.PRESETS["security"].items():
        for c in cmds:
            n += 1
            for p in (g.readonly_problem(osf, c), g.win_preset_problem(c) if osf == "windows" else None):
                if p:
                    fails.append(f"preset {osf} rejected: {c[:60]!r}: {p}")
    # 2. write / unsafe commands are still rejected (general validator, and static vetting for Windows texts)
    for osf, cmds in REJECT.items():
        for c in cmds:
            if not g.readonly_problem(osf, c):
                fails.append(f"{osf} write command ACCEPTED: {c!r}")
            if osf == "windows" and not g.win_preset_problem(c) and "Stop-Service x" in c:
                fails.append(f"static vetting accepted {c!r}")
    # 2b. a preset-like text with a write cmdlet must fail the static vetting even though it is not in the preset
    for bad in ["try { Get-Date } catch { Stop-Service Spooler }", "try { Set-MpPreference -Foo 1 } catch { 'x' }",
                "Get-Date; Remove-Item C:\\x", "try { Get-WinEvent -FilterHashtable @{A=(Invoke-Thing)} } catch { 'x' }",
                "try { (Get-Date).Delete() } catch { 'x' }"]:
        if not g.win_preset_problem(bad):
            fails.append(f"static vetting accepted {bad!r}")
    # 3. fixture run
    hosts, failures = gs.load_dir(HERE / "fixtures" / "guest_security")
    s = gs.analyze(hosts, failures, {"mode": "test"}, datetime(2026, 10, 27))
    st = {i["id"]: i for i in s["items"]}
    has = lambda iid, host, sev, text: any(f["target"] == host and f["severity"] == sev and text in f["detail"] for f in st[iid]["findings"])
    expect = [
        ("E36", "FAKE-WIN2012", "CRIT", "last hotfix"), ("E36", "FAKE-WIN2012", "WARN", "reboot pending"),
        ("E36", "FAKE-UBU22", "CRIT", "23 pending security"), ("E36", "FAKE-UBU22", "WARN", "87 days"),
        ("E37", "FAKE-WIN2012", "CRIT", "no active antivirus"), ("E37", "FAKE-WIN2019", "WARN", "signatures are 5 days"),
        ("E38", "FAKE-WIN2012", "WARN", "Public"), ("E38", "FAKE-UBU22", "WARN", "no active host firewall"),
        ("E39", "FAKE-WIN2012", "CRIT", "SMB1"), ("E39", "FAKE-WIN2012", "CRIT", "ftp"), ("E39", "FAKE-WIN2012", "WARN", "Network Level"),
        ("E39", "FAKE-UBU22", "CRIT", "telnet"), ("E40", "FAKE-WIN2012", "WARN", "SID -500"),
        ("E40", "FAKE-WIN2012", "WARN", "never expires"), ("E40", "FAKE-WIN2019", "INFO", "ops_team"),
        ("E41", "FAKE-WIN2012", "CRIT", "350"), ("E41", "FAKE-WIN2019", "WARN", "45 failed"), ("E41", "FAKE-UBU22", "CRIT", "203.0.113.5"),
        ("E42", "FAKE-WIN2012", "WARN", "BackupAgent"), ("E43", "FAKE-WIN2012", "WARN", "Local CMOS"),
        ("E43", "FAKE-UBU22", "WARN", "not synchronized"), ("E44", "FAKE-UBU22", "CRIT", "PermitRootLogin"),
        ("E44", "FAKE-UBU22", "WARN", "PasswordAuthentication"), ("E44", "FAKE-UBU22", "WARN", "AppArmor"),
    ]
    fails += [f"missing finding {e}" for e in expect if not has(*e)]
    # clean cases: the healthy 2019 host must have no WARN/CRIT in these items, and constant-ignored services stay quiet
    for iid in ("E36", "E38", "E39", "E40", "E42", "E43"):
        bad = [f for f in st[iid]["findings"] if f["target"] == "FAKE-WIN2019" and f["severity"] != "INFO"]
        if bad:
            fails.append(f"unexpected finding on healthy host {iid}: {bad}")
    if s["hosts"] != {"ok": 3, "failed": 1, "failures": [{"machine": "FAKE-DOWN", "error": "ConnectTimeout: timeout after 30s"}]}:
        fails.append(f"hosts block wrong: {s['hosts']}")
    # contract shape, and skip when nothing was collected
    for i in s["items"]:
        if set(i) != {"id", "section", "title", "status", "reason", "findings"} or i["status"] not in ("pass", "warn", "crit", "info", "skip"):
            fails.append(f"bad item shape {i['id']}")
        if any(set(f) != {"target", "vcenter", "severity", "detail", "suggestion"} for f in i["findings"]):
            fails.append(f"bad finding shape {i['id']}")
    empty = gs.analyze([], [{"machine": "x", "error": "e"}], {}, datetime(2026, 10, 27))
    if any(i["status"] != "skip" or not i["reason"] for i in empty["items"]):
        fails.append("empty run should skip every item with a reason")
    print(f"{n} preset commands checked, {sum(map(len, REJECT.values()))} write commands rejected, "
          f"{sum(len(i['findings']) for i in s['items'])} fixture findings")
    for f in fails:
        print("FAIL", f)
    print("ALL OK" if not fails else f"{len(fails)} FAILURE(S)")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
