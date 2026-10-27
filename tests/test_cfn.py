"""Regression test for bin/cfn + scripts/cfn.py (the launcher).

Usage: python3 tests/test_cfn.py
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CFN = REPO / "bin" / "cfn"
NAMES = ["inventory", "discover", "show", "backup", "sophos_api", "audit", "log_audit", "change", "vsphere",
         "vsphere_audit", "vsphere_storage", "guest_show", "tasks", "guest_security", "vsphere_checklist", "switch_checklist",
         "sophos_checklist", "veeam_api", "veeam_checklist"]


def cfn(args, cwd, env=None):
    e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"), **(env or {})}
    p = subprocess.run(["bash", str(CFN), *args], cwd=cwd, env=e, capture_output=True, text=True, check=False)
    return p.returncode, p.stdout + p.stderr


def main():
    cases = []
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        rc, out = cfn(["nosuchscript"], t)
        cases.append(("unknown name exits 2", rc, 2))
        cases.append(("unknown name lists the scripts", "show" in out and "inventory" in out, True))
        rc, out = cfn(["--help"], t)
        cases.append(("--help exits 0", rc, 0))
        cases.append(("--help lists every runnable script", [n for n in NAMES if n not in out], []))
        cases.append(("--help mentions init", "init" in out, True))
        empty = {"XDG_DATA_HOME": str(t / "nodata")}
        rc, out = cfn(["inventory", "counts"], t, empty)
        cases.append(("no venv: exits 2", rc, 2))
        cases.append(("no venv: tells the user to run cfn init", "cfn init" in out, True))
        rc, out = cfn(["sophos-api", "--help"], t, empty)
        cases.append(("dash alias resolves (reaches the venv check, not 'unknown')", rc == 2 and "cfn init" in out, True))
        (t / "site").mkdir()
        (t / "site" / ".claude-for-network").write_text("{}")
        venv = REPO / ".venv"
        if venv.is_dir():
            link = t / "data" / "claude-for-network"
            link.mkdir(parents=True)
            (link / "venv").symlink_to(venv)
            rc, out = cfn(["show", "--help"], t / "site", {"XDG_DATA_HOME": str(t / "data")})
            cases.append(("with a venv, cfn show --help runs show.py", rc == 0 and "usage" in out.lower(), True))

    failed = 0
    for name, got, want in cases:
        ok = got == want
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  (got {got!r}, want {want!r})"))
    print(f"\n{len(cases) - failed}/{len(cases)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
