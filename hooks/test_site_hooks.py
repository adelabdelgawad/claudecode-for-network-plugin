"""Regression test for setup_trigger.py (UserPromptSubmit) and site_rules.py (SessionStart).

Usage: python3 hooks/test_site_hooks.py
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRIGGER = str(HERE / "setup_trigger.py")
RULES = str(HERE / "site_rules.py")


def run(hook, data, root):
    p = subprocess.run([sys.executable, hook], input=json.dumps({**data, "cwd": str(root)}), capture_output=True,
                       text=True, env={"CLAUDE_PROJECT_DIR": str(root), "PATH": "/usr/bin:/bin"}, check=False)
    return p.returncode, p.stdout


def main():
    cases = []
    fire = ["setup claude for network here", "Setup Claude for Network here.", "  set up claude for network here!",
            "set-up claude for network here", "SETUP CLAUDE FOR NETWORK HERE"]
    quiet = ["how do I setup claude for network here?", "setup claude for network here and run discovery",
             "setup network here", "please setup claude for network here", ""]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for prompt in fire:
            rc, out = run(TRIGGER, {"prompt": prompt}, root)
            cases.append((f"fires: {prompt!r}", rc == 0 and "network-workspace-init" in out and str(root) in out, True))
        for prompt in quiet:
            rc, out = run(TRIGGER, {"prompt": prompt}, root)
            cases.append((f"quiet: {prompt!r}", (rc, out), (0, "")))

        rc, out = run(RULES, {"source": "startup"}, root)
        cases.append(("rules: unmarked dir prints nothing", (rc, out), (0, "")))
        (root / "inventory").mkdir()
        (root / "inventory" / "inventory.db").write_bytes(b"")
        rc, out = run(RULES, {"source": "startup"}, root)
        cases.append(("rules: a DB without the marker prints nothing", (rc, out), (0, "")))
        (root / ".claude-for-network").write_text("{}")
        rc, out = run(RULES, {"source": "startup"}, root)
        cases.append(("rules: marked site gets the CRITICAL rules",
                      rc == 0 and "NO CHANGE WITHOUT THE USER'S APPROVAL" in out, True))
        sub = root / "sub"
        sub.mkdir()
        rc, out = run(RULES, {"source": "startup"}, sub)
        cases.append(("rules: a subdir of a site gets the rules", "NO CHANGE WITHOUT THE USER'S APPROVAL" in out, True))

    failed = 0
    for name, got, want in cases:
        ok = got == want
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  (got {got!r}, want {want!r})"))
    print(f"\n{len(cases) - failed}/{len(cases)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
