"""Regression test for scripts/init_workspace.py (`cfn init` / `setup claude for network here`).

Usage: python3 tests/test_init_workspace.py
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import init_workspace

SETTINGS = {"extraKnownMarketplaces": {"network-ops": {"source": {"source": "github",
                                                                  "repo": "adelabdelgawad/claudecode-for-network-plugin"}}},
            "enabledPlugins": {"network-ops@network-ops": True}}
FILES = [".claude-for-network", "inventory/inventory.db", ".env", ".env.example", ".gitignore", "CLAUDE.md",
         "CLAUDE.local.md", ".claude/settings.json"]
DIRS = ["backups", "outputs", "reports", "audits", "changes", ".claude/approvals"]


def snapshot(root):
    return {p.relative_to(root).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in sorted(root.rglob("*")) if p.is_file()}


def main():
    cases = []
    with tempfile.TemporaryDirectory() as td:
        site = Path(td) / "site"
        res = dict(init_workspace.init_workspace(site, make_venv=False))
        cases.append(("empty dir: every file created", [f for f in FILES if res.get(f) != "created"], []))
        cases.append(("empty dir: every data dir created", [d for d in DIRS if not (site / d).is_dir()], []))
        cases.append(("venv skipped with make_venv=False", res.get("venv"), "skipped"))
        tables = {r[0] for r in sqlite3.connect(site / "inventory/inventory.db").execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        cases.append(("DB has the devices and tasks tables", {"devices", "tasks"} <= tables, True))
        if os.name != "nt":
            cases.append((".env is chmod 600", oct((site / ".env").stat().st_mode & 0o777), "0o600"))
        cases.append(("settings.json enables the plugin", json.loads((site / ".claude/settings.json").read_text()),
                      SETTINGS))
        marker = json.loads((site / ".claude-for-network").read_text())
        cases.append(("marker names the plugin and version", (marker["plugin"], marker["version"]),
                      ("network-ops", "0.2.1")))
        cases.append(("CLAUDE.local.md holds no data rows", "10." in (site / "CLAUDE.local.md").read_text(), False))

        before = snapshot(site)
        res2 = dict(init_workspace.init_workspace(site, make_venv=False))
        cases.append(("second run: every file reported exists", [f for f in FILES if res2.get(f) != "exists"], []))
        cases.append(("second run: nothing changed on disk", snapshot(site) == before, True))

        pre = Path(td) / "pre"
        (pre / "inventory").mkdir(parents=True)
        (pre / ".claude").mkdir()
        known = {"CLAUDE.md": b"my rules\n", ".env": b"NET_DEFAULT_USERNAME=x\n",
                 ".claude/settings.json": b'{"model": "opus"}\n', "inventory/inventory.db": b"not really a db"}
        for rel, data in known.items():
            (pre / rel).write_bytes(data)
        res3 = dict(init_workspace.init_workspace(pre, make_venv=False))
        cases.append(("existing files are byte-identical", {r: (pre / r).read_bytes() for r in known}, known))
        cases.append(("existing files reported exists", {r: res3.get(r) for r in known}, dict.fromkeys(known, "exists")))
        cases.append(("missing items still added next to existing ones", res3.get(".claude-for-network"), "created"))

    tmpl = sorted(p.relative_to(REPO).as_posix() for p in (REPO / "templates").rglob("*") if p.is_file())
    ignored = subprocess.run(["git", "check-ignore", "--no-index", *tmpl], cwd=REPO, capture_output=True, text=True,
                             check=False).stdout.split()
    cases.append(("C1: no template file is git-ignored (it would be missing from a clean install)", ignored, []))

    failed = 0
    for name, got, want in cases:
        ok = got == want
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  (got {got!r}, want {want!r})"))
    print(f"\n{len(cases) - failed}/{len(cases)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
