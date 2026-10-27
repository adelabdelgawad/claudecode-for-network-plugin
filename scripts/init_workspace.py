"""Set up (or complete) a claude-for-network site workspace. Stdlib only; never overwrites anything.

Usage: cfn init [DIR] [--no-venv]      (DIR defaults to the current directory)
Same as typing `setup claude for network here` in Claude Code.
"""
import argparse
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import paths

VERSION = json.loads((paths.PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]
DATA_DIRS = ["backups", "outputs", "reports", "audits", "changes", ".claude/approvals"]
SETTINGS = {
    "extraKnownMarketplaces": {
        "network-ops": {"source": {"source": "github", "repo": "adelabdelgawad/claudecode-for-network-plugin"}},
    },
    "enabledPlugins": {"network-ops@network-ops": True},
}


def owner_only(path):
    if os.name == "nt":
        user = os.environ.get("USERNAME")
        ok = bool(user) and subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                                           capture_output=True, check=False).returncode == 0
        if not ok:
            print(f"WARNING: could not restrict {path} to your account; set its permissions to owner-only yourself.")
    else:
        path.chmod(0o600)


def make_db(path, plugin_root):
    db = sqlite3.connect(path)
    try:
        db.executescript((plugin_root / "inventory" / "schema.sql").read_text())
    finally:
        db.close()


def init_workspace(target, plugin_root=paths.PLUGIN_ROOT, make_venv=True):
    """Create whatever is missing in `target`. Returns [(relpath, 'created' | 'exists'), ..., ('venv', ...)]."""
    target = Path(target).resolve()
    templates = plugin_root / "templates" / "workspace"
    results = []

    def add(rel, write):
        p = target / rel
        if p.exists():
            results.append((rel, "exists"))
            return
        p.parent.mkdir(parents=True, exist_ok=True)
        write(p)
        results.append((rel, "created"))

    target.mkdir(parents=True, exist_ok=True)
    add(paths.MARKER, lambda p: p.write_text(json.dumps(
        {"plugin": "network-ops", "version": VERSION,
         "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}, indent=2) + "\n"))  # noqa: UP017 (py<3.11)
    add("inventory/inventory.db", lambda p: make_db(p, plugin_root))
    for d in DATA_DIRS:
        (target / d).mkdir(parents=True, exist_ok=True)

    def env(p):
        shutil.copyfile(templates / ".env.example", p)
        owner_only(p)

    add(".env", env)
    add(".env.example", lambda p: shutil.copyfile(templates / ".env.example", p))
    add(".gitignore", lambda p: shutil.copyfile(templates / "gitignore", p))
    add("CLAUDE.md", lambda p: shutil.copyfile(templates / "CLAUDE.md", p))
    add("CLAUDE.local.md", lambda p: shutil.copyfile(templates / "CLAUDE.local.md", p))
    add(".claude/settings.json", lambda p: p.write_text(json.dumps(SETTINGS, indent=2) + "\n"))

    if make_venv:
        import cfn
        results.append(("venv", cfn.ensure_venv(cfn.venv_dir(), plugin_root / "requirements.txt")))
    else:
        results.append(("venv", "skipped"))
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cfn init", description=__doc__.splitlines()[0])
    ap.add_argument("dir", nargs="?", default=".", help="site directory (default: current directory)")
    ap.add_argument("--no-venv", action="store_true", help="do not create/check the shared Python venv")
    args = ap.parse_args(argv)
    target = Path(args.dir).resolve()
    results = init_workspace(target, make_venv=not args.no_venv)
    print(f"claude-for-network site: {target}")
    for rel, state in results:
        print(f"  {state:8} {rel}")
    print("\nNext steps:\n"
          "  1. Fill in the credentials in .env yourself (it is owner-only; never paste them into chat).\n"
          "  2. Add this site's subnets to CLAUDE.local.md.\n"
          "  3. Discover devices: cfn discover <subnet> [--cred REF]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
