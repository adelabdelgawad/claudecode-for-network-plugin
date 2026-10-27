"""Where things live: the plugin (code, schema, templates) vs the site workspace (data). Stdlib only.

A site is the nearest directory at or above CLAUDE_PROJECT_DIR (else cwd) that holds the MARKER file,
created by `setup claude for network here` / `cfn init`.
"""
import os
from pathlib import Path

MARKER = ".claude-for-network"
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
NOT_A_SITE = ("Not a claude-for-network site (no .claude-for-network found here or above). "
              "Run `setup claude for network here` first.")


def find_site(start):
    """Nearest of `start` and its parents that contains MARKER, or None."""
    start = Path(start).resolve()
    for d in (start, *start.parents):
        if (d / MARKER).is_file():
            return d
    return None


def site_root():
    """The site workspace for this run; exits with the setup hint when there is none."""
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    site = (find_site(env) if env else None) or find_site(Path.cwd())
    if site is None:
        raise SystemExit(NOT_A_SITE)
    return site


def data_dir(os_name=os.name, env=os.environ):
    """Per-user dir for the shared venv."""
    if os_name == "nt":
        base = Path(env.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(env.get("XDG_DATA_HOME") or Path(env.get("HOME") or Path.home()) / ".local" / "share")
    return base / "claude-for-network"


def venv_python(venv, os_name=os.name):
    venv = Path(venv)
    return venv / "Scripts" / "python.exe" if os_name == "nt" else venv / "bin" / "python"
