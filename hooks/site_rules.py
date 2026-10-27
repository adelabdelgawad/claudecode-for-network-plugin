#!/usr/bin/env python3
"""SessionStart hook: in a claude-for-network site (marker at or above the project dir), load the site rules.

Prints templates/rules.md as session context; prints nothing outside a site. Always exits 0.
"""
import json
import os
import sys
from pathlib import Path

MARKER = ".claude-for-network"
RULES = Path(__file__).resolve().parent.parent / "templates" / "rules.md"


def site_of(start):
    start = Path(start).resolve()
    for d in (start, *start.parents):
        if (d / MARKER).is_file():
            return d
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        data = {}
    site = site_of(os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or ".")
    if site:
        print(f"claude-for-network site: {site}\n\n{RULES.read_text(encoding='utf-8')}")


if __name__ == "__main__":
    main()
