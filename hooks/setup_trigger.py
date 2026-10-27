#!/usr/bin/env python3
"""UserPromptSubmit hook: when the whole prompt is `setup claude for network here`, point Claude at the init skill.

Runs everywhere (a site does not exist yet). Prints context only on a full match; always exits 0.
"""
import json
import os
import re
import sys

TRIGGER = re.compile(r"^\s*set\s*-?\s*up\s+claude\s+for\s+network\s+here\s*[.!]?\s*$", re.IGNORECASE)


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:  # noqa: BLE001 - never block the prompt
        return
    if TRIGGER.match(data.get("prompt") or ""):
        where = os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or os.getcwd()
        print(f"[claude-for-network] The user asked to set up a claude-for-network site workspace in {where}. "
              "Use the network-workspace-init skill now.")


if __name__ == "__main__":
    main()
