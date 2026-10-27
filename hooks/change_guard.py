#!/usr/bin/env python3
"""PreToolUse hook: block device-changing actions and edits to the guard itself.

Device changes must go through `cfn change plan` -> user types APPROVE <ID> -> `cfn change apply <ID>`.
Device checks act inside a site: a dir at/above the project dir or the tool call's cwd holding the
.claude-for-network marker or inventory/inventory.db. The plugin's own gate files are protected everywhere.
Deny = message on stderr + exit 2 (also on any internal error). Anything else exits 0 silently.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOLS = {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"}
MARKER = ".claude-for-network"
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
# Relative to the plugin (code) root and to the site (data) root respectively.
PLUGIN_PROTECTED = ["hooks/", "bin/", ".claude-plugin/", "scripts/change.py", "scripts/netlib.py", "scripts/paths.py",
                    "scripts/cfn.py", "scripts/vmlib.py", "scripts/show.py", "scripts/guest_show.py",
                    "scripts/sophos_api.py", "templates/rules.md"]
SITE_PROTECTED = [".claude/settings.json", ".claude/settings.local.json", ".claude/approvals/", MARKER]
# Substrings that mark a Bash command as touching the gate (blocked when the command also looks like a write).
BASH_PROTECTED = ["change_guard", "approval_capture", "site_rules", "setup_trigger", "run-python", "hooks.json",
                  "change.py", "netlib.py", "paths.py", "cfn.py", "vmlib.py", "guest_show.py", "sophos_api.py",
                  "scripts/show.py", "rules.md", "bin/cfn", ".claude-plugin", ".claude/settings", MARKER,
                  str(PLUGIN_ROOT)]
WRITEISH = ["sed -i", "perl -i", "tee", "cp ", "mv ", "rm ", "truncate", "chmod", "chown", "ln ",
            "install ", "dd ", "open(", "write_text", "unlink"]
DEVICE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"send_config_set", r"send_config_from_file", r"save_config", r"write_channel", r"\.commit\s*\(",
    r"\bconf(ig(ure)?)?\s+t(erm(inal)?)?\b", r"\bwr(ite)?\s+mem(ory)?\b", r"\bwrite\s+erase\b",
    r"\bcopy\s+run(ning-config)?\s+start(up-config)?\b", r"(?<!show )\breload\b",
    r"\bno\s+shut(down)?\b", r"\bshutdown\b", r"\berase\s+(startup|nvram|flash)",
    r"\b(sshpass|telnet|plink)\b", r"\bssh\s+\S*@?\d+\.\d+\.\d+\.\d+",
    r"\b(curl|wget|http|https|httpie)\b.*(-X\s*(POST|PUT|PATCH|DELETE)|--data|\s-d\s|--request\s+(POST|PUT|PATCH|DELETE))",
    r"postman\s+request\b.*\b(POST|PUT|PATCH|DELETE)\b",
]]
COMMIT = r"\.commit\s*\("
INV_DB = "inventory/inventory.db"
DEVICE_IO = re.compile(r"netmiko|ConnectHandler|paramiko|\bssh\b|urllib|requests|https?:|curl|wget|socket|telnetlib",
                       re.IGNORECASE)
SINGLE_CHANGE = re.compile(r"^\s*((\S*python3?\s+)?\S*scripts/change\.py|\S*\bcfn\s+change)\s+(plan|show|list|apply)\b")
APPLY = re.compile(r"(scripts/change\.py|\bcfn\s+change)\s+apply\b")
CHAINERS = [";", "&", "|", "`", "$(", ">(", "<(", "\n", "\r"]
NOISE = ["2>&1", ">&2", "2>/dev/null", ">/dev/null"]
DATA_EXT = (".py", ".sh", ".bash", ".pl", ".rb", ".js")

HOW = ("Device changes go only through `cfn change plan` -> the user types `APPROVE <ID>` -> "
       "`cfn change apply <ID>`. Do not try to work around this hook.")
NO_SITE = ("outside a claude-for-network site there is no approval store, so the gate files cannot be unlocked here. "
           "Edit the plugin source in its own repository.")


def deny(reason):
    print(f"[change-guard] BLOCKED: {reason} {HOW}", file=sys.stderr)
    sys.exit(2)


def approval_valid(root, name):
    """True if the user typed `APPROVE <name>` (GUARD-EDIT / INV-EDIT) within the last 15 minutes."""
    if root is None:
        return False
    try:
        d = json.loads((root / ".claude" / "approvals" / f"{name}.json").read_text())
        age = datetime.now(timezone.utc) - datetime.fromisoformat(d["approved_at"])  # noqa: UP017 (py<3.11)
        return d.get("status") == "approved" and age.total_seconds() < 15 * 60
    except Exception:  # noqa: BLE001
        return False


def guard_edit_valid(root):
    return approval_valid(root, "GUARD-EDIT")


def inventory_write(text):
    """A local inventory DB write: `.commit(` is the only device pattern hit, and nothing can reach a device."""
    hits = [p.pattern for p in DEVICE_PATTERNS if p.search(text)]
    return hits == [COMMIT] and INV_DB in text and not DEVICE_IO.search(text)


def site_of(start):
    """Nearest dir at/above `start` holding the marker or an inventory DB, or None."""
    start = Path(start).resolve()
    for d in (start, *start.parents):
        if (d / MARKER).is_file() or (d / INV_DB).is_file():
            return d
    return None


def norm(path):
    """Resolved (symlinks), case-normalised path; matching is done on these on both sides."""
    return os.path.normcase(os.path.realpath(path))


def rel_to(path, base):
    try:
        return os.path.relpath(norm(path), norm(base)).replace(os.sep, "/")
    except ValueError:  # different drive on Windows
        return str(path)


def is_protected(rel, protected):
    rel = rel.lower() if os.name == "nt" else rel
    for pr in protected:
        pr = pr.lower() if os.name == "nt" else pr
        if pr.endswith("/"):
            if rel == pr[:-1] or rel.startswith(pr):
                return pr
        elif rel == pr:
            return pr
    return None


def contents(tool_input):
    out = [tool_input.get(k) for k in ("content", "new_string", "new_source")]
    out += [e.get("new_string") for e in tool_input.get("edits") or [] if isinstance(e, dict)]
    return [c for c in out if isinstance(c, str)]


def check_patterns(text, root):
    if inventory_write(text):
        if approval_valid(root, "INV-EDIT"):
            return
        deny("local inventory DB write needs the user to type `APPROVE INV-EDIT` (valid 15 min).")
    for pat in DEVICE_PATTERNS:
        if pat.search(text):
            deny(f"device-changing pattern /{pat.pattern}/ detected.")


def handle_file_tool(tool_input, sites, cwd):
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not path:
        return
    p = Path(path)
    if not p.is_absolute():
        p = cwd / p
    root = sites[0] if sites else None
    prot = is_protected(rel_to(p, PLUGIN_ROOT), PLUGIN_PROTECTED)
    for s in sites:
        prot = prot or is_protected(rel_to(p, s), SITE_PROTECTED)
    if prot:
        if prot == ".claude/approvals/":
            deny("approval files are written only by the user's APPROVE prompt.")
        if root is None:
            deny(f"{path} is a protected guard file; {NO_SITE}")
        if not guard_edit_valid(root):
            deny(f"{path} is a protected guard file (the user must type `APPROVE GUARD-EDIT` to unlock for 15 min).")
        return
    if root is None:
        return
    rel = rel_to(p, root)
    if rel.endswith(".md"):
        return
    if rel.startswith("changes/") and not rel.endswith(DATA_EXT):
        return
    for text in contents(tool_input):
        check_patterns(text, root)


def handle_bash(cmd, sites):
    root = sites[0] if sites else None
    stripped = cmd
    for n in NOISE:
        stripped = stripped.replace(n, "")
    if ".claude/approvals" in cmd or "approvals/" in cmd:
        deny("the approvals directory may not be touched from Bash.")
    hit = [p for p in BASH_PROTECTED if p.rstrip("/") in cmd]
    if hit and (">" in stripped or any(t in stripped for t in WRITEISH)):
        if root is None:
            deny(f"command appears to modify protected file(s) {hit}; {NO_SITE}")
        if not guard_edit_valid(root):
            deny(f"command appears to modify protected file(s) {hit} (user must type `APPROVE GUARD-EDIT`).")
    if root is None:
        return
    if SINGLE_CHANGE.match(cmd) and not any(c in stripped for c in CHAINERS):
        return
    if APPLY.search(cmd) and not re.match(r"^\s*(cat|less|grep|head|tail|ls)\b", cmd):
        deny("`cfn change apply` must be run as a single, unchained command.")
    check_patterns(cmd, root)


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:  # noqa: BLE001 - not a tool call we can read
        return
    try:
        tool = data.get("tool_name")
        if tool not in TOOLS:
            return
        tin = data.get("tool_input") or {}
        cwd = Path(data.get("cwd") or os.getcwd())
        sites = []
        for start in (os.environ.get("CLAUDE_PROJECT_DIR"), cwd):
            s = site_of(start) if start else None
            if s and s not in sites:
                sites.append(s)
        if tool == "Bash":
            handle_bash(tin.get("command") or "", sites)
        else:
            handle_file_tool(tin, sites, cwd)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - fail closed: an erroring guard must not let the call through
        deny(f"guard error ({type(e).__name__}: {e}).")


if __name__ == "__main__":
    main()
