# Claude Code for Network

A Claude Code plugin for running IT network operations safely: device inventory, read-only `show` collection,
config backups, security and logging audits, Sophos XG firewalls, VMware vSphere, and configuration changes. Claude
does the legwork across dozens of devices at once. **A human approves every change.** No command that modifies a
device runs until you type `APPROVE <CHG-ID>` for that exact plan, and the plugin's hooks enforce it.

## Installation

In Claude Code:

```bash
/plugin marketplace add https://github.com/adelabdelgawad/claudecode-for-network-plugin
/plugin install network-ops@network-ops
```

Restart Claude Code after installing. Needs Python 3.8+ (and [`uv`](https://docs.astral.sh/uv/) recommended) on
Linux, or on Windows with Git for Windows.

## Set up a site

Make a directory for a site, start Claude Code in it, and type one line:

```bash
mkdir ~/sites/hq && cd ~/sites/hq
claude
```

```
setup claude for network here
```

That creates the site workspace (it never overwrites anything already there):

```
hq/
├── .claude-for-network      # marks this directory as a site
├── .claude/settings.json    # enables the plugin for this directory
├── .env                     # credentials (owner-only) — fill this in yourself
├── .env.example
├── .gitignore               # keeps site data out of git
├── CLAUDE.md                # short pointer; the rules come from the plugin
├── CLAUDE.local.md          # this site's subnets and notes
├── inventory/inventory.db   # this site's inventory
└── backups/ outputs/ reports/ audits/ changes/
```

The first setup on a machine also builds one shared Python environment for every site. Then:

1. Fill in `.env` with your device credentials in your own editor.
2. Add the site's subnets to `CLAUDE.local.md`.
3. Ask Claude: *"Discover the switches on 192.0.2.0/24"*.

## What You Get

- **Inventory first** — a SQLite inventory per site is the source of truth for devices, credential references,
  firewalls and vSphere objects, filled by an SSH discovery sweep.
- **Concurrent, read-only collection** — one call runs allowlisted `show` commands on many switches in parallel and
  keeps raw output in files, not in the chat.
- **Audits** — security posture (SSH, SNMP, HTTP, VTP, Smart Install, DHCP snooping …), logging coverage, Sophos XG
  rule audits, vSphere snapshots/storage, with JSON/CSV/Markdown reports.
- **Approval-gated changes** — `plan → APPROVE → apply` with hash-bound, single-use approvals, automatic pre-change
  backups, verify commands, rollback files and a change log.
- **Task list** — audit findings become tracked tasks (severity, status, owner, due date). Ask *"show my tasks"*.
- **8 skills** that teach Claude the change workflow, read-only collection, inventory lookups, multi-device fan-out,
  Sophos XG, vSphere, the task list, and site setup.

## Quick Start

Ask Claude things like:

- *"Which access switches are still running IOS 12.2?"*
- *"Back up the running config of every core switch."*
- *"Audit logging coverage across all active switches."*
- *"Set the NTP servers on all `SW-*` switches."* → Claude plans the change and waits for `APPROVE <CHG-ID>`.
- *"Show my open tasks"* / *"Mark task 12 done."*

Or run the tools yourself through the `cfn` launcher, from anywhere inside a site:

```bash
cfn --help                              # every script
cfn inventory counts
cfn show -c "show version" --all --out  # read-only, saved under outputs/
cfn backup --all
cfn tasks list
```

## How a change works

```
1. Claude reads state       cfn show, cfn backup                 (read-only)
2. Claude plans             cfn change plan ...                  → CHG-YYYYMMDD-HHMMSS-xxxx
3. Claude shows the plan    targets, commands, verify, rollback, save → and stops
4. You approve              APPROVE CHG-...                      (typed by you, nobody else)
5. Claude applies           the approved ID, as a single command backup → push → verify → log
```

## Enforcement (not just guidance)

| Hook | When | What it enforces |
|------|------|------------------|
| `change_guard` | Before every Bash / file edit | Blocks config commands, raw SSH and write API calls outside `cfn change`, chained applies, and edits to the gate's own files |
| `approval_capture` | Every prompt | Records only what *you* type: `APPROVE` / `REJECT <ID>`, `APPROVE GUARD-EDIT`, `APPROVE INV-EDIT` |
| `setup_trigger` | Every prompt | Turns `setup claude for network here` into a site setup |
| `site_rules` | Session start | Loads the site rules (the approval gate) into every session in a site |

The guard and approval hooks act only inside a site, so the plugin never gets in the way in your other projects.

## Supported devices

| Area | Technologies |
|------|-------------|
| Switches | Cisco IOS / IOS-XE (Netmiko; old 2960s with `diffie-hellman-group1-sha1` via `paramiko<4`) |
| Firewalls | Sophos XG / SFOS (XML API, Get-only; SSH console) |
| Virtualisation | VMware vCenter / ESXi (pyVmomi, read-only), Windows (WinRM) and Linux (SSH) guests |

## Updating

```bash
/plugin marketplace update network-ops
```

Your sites keep their data. If a release adds Python packages, `cfn init` in any site rebuilds the shared Python
environment when an import is missing.

## Links

- [Setup](docs/setup.md) · [Change workflow](docs/change-workflow.md) · [Scripts](docs/scripts.md) ·
  [Inventory](docs/inventory.md) · [Security](docs/security.md)
- **Author**: [Adel Abdelgawad](https://github.com/adelabdelgawad)

## License

MIT
