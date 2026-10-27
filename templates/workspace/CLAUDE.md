# claude-for-network site

This directory is a claude-for-network site workspace (marker: `.claude-for-network`).
The plugin (`network-ops`) loads the full rules at session start, including the approval gate:
**no device change without the user typing `APPROVE <CHG-ID>`**. Site facts (subnets, notes) go in `CLAUDE.local.md`.

## Quick reference

| Command | What it does |
|---|---|
| `cfn --help` | list every script |
| `cfn inventory list` / `counts` | read the site inventory |
| `cfn discover 192.0.2.0/24` | SSH sweep + `show version`, upserts the inventory |
| `cfn show -c "show version" --all --out` | read-only collection, saved under `outputs/` |
| `cfn backup --all` | running-config backups under `backups/` |
| `cfn vsphere-checklist` / `switch-checklist` / `sophos-checklist` / `veeam-checklist` | read-only per-device-type checklists (`checklist` skill), reports under `reports/checklist/` |
| `cfn change plan ...` → user types `APPROVE <ID>` → `cfn change apply <ID>` | the only path to a device change |

Credentials live in `.env` (owner-only). Never print, log or commit them.
