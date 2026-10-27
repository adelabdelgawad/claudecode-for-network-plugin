---
name: network-show-collect
description: Use when gathering read-only information from network switches — show/display output, interface/VLAN/MAC/CDP/LLDP status, version or uptime checks, config audits, troubleshooting data, or taking running-config backups — across one or many inventory devices.
---

# Network Show Collect (read-only)

## Overview

Read-only collection runs through two tools. Both resolve targets from `inventory/inventory.db` and load credentials from `.env`; never put credentials on the command line.

| Tool | Purpose |
|---|---|
| `cfn show` | Runs read-only commands in parallel. It allows only `show`, `display`, `get`, `ping`, `traceroute`, `dir`, and `more`, and rejects `\| redirect/tee/append`, `>`, and `;`. |
| `cfn backup` | Saves the running config to `backups/<hostname>/<timestamp>.cfg` |

## Quick reference

```bash
# one device / several / by pattern / by role / all active
cfn show -c "show ip interface brief" CORE-SW1
cfn show -c "show vlan brief" -c "show cdp neighbors" SW-A1 192.0.2.21
cfn show -c "show version | include uptime" --match 'SW-*'
cfn show -c "show interfaces status err-disabled" --all --out   # saves to outputs/<ts>/

cfn backup --all
```

Target selectors (same for every script): hostnames/IPs, `--match GLOB`, `--role ROLE`, `--all`; `--status` defaults to `active`.

## Rules

- **Multiple devices → one concurrent call** (`network-fanout` skill). Pass all targets in one call and keep raw output in files: use `--out`, `--grep`, or `--quiet`. Never loop over devices in the shell.
- Use the inventory; **do not rescan** known subnets (see the site rules and CLAUDE.local.md).
- Bulk collection (many devices or many commands) goes to a **Haiku** subagent. Tell it to use these scripts with `--out` and to return a summary, not raw dumps.
- When output reveals new device facts (OS version, serial, model), update the inventory (`network-inventory` skill).
- If a needed command is rejected as not read-only, stop: it is a change, so use the `network-change` skill.

## Common mistakes

- Writing ad-hoc netmiko snippets instead of `show.py`. The ad-hoc snippet gets no allowlist, and the guard hook may block it anyway.
- Paging/timeouts on huge outputs: prefer `--out` and grep the files under `outputs/`.
- `auth_failed` devices aren't `active`, so they're skipped. Target them with `--status auth_failed` only after fixing `credential_ref`.
