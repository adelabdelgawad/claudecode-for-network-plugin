---
name: network-inventory
description: Use when the user asks for information about any inventory device (switch, firewall, ESXi host, VM, vCenter) — which devices exist, their IPs, models, OS versions, serials, roles, sites, status or counts — when choosing targets for a task, or when recording newly learned device facts in inventory/inventory.db.
---

# Network Inventory

## Overview

`inventory/inventory.db` (SQLite) is the source of truth for devices; the schema is in the site rules and `inventory/schema.sql` in the plugin. `cfn inventory` is the read-only query tool. Use it before anything that touches devices.

## Quick reference

```bash
cfn inventory list                       # all active
cfn inventory list --match 'SW-*' --json
cfn inventory list --status auth_failed
cfn inventory list --status any
cfn inventory get CORE-SW1              # or an IP
cfn inventory counts                     # by status / model
```

## Ask before answering from stored data

Inventory records can be outdated or legacy. When the user asks for information about devices in the inventory, **ask whether to refresh those devices first**, then answer.

1. Resolve the devices from the DB (`inventory.py get/list/vms/esxi`) and note each record's `updated_at`.
2. Ask with `AskUserQuestion`, for example: *"The stored data for access-sw-* (12 switches) was last updated 2026-10-27 08:55. Refresh the inventory for these devices before I answer?"* Options: **Refresh first** / **Answer from stored data**.
3. **Refresh first** → one read-only call covering only those devices (bulk goes through the `network-fanout` pattern; no `APPROVE` needed):

   | Device kind | Refresh command | Refreshes |
   |---|---|---|
   | Switches (`devices`) | `cfn discover <mgmt_ip> [...] [--cred <credential_ref>]` | hostname, model, serial, os_type, os_version |
   | Sophos firewalls | `cfn sophos-api facts <fw> [...] --update-inventory` | os_version, api_enabled, HA facts |
   | ESXi hosts, VMs, port groups | `cfn vsphere discover [VCENTER]` | everything vCenter reports (not user-owned fields) |

   Then answer from the refreshed records and report what changed (or "no changes"). If the refresh fails for a device (unreachable, auth failure), say so and mark its answer as stored data.
4. **Answer from stored data** → answer and label it as stored data with its `updated_at`.

Skip the question when:
- the user already said "refresh" or "from the inventory / stored data is fine";
- those devices were refreshed earlier in this session;
- the task collects live data anyway (`show.py`, audits, backups, `guest_show.py`); the DB only picks the targets there.

Pass `--cred` from the device's `credential_ref` so `discover.py` doesn't mark it `auth_failed` with the default set. Never rescan a whole subnet as a "refresh"; pass the specific IPs.

## Updating inventory facts

Updating *inventory records* (OS version, serial, model, role, site, status, credential_ref) does **not** change a device, so it needs no `APPROVE <CHG-ID>`. The guard hook still blocks DB commits until the user types `APPROVE INV-EDIT` (valid 15 min); ask for it, don't work around the hook. Do it with a short `python3 -c "import sqlite3; ..."` UPDATE keyed by `hostname` or `mgmt_ip`, using parameterized queries, and tell the user what you changed.

- New or missing devices: `cfn discover <ip|subnet> [--cred REF]`. Run it only when the user asks or when a device is missing; it upserts by `mgmt_ip`. It probes SSH, then telnet, and stores the answering port in `devices.port` (`23` = managed over telnet).
- `change_log` is written by `cfn change apply`. Don't insert fake entries by hand.
- `status` values: `active` | `spare` | `decommissioned` | `auth_failed`.

## VMware vSphere (VMs, ESXi, vCenter)

- VMs and their guest OS go in `machines` (+ `machine_nics`), hypervisors in `esxi_hosts`, controllers in `vcenters`, and VM networks/VLANs in `port_groups`. Never put them in `devices`, because network scripts target every row in `devices`.
- Upsert VMs by `instance_uuid` and ESXi hosts by `hostname`. Set `os_family` (`windows`/`linux`/`other`), `mgmt_protocol` and `credential_ref` (`WINDOWS`/`LINUX`).
- To check which switch port or VLAN a VM uses, join `machine_nics.mac` against the switches' `show mac address-table` output and `port_groups.vlan_id`.

## Choosing targets for bulk work

Pick targets with selectors (`--match`, `--role`, `--all`) and give them to a single concurrent script call (`network-fanout` skill), not a per-device loop.

## Common mistakes

- Answering device questions from the DB without first asking whether to refresh.
- Refreshing without asking, or rescanning the known subnets to "refresh" the device list. Refresh only the asked-about devices, and only after the user picks **Refresh first**.
- Targeting non-`active` devices without being asked.
- Changing `status`/`credential_ref` to make a failing device "work" without telling the user.
