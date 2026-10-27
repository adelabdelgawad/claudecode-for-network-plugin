---
name: vsphere
description: Use when a task involves VMware vSphere, vCenter, ESXi hosts, virtual machines or their guest operating systems (Windows/Linux servers) — VM/host inventory, guest OS versions, snapshots, datastores, alarms, VMware Tools, port groups/VLANs, which switch port an ESXi host or VM is on, vSphere audits, or running read-only commands inside guests — including any request to power, snapshot, migrate or reconfigure a VM.
---

# vSphere and virtual machines

## Overview

vSphere objects live in their own inventory tables (`vcenters`, `esxi_hosts`, `port_groups`, `machines`, `machine_nics`), never in `devices`. Every tool here is **read-only**. `scripts/vmlib.py` `call_ro()` allowlists the vSphere API methods, and `guest_show.py` allowlists guest commands.

| Tool | Purpose |
|---|---|
| `cfn inventory vms / vm / esxi / vcenters / counts` | Query the inventory DB (no network) |
| `cfn vsphere add-vcenter` | Register a vCenter (inventory record only) |
| `cfn vsphere discover` | Read the whole vCenter and upsert hosts, port groups, VMs and NICs |
| `cfn vsphere show snapshots / datastores / alarms / host-nics / vm` | Live read-only views (`--json`, `--out`) |
| `cfn vsphere-audit` | Audit → `reports/vsphere_audit/<ts>/` (`summary.json`, `report.md`, `raw/`) |
| `cfn vsphere-storage` | Storage-risk report (datastores, guest volumes, snapshots) → `reports/vsphere_storage/<ts>/` |
| `cfn guest-show` | Read-only commands inside Windows (WinRM) / Linux (SSH) guests, concurrent |

## Quick reference

```bash
cfn inventory vms --os windows            # from the DB, instant
cfn inventory vms --power poweredOff --status any
cfn inventory vm SOME-VM                  # all columns + NICs/VLANs
cfn vsphere discover                       # refresh the inventory from vCenter
cfn vsphere show host-nics --out           # ESXi vmnic -> Cisco switch port (CDP/LLDP)
cfn vsphere show snapshots --older-days 3
cfn vsphere-audit                          # full audit; read report.md
cfn vsphere-audit --switch-vlans outputs/<ts>/   # + port-group VLANs vs switch `show vlan brief`
cfn guest-show --preset os --os linux --all --out --quiet
cfn guest-show -c "Get-HotFix" --match 'SMH-*' --out --quiet
```

## Rules

- **"check vsphere X" / "check vcenter X" / "health check X" → run the approved checklist** (`checklist` skill, `cfn vsphere-checklist --vcenter X`), not an ad-hoc selection of the tools above.

- **Inventory first, but ask about freshness.** Answer "which VMs/OS/where" from `inventory.py`, after asking whether to refresh first (`network-inventory` skill, "Ask before answering from stored data"). On **Refresh first**, run `vsphere.py discover [VCENTER]`; otherwise label the answer as stored data with its `updated_at`. Also run `discover` when a VM is missing.
- **Keep output in files.** Use `--out`/`--json`/`--quiet`, then parse the files with Python and report aggregates. Bulk collection goes to a **Haiku** subagent, which returns a summary.
- **Many VMs → one `guest_show.py` call** with selectors, never one call or subagent per VM (`network-fanout` skill).
- **Changes are gated.** Power on/off/reset, guest restart, snapshot create/revert/remove, vMotion, reconfiguring VM hardware/NICs/port groups, host maintenance mode, and guest commands that write are all **changes** (CRITICAL site rules). `change.py` has **no vSphere backend yet**, so tell the user the change cannot be executed and give the exact steps for them to run instead. Adding a backend requires the user to type `APPROVE GUARD-EDIT`. Never write ad-hoc pyvmomi, PowerCLI, govc or WinRM/SSH code that modifies anything.
- If `guest_show.py` rejects a command as not read-only, treat it as a change. Don't rephrase it to pass the allowlist.
- New user-owned facts (`role`, `environment`, `owner`, `notes`, `credential_ref`) go into `machines` with a parameterized UPDATE (`network-inventory` skill). `discover` never overwrites them.

## Credentials

`VCENTER` (vCenter SSO), `ESXI` (direct host), `WINDOWS` (WinRM, `WINRM_TRANSPORT`), `LINUX` (SSH, `NET_LINUX_SSH_KEY`), stored as `NET_<REF>_*` in `.env`. Check whether a set is filled with `dotenv_values` and print only `set`/`EMPTY`, never the values.

## Common mistakes

- Putting VMs or ESXi hosts in `devices`, where `show.py --all` would then try to SSH into them as switches.
- Assuming CDP/LLDP data exists: it needs discovery enabled on the vSwitch.
- Treating `toolsOld`/`toolsNotInstalled` VMs as unreachable by IP: their `primary_ip` may be missing, so check `machine_nics.ip_addresses`.
