---
name: sophos-xg
description: Use when a task involves the Sophos XG / SFOS firewalls — firewall rules, NAT, objects, interfaces/VLANs/zones, VPN, HA, firmware/API facts, config backups, rule audits, or adding firewalls to the inventory — including "check the firewall", "export the rules", "audit the firewall policy" or "allow X through the firewall".
---

# Sophos XG (SFOS) firewalls

## Overview

Firewalls are `devices` rows with `device_type='firewall'`, `vendor='sophos'`, `os_type='sophos_sfos'`, `credential_ref='SOPHOS'`, plus an optional `firewall_details` row (API port, API enabled, verify_ssl, `api_credential_ref`, HA mode/role/peer, licence expiry). Two access paths, both **read-only** today:

| Path | Tool | Credentials (`.env`) | Use for |
|---|---|---|---|
| XML API `https://<ip>:4444/webconsole/APIController` | `cfn sophos-api` | `NET_SOPHOSAPI_*` (via `firewall_details.api_credential_ref`) | Structured config: rules, NAT, objects, interfaces, VPN, backups, audits |
| SSH device console (menu option 4) | `cfn show` | `NET_SOPHOS_*` | `show ...` CLI diagnostics |

`sophos_api.py` can only build `<Login>` + `<Get>` requests; it asserts this before every send. **`<Set>` / `<Remove>` are changes.** Sophos changes are **not supported yet**: `change.py` is netmiko-only, and extending it requires the user to type `APPROVE GUARD-EDIT`. Until then, prepare the change as a written proposal (exact XML or GUI steps, verify, rollback) for the user to apply. Never send a Set/Remove any other way (curl, Postman, ad-hoc Python).

Before answering firewall facts (version, HA, license, API status) from the inventory, ask whether to refresh first (`network-inventory` skill). On **Refresh first**, run `sophos_api.py facts <fw> --update-inventory`.

## Quick reference

```bash
# inventory
cfn inventory list --match '*FW*'
cfn inventory get <fw-hostname>          # includes firewall_details

# XML API (read-only) — targets: positional / --match / --role / --all (get uses --host)
cfn sophos-api facts --all [--update-inventory]
cfn sophos-api get FirewallRule NATRule --host <fw> --out --quiet
cfn sophos-api backup --all              # backups/<host>/<ts>.xml (chmod 600)
cfn sophos-api audit --all               # reports/sophos_audit/<ts>/summary.json + report.md
cfn backup --all                         # switches -> .cfg, Sophos -> .xml

# SSH console (only show/get/ping/traceroute/more pass the allowlist)
cfn show -c "show network interfaces" <fw>
```

## Adding firewalls

1. The user supplies hostname, mgmt IP, site, HA pair/role. Do not scan for them.
2. Insert the `devices` row (and a `firewall_details` row for HA, a non-default API port, or `verify_ssl=1`) with parameterized SQL, per the `network-inventory` skill. Tell the user what was written.
3. The user enables the API on each XG (Backup & firmware > API, allow this host's IP) and fills `NET_SOPHOS_*` / `NET_SOPHOSAPI_*` in `.env`. Never read or print `.env` values.
4. Run `sophos_api.py facts --all --update-inventory` to confirm access and record `api_enabled` / `os_version`.

## Rules

- Read-only is free to run. Anything that would alter a firewall (rule, NAT, object, interface, HA, firmware, reboot, `system ...` console commands) is a change → `network-change` skill → today, a written proposal only.
- Bulk work over several firewalls → one call (`network-fanout`), raw XML in files, report aggregates. Haiku runs collection; Sonnet extends the scripts.
- Backup XML can contain PSKs, SNMP communities and other secrets: keep it in `backups/`, never paste it into chat, tickets or Teams.
- For HA pairs, read from the primary; the auxiliary may reject the API.

## Known limits (verify on the first real unit)

- `show.py` enters the device console by sending `4` at the SFOS menu (`enter_console()`); untested on hardware.
- `system diagnostics show ...` is rejected by `netlib.require_readonly`; allowing it needs `APPROVE GUARD-EDIT`.
- `facts` records the API schema version (`API 2000.1`), not the firmware build.
- Entity/tag names vary by SFOS version. Unsupported entities are skipped and noted in the backup; unparsed rules are listed separately in the audit. Unused-object findings include built-in objects (noise).

## Common mistakes

- Using curl/Postman for the API: the hook blocks POST bodies, and the XML API is POST even for reads. Use `sophos_api.py`.
- Treating "Authentication Failure" as bad credentials only: it is also returned when this host's IP isn't on the API allow list.
- Flipping `status` or `credential_ref` to make a failing firewall "work" without telling the user.
