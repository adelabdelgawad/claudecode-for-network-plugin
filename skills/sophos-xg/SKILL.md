---
name: sophos-xg
description: Use when a task involves the Sophos XG / SFOS firewalls — firewall rules, NAT, objects, rule groups, renaming rules, interfaces/VLANs/zones, VPN, HA, firmware/API facts, config backups, rule audits, comparing firewalls, or adding firewalls to the inventory — including "check the firewall", "export the rules", "audit the firewall policy", "rename the rules" or "allow X through the firewall".
---

# Sophos XG (SFOS) firewalls

## Overview

Firewalls are `devices` rows with `device_type='firewall'`, `vendor='sophos'`, `os_type='sophos_sfos'`, `credential_ref='SOPHOS'`, plus an optional `firewall_details` row (API port, API enabled, verify_ssl, `api_credential_ref`, HA mode/role/peer, licence expiry). Two access paths:

| Path | Tool | Credentials (`.env`) | Use for |
|---|---|---|---|
| XML API `https://<ip>:4444/webconsole/APIController` | `cfn sophos-api`, `sophos-inspect`, `sophos-compare`, `sophos-rename`, `sophos-xml`, `change` | `NET_SOPHOSAPI_*` (via `firewall_details.api_credential_ref`) | Structured config, backups, audits, comparisons; gated changes (need an API account with **write** permission) |
| SSH device console (menu option 4) | `cfn show` | `NET_SOPHOS_*` | `show ...` CLI diagnostics |

Every command except `cfn change apply` only **reads** (`<Login>` + `<Get>`, asserted before every send). **Writes are XML resources**: one template per action in the plugin's `resources/sophos/` (`cfn sophos-xml list`), executed only by `cfn change apply` after the user types `APPROVE <ID>` (`scripts/sophos_xml.py` is the one executor; it escapes every value, asserts the request shape and refuses anything the approved plan does not list). An action with no resource is a proposal (exact XML or GUI steps, verify, rollback) for the user to apply, or a new resource added to the plugin (gate file: `APPROVE GUARD-EDIT`). Never send a write any other way (curl, Postman, ad-hoc Python).

Before answering firewall facts (version, HA, license, API status) from the inventory, ask whether to refresh first (`network-inventory` skill). On **Refresh first**, run `cfn sophos-api facts <fw> --update-inventory`.

## Run the scripts, do not read XML

Raw XML and ad-hoc Python cost tokens and invite mistakes. These commands return the answer as short tables; use them before anything else.

```bash
# look at a firewall: SOURCE = hostname (live, read-only), a backup .xml, or an outputs/<ts>/<host>/ directory
cfn sophos-inspect rules  <SOURCE>... [--name GLOB] [--group NAME] [--disabled]
cfn sophos-inspect find   <SOURCE>... --name TEXT [--name TEXT]     # where does a name exist (rules, NAT, hosts, groups, members)
cfn sophos-inspect usage  <SOURCE>... --object NAME                  # what references an object
cfn sophos-inspect diff   <BEFORE> <AFTER>                           # renamed / added / removed / changed, groups, NAT, order

# raw material
cfn sophos-api get FirewallRule FirewallRuleGroup NATRule --host <fw> --out --quiet    # -> outputs/<ts>/<host>/<Entity>.xml
cfn sophos-api backup <fw>...        # backups/<host>/<ts>.xml (chmod 600), includes rule groups; takes minutes: run it in the background
cfn sophos-api facts --all [--update-inventory]
cfn sophos-api audit --all           # reports/sophos_audit/<ts>/
cfn show -c "show network interfaces" <fw>     # SSH console, allowlisted show commands only

# compare several firewalls (read-only): common to all / to some / site-specific, recommended names, order problems
cfn sophos-compare <SOURCE> <SOURCE> [<SOURCE>...] [--min-score 0.6] [--groups pins.json]   # -> reports/sophos_compare/<ts>/report.md + groups.json
```

## Comparing firewalls

Rules are matched by **purpose** (action, direction, sources, destinations, services, web filter) plus a typo-tolerant name match, never by literal name. Feed it one `cfn sophos-api get FirewallRule --match <glob> --out` directory per firewall (or hostnames for a live read). If a grouping is wrong, pin it with `--groups pins.json` (a JSON list of `{"<firewall>": "<rule name>", ...}`) and rerun; do not hand-edit the report. Section 4 lists rules that never match (shadowed by an earlier rule) and rules blocked for an earlier deny rule's sources: report them as findings, not as changes.

## Other changes (XML resources)

1. `cfn sophos-xml list` shows each resource, its verb, entity and variables. `cfn sophos-xml render <resource> --var k=v ... [--host <fw>]` previews the exact request (password masked; with `--host`, an update is merged onto the live record, read-only).
2. Write the steps to `changes/<name>.json`: `[{"resource": "firewall_rule.move", "vars": {"name": "...", "position": "After", "after": "..."}}, ...]`. Take names from `sophos-inspect rules` against the live firewall, never from memory or an old report.
3. `cfn change plan --title "<why>" --sophos-steps changes/<name>.json <fw>`: the plan stores every rendered request, so the approval covers the exact XML. Show it to the user, ask for `APPROVE <ID>`, then run `cfn change apply <ID>` alone. `apply` backs up first, runs the steps in order, re-reads after each and stops at the first discrepancy.
4. `cfn sophos-inspect diff <backup apply took> <fw>` is the after-check.
5. **Moving a rule that is in a rule group:** SFOS ignores `<Position>` on a grouped rule and drops it from its group (seen on SFOS 21), so `cfn change plan` refuses `firewall_rule.move` for grouped rules. Rule order inside a group follows the group's member list: reorder with `firewall_rule_group.update` (all members, in the new order), then confirm with `cfn sophos-inspect rules <fw>`. `firewall_rule.move` is for ungrouped rules only.
6. Plan each step file from the live state right before approval; after any apply on that firewall, re-plan the next one.
7. The first use of a resource on a firmware version is a one-step canary (`move` and the `update` resources send the full merged record, as the Sophos SDK does; not yet proven on hardware).

## Renaming rules (the approval-gated flow)

SFOS cannot rename a rule in place: the rule name is its key, and an update with `<NewName>` is refused (`501 Configuration parameters validation failed`; checked on SFOS 21). A rename is therefore **copy under the new name -> verify -> delete the original**, done per rule by `cfn change apply`.

1. **Names.** Write `old name => new name` lines to `changes/<name>.txt`, or take them from a report table with a `Recommended name` column (`--from-report`). Old names differ per firewall (typos, spacing): never reuse one list across firewalls, and never type names from memory.
2. **Pre-flight (read-only):** `cfn sophos-rename check --file changes/<name>.txt <fw>` (or `--from-report REPORT.md <fw>...`). One table per firewall: position, status, rule group, verdict `ok` / `resume` / `BLOCK` (old rule missing or duplicated, new name taken by a different rule, a NAT rule links to the rule). Fix every BLOCK first.
3. **Backup:** `cfn sophos-api backup <fw>` if the user asked for one explicitly. `apply` also takes one first, and verification compares against it.
4. **Plan (nothing is sent):** `cfn sophos-rename plan --title "<why>" --file changes/<name>.txt --canary <fw>`. `--canary` plans only the canary (one ungrouped plus one grouped rule) and saves the rest to `changes/<fw>-rename-<ts>-rest.txt`; plan the rest **after** the canary is applied and verified (a plan fixes the group member lists it expects, so a rest planned up front goes stale). One firewall per plan.
5. **Approval.** Show the user the change ID(s) and the old -> new list, then stop and ask for `APPROVE <ID>`. Only a line the user types as `APPROVE <ID>` counts; an ID quoted inside a sentence does not, and `cfn change list` shows each plan's status (`pending` until approved).
6. **Apply, as its own single command:** `cfn change apply <ID>`. It takes minutes (several reads per rule): run it in the background and wait for the completion notice instead of polling.
7. **Verify (read-only):** `cfn sophos-rename verify <ID>` compares the live firewall with the backup `apply` took first: rule count, order, every field except name/position, group membership, NAT rules. `RESULT: PASS` is the evidence; a partial run shows the in-flight copy as `WARN`. Then run plan 2 the same way.

What `apply` does per rule (so you can explain it): create a copy right after the original with the same status; re-read and require an identical copy in the expected place; make sure the copy is in the original's rule group (it often joins by itself); delete the original; re-read and require the expected names, order, content and group membership. It stops at the first discrepancy and **never deletes the original before the copy is verified**: the worst outcome is a harmless duplicate. A rerun reuses an identical copy that already follows the original (`resume`).

## Lessons that save time

- **Lists are sets.** SFOS lists networks, zones and services of a copied rule in another order; the tools compare canonical content, so a reorder is not a difference. A different member set still is.
- **Rule groups.** Deleting a rule drops it from its group; the tools handle it, but a backup taken by an older version has no group data (`verify` then warns). Group membership is not in the rule record.
- **New ID, new counters.** A copy is a new rule: hit counters restart, old log entries keep the old name. Say so when asking for approval.
- **NAT links.** A rule referenced by a NAT rule (`LinkedFirewallrule`) is refused, because deleting it would break the NAT rule.
- **Positions move.** Rules are matched by name, never by position; the positions in an old report are stale as soon as anyone edits the firewall. Re-run `check` right before planning.
- **Concurrency.** If another admin changes the firewall during `apply`, verification stops the run. Ask whether others are editing before a long apply.
- **One firewall per plan, canary first.** Names, groups and positions differ per firewall.
- **Guard behaviour.** `cfn change apply` must be a single unchained command; plan files are written with the Write tool; the `change-guard` blocks edits to gate files unless the user typed `APPROVE GUARD-EDIT` (15 min, inside a site only).

## Adding firewalls

1. The user supplies hostname, mgmt IP, site, role, HA pair/role. Do not scan for them. Hostnames are unique: prefix the site (`<SITE>-Internet-FW`).
2. Preview, then ask the user for `APPROVE INV-EDIT`, then write (one command per firewall):
   `cfn inventory-edit add <HOST> <IP> --type firewall --vendor sophos --site <SITE> --role <ROLE> --notes "<purpose>" [--ha-mode active-passive --ha-role primary --ha-peer <HOST>] --dry-run`
   Corrections: `cfn inventory-edit set <HOST|IP> --ip <IP>` (or `--role`, `--site`, `--notes`, firewall options). The script refuses duplicates and exits 2 without the approval. Add one line per site to the site's `CLAUDE.local.md` known-networks table.
3. The user enables the API on each XG (Backup & firmware > API, allow this host's IP) and fills `NET_SOPHOS_*` / `NET_SOPHOSAPI_*` in `.env`. Never read or print `.env` values. Changes need an API account with write permission.
4. **Check the logins** (read-only): `cfn sophos-api facts --match '<glob>'` (API) and `cfn show -c "show network interfaces" --match '<glob>' --out` (SSH). `missing credential env var NET_SOPHOS_USERNAME` means `.env` lacks the SSH set; 534 / "Authentication Failure" usually means this host's IP is not on the API allow list.
5. Record the result: `cfn sophos-api facts --match '<glob>' --update-inventory` (needs `APPROVE INV-EDIT`) sets `api_enabled` and `os_version` (the API version, not the firmware build).

## Rules

- Read-only is free to run. Anything that would alter a firewall (rule, NAT, object, interface, HA, firmware, reboot, `system ...` console commands) is a change -> `network-change` skill. Rule renames and the actions in `cfn sophos-xml list` have scripts; anything else is a proposal.
- Bulk work over several firewalls -> one call (`network-fanout`), raw XML in files, report aggregates.
- Backup XML can contain PSKs, SNMP communities and other secrets: keep it in `backups/`, never paste it into chat, tickets or Teams.
- For HA pairs, read from the primary; the auxiliary may reject the API.

## Known limits (verify on the first real unit)

- `show.py` enters the device console by sending `4` at the SFOS menu (`enter_console()`); untested on hardware.
- `system diagnostics show ...` is rejected by `netlib.require_readonly`; allowing it needs `APPROVE GUARD-EDIT`.
- `facts` records the API schema version (`API 2000.1`), not the firmware build.
- Entity/tag names vary by SFOS version. Unsupported entities are skipped and noted in the backup; unparsed rules are listed separately in the audit. Unused-object findings include built-in objects (noise).
- The rename was written against SFOS 21 (API 2100.1) behaviour; the first run on another version should be a one-rule canary.

## Common mistakes

- Using curl/Postman for the API: the hook blocks POST bodies, and the XML API is POST even for reads. Use the scripts.
- Treating "Authentication Failure" as bad credentials only: it is also returned when this host's IP isn't on the API allow list.
- Flipping `status` or `credential_ref` to make a failing firewall "work" without telling the user.
- Sending `<NewName>` to rename: refused. Use the copy + verify + delete flow.
- Planning from a report's rule positions or names without `cfn sophos-rename check` against the live firewall first.
