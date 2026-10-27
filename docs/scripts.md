# Scripts reference

All scripts live in the plugin's `scripts/` and run through the launcher as `cfn <name>` (underscores or dashes:
`cfn sophos-api` = `scripts/sophos_api.py`), from anywhere inside a site. `cfn --help` lists them; `cfn <name> --help`
gives the full option list.

## Target selectors

`show.py`, `backup.py`, `change.py plan` and `inventory.py list` share these (from `netlib.py`):

| Selector | Meaning |
|---|---|
| `HOST_OR_IP ...` | Hostnames or management IPs from the inventory |
| `--match GLOB` | fnmatch on hostname, repeatable (`--match 'SW-*'`) |
| `--role ROLE` | Devices with this role (`core`, `access`, ...) |
| `--all` | Every device with the selected status |
| `--status S` | Inventory status to target (default `active`) |

Only `devices` rows are ever targeted, never VMs or ESXi hosts.

## Read-only tools

### `inventory.py` — query the inventory (no device access)

```bash
inventory.py list [HOSTS...] [--match GLOB] [--role R] [--status active|any|...] [--json]
inventory.py get HOST_OR_IP
inventory.py counts
inventory.py vms [NAMES...] [--match GLOB] [--os windows|linux|other] [--cluster C] [--power ...] [--json]
inventory.py vm NAME_OR_IP
inventory.py esxi [--match GLOB] [--cluster C] [--json]
inventory.py vcenters [--json]
```

### `discover.py` — find devices and upsert the inventory

```bash
discover.py 192.0.2.0/24 [192.0.2.13 ...] [--cred DEFAULT] [--workers 32]
```

Port sweep (SSH 22 first, telnet 23 when SSH is closed), then `show version`. Upserts by `mgmt_ip` (hostname,
model, serial, os_type, os_version, port). Credential rejections are stored as `auth_failed` with the SSH banner in
`notes`.

`devices.port` selects the transport for every script (`netlib.conn_params`): `23` uses Netmiko's telnet driver
for the device's `os_type`, anything else uses SSH. `os_type` stays the platform (`cisco_ios`, `cisco_xe`).
Telnet is cleartext; treat telnet-managed devices as a finding (switch checklist SW18) and move them to SSH.

### `show.py` — run read-only commands in parallel

```bash
show.py -c "show ip interface brief" [-c "show vlan brief" ...] TARGETS \
    [--out] [--grep REGEX ...] [--quiet] [--workers 16]
```

- Only `show`, `display`, `get`, `ping`, `traceroute`, `dir` and `more` are accepted; newlines,
  `;`, `>` and pipes into `redirect`/`tee`/`append` are rejected.
- `--out` saves full output to `outputs/<ts>/<hostname>.txt`.
- `--grep` prints only matching lines, prefixed with the hostname (saved files stay unfiltered).
- `--quiet` prints one OK/FAIL line per device (requires `--out`).

### `backup.py` — running-config backups

```bash
backup.py TARGETS [--workers 8]
```

Writes `backups/<hostname>/<timestamp>.cfg`.

### `audit.py` — security audit

```bash
audit.py [--hosts HOST ...] [--workers 16] [--outdir audits]
```

Collects ~18 show commands per switch (SSH, SNMP, HTTP server, lines, VTP, Smart Install, DHCP
snooping, DAI, NTP, logging, STP ...) and writes `audits/<date>/findings.json`, `findings.csv`
and `summary.txt`, plus raw output per host. Directories are created `700` and files `600`;
secrets are masked in the findings.

### `log_audit.py` — logging coverage and abnormal logs

```bash
log_audit.py [--host HOST ...] [--workers 10] [--out DIR]
```

Checks logging/NTP/timestamp configuration and scans `show logging` for abnormal events. Writes
`reports/log_audit/<ts>/summary.json`, `report.md` and `raw/`. Remediation commands in the
report are suggestions only — apply them through the [change workflow](change-workflow.md).

### `veeam_api.py` — Veeam Backup & Replication (read-only)

```bash
veeam_api.py {facts|jobs|repos} --host HOST [--port 9419] [--cred VEEAM] [--api-version 1.1-rev0] [--verify-ssl]
veeam_api.py sessions --host HOST [--hours 24]
veeam_api.py get --host HOST /api/v1/jobs [...] [--out] [--quiet]
veeam_api.py report --host HOST [--hours 24] [--out DIR]
veeam_api.py selftest
```

REST API client for Veeam B&R v12+. The server is not in the inventory, so `--host` is required
(repeatable). Credentials come from `NET_VEEAM_USERNAME` / `NET_VEEAM_PASSWORD` in `.env`
(`--cred REF` selects `NET_<REF>_*`). The only POSTs are the token login and logout; every other
request is a GET of an allowlisted `/api/v1/` path (action paths such as `.../start` are rejected;
`selftest` shows this offline). `report` writes `reports/veeam/<ts>/` (`summary.json`, `report.md`,
`raw/`) and flags failed/warning jobs, jobs not run in over 48 h, and repositories under 15% free.

### `vsphere.py` — vSphere inventory and views

```bash
vsphere.py add-vcenter NAME HOST [--port 443] [--no-verify-ssl] [--cred VCENTER] [--site NAME]
vsphere.py discover [VCENTER ...] [--workers 4]
vsphere.py show {snapshots|datastores|alarms|host-nics|vm} [--vcenter NAME ...] [--json] [--out]
```

`discover` upserts `vcenters`, `esxi_hosts`, `port_groups`, `machines` and `machine_nics`.
User-owned columns (role, environment, owner, site, notes, status) are never overwritten; VMs that
disappear from vCenter are marked `decommissioned`, not deleted.

### `vsphere_audit.py` — vSphere audit

```bash
vsphere_audit.py [--vcenter NAME ...] [--snapshot-days 3] [--min-hw vmx-15] \
    [--datastore-free-pct 15] [--switch-vlans DIR_OR_FILE] [--workers 4] [--out DIR]
```

Flags old snapshots, outdated VM hardware, low datastore space, and (with `--switch-vlans`
pointing at saved `show vlan brief` output) port groups whose VLAN exists on no switch. Writes
`reports/vsphere_audit/<ts>/`.

### `vsphere_storage.py` — storage risk

```bash
vsphere_storage.py [--vcenter NAME ...] [--snapshot-days 3] [--ds-free-crit 10] [--guest-free-warn 15] ...
```

Read-only. Flags datastores that are low on free space or thin-overcommitted, guest volumes that are nearly full
(read through VMware Tools, so no guest login is needed), old or large snapshots, disks that need consolidation,
and VMs on single-host datastores. Writes `report.md`, `summary.json`, `vm_storage.csv` and `raw/` to
`reports/vsphere_storage/<ts>/`. Run `--help` for all thresholds.

### `switch_checklist.py` — switch / router checklist

```
switch_checklist.py [TARGETS...] [--match GLOB] [--role R] [--all] [--workers 16] [--timeout 30]
                    [--out DIR] [--from-raw DIR] [--threshold KEY=VALUE ...]
```

Read-only checklist for active `cisco_ios` / `cisco_xe` devices (default `--all`). One concurrent netmiko pass per
device sends only `show` commands (checked with `netlib.require_readonly`; a command the device rejects makes the item
skip for that device, not fail). Items SW01-SW34 are the approved list in the `checklist` skill's `switch.md`; thresholds
are the `TH` constants at the top of the script. SW02 and SW14-SW28 map `audit.analyze()` findings; SW12, SW25, SW28 and
SW29 reuse `log_audit.assess()` on the last 24 h of `show logging` (device clock). "Core" for SW13/SW14 is the device
with role `core`, else every collected hostname containing `core`; without one those items skip. SW33/SW34 apply only to
devices with a routing protocol or HSRP/VRRP configured. SW31 checks the newest file in `backups/<host>/`.
`auth_failed` inventory devices (full runs) and unreachable devices are listed in SW01 and never abort the run.
`audit.py` findings with no item (legacy services) go to `other_findings` in `summary.json` and the "Other hardening
findings" section of `checklist.md`.

Outputs under `reports/checklist/switch/<ts>/`: `summary.json` (same item schema as the vSphere checklist; finding
`target` = hostname), `checklist.md`, `findings.csv`, `raw/<host>/` (masked command output plus `meta.json`; dirs 700,
files 600). `--from-raw DIR` re-analyzes a saved run offline with identical results.

### `sophos_checklist.py` — Sophos XG / SFOS firewall checklist

```
sophos_checklist.py [TARGETS...] [--match GLOB] [--role R] [--all] [--workers 4] [--timeout 30]
                    [--out DIR] [--from-raw DIR] [--threshold KEY=VALUE ...]
```

Read-only checklist for `vendor='sophos'` + `device_type='firewall'` devices (default: all active). One concurrent pass
per firewall fetches about 40 entities through `sophos_api.fetch_entity()`, so every request is `<Login>` + `<Get>`
only (`assert_get_only` runs before each send; nothing here builds a request). Items FW01-FW27 are the approved list in
the `checklist` skill's `sophos.md`; thresholds are the `TH` constants at the top of the script. FW07-FW10 and the
undefined-object part of FW13 reuse `sophos_api.analyze()`.

An entity the firmware does not know (529), the account may not read (599) or that times out turns its items into skip
with the entity named in `reason`; one slow entity (for example `User` on a big unit) does not fail the run, raise
`--timeout` for it. Unreachable firewalls show as CRIT in FW01. What the XML API does not expose is skip with "not
exposed by the XML API on firmware API x": CPU/memory/disk (FW04), licence dates (FW05, falls back to
`firewall_details.license_expiry` when set), HA peer state/sync (FW03), IPsec tunnel up/down (FW23), API allowed-IP list
(FW19), NTP server list and sync (FW27 checks clock drift against this host instead), firmware auto-update (FW22) and
signature age (FW21). No SSH console scraping. The firmware string is not exposed either: FW02 judges the API schema
version (`eos_api_below`, `latest_api` in `TH`; update `latest_api` when Sophos ships a newer release). FW12 assumes the
API returns rules in evaluation order. FW08 goes by the zone name, so a WAN zone that is really an inter-site link also fires;
read those findings with that in mind.

Outputs under `reports/checklist/sophos/<ts>/`: `summary.json` (same item schema as the vSphere checklist; finding
`target` = firewall hostname, rule/object name in `detail`), `checklist.md`, `findings.csv`, `raw/<host>/<Entity>.xml`
plus `_meta.json` (passwords, PSKs, SNMP communities and API tokens masked; dirs 700, files 600). `--from-raw DIR`
(the run dir or its `raw/`) re-runs the checks offline with identical results.

### `vsphere_checklist.py` — vSphere health and security checklist

```
vsphere_checklist.py [--vcenter NAME ...] [--veeam-host HOST] [--guest-results DIR] [--perf-minutes 30]
                     [--out DIR] [--workers 4] [--threshold KEY=VALUE ...] [--json]
```

Read-only, one pass per vCenter (concurrent): property collection plus performance queries (`QueryPerf`, realtime
20 s samples over `--perf-minutes`, for CPU ready and datastore latency). Items have stable IDs (A01-H52, see the
`checklist` skill's `vsphere.md`); each ends as pass / info / warn / crit, or skip with a reason (for example
guest items without a `guest_security` run, or H51/H52 without `--veeam-host`). An item that errors becomes skip,
never a traceback. Unreachable or auth-failed vCenters show as CRIT in A01; name one explicitly with `--vcenter` to
include it even when its status is not `active`.

Reuses `vsphere_storage` (datastore, snapshot and guest-volume analysis), `vsphere_audit` (alarms, ESXi builds,
host state, Tools, hardware version) and `veeam_api` (GET-only job config and states). E36-E44 are merged from the
`summary.json` of `guest_security.py` (`--guest-results DIR`, else the newest run under 24 h old). H51/H52 resolve job
includes by VM moref/name and by cluster/host/folder/datastore containers; tag-based includes cannot be resolved and
are noted in the item's reason. Thresholds and the end-of-life OS table are constants at the top of the script.

Outputs under `reports/checklist/vsphere/<ts>/`: `summary.json` (`items`, `rankings`, `counts`), `checklist.md`,
`findings.csv`, `raw/*.json` (no credentials).

### `veeam_checklist.py` — Veeam Backup & Replication checklist

```
veeam_checklist.py --host HOST [--host HOST ...] [--port 9419] [--cred VEEAM] [--api-version 1.1-rev0]
                   [--out DIR] [--from-raw DIR] [--workers 4] [--timeout 60] [--json]
```

Read-only. Logs in through `veeam_api.py` (the token POST is the only non-GET call), GETs a fixed set of endpoints
(`serverInfo`, `license`, `configBackup`, `jobs` + `states`, `sessions` for the last 30 days, repositories + `states`,
proxies, managed servers, `backups`, malware events, encryption passwords) and evaluates items VB01-VB20 (see the
`checklist` skill's `veeam.md`). An endpoint answering 404/400 (not in this Veeam version) or 403 (account lacks
permission) turns its items into skip with the reason, never a traceback; VB03 falls back to the
`ConfigurationBackup` sessions when `/configBackup` is unreadable. On B&R 12.0 (API 1.1-rev0) expect VB02, VB19 and
VB20 to be skipped. VB17/VB18 compare job includes (vCenter hostName + moref, then name) with the inventory `machines`
table, opened read-only; a vCenter that is not in the inventory, is not `active` or has no discovered VMs is listed as
info instead. Thresholds, the latest known 12.x build (`LATEST_KNOWN_12X`, update it when Veeam ships a newer patch)
and the VB08 DB/DC/Exchange name regex are constants at the top of the script.

Outputs under `reports/checklist/veeam/<ts>/`: `summary.json` (same item schema as the vSphere checklist), `checklist.md`,
`findings.csv`, `raw/<host>/*.json` (no tokens or credentials). `--from-raw DIR` re-runs the analysis from a previous
run's directory without touching the network.

### `guest_show.py` — read-only commands inside VMs

```bash
guest_show.py [NAME|HOSTNAME|IP ...] [--match GLOB] [--os windows|linux] [--role R] [--cluster C] [--all] \
    (-c CMD ... | --preset os|network|disk|services|listening|time|security ...) [--out] [--grep REGEX] [--quiet]
```

Linux over SSH (no sudo, no pty), Windows over WinRM (PowerShell). Every command is checked
against an allowlist before any connection is made.

`--preset security` collects the in-guest security posture used by `guest_security.py`. Windows: OS version, last
hotfixes, pending reboot keys, Defender status (plus Security Center AV as fallback), firewall profiles, SMB1, RDP/NLA,
listening ports, local Administrators and local users, failed logons (event 4625, 24h), stopped Automatic services and
`w32tm /query /status /verbose`. Every Windows command is wrapped in try/catch and has an older-PowerShell fallback
(`net localgroup`, `Win32_UserAccount`, `netstat -ano`, SMB1 registry key). Linux: os-release, uptime, pending
updates (`apt list --upgradable`, cache-only `yum`/`dnf -C`), last update time, reboot-required, sshd_config
settings, SELinux/AppArmor, firewall unit state, `ss -tlnp`, sudo/wheel/admin groups, failed SSH logins
(`lastb`, journal), failed units and time sync. Nothing writes state and no package cache is refreshed. Limits: the
`sshd_config` grep cannot see `Match` blocks (`sshd -T` needs root), and `lastb`/journal reads need the group
rights of the login used.

### `guest_security.py` — in-guest OS security audit

```bash
guest_security.py [NAME|HOSTNAME|IP ...] [--match GLOB] [--os windows|linux] [--role R] [--cluster C] [--all] \
    [--workers 16] [--timeout 60] [--out DIR]
guest_security.py --from DIR [--out DIR]     # parse an existing guest_show.py --preset security --out directory
```

Read-only. Runs the `security` preset concurrently (live mode) or parses saved output (`--from`), then evaluates
checklist items E36 Patches, E37 Antivirus/Defender, E38 Host firewall, E39 Risky services (SMB1, RDP without NLA,
telnet/ftp/rsh listening), E40 Local admins/accounts, E41 Failed-logon spikes, E42 Stopped Automatic services, E43 Time
sync and E44 Linux hardening. Thresholds are constants at the top of the script. Writes `summary.json` (the shared
checklist contract), `report.md` and `findings.csv` to `reports/guest_security/<ts>/` (plus `raw/` in live mode).
Unreachable guests count in `hosts.failed`; an item with no data from any host is `skip`. Suggestions are text only.
Offline self-test with fake fixtures: `.venv/bin/python tests/test_guest_security.py` (plugin repo).

## Change tool

### `change.py`

```bash
change.py plan --title TEXT (-c CMD ... | --commands-file FILE) [--verify "show ..."] \
    [--rollback-file FILE] [--save] [--continue-on-error] TARGETS
change.py show ID
change.py list
change.py apply ID
```

See [change-workflow.md](change-workflow.md).

## Libraries

| Module | Purpose |
|---|---|
| `netlib.py` | Inventory targeting, Netmiko connection params from `credential_ref`, the read-only command allowlist, running-config backup helper. Protected by the guard. |
| `vmlib.py` | vSphere helpers. `call_ro()` only allows a fixed set of read-only API methods (property retrieval, container views). |

## Writing a new script

Follow the `log_audit.py` pattern:

- Read targets from the inventory (`netlib.resolve_targets`) — never hardcode hosts.
- Run devices concurrently with a `ThreadPoolExecutor` and a `--workers` option.
- Write raw output to files and print only a summary.
- Stay read-only. Anything that changes a device belongs in a `change.py` plan.
