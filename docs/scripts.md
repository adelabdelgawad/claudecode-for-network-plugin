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

SSH port sweep, then `show version`. Upserts by `mgmt_ip` (hostname, model, serial, os_type,
os_version). Credential rejections are stored as `auth_failed` with the SSH banner in `notes`.

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

### `guest_show.py` — read-only commands inside VMs

```bash
guest_show.py [NAME|HOSTNAME|IP ...] [--match GLOB] [--os windows|linux] [--role R] [--cluster C] [--all] \
    (-c CMD ... | --preset os|network|disk|services|listening|time ...) [--out] [--grep REGEX] [--quiet]
```

Linux over SSH (no sudo, no pty), Windows over WinRM (PowerShell). Every command is checked
against an allowlist before any connection is made.

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
