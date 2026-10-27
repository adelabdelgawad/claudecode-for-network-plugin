# Setup

## Requirements

- [Claude Code](https://claude.com/claude-code)
- Python 3.8+ on the PATH (`python3`, `python` or `py`)
- [`uv`](https://docs.astral.sh/uv/) (recommended; without it setup falls back to `python -m venv` + pip)
- Linux, or Windows with [Git for Windows](https://git-scm.com/download/win) (Claude Code's Bash tool uses Git Bash)
- SSH reachability from this host to the management IPs of your devices

## 1. Install the plugin

In Claude Code:

```bash
/plugin marketplace add https://github.com/adelabdelgawad/claudecode-for-network-plugin
/plugin install network-ops@network-ops
```

Restart Claude Code. Check with `/plugin` that `network-ops` is enabled and with `/hooks` that its hooks loaded.

## 2. Create a site

Each site (campus, data centre, customer) gets its own directory with its own inventory and credentials:

```bash
mkdir -p ~/sites/hq && cd ~/sites/hq
claude
```

Then type:

```
setup claude for network here
```

Claude runs `cfn init`, which creates only what is missing and never overwrites a file:

| Path | What it is |
|---|---|
| `.claude-for-network` | Marks the directory as a site. Scripts and hooks look for it here or in a parent directory |
| `.claude/settings.json` | Declares the marketplace and enables `network-ops` for this directory, so the gate is always on |
| `.env` / `.env.example` | Credentials (owner-only: `chmod 600` on Linux, owner ACL on Windows) and the template |
| `.gitignore` | Keeps site data out of git if you version the site |
| `CLAUDE.md` / `CLAUDE.local.md` | Short pointer / this site's subnets and notes |
| `inventory/inventory.db` | Empty inventory from the plugin's `inventory/schema.sql` |
| `backups/ outputs/ reports/ audits/ changes/ .claude/approvals/` | Site data |

The first setup on a machine also creates one shared Python environment for all sites
(`~/.local/share/claude-for-network/venv` on Linux, `%LOCALAPPDATA%\claude-for-network\venv` on Windows), with the
packages from `requirements.txt`.

> **`paramiko` stays below 4.** Older Cisco switches (2960 / 2960+ / 2960L on IOS 12.2–15.x) only offer
> `diffie-hellman-group1-sha1`, which paramiko 4+ removed.

Without Claude Code (e.g. in a terminal), the same setup is `cfn init [DIR]` if the plugin's `bin/` is on your PATH.

## 3. Credentials

Open `.env` in your own editor and fill in the credential sets you need. Never paste credentials into the chat.
Each device row has a `credential_ref`; the scripts read `NET_<REF>_USERNAME`, `NET_<REF>_PASSWORD` and
`NET_<REF>_ENABLE`.

| `credential_ref` | Used for |
|---|---|
| `DEFAULT` | Switches and routers (default for new devices) |
| `SOPHOS` / `SOPHOSAPI` | Sophos XG SSH console / XML API (Get-only) |
| `VCENTER` / `ESXI` | vSphere (use a read-only role) |
| `WINDOWS` / `LINUX` | Guest operating systems (WinRM / SSH) |
| `VEEAM` | Veeam Backup & Replication REST API (port 9419, read-only Backup Viewer role) |

Hosts and IPs go in the inventory, never in `.env`.

## 4. Discover devices

Read-only: an SSH port sweep (telnet when a device has no SSH) plus `show version`, upserted into the site
inventory with the port that answered.

```bash
cfn discover 192.0.2.0/24 --cred DEFAULT
cfn inventory counts
```

Or just ask Claude to do it. Devices that answer SSH but reject the credentials are stored as `auth_failed`; don't add a new `credential_ref` for them — make the type's shared account valid on those devices (or fix it in `.env`) and rerun discovery for their IPs.

One credential set per inventory type (`DEFAULT` switches, `SOPHOS`/`SOPHOSAPI`, `VCENTER`, `ESXI`, `WINDOWS`, `LINUX`, `VEEAM`), never per site or per device: use a service account that is valid on every device of that type (e.g. an AD domain account added to each vCenter's SSO identity sources).

## 5. Site context

Put site facts — known subnets, core switch names, naming conventions — in `CLAUDE.local.md`. Claude loads it in
every session in the site, and Claude asks the inventory before rescanning a known subnet.

## Updating the plugin

```bash
/plugin marketplace update network-ops
```

Site data is never touched by an update. Run `cfn init` in a site if a release adds Python packages.

Next: [change workflow](change-workflow.md) · [scripts](scripts.md)
