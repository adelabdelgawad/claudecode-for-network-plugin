# vSphere checklist — approved items

Approved by the user on 2026-10-27. Runner: `cfn vsphere-checklist`; E36–E44 come from `cfn guest-security`. Thresholds are constants in those scripts — keep this file and the scripts in sync.

`summary.json` item schema (shared by both runners):
`{"id", "section", "title", "status": "pass|warn|crit|info|skip", "reason", "findings": [{"target", "vcenter", "severity": "INFO|WARN|CRIT", "detail", "suggestion"}]}`

## A. vCenter
| ID | Check | Thresholds |
|---|---|---|
| A01 | Reachable, login, version/build | unreachable/auth failed ❌ |
| A02 | Active alarms | red ❌, yellow ⚠️ |
| A03 | Inventory drift vs inventory DB | VMs/hosts missing or gone ℹ️ |

## B. Clusters
| ID | Check | Thresholds |
|---|---|---|
| B04 | HA enabled + admission control | |
| B05 | DRS enabled + automation level | |
| B06 | Cluster CPU / memory usage | ⚠️ >75%, ❌ >90% |
| B07 | N+1: load fits if the largest host fails | |
| B08 | Mixed ESXi builds in a cluster | |

## C. ESXi hosts
| ID | Check | Thresholds |
|---|---|---|
| C09 | Connection / power state, maintenance mode | disconnected ❌, maintenance ⚠️ |
| C10 | Overall status | red ❌, yellow ⚠️ |
| C11 | CPU % and memory % | ⚠️ >80%, ❌ >90% |
| C12 | Hardware sensors (fans, PSU, temperature, disks, memory) | red ❌, yellow ⚠️ |
| C13 | Reboot required | |
| C14 | Uptime | ⚠️ >180 days |
| C15 | NTP configured + service running | |
| C16 | SSH / ESXi Shell running | ⚠️ |
| C17 | Lockdown mode off | ℹ️ |
| C18 | Host certificate expiry | ⚠️ <60 d, ❌ <15 d / expired |
| C19 | Dead / degraded storage paths | |
| C20 | Uplink pNICs link down | |
| C21 | CPU ready % (perf counters) | ⚠️ >5%, ❌ >10% |

## D. Datastores
| ID | Check | Thresholds |
|---|---|---|
| D22 | Accessible / mounted, status, maintenance mode | |
| D23 | Free space | ⚠️ <20%, ❌ <10% |
| D24 | Overcommit (provisioned / capacity) | ⚠️ >100%, ❌ >150% |
| D25 | Not mounted on all hosts of a cluster | |
| D26 | Read/write latency (perf counters) | ⚠️ >20 ms, ❌ >50 ms |

## E1. VM operating system and security (vCenter data)
| ID | Check | Thresholds |
|---|---|---|
| E27 | End-of-support guest OS (Win 2003–2012 R2, Win 7/8, RHEL/CentOS ≤7, old Ubuntu/Debian/SLES) | ❌ |
| E28 | Tools-reported OS ≠ configured OS | ⚠️ |
| E29 | Unknown / "Other" OS | ⚠️ |
| E30 | VMware Tools not running / not installed / old | |
| E31 | Powered-on VM with no IP or hostname | |
| E32 | Exposure: DMZ/internet/mgmt port groups ℹ️; NICs in ≥2 VLANs ⚠️ | |
| E33 | Insecure VM settings: copy/paste/drag-drop ℹ️; serial/parallel port ⚠️; ISO connected ⚠️ | |
| E34 | VM state: orphaned/inaccessible/invalid ❌, question pending ❌, consolidation needed ⚠️, status red/yellow | |
| E35 | Snapshots | ⚠️ >3 d, ❌ >14 d or >100 GB |
| E35b | Powered-off VMs and templates | ℹ️ |
| E35c | Hardware version < vmx-15 | ℹ️ |

## E2. Inside the guest OS (`cfn guest-security`, needs WINDOWS / LINUX credentials)
| ID | Check | Thresholds |
|---|---|---|
| E36 | Patches: last update, pending reboot, Linux security updates | ⚠️ >60 d, ❌ >120 d |
| E37 | Antivirus / Defender: running, real-time, signature age | off ❌, signatures ⚠️ >3 d |
| E38 | Host firewall off | ⚠️ |
| E39 | Risky services: SMBv1 ❌, RDP without NLA ⚠️, telnet/ftp/rsh ❌, other listeners ℹ️ | |
| E40 | Local admins / accounts: built-in Administrator enabled ⚠️, password never expires ⚠️ | |
| E41 | Failed-logon spikes (24 h) | ⚠️ >20, ❌ >200 |
| E42 | Stopped automatic services | ⚠️ |
| E43 | Time sync offset / source | ⚠️ >5 s, ❌ >60 s |
| E44 | Linux hardening: root SSH login ❌, password auth ⚠️, SELinux/AppArmor off ⚠️ | |

## F. VM resource use
| ID | Check | Thresholds |
|---|---|---|
| F45 | CPU vs allocated | ⚠️ >80% |
| F46 | Active memory vs allocated | ⚠️ >90% |
| F47 | Ballooned / swapped / compressed memory | ⚠️ >0 |
| F48 | Oversized VMs (≥8 vCPU or ≥32 GB, low use) | ℹ️ |
| F49 | Top 10 by CPU, memory, disk | ranking tables |

## G. Guest storage
| ID | Check | Thresholds |
|---|---|---|
| G50 | Guest volume free space (VMware Tools) | ⚠️ <15%, ❌ <10% |

## H. Backup coverage (Veeam, `--veeam-host`)
| ID | Check | Thresholds |
|---|---|---|
| H51 | Powered-on VMs not in any Veeam job | ⚠️ |
| H52 | VM's Veeam job failed/warning or not run | ⚠️ >48 h |
