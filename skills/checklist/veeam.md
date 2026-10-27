# Veeam Backup & Replication checklist — approved items

Approved by the user on 2026-10-27. Runner: `cfn veeam-checklist` (REST API, GET-only via `veeam_api.py`; host from `--host`, see `CLAUDE.local.md`). Same `summary.json` item schema as [`vsphere.md`](vsphere.md). Items the API cannot read on the installed version are ➖ skip with the reason.

## A. Server
| ID | Check | Thresholds |
|---|---|---|
| VB01 | API reachable + login; version/build, not latest patch | ❌ / ⚠️ |
| VB02 | Licence expiry; instances used vs licensed | ⚠️ <60 d; ⚠️ >90% |
| VB03 | Configuration backup: present, recent success, encrypted | ⚠️/❌ |

## B. Backup jobs
| ID | Check | Thresholds |
|---|---|---|
| VB04 | Last result per job | Failed ❌, Warning ⚠️ |
| VB05 | No successful run (daily jobs) | ⚠️ >48 h, ❌ >7 d |
| VB06 | Running too long | ⚠️ >12 h |
| VB07 | Disabled jobs ⚠️; no schedule ℹ️ | |
| VB08 | Application-aware processing off on DB / DC / Exchange VMs | ⚠️ |
| VB09 | Retention <7 restore points ⚠️; no GFS anywhere ℹ️ | |
| VB10 | Retry disabled | ℹ️ |

## C. Repositories and storage
| ID | Check | Thresholds |
|---|---|---|
| VB11 | Repository free space; offline repo | ⚠️ <20%, ❌ <10%; offline ❌ |
| VB12 | No immutable / hardened repository | ⚠️ |
| VB13 | Backup encryption off | ⚠️ |

## D. 3-2-1 and resilience
| ID | Check | Thresholds |
|---|---|---|
| VB14 | No backup copy job / second copy | ❌ |
| VB15 | All jobs on a single repository | ⚠️ |
| VB16 | SureBackup / restore verification never run | ℹ️ |

## E. Coverage (vs vCenter)
| ID | Check | Thresholds |
|---|---|---|
| VB17 | Powered-on VMs with no backup job | ⚠️ |
| VB18 | Jobs pointing at VMs that no longer exist | ⚠️ |

## F. Infrastructure
| ID | Check | Thresholds |
|---|---|---|
| VB19 | Proxies / managed servers offline ❌; outdated components ⚠️ | |
| VB20 | Active alarms / malware detection events | ❌ |
