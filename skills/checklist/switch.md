# Switch / router checklist — approved items

Approved by the user on 2026-10-27. Runner: `cfn switch-checklist` (Cisco IOS / IOS-XE from `devices`, `status='active'`). Same `summary.json` item schema as [`vsphere.md`](vsphere.md); finding `target` = hostname. Thresholds are constants in the runner — keep both in sync.

## A. Reachability and platform
| ID | Check | Thresholds |
|---|---|---|
| SW01 | SSH reachable + login; `auth_failed` devices listed | unreachable / auth failed ❌ |
| SW02 | Software EOL ❌ (audit.py OS-EOL); version spread across fleet ℹ️ | |
| SW03 | Uptime; last reload reason crash/power | ⚠️ >365 d; unexpected reload ⚠️ |
| SW04 | Inventory drift: serial/model/version ≠ inventory DB | ℹ️ |

## B. Hardware health
| ID | Check | Thresholds |
|---|---|---|
| SW05 | PSU / fans / temperature (`show environment`) | failed/critical ❌ |
| SW06 | CPU 5-min avg; memory free | CPU ⚠️ >70% ❌ >90%; mem free ⚠️ <20% |
| SW07 | Flash free | ⚠️ <15% |
| SW08 | Stack members / ring; PoE budget | member missing / ring half ❌; PoE ⚠️ >85% |
| SW09 | SFP optics out of range (`show interfaces transceiver`) | ⚠️ |

## C. Interfaces and L2
| ID | Check | Thresholds |
|---|---|---|
| SW10 | CRC / input errors / runts; err-disabled ports | errors ⚠️; err-disabled ❌ |
| SW11 | Half duplex / duplex mismatch; uplinks below expected speed | ⚠️ |
| SW12 | Flapping interfaces (logs) | ⚠️ |
| SW13 | STP root not the core ❌; topology changes in 24 h ⚠️; edge ports without BPDU guard ℹ️ | |
| SW14 | Native VLAN 1 / access VLAN 1 (audit.py); VLANs on access switches missing on core | ⚠️ |
| SW15 | EtherChannel members down/suspended | ⚠️ |
| SW16 | Unused ports not shut down (audit.py) | ℹ️ |

## D. Security hardening (audit.py)
| ID | Check | Thresholds |
|---|---|---|
| SW17 | Smart Install enabled | ❌ |
| SW18 | Telnet on vty ❌; SSH v1 ❌; RSA key <2048 ⚠️ | |
| SW19 | No vty ACL; no/disabled exec-timeout; no `login block-for` | ⚠️ |
| SW20 | `enable password`, weak/type-5 secrets, no password-encryption | ❌/⚠️ |
| SW21 | No AAA ⚠️; local accounts only ℹ️ | |
| SW22 | SNMP default/weak community ❌; no ACL ⚠️; v1/v2c ℹ️ | |
| SW23 | HTTP/HTTPS server enabled | ⚠️ |
| SW24 | VTP server/client without password | ⚠️ |
| SW25 | DHCP snooping / DAI off ℹ️; port-security violations in 24 h ⚠️ | |
| SW26 | No banner ℹ️; CDP enabled ℹ️ | |

## E. Management and operations
| ID | Check | Thresholds |
|---|---|---|
| SW27 | NTP: none configured ⚠️; not synchronized ❌ | |
| SW28 | No remote syslog ⚠️; small logging buffer ℹ️ | |
| SW29 | Critical log events (sev 0–2) in 24 h (log_audit.py) | ❌ |
| SW30 | Running config not saved to startup | ⚠️ |
| SW31 | Latest backup in `backups/<host>/` | ⚠️ >7 d / none |
| SW32 | Users logged in now | ℹ️ |

## F. Routing (L3 devices only)
| ID | Check | Thresholds |
|---|---|---|
| SW33 | OSPF/EIGRP/BGP neighbors not in full/established ❌; flaps in 24 h ⚠️ | |
| SW34 | Default route missing ❌; HSRP/VRRP state unexpected ⚠️ | |
