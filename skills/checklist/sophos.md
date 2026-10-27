# Sophos XG / SFOS checklist — approved items

Approved by the user on 2026-10-27. Runner: `cfn sophos-checklist` (XML API `<Get>` only, firewalls from `devices` + `firewall_details`). Same `summary.json` item schema as [`vsphere.md`](vsphere.md). Items the API cannot read on a firmware are ➖ skip with the reason.

## A. Platform and health
| ID | Check | Thresholds |
|---|---|---|
| FW01 | API reachable + login; firmware recorded | ❌ |
| FW02 | Firmware end of support ❌ / not latest MR ⚠️ | |
| FW03 | HA mode, peer state, sync | peer faulty / not in sync ❌ |
| FW04 | CPU / memory / disk | ⚠️ >80%, ❌ >90% |
| FW05 | Licence / subscription expiry | ⚠️ <60 d, ❌ <15 d / expired |
| FW06 | Latest XML backup in `backups/<host>/`; scheduled backup off | ⚠️ >7 d / off |

## B. Firewall rules
| ID | Check | Thresholds |
|---|---|---|
| FW07 | Any-any-any rules | ❌ |
| FW08 | WAN → LAN rules ⚠️; WAN → LAN allowing RDP/SMB/SSH/telnet ❌ | |
| FW09 | Disabled rules; rules without description | ℹ️ |
| FW10 | Rules with logging off | ⚠️ |
| FW11 | Allow rules without IPS / web / app-control policy | ⚠️ |
| FW12 | Shadowed / duplicate rules | ℹ️ |
| FW13 | Referenced-but-undefined objects ❌; unused objects ℹ️ | |

## C. NAT and exposure
| ID | Check | Thresholds |
|---|---|---|
| FW14 | DNAT / port forwards listed; RDP/SMB/DB ports exposed | ❌ |
| FW15 | Exposed services without source restriction | ⚠️ |

## D. Admin and access security
| ID | Check | Thresholds |
|---|---|---|
| FW16 | Admin HTTPS/SSH from WAN ❌; from guest/untrusted zones ⚠️ | |
| FW17 | Default admin enabled; admins without MFA | ⚠️ |
| FW18 | Weak admin password policy / long session timeout | ⚠️ |
| FW19 | API enabled with broad allowed-IP list | ⚠️ |
| FW20 | SNMP v1/v2c with default community | ❌ |

## E. Threat protection
| ID | Check | Thresholds |
|---|---|---|
| FW21 | IPS / ATP / web / zero-day off or definitions stale | ⚠️ >3 d |
| FW22 | Pattern / firmware auto-update off | ⚠️ |

## F. VPN
| ID | Check | Thresholds |
|---|---|---|
| FW23 | IPsec tunnels configured active but down | ❌ |
| FW24 | Weak crypto (DES/3DES/MD5/SHA1, DH group <14) | ⚠️ |
| FW25 | SSL VPN without MFA ⚠️; split tunnel + reachable networks ℹ️ | |

## G. Logging and time
| ID | Check | Thresholds |
|---|---|---|
| FW26 | No remote syslog / central reporting | ⚠️ |
| FW27 | NTP not configured / not synced | ⚠️ |
