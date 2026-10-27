"""Discover Cisco devices in a subnet via SSH (telnet as fallback) and upsert them into the inventory.

Usage: cfn discover 192.0.2.0/24 [192.0.2.13 ...] [--cred DEFAULT] [--workers 32]

Ports 22 and 23 are probed (hosts that do not answer get a second pass). Login tries SSH first and telnet when SSH
is closed or fails; the port that worked is stored in devices.port and selects the transport for every later script
(netlib.conn_params). Hosts that answer but reject the credentials are stored with status 'auth_failed'.
"""
import argparse
import ipaddress
import os
import re
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv
from netmiko import ConnectHandler

import netlib
import paths

ROOT = paths.site_root()
load_dotenv(ROOT / ".env")
DB = ROOT / os.getenv("INVENTORY_DB", "inventory/inventory.db")


PROTO = {netlib.SSH_PORT: "SSH", netlib.TELNET_PORT: "telnet"}
PROBE_TIMEOUT = 3        # seconds; a cold ARP cache can delay the first SYN past 1.5 s
PROBE_WORKERS = 32       # simultaneous TCP probes; a larger burst drops hosts while ARP resolves


def port_open(ip, port, timeout=PROBE_TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def open_ports(ip):
    """Management ports (SSH, then telnet) that accept a TCP connection, in that order."""
    return [p for p in PROTO if port_open(ip, p)]


def sweep(hosts, workers):
    """{ip: [open ports]} for hosts answering on 22 or 23; non-answering hosts get one more pass."""
    found, pending = {}, hosts
    for _ in range(2):
        with ThreadPoolExecutor(min(workers, PROBE_WORKERS)) as ex:
            for ip, ports in zip(pending, ex.map(open_ports, pending)):
                if ports:
                    found[ip] = ports
        pending = [ip for ip in pending if ip not in found]
    return found


def ssh_banner(ip):
    try:
        with socket.create_connection((ip, netlib.SSH_PORT), timeout=3) as s:
            return s.recv(100).decode(errors="replace").strip()
    except OSError:
        return None


def os_type_from(ver):
    if "NX-OS" in ver:
        return "cisco_nxos"
    if re.search(r"IOS[ -]XE", ver):
        return "cisco_xe"
    return "cisco_ios"


def collect(ip, ports, cred):
    """Log in over each open port in order (SSH first, telnet if SSH is closed or fails); first success wins."""
    errors, auth_port = [], None
    for port in ports:
        res = collect_on(ip, port, cred)
        if "error" not in res:
            return res
        errors.append(f"{PROTO[port]}: {res['error']}")
        if res["auth"] and auth_port is None:
            auth_port = port
    return {"ip": ip, "port": auth_port or ports[0], "error": "; ".join(errors), "auth": auth_port is not None}


def collect_on(ip, port, cred):
    params = {
        "device_type": netlib.netmiko_type("cisco_ios", port),
        "host": ip,
        "port": port,
        "username": os.getenv(f"NET_{cred}_USERNAME"),
        "password": os.getenv(f"NET_{cred}_PASSWORD"),
        "secret": os.getenv(f"NET_{cred}_ENABLE") or "",
        "conn_timeout": 15,
        "auth_timeout": 20,
    }
    try:
        with ConnectHandler(**params) as conn:
            ver = conn.send_command("show version")
            prompt = conn.find_prompt()
            parsed = conn.send_command("show version", use_textfsm=True)
    except Exception as e:  # noqa: BLE001 - report any failure per host
        msg = str(e).splitlines()[0][:120] if str(e) else ""
        return {"ip": ip, "error": f"{type(e).__name__}: {msg}", "auth": "Authentication" in type(e).__name__}
    info = parsed[0] if isinstance(parsed, list) and parsed else {}
    hw = info.get("hardware") or info.get("platform") or []
    sn = info.get("serial") or info.get("serial_number") or []
    return {
        "ip": ip,
        "port": port,
        "hostname": info.get("hostname") or prompt.rstrip("#>"),
        "model": hw[0] if isinstance(hw, list) and hw else (hw or None),
        "serial": sn[0] if isinstance(sn, list) and sn else (sn or None),
        "os_version": info.get("version") or info.get("os"),
        "os_type": os_type_from(ver),
    }


def upsert(db, d, cred):
    db.execute(
        """
        INSERT INTO devices (hostname, mgmt_ip, device_type, vendor, model, os_type,
                             os_version, serial, port, credential_ref, notes)
        VALUES (?, ?, 'switch', 'cisco', ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mgmt_ip) DO UPDATE SET
            hostname=excluded.hostname, model=excluded.model, os_type=excluded.os_type,
            os_version=excluded.os_version, serial=excluded.serial, port=excluded.port,
            credential_ref=excluded.credential_ref, status='active', notes=excluded.notes
        """,
        (d["hostname"], d["ip"], d["model"], d["os_type"], d["os_version"], d["serial"], d["port"], cred,
         f"discovered by scripts/discover.py over {PROTO[d['port']]}"),
    )


def record_auth_failed(db, r, cred):
    banner = ssh_banner(r["ip"]) if r["port"] == netlib.SSH_PORT else None
    db.execute(
        """
        INSERT INTO devices (hostname, mgmt_ip, device_type, vendor, port, credential_ref, status, notes)
        VALUES (?, ?, 'unknown', ?, ?, ?, 'auth_failed', ?)
        ON CONFLICT(mgmt_ip) DO UPDATE SET status='auth_failed', port=excluded.port, notes=excluded.notes
        """,
        (f"unknown-{r['ip']}", r["ip"], "cisco" if banner and "Cisco" in banner else None, r["port"], cred,
         f"NET_{cred}_* credentials rejected ({r['error'][:200]}); banner: {banner}"),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+", help="subnets and/or single IPs")
    ap.add_argument("--cred", default="DEFAULT")
    ap.add_argument("--workers", type=int, default=32)
    args = ap.parse_args()

    hosts = []
    for t in args.targets:
        net = ipaddress.ip_network(t, strict=False)
        hosts += [str(h) for h in (net.hosts() if net.num_addresses > 1 else [net.network_address])]
    found = sweep(hosts, args.workers)
    telnet_only = sum(ports == [netlib.TELNET_PORT] for ports in found.values())
    print(f"{len(found)} hosts with SSH or telnet open in {' '.join(args.targets)} ({telnet_only} telnet only)")

    with ThreadPoolExecutor(min(args.workers, 16)) as ex:
        results = list(ex.map(lambda ip: collect(ip, found[ip], args.cred), found))

    db = sqlite3.connect(DB)
    for r in sorted(results, key=lambda r: ipaddress.ip_address(r["ip"])):
        if "error" in r:
            print(f"FAIL {r['ip']:15} {r['error']}")
            if r["auth"]:
                record_auth_failed(db, r, args.cred)
            continue
        upsert(db, r, args.cred)
        print(f"OK   {r['ip']:15} {PROTO[r['port']]:6} {r['hostname']:30} {r['model'] or '-':22} "
              f"{r['os_type']:10} {r['os_version'] or '-'}")
    db.commit()


if __name__ == "__main__":
    main()
