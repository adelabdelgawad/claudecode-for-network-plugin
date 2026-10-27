"""Discover Cisco devices in a subnet via SSH and upsert them into the inventory.

Usage: cfn discover 192.0.2.0/24 [192.0.2.13 ...] [--cred DEFAULT] [--workers 32]

Hosts that answer SSH but reject the credentials are stored with status 'auth_failed'.
"""
import argparse
import ipaddress
import os
import re
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dotenv import load_dotenv
from netmiko import ConnectHandler

import paths

ROOT = paths.site_root()
load_dotenv(ROOT / ".env")
DB = ROOT / os.getenv("INVENTORY_DB", "inventory/inventory.db")


def port_open(ip, port, timeout=1.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def ssh_banner(ip):
    try:
        with socket.create_connection((ip, 22), timeout=3) as s:
            return s.recv(100).decode(errors="replace").strip()
    except OSError:
        return None


def os_type_from(ver):
    if "NX-OS" in ver:
        return "cisco_nxos"
    if re.search(r"IOS[ -]XE", ver):
        return "cisco_xe"
    return "cisco_ios"


def collect(ip, cred):
    params = {
        "device_type": "cisco_ios",
        "host": ip,
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
                             os_version, serial, credential_ref, notes)
        VALUES (?, ?, 'switch', 'cisco', ?, ?, ?, ?, ?, 'discovered by scripts/discover.py')
        ON CONFLICT(mgmt_ip) DO UPDATE SET
            hostname=excluded.hostname, model=excluded.model, os_type=excluded.os_type,
            os_version=excluded.os_version, serial=excluded.serial,
            credential_ref=excluded.credential_ref, status='active', notes=excluded.notes
        """,
        (d["hostname"], d["ip"], d["model"], d["os_type"], d["os_version"], d["serial"], cred),
    )


def record_auth_failed(db, ip, cred):
    banner = ssh_banner(ip)
    db.execute(
        """
        INSERT INTO devices (hostname, mgmt_ip, device_type, vendor, credential_ref, status, notes)
        VALUES (?, ?, 'unknown', ?, ?, 'auth_failed', ?)
        ON CONFLICT(mgmt_ip) DO UPDATE SET status='auth_failed', notes=excluded.notes
        """,
        (f"unknown-{ip}", ip, "cisco" if banner and "Cisco" in banner else None, cred,
         f"SSH open but NET_{cred}_* credentials rejected; banner: {banner}"),
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
    with ThreadPoolExecutor(args.workers) as ex:
        ssh = [ip for ip, ok in zip(hosts, ex.map(lambda i: port_open(i, 22), hosts)) if ok]
    print(f"{len(ssh)} hosts with SSH open in {' '.join(args.targets)}")

    with ThreadPoolExecutor(min(args.workers, 16)) as ex:
        results = list(ex.map(lambda i: collect(i, args.cred), ssh))

    db = sqlite3.connect(DB)
    for r in sorted(results, key=lambda r: ipaddress.ip_address(r["ip"])):
        if "error" in r:
            print(f"FAIL {r['ip']:15} {r['error']}")
            if r["auth"]:
                record_auth_failed(db, r["ip"], args.cred)
            continue
        upsert(db, r, args.cred)
        print(f"OK   {r['ip']:15} {r['hostname']:30} {r['model'] or '-':22} {r['os_type']:10} {r['os_version'] or '-'}")
    db.commit()


if __name__ == "__main__":
    main()
