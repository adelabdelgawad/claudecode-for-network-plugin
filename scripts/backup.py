"""Back up running configs to backups/<hostname>/<timestamp>.cfg (read-only on devices).
Sophos firewalls (os_type sophos_sfos) go through sophos_api and are saved as <timestamp>.xml.

Usage: cfn backup TARGETS... [--match SW-*] [--all] [--workers 8]
"""
import argparse
from concurrent.futures import ThreadPoolExecutor

from netmiko import ConnectHandler

import netlib
import sophos_api


def backup(dev):
    if dev.get("os_type") == "sophos_sfos":  # firewalls: XML API backup, no SSH
        try:
            return dev, sophos_api.backup_device(dev), None
        except sophos_api.ApiError as e:
            return dev, None, f"{e.kind}: {e}"
        except Exception as e:  # noqa: BLE001 - report any failure per host
            return dev, None, netlib.err_text(e)
    try:
        with ConnectHandler(**netlib.conn_params(dev)) as conn:
            return dev, netlib.save_running_config(conn, dev["hostname"]), None
    except Exception as e:  # noqa: BLE001 - report any failure per host
        return dev, None, netlib.err_text(e)


def main():
    ap = argparse.ArgumentParser()
    netlib.add_target_args(ap)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    devs = netlib.resolve_targets(args)
    with ThreadPoolExecutor(min(args.workers, len(devs))) as ex:
        results = list(ex.map(backup, devs))
    for dev, path, err in results:
        if err:
            print(f"FAIL {dev['hostname']:30} {dev['mgmt_ip']:15} {err}")
        else:
            print(f"OK   {dev['hostname']:30} {path}")


if __name__ == "__main__":
    main()
