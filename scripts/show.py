"""Run read-only show commands on inventory devices in parallel.

Usage: cfn show -c "show ip int brief" [-c "show vlan brief" ...] TARGETS... [--match SW-*] [--all] [--out] [--grep REGEX ...] [--quiet] [--workers 16]

Only show/display/get/ping/traceroute/dir/more commands are accepted.
"""
import argparse
import re
from concurrent.futures import ThreadPoolExecutor

from netmiko import ConnectHandler

import netlib
from netlib import ROOT


def enter_console(conn):
    """SFOS login lands on the numbered main menu; option 4 is the Device Console, where `show ...` works.

    netmiko 4.8's sophos_sfos driver stops at the menu (its SOPHOS_MENU_DEFAULT is defined but unused),
    and its enable() is a no-op. Selecting a menu entry is navigation only, not a change.
    UNTESTED against a real firewall.
    """
    conn.send_command_timing("4", read_timeout=15)


def run(dev, commands):
    try:
        with ConnectHandler(**netlib.conn_params(dev)) as conn:
            if dev.get("os_type") == "sophos_sfos":
                enter_console(conn)
            else:
                conn.enable()
            return dev, [(c, conn.send_command(c)) for c in commands], None
    except Exception as e:  # noqa: BLE001 - report any failure per host
        return dev, None, netlib.err_text(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--command", action="append", required=True, dest="commands")
    netlib.add_target_args(ap)
    ap.add_argument("--out", action="store_true", help="also save to outputs/<timestamp>/<hostname>.txt")
    ap.add_argument("--grep", action="append", default=[], metavar="REGEX", help="print only matching lines (case-insensitive, repeatable) prefixed 'hostname: '; --out files stay unfiltered")
    ap.add_argument("--quiet", action="store_true", help="print one OK/FAIL line per device, no output (requires --out)")
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

    netlib.require_readonly(args.commands)
    if args.quiet and not args.out:
        ap.error("--quiet requires --out")
    try:
        pats = [re.compile(g, re.IGNORECASE) for g in args.grep]
    except re.error as e:
        ap.error(f"bad --grep regex: {e}")
    devs = netlib.resolve_targets(args)
    outdir = ROOT / "outputs" / netlib.timestamp() if args.out else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)

    with ThreadPoolExecutor(min(args.workers, len(devs))) as ex:
        results = list(ex.map(lambda d: run(d, args.commands), devs))

    ok = 0
    for dev, outs, err in results:
        host, ip = dev["hostname"], dev["mgmt_ip"]
        if err:
            print(f"FAIL {host:30} {ip:15} {err}")
            continue
        ok += 1
        text = ""
        for c, o in outs:
            text += f"===== {host} ({ip}) :: {c} =====\n{o}\n"
        if outdir:
            (outdir / f"{host}.txt").write_text(text)
        if args.quiet:
            print(f"OK   {host} {ip} {text.count(chr(10))} lines")
        elif pats:
            for line in text.splitlines():
                if any(p.search(line) for p in pats):
                    print(f"{host}: {line}")
        else:
            print(text, end="")
    if outdir:
        print(f"saved to {outdir}")
    print(f"{ok} ok / {len(results) - ok} failed")


if __name__ == "__main__":
    main()
