"""Offline selftest for the SSH/telnet transport choice (netlib.conn_params, discover.collect); no device contact.

Run: .venv/bin/python tests/test_transport.py   (needs the venv python for netmiko)
"""
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
# The scripts resolve a site root at import time; give them an empty throwaway site (the test reads no site data).
_SITE = tempfile.mkdtemp(prefix="cfn-test-site-")
Path(_SITE, ".claude-for-network").write_text("{}")
os.environ["CLAUDE_PROJECT_DIR"] = _SITE
os.environ.update({"NET_DEFAULT_USERNAME": "u", "NET_DEFAULT_PASSWORD": "p"})

from netmiko.ssh_dispatcher import CLASS_MAPPER  # noqa: E402

import discover  # noqa: E402
import netlib  # noqa: E402


def check_conn_params(fails):
    base = {"mgmt_ip": "192.0.2.10", "credential_ref": "DEFAULT"}
    for os_type, port, want_port in [("cisco_ios", None, 22), ("cisco_xe", 22, 22), ("cisco_ios", 23, 23),
                                     ("cisco_xe", 23, 23), (None, 23, 23)]:
        p = netlib.conn_params({**base, "os_type": os_type, "port": port})
        telnet = want_port == netlib.TELNET_PORT
        if p["port"] != want_port:
            fails.append(f"{os_type}/{port}: port {p['port']} != {want_port}")
        if p["device_type"] not in CLASS_MAPPER:
            fails.append(f"{os_type}/{port}: {p['device_type']} is not a Netmiko driver")
        if p["device_type"].endswith("_telnet") != telnet:
            fails.append(f"{os_type}/{port}: wrong transport {p['device_type']}")
    if netlib.netmiko_type(netlib.netmiko_type("cisco_ios", 23), 23) != netlib.netmiko_type("cisco_ios", 23):
        fails.append("netmiko_type is not idempotent")


def check_fallback(fails):
    calls = []

    def fake(results):
        def collect_on(ip, port, cred):
            calls.append(port)
            return results[port]
        return collect_on

    ok = {"ip": "192.0.2.10", "port": 23, "hostname": "SW-ACCESS-01"}
    ssh_err = {"ip": "192.0.2.10", "error": "SSHException: kex", "auth": False}
    auth_err = {"ip": "192.0.2.10", "error": "NetmikoAuthenticationException: x", "auth": True}
    real = discover.collect_on
    try:
        discover.collect_on = fake({22: ssh_err, 23: ok})
        if discover.collect("192.0.2.10", [22, 23], "DEFAULT") is not ok or calls != [22, 23]:
            fails.append("SSH failure should fall back to telnet")
        calls.clear()
        discover.collect_on = fake({22: {**ok, "port": 22}})
        if discover.collect("192.0.2.10", [22, 23], "DEFAULT")["port"] != 22 or calls != [22]:
            fails.append("SSH success must not try telnet")
        discover.collect_on = fake({22: auth_err, 23: ssh_err})
        r = discover.collect("192.0.2.10", [22, 23], "DEFAULT")
        if not (r["auth"] and r["port"] == 22 and "SSH:" in r["error"] and "telnet:" in r["error"]):
            fails.append(f"auth failure should be recorded on the SSH port with both errors: {r}")
    finally:
        discover.collect_on = real


def main():
    fails = []
    check_conn_params(fails)
    check_fallback(fails)
    for f in fails:
        print("FAIL", f)
    print("ALL OK" if not fails else f"{len(fails)} FAILURE(S)")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
