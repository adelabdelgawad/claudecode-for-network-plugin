"""Pre-push scan: secrets and site identifiers in tracked files (and, with --history, every commit). Read-only.

Usage: python3 tools/prepush_scan.py [--history] [--deny WORD ...]   (scans tracked + untracked-not-ignored files)
Checks: private IPv4 (10/8, 172.16/12, 192.168/16), hostnames from the local inventory DB (if present), --deny words
(company name, internal email domain), non-empty NET_*_PASSWORD/ENABLE values, private-key headers, and forbidden
tracked paths (site data). Prints `where: rule: masked match` and exits 1 on any hit.
"""
import argparse
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")
SECRET = re.compile(r"\bNET_[A-Z0-9]+_(?:PASSWORD|ENABLE)\s*=\s*\S+")
KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
FORBIDDEN = re.compile(r"^(?!templates/)(.*/)?(\.env|CLAUDE\.local\.md)$|\.db$|^(backups|outputs|reports|audits|changes)/(?!\.gitkeep$)"
                       r"|^\.claude/approvals/(?!\.gitkeep$)")


def git(*args):
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=True).stdout


def inventory_names(db):
    if not db or not db.is_file():
        return set()
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    names = set()
    for table, col in [("devices", "hostname"), ("machines", "name"), ("esxi_hosts", "hostname"), ("vcenters", "host")]:
        try:
            names |= {r[0] for r in con.execute(f"SELECT {col} FROM {table}") if r[0] and len(r[0]) >= 4}
        except sqlite3.Error:
            pass
    con.close()
    return names


def mask(s):
    return s[:3] + "*" * max(len(s) - 3, 3)


def rules(deny, db=None):
    out = [("private-ip", PRIVATE_IP), ("secret", SECRET), ("private-key", KEY)]
    words = sorted(deny | inventory_names(db), key=len, reverse=True)
    if words:
        out.append(("identifier", re.compile("|".join(re.escape(w) for w in words), re.IGNORECASE)))
    return out


def scan_text(where, text, rx_rules, hits, allow=frozenset()):
    for n, line in enumerate(text.splitlines(), 1):
        for rule, rx in rx_rules:
            for m in rx.finditer(line):
                if m.group(0) in allow:
                    continue
                hits.append(f"{where}:{n}: {rule}: {mask(m.group(0))}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--history", action="store_true", help="also scan every commit's diff")
    ap.add_argument("--deny", action="append", default=[], metavar="WORD", help="extra word to flag (repeatable)")
    ap.add_argument("--allow", action="append", default=[], metavar="TEXT", help="exact match to accept (repeatable)")
    ap.add_argument("--inventory", type=Path, metavar="DB", help="a site's inventory.db: flag its hostnames")
    args = ap.parse_args()
    rx_rules, hits, allow = rules(set(args.deny), args.inventory), [], set(args.allow)
    for path in git("ls-files", "--cached", "--others", "--exclude-standard").splitlines():
        if FORBIDDEN.search(path):
            hits.append(f"{path}: forbidden-path: site data must not be tracked")
        f = REPO / path
        if f.is_file():
            try:
                scan_text(path, f.read_text(encoding="utf-8"), rx_rules, hits, allow)
            except UnicodeDecodeError:
                pass
    if args.history:
        for line in git("log", "--all", "--name-only", "--format=").splitlines():
            if line and FORBIDDEN.search(line):
                hits.append(f"history:{line}: forbidden-path: was committed")
        added = [ln[1:] for ln in git("log", "-p", "--all", "--format=commit %h").splitlines()
                 if ln.startswith("+") and not ln.startswith("+++")]
        scan_text("history(+lines)", "\n".join(added), rx_rules, hits, allow)
    for h in dict.fromkeys(hits):
        print(h)
    print(f"\n{len(set(hits))} finding(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
