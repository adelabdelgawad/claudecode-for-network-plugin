"""READ-ONLY analysis of a bulk-run output directory (stdlib only; never writes, never contacts devices).

Usage:
    cfn results [RUN_DIR] [summary]
    cfn results [RUN_DIR] grep REGEX [--host GLOB] [-i] [--count]
    cfn results [RUN_DIR] field PATH [--top N]
    cfn results [RUN_DIR] failed

RUN_DIR defaults to the newest run under the site's outputs/ or reports/ (one that has summary.json, raw/,
per-host .txt files or per-host dirs of .xml files). Layouts understood:
    <run>/summary.json + <run>/raw/<host>.txt    log_audit.py, sophos_api.py audit, other fan-out scripts
    <run>/<host>.txt                             `cfn show --out` (outputs/<ts>/)
    <run>/<host>/<Entity>.xml                    `cfn sophos-api get --out` (outputs/<ts>/)
summary.json is {"devices": [...]}, each entry keyed by hostname/host and carrying error/connect_error on failure.
"""
import argparse
import fnmatch
import json
import re
import sys
from collections import Counter
from pathlib import Path

HOST_KEYS = ("hostname", "host", "name")
ERR_KEYS = ("error", "connect_error")
SUBCMDS = ("summary", "grep", "field", "failed")
TIME_KEYS = ("elapsed", "elapsed_s", "duration", "duration_s", "seconds")


def site_root():
    import paths  # deferred: --help and tests on explicit dirs need no site
    return paths.site_root()


def _is_run(d):
    if not d.is_dir():
        return False
    if (d / "summary.json").is_file() or (d / "raw").is_dir() or any(d.glob("*.txt")):
        return True
    return any(any(s.glob("*.xml")) for s in d.iterdir() if s.is_dir())


def newest_run(root):
    cands = [p for base in (root / "outputs", root / "reports") if base.is_dir()
             for p in [base, *base.iterdir(), *(q for s in base.iterdir() if s.is_dir() for q in s.iterdir())]]
    runs = [p for p in cands if _is_run(p)]
    if not runs:
        raise SystemExit("no run directory found under outputs/ or reports/ (pass RUN_DIR)")
    return max(runs, key=lambda p: p.stat().st_mtime)


def load_devices(run):
    f = run / "summary.json"
    if not f.is_file():
        return None
    data = json.loads(f.read_text())
    devs = data.get("devices", data.get("results")) if isinstance(data, dict) else data
    return [d for d in devs or [] if isinstance(d, dict)]


def dev_host(d):
    return next((str(d[k]) for k in HOST_KEYS if d.get(k)), "?")


def dev_error(d):
    return next((str(d[k]) for k in ERR_KEYS if d.get(k)), None)


def dev_time(d):
    for k in TIME_KEYS:
        if isinstance(d.get(k), (int, float)):
            return d[k]
    return None


def dotted(obj, path):
    for part in path.split("."):
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


def raw_files(run):
    """Yield (label, host, path) for every raw output file in either layout."""
    seen = set()
    for p in sorted((run / "raw").glob("*.txt")) if (run / "raw").is_dir() else []:
        seen.add(p)
        yield p.stem, p.stem, p
    for p in sorted(run.glob("*.txt")):
        yield p.stem, p.stem, p
    for d in sorted(s for s in run.iterdir() if s.is_dir() and s.name != "raw"):
        for p in sorted([*d.glob("*.txt"), *d.glob("*.xml")]):
            yield f"{d.name}/{p.stem}", d.name, p


def table(rows, headers):
    rows = [[str(c) for c in r] for r in rows]
    w = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(w[i]) for i, h in enumerate(headers)).rstrip()]
    lines += ["  ".join(c.ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in rows]
    return "\n".join(lines)


def cmd_summary(run, args):
    devs = load_devices(run)
    print(f"run: {run}")
    if devs is None:
        files = list(raw_files(run))
        hosts = sorted({h for _, h, _ in files})
        print(f"no summary.json; {len(hosts)} host(s), {len(files)} raw file(s)")
        return 0
    errs = [(dev_host(d), dev_error(d)) for d in devs]
    failed = sum(1 for _, e in errs if e)
    print(f"devices: {len(devs)}  ok: {len(devs) - failed}  failed: {failed}")
    st = Counter(str(d["status"]) for d in devs if "status" in d)
    if st:
        print("\n" + table(st.most_common(), ["status", "count"]))
    groups = Counter(e.splitlines()[0][:100] for _, e in errs if e)
    if groups:
        print("\ntop errors:\n" + table([(n, e) for e, n in groups.most_common(10)], ["count", "error"]))
    timed = sorted(((dev_time(d), dev_host(d)) for d in devs if dev_time(d) is not None), reverse=True)[:5]
    if timed:
        print("\nslowest:\n" + table([(h, f"{t:.1f}") for t, h in timed], ["host", "seconds"]))
    return 0


def cmd_grep(run, args):
    try:
        rx = re.compile(args.regex, re.I if args.ignore_case else 0)
    except re.error as e:
        raise SystemExit(f"bad regex: {e}")
    counts = Counter()
    for label, host, path in raw_files(run):
        if args.host and not fnmatch.fnmatch(host, args.host):
            continue
        with open(path, errors="replace") as fh:
            for line in fh:
                if rx.search(line):
                    counts[label] += 1
                    if not args.count:
                        print(f"{label}: {line.rstrip()[:300]}")
    if args.count:
        print(table(sorted(counts.items()), ["host", "matches"]))
    return 0 if counts else 1


def cmd_field(run, args):
    devs = load_devices(run)
    if devs is None:
        raise SystemExit("no summary.json in this run; `field` needs it")
    c = Counter()
    for d in devs:
        v = dotted(d, args.path)
        c["<missing>" if v is None else json.dumps(v) if isinstance(v, (dict, list)) else str(v)] += 1
    print(table([(n, v) for v, n in c.most_common(args.top)], ["count", "value"]))
    return 0


def cmd_failed(run, args):
    for d in load_devices(run) or []:
        if dev_error(d):
            print(f"{dev_host(d)}\t{dev_error(d).splitlines()[0][:200]}")
    return 0


def build_parser():
    ap = argparse.ArgumentParser(description="Read-only analysis of a bulk-run output directory",
                                 usage="cfn results [RUN_DIR] {summary,grep,field,failed} ...  (RUN_DIR default: newest under outputs/ or reports/)")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("summary", help="counts, top errors, slowest hosts (default)")
    p = sub.add_parser("grep", help="search raw files, print host: line")
    p.add_argument("regex")
    p.add_argument("--host", metavar="GLOB")
    p.add_argument("-i", "--ignore-case", action="store_true")
    p.add_argument("--count", action="store_true", help="matches per host instead of lines")
    p = sub.add_parser("field", help="count values of a dotted key across summary.json devices")
    p.add_argument("path")
    p.add_argument("--top", type=int, default=20)
    sub.add_parser("failed", help="failed hosts with their error")
    return ap


def split_run_dir(argv, cmds):
    """RUN_DIR is an optional leading positional before the subcommand (argparse cannot do that)."""
    if argv and not argv[0].startswith("-") and argv[0] not in cmds:
        return argv[0], argv[1:]
    return None, argv


def main(argv=None):
    ap = build_parser()
    run_dir, rest = split_run_dir(list(sys.argv[1:] if argv is None else argv), SUBCMDS)
    args = ap.parse_args(rest)
    run = Path(run_dir) if run_dir else newest_run(site_root())
    if not run.is_dir():
        raise SystemExit(f"not a directory: {run}")
    fn = {"grep": cmd_grep, "field": cmd_field, "failed": cmd_failed}.get(args.cmd, cmd_summary)
    return fn(run, args)


if __name__ == "__main__":
    sys.exit(main())
