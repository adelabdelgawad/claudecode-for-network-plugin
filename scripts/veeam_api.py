"""READ-ONLY Veeam Backup & Replication (v12+) REST API client: facts, get, jobs, sessions, repos, report.

Usage: cfn veeam-api facts    --host H [--host H ...] [--port 9419] [--cred VEEAM]
       cfn veeam-api get      --host H PATH [PATH ...] [--out] [--quiet]
       cfn veeam-api jobs     --host H
       cfn veeam-api sessions --host H [--hours 24]
       cfn veeam-api repos    --host H
       cfn veeam-api report   --host H [--hours 24] [--out DIR]
       cfn veeam-api selftest          (offline check of the path allowlist)

Transport: https://<host>:<port>/api/v1/... with header `x-api-version` (default 1.1-rev0, set with
--api-version) and a bearer token. The server is not in the inventory DB; pass it with --host.

READ-ONLY GUARANTEE: the only non-GET request this module can send is the token request in login()
(POST /api/oauth2/token), plus the optional session close in logout() (POST /api/oauth2/logout).
Everything else goes through api_get(), which hard-codes method GET, and assert_read_path() rejects
any path outside /api/v1/, any action segment (the API's start/stop/retry/enable/disable/rescan/...
verbs), `..`, and anything that is not a plain query string, before every send. Acting on the
backup server (running, stopping or editing jobs) is a change and does not belong in this file.

Credentials: NET_<REF>_USERNAME / NET_<REF>_PASSWORD from .env (default REF = VEEAM). Passwords and
tokens are never printed, logged or saved. Self-signed certs are normal, so TLS is not verified
unless --verify-ssl is given.
"""
import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import netlib  # also loads .env
from netlib import ROOT

DEFAULT_PORT = 9419
DEFAULT_API_VERSION = "1.1-rev0"
DEFAULT_CRED = "VEEAM"
PAGE_SIZE = 200
MAX_ITEMS = 50000          # safety cap per list endpoint
MAX_BODY = 64 * 1024 * 1024
STALE_HOURS = 48           # report: enabled job with no run for longer than this
LOW_FREE_PCT = 15.0        # report: repository free space below this

TOKEN_PATH = "/api/oauth2/token"     # the ONLY allowed POST (login)
LOGOUT_PATH = "/api/oauth2/logout"   # optional POST at the end (closes the session)

HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
PATH_RE = re.compile(r"^/api/v1/[A-Za-z0-9_/-]*$")      # no dots: `..` cannot occur
QUERY_PAIR_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}=[A-Za-z0-9_.:+%-]{0,200}$")
GUID_RE = re.compile(r"^[0-9a-fA-F-]{32,36}$")
# Path segments that name an action rather than a resource. Lower-case. Defence in depth: the
# request method is GET anyway, but a path that names an action is refused outright.
ACTION_EXACT = {"run", "restore", "reset", "clear", "add", "edit", "update", "import", "export",
                "apply", "set", "mount", "unmount", "migrate", "assign", "move", "test", "sync",
                "upgrade", "patch", "install", "takeover", "failover", "failback", "commit",
                "undo", "approve", "logout", "token", "login", "connect", "disconnect"}
ACTION_PREFIX = ("start", "stop", "retry", "disable", "enable", "rescan", "delete", "remove",
                 "create", "cancel", "terminate", "kill")


class ApiError(Exception):
    """Fatal per-host problem (transport, login, API access). kind: conn|auth|api|proto."""

    def __init__(self, kind, msg):
        super().__init__(msg)
        self.kind = kind


# --------------------------------------------------------------------------- read-only guard
def assert_read_path(path):
    """Raise ValueError unless `path` is a plain /api/v1/ read path (optionally with ?k=v&k=v)."""
    if not isinstance(path, str) or not path:
        raise ValueError("empty path")
    base, sep, query = path.partition("?")
    if not PATH_RE.match(base) or "//" in base:
        raise ValueError(f"path {base!r} must start with /api/v1/ and use only letters, digits, '_', '-', '/'")
    for seg in base.split("/"):
        s = seg.lower()
        if not s or GUID_RE.match(seg):
            continue
        if s in ACTION_EXACT or s.startswith(ACTION_PREFIX):
            raise ValueError(f"path segment {seg!r} names an action; this tool is read-only")
    if sep:
        for pair in query.split("&"):
            if not QUERY_PAIR_RE.match(pair):
                raise ValueError(f"bad query parameter {pair!r}")
    return path


# --------------------------------------------------------------------------- client
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: the bearer token must only go to the host we were asked to query."""

    def redirect_request(self, *a, **kw):
        return None


def credentials(ref):
    ref = (ref or DEFAULT_CRED).upper()
    user, pw = os.getenv(f"NET_{ref}_USERNAME"), os.getenv(f"NET_{ref}_PASSWORD")
    for name, val in ((f"NET_{ref}_USERNAME", user), (f"NET_{ref}_PASSWORD", pw)):
        if not val:
            raise ApiError("auth", f"missing or empty credential env var {name} (set it in .env)")
    return user, pw


class Veeam:
    def __init__(self, host, port, api_version, verify_ssl, timeout):
        self.base = f"https://{host}:{int(port)}"
        self.api_version = api_version
        self.timeout = timeout
        ctx = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()  # self-signed cert
        self._opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect)
        self._token = None

    def _headers(self):
        h = {"x-api-version": self.api_version, "Accept": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _send(self, req, what):
        """Open one prepared request; map every failure to ApiError. Returns the body bytes."""
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                return r.read(MAX_BODY)
        except urllib.error.HTTPError as e:
            detail = ""
            try:  # the server's own error text; it never contains our secrets
                j = json.loads(e.read(4096).decode("utf-8", "replace"))
                detail = str(j.get("error_description") or j.get("message") or "")[:100]
            except (ValueError, AttributeError, OSError):
                detail = ""
            kind = "auth" if (e.code == 401 or (e.code == 400 and what == "login")) else "api"
            hint = {403: " (account lacks permission)", 404: " (not found / unsupported on this version)"}.get(e.code, "")
            raise ApiError(kind, f"{what}: HTTP {e.code}{hint}{(': ' + detail) if detail else ''}")
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise ApiError("conn", f"{type(reason).__name__}: {str(reason)[:100]}")

    def login(self, username, password):
        """The ONLY non-GET call: OAuth2 password grant. Stores the token in memory, never elsewhere."""
        body = urllib.parse.urlencode({"grant_type": "password", "username": username,
                                       "password": password}).encode()
        h = self._headers()
        h["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(self.base + TOKEN_PATH, data=body, headers=h, method="POST")
        raw = self._send(req, "login")
        try:
            self._token = json.loads(raw)["access_token"]
        except (ValueError, KeyError, TypeError):
            raise ApiError("proto", "login: response has no access_token (is this a Veeam B&R REST API?)")

    def logout(self):
        """Best-effort session close; failures are ignored (the token expires on its own)."""
        if not self._token:
            return
        req = urllib.request.Request(self.base + LOGOUT_PATH, data=b"", headers=self._headers(), method="POST")
        try:
            self._send(req, "logout")
        except ApiError:
            pass
        self._token = None

    def api_get(self, path):
        """GET one allowlisted path (query string allowed) and return the parsed JSON."""
        assert_read_path(path)
        req = urllib.request.Request(self.base + path, headers=self._headers(), method="GET")
        raw = self._send(req, f"GET {path.partition('?')[0]}")
        try:
            return json.loads(raw)
        except ValueError:
            raise ApiError("proto", f"GET {path.partition('?')[0]}: response is not JSON")

    def get_all(self, path, params=None):
        """GET a list endpoint, following skip/limit pages. Returns {"data": [...], "pagination": {...}}."""
        params = dict(params or {})
        items, skip, total = [], 0, None
        while True:
            q = urllib.parse.urlencode({**params, "skip": skip, "limit": PAGE_SIZE})
            page = self.api_get(f"{path}?{q}")
            if not isinstance(page, dict) or not isinstance(page.get("data"), list):
                return page  # not a paged list (single object): hand back as is
            items += page["data"]
            total = (page.get("pagination") or {}).get("total", len(items))
            skip += len(page["data"])
            if not page["data"] or skip >= total or len(items) >= MAX_ITEMS:
                break
        return {"data": items, "pagination": {"total": total, "fetched": len(items)}}


# --------------------------------------------------------------------------- helpers
def check_host(h):
    if not HOST_RE.match(h):
        raise SystemExit(f"invalid --host {h!r} (hostname or IP only, no scheme/port/path)")
    return h


def parse_ts(s):
    """ISO-8601 string from the API -> aware datetime (naive treated as UTC), or None."""
    if not s or not isinstance(s, str):
        return None
    s = s.strip().replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # fromisoformat takes at most 6 fractional digits
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def fmt_ts(s):
    d = parse_ts(s)
    return d.strftime("%Y-%m-%d %H:%M") if d else "-"


def result_of(sess):
    r = sess.get("result")
    return (r.get("result") if isinstance(r, dict) else r) or "-"


def data_of(resp):
    return resp.get("data", []) if isinstance(resp, dict) else []


def clip(v, n):
    v = "-" if v in (None, "") else str(v)
    return v if len(v) <= n else v[:n - 1] + "~"


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))
    os.chmod(path, 0o600)


def safe_name(h):
    return re.sub(r"[^A-Za-z0-9._-]", "_", h)


# --------------------------------------------------------------------------- collection
def plan(want, hours):
    """name -> (path, params) for the endpoints each subcommand needs."""
    after = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    all_plans = {
        "serverInfo": ("/api/v1/serverInfo", None),
        "jobs": ("/api/v1/jobs", None),
        "jobs_states": ("/api/v1/jobs/states", None),
        "sessions": ("/api/v1/sessions", {"orderColumn": "CreationTime", "orderAsc": "false",
                                          "createdAfterFilter": after}),
        "repos_states": ("/api/v1/backupInfrastructure/repositories/states", None),
    }
    return {n: all_plans[n] for n in want}


def fetch_host(args, host, want):
    """Login, fetch the wanted endpoints, logout. -> (raw {name: json}, errors {name: msg}). ApiError if fatal."""
    user, pw = credentials(args.cred)
    cli = Veeam(host, args.port, args.api_version, args.verify_ssl, args.timeout)
    cli.login(user, pw)
    raw, errs = {}, {}
    try:
        for name, (path, params) in plan(want, getattr(args, "hours", 24)).items():
            try:
                raw[name] = cli.api_get(path) if name == "serverInfo" else cli.get_all(path, params)
            except ApiError as e:
                errs[name] = f"{e.kind}: {e}"
    finally:
        cli.logout()
    return raw, errs


def run_hosts(args, want):
    hosts = list(dict.fromkeys(check_host(h) for h in args.host))

    def one(h):
        try:
            raw, errs = fetch_host(args, h, want)
            return h, raw, errs, None
        except ApiError as e:
            return h, None, None, f"{e.kind}: {e}"
        except Exception as e:  # noqa: BLE001 - report any failure per host
            return h, None, None, netlib.err_text(e)

    with ThreadPoolExecutor(min(args.workers, len(hosts))) as ex:
        return list(ex.map(one, hosts))


# --------------------------------------------------------------------------- analysis
def job_rows(raw):
    """Merge /jobs (config) with /jobs/states (runtime) by id."""
    states = {s.get("id"): s for s in data_of(raw.get("jobs_states"))}
    rows, seen = [], set()
    for j in data_of(raw.get("jobs")):
        s = states.get(j.get("id"), {})
        seen.add(j.get("id"))
        rows.append({"name": j.get("name"), "type": j.get("type") or s.get("type"),
                     "disabled": bool(j.get("isDisabled")) or s.get("status") == "disabled",
                     "last_result": s.get("lastResult"), "last_run": s.get("lastRun"),
                     "next_run": s.get("nextRun"), "status": s.get("status")})
    for jid, s in states.items():  # states without a config row (e.g. jobs list was refused)
        if jid not in seen:
            rows.append({"name": s.get("name"), "type": s.get("type"), "disabled": s.get("status") == "disabled",
                         "last_result": s.get("lastResult"), "last_run": s.get("lastRun"),
                         "next_run": s.get("nextRun"), "status": s.get("status")})
    return sorted(rows, key=lambda r: (r["name"] or "").lower())


def stale_jobs(rows, now=None):
    now = now or datetime.now(UTC)
    out = []
    for r in rows:
        if r["disabled"]:
            continue
        d = parse_ts(r["last_run"])
        if d is None or now - d > timedelta(hours=STALE_HOURS):
            out.append(r)
    return out


def bad_jobs(rows):
    return [r for r in rows if (r["last_result"] or "").lower() in ("failed", "warning")]


def session_summary(raw, hours, now=None):
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(hours=hours)
    recent = []
    for s in data_of(raw.get("sessions")):
        d = parse_ts(s.get("creationTime"))
        if d is None or d >= cutoff:
            recent.append(s)
    counts = {}
    for s in recent:
        k = result_of(s)
        counts[k] = counts.get(k, 0) + 1
    flagged = [{"name": s.get("name"), "type": s.get("sessionType"), "result": result_of(s),
                "created": s.get("creationTime"),
                "message": ((s.get("result") or {}).get("message") or "")[:200] if isinstance(s.get("result"), dict) else ""}
               for s in recent if result_of(s).lower() in ("failed", "warning")]
    return {"hours": hours, "total": len(recent), "by_result": counts, "flagged": flagged}


def repo_rows(raw):
    rows = []
    for r in data_of(raw.get("repos_states")):
        cap, free = r.get("capacityGB"), r.get("freeGB")
        pct_free = (free / cap * 100) if isinstance(cap, (int, float)) and cap and isinstance(free, (int, float)) else None
        used = r.get("usedSpaceGB")
        if used is None and pct_free is not None:
            used = cap - free
        rows.append({"name": r.get("name"), "type": r.get("type"), "capacity_gb": cap, "free_gb": free,
                     "used_gb": used, "free_pct": None if pct_free is None else round(pct_free, 1),
                     "used_pct": None if pct_free is None else round(100 - pct_free, 1),
                     "online": r.get("isOnline")})
    return sorted(rows, key=lambda r: (r["name"] or "").lower())


def low_repos(rows):
    return [r for r in rows if r["free_pct"] is not None and r["free_pct"] < LOW_FREE_PCT]


# --------------------------------------------------------------------------- printing
def print_errors(host, errs):
    for name, msg in (errs or {}).items():
        print(f"     {host} {name}: {msg}")


def print_jobs(rows):
    print(f"     {'NAME':32} {'TYPE':20} {'LAST RESULT':11} {'LAST RUN':16} {'NEXT RUN':16} STATUS")
    for r in rows:
        print(f"     {clip(r['name'], 32):32} {clip(r['type'], 20):20} {clip(r['last_result'], 11):11} "
              f"{fmt_ts(r['last_run']):16} {fmt_ts(r['next_run']):16} {clip(r['status'], 12)}")


def print_repos(rows):
    print(f"     {'NAME':32} {'CAPACITY GB':>12} {'FREE GB':>10} {'USED %':>7}")
    for r in rows:
        used = "-" if r["used_pct"] is None else f"{r['used_pct']:.1f}"
        print(f"     {clip(r['name'], 32):32} {clip(r['capacity_gb'], 12):>12} {clip(r['free_gb'], 10):>10} {used:>7}")


# --------------------------------------------------------------------------- subcommands
def each_result(args, want, show):
    """Run `want` on every host, print OK/FAIL lines, call show(host, raw) for successes."""
    results = run_hosts(args, want)
    ok = 0
    for host, raw, errs, err in results:
        if err:
            print(f"FAIL {host:30} {err}")
            continue
        if errs and len(errs) == len(want_names(want)):
            print(f"FAIL {host:30} " + "; ".join(errs.values()))
            continue
        ok += 1
        print(f"OK   {host:30}")
        print_errors(host, errs)
        if not args.quiet:
            show(host, raw)
    print(f"{ok} ok / {len(results) - ok} failed")
    return results


def want_names(want):
    return list(want)


def cmd_facts(args):
    def show(host, raw):
        i = raw.get("serverInfo") or {}
        print(f"     name={i.get('name')}  build={i.get('buildVersion')}  db={i.get('databaseVendor')}  "
              f"sql={i.get('sqlServerVersion')}  patches={len(i.get('patches') or [])}")
    each_result(args, ["serverInfo"], show)


def cmd_get(args):
    for p in args.paths:
        try:
            assert_read_path(p)
        except ValueError as e:
            raise SystemExit(f"Rejected path {p!r}: {e}")
    if args.quiet and not args.out:
        raise SystemExit("--quiet requires --out")
    outdir = ROOT / "outputs" / netlib.timestamp() if args.out else None
    hosts = list(dict.fromkeys(check_host(h) for h in args.host))

    def one(h):
        got = {}
        try:
            user, pw = credentials(args.cred)
            cli = Veeam(h, args.port, args.api_version, args.verify_ssl, args.timeout)
            cli.login(user, pw)
            try:
                for p in args.paths:
                    paged = "skip=" not in p and "limit=" not in p
                    base, _, q = p.partition("?")
                    params = dict(x.split("=", 1) for x in q.split("&")) if q else {}
                    got[p] = cli.get_all(base, params) if paged else cli.api_get(p)
            finally:
                cli.logout()
        except ApiError as e:
            return h, None, f"{e.kind}: {e}"
        except Exception as e:  # noqa: BLE001
            return h, None, netlib.err_text(e)
        return h, got, None

    with ThreadPoolExecutor(min(args.workers, len(hosts))) as ex:
        results = list(ex.map(one, hosts))
    ok = 0
    for host, got, err in results:
        if err:
            print(f"FAIL {host:30} {err}")
            continue
        ok += 1
        counts = {p: (len(v["data"]) if isinstance(v, dict) and isinstance(v.get("data"), list) else "obj")
                  for p, v in got.items()}
        print(f"OK   {host:30} " + "  ".join(f"{p}={n}" for p, n in counts.items()))
        for p, v in got.items():
            if outdir:
                write_json(outdir / safe_name(host) / (re.sub(r"[^A-Za-z0-9]+", "_", p.partition("?")[0].strip("/")) + ".json"), v)
            if not args.quiet:
                print(json.dumps(v, indent=2))
    if outdir:
        print(f"saved to {outdir}")
    print(f"{ok} ok / {len(results) - ok} failed")


def cmd_jobs(args):
    def show(host, raw):
        rows = job_rows(raw)
        print_jobs(rows)
        print(f"     {len(rows)} jobs, {len(bad_jobs(rows))} failed/warning, {len(stale_jobs(rows))} not run in >{STALE_HOURS}h")
    each_result(args, ["jobs", "jobs_states"], show)


def cmd_sessions(args):
    def show(host, raw):
        s = session_summary(raw, args.hours)
        print(f"     last {s['hours']}h: {s['total']} sessions  " + "  ".join(f"{k}={v}" for k, v in sorted(s["by_result"].items())))
        for f in s["flagged"]:
            print(f"     {f['result']:8} {fmt_ts(f['created']):16} {clip(f['name'], 40):40} {clip(f['message'], 60)}")
    each_result(args, ["sessions"], show)


def cmd_repos(args):
    def show(host, raw):
        rows = repo_rows(raw)
        print_repos(rows)
        for r in low_repos(rows):
            print(f"     LOW SPACE: {r['name']} has {r['free_pct']}% free (< {LOW_FREE_PCT:g}%)")
    each_result(args, ["repos_states"], show)


# --------------------------------------------------------------------------- report
def host_report(host, raw, errs, hours):
    rows = job_rows(raw)
    repos = repo_rows(raw)
    info = raw.get("serverInfo") or {}
    return {"host": host,
            "server": {k: info.get(k) for k in ("name", "buildVersion", "databaseVendor", "sqlServerVersion")},
            "errors": errs,
            "job_count": len(rows), "failed_warning_jobs": bad_jobs(rows), "stale_jobs": stale_jobs(rows),
            "sessions": session_summary(raw, hours),
            "repos": repos, "low_space_repos": low_repos(repos)}


def write_md(out, reports, started, hours):
    L = [f"# Veeam backup report ({started:%Y-%m-%d %H:%M})", "",
         (f"Read-only REST API snapshot. Flags: failed/warning jobs, enabled jobs not run in >{STALE_HOURS}h, "
          f"repositories with <{LOW_FREE_PCT:g}% free, failed/warning sessions in the last {hours}h."), ""]
    for r in reports:
        L += [f"## {r['host']}"]
        if "fatal" in r:
            L += ["", f"Error: {r['fatal']}", ""]
            continue
        s = r["server"]
        L += [f"Server: {s['name']}  build {s['buildVersion']}  db {s['databaseVendor']}", ""]
        for name, msg in r["errors"].items():
            L.append(f"- endpoint {name} failed: {msg}")
        by = ", ".join(f"{k}={v}" for k, v in sorted(r["sessions"]["by_result"].items()))
        L += [(f"- Jobs: {r['job_count']}  failed/warning: {len(r['failed_warning_jobs'])}  "
               f"stale (>{STALE_HOURS}h): {len(r['stale_jobs'])}"),
              f"- Sessions ({hours}h): {r['sessions']['total']}  {by}",
              f"- Repositories: {len(r['repos'])}  low space: {len(r['low_space_repos'])}", ""]
        for title, key in (("Failed or warning jobs", "failed_warning_jobs"), (f"Jobs not run in over {STALE_HOURS}h", "stale_jobs")):
            if r[key]:
                L += [f"### {title}", "", "| Job | Type | Last result | Last run | Status |", "|---|---|---|---|---|"]
                L += [f"| {j['name']} | {j['type']} | {j['last_result'] or '-'} | {fmt_ts(j['last_run'])} | {j['status'] or '-'} |"
                      for j in r[key]]
                L.append("")
        if r["sessions"]["flagged"]:
            L += [f"### Failed or warning sessions ({hours}h)", "", "| Result | Created | Session | Message |", "|---|---|---|---|"]
            L += [f"| {f['result']} | {fmt_ts(f['created'])} | {f['name']} | {(f['message'] or '-').replace('|', '/')[:120]} |"
                  for f in r["sessions"]["flagged"][:100]]
            L.append("")
        if r["repos"]:
            L += ["### Repositories", "", "| Name | Capacity GB | Free GB | Used % | Flag |", "|---|---|---|---|---|"]
            for p in r["repos"]:
                flag = "LOW SPACE" if p in r["low_space_repos"] else ""
                L.append(f"| {p['name']} | {p['capacity_gb']} | {p['free_gb']} | {p['used_pct'] if p['used_pct'] is not None else '-'} | {flag} |")
            L.append("")
    path = out / "report.md"
    path.write_text("\n".join(L) + "\n")
    os.chmod(path, 0o600)


def cmd_report(args):
    started = datetime.now()
    out = ROOT / (args.out_dir or f"reports/veeam/{started:%Y%m%d-%H%M%S}")
    want = ["serverInfo", "jobs", "jobs_states", "sessions", "repos_states"]
    results = run_hosts(args, want)
    reports, nbad = [], 0
    for host, raw, errs, err in results:
        if err:
            print(f"FAIL {host:30} {err}")
            reports.append({"host": host, "fatal": err})
            continue
        for name, v in raw.items():
            write_json(out / "raw" / f"{safe_name(host)}_{name}.json", v)
        r = host_report(host, raw, errs, args.hours)
        reports.append(r)
        n = len(r["failed_warning_jobs"]) + len(r["stale_jobs"]) + len(r["low_space_repos"]) + len(r["sessions"]["flagged"])
        nbad += n
        print(f"OK   {host:30} jobs={r['job_count']} failed_warn={len(r['failed_warning_jobs'])} "
              f"stale={len(r['stale_jobs'])} low_repos={len(r['low_space_repos'])} "
              f"flagged_sessions={len(r['sessions']['flagged'])}")
        print_errors(host, errs)
    if not any("fatal" not in r for r in reports):
        print("nothing collected; no report written")
        return
    summary = {"generated": started.isoformat(timespec="seconds"), "read_only": True, "hours": args.hours,
               "thresholds": {"stale_hours": STALE_HOURS, "low_free_pct": LOW_FREE_PCT}, "hosts": reports}
    write_json(out / "summary.json", summary)
    write_md(out, reports, started, args.hours)
    print(f"Flags: {nbad}\nReport: {out / 'report.md'}\nJSON:   {out / 'summary.json'}")


# --------------------------------------------------------------------------- selftest
def cmd_selftest(args):
    good = ["/api/v1/serverInfo", "/api/v1/jobs", "/api/v1/jobs/states?skip=0&limit=200",
            "/api/v1/backupInfrastructure/repositories/states",
            "/api/v1/sessions?orderColumn=CreationTime&orderAsc=false&createdAfterFilter=2026-01-01T00%3A00%3A00.000Z",
            "/api/v1/jobs/6b4b6e0a-1c0d-4f3e-9a7a-0d6d7f1c2b3a", "/api/v1/restorePoints"]
    bad = ["/api/v1/jobs/X/start", "/api/v1/jobs/X/stop", "/api/v1/jobs/X/retry", "/api/v1/jobs/X/disable",
           "/api/v1/jobs/X/enable", "/api/v1/backupInfrastructure/repositories/rescan", "/api/v1/jobs/X/delete",
           "/api/v1/jobs/Startnow", "/api/v1/../oauth2/token", "/api/oauth2/token", "/api/v1/jobs/%2e%2e/x",
           "/api/v1/jobs?x=1;y", "/api/v1/jobs?a=b#c", "/api/v1/jobs?q=a b", "api/v1/jobs", "/api/v2/jobs", "",
           "/api/v1//jobs", "/api/v1/jobs/X/run", "/api/v1/jobs?=1"]
    fails = 0
    for p in good:
        try:
            assert_read_path(p)
            print(f"ok    allowed   {p}")
        except ValueError as e:
            fails += 1
            print(f"FAIL  wrongly rejected {p}: {e}")
    for p in bad:
        try:
            assert_read_path(p)
            fails += 1
            print(f"FAIL  wrongly allowed  {p!r}")
        except ValueError:
            print(f"ok    rejected  {p!r}")
    print("selftest: " + ("PASS" if not fails else f"{fails} FAILURES"))
    sys.exit(1 if fails else 0)


# --------------------------------------------------------------------------- CLI
def _common(p):
    p.add_argument("--host", action="append", required=True, metavar="HOST", help="Veeam server hostname or IP (repeatable)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"REST API port (default {DEFAULT_PORT})")
    p.add_argument("--cred", default=DEFAULT_CRED, metavar="REF", help=f"credential set NET_<REF>_USERNAME/_PASSWORD (default {DEFAULT_CRED})")
    p.add_argument("--api-version", default=DEFAULT_API_VERSION, help=f"x-api-version header (default {DEFAULT_API_VERSION})")
    p.add_argument("--verify-ssl", action="store_true", help="verify the TLS certificate (default: off, self-signed is normal)")
    p.add_argument("--quiet", action="store_true", help="one OK/FAIL line per host, no tables")
    p.add_argument("--workers", type=int, default=4, help="hosts queried concurrently")
    p.add_argument("--timeout", type=int, default=30, help="per-request timeout seconds")


def main():
    ap = argparse.ArgumentParser(description="Read-only Veeam Backup & Replication REST API client")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("facts", help="server name, build, version, database vendor (/api/v1/serverInfo)")
    _common(p)
    p.set_defaults(fn=cmd_facts)
    p = sub.add_parser("get", help="raw GET of /api/v1/ paths (allowlisted, read-only)")
    p.add_argument("paths", nargs="+", metavar="PATH", help="e.g. /api/v1/jobs (query string allowed)")
    _common(p)
    p.add_argument("--out", action="store_true", help="save JSON to outputs/<ts>/<host>/<path>.json")
    p.set_defaults(fn=cmd_get)
    p = sub.add_parser("jobs", help="jobs table: name, type, last result, last/next run, status")
    _common(p)
    p.set_defaults(fn=cmd_jobs)
    p = sub.add_parser("sessions", help="recent sessions, failed/warning summary")
    _common(p)
    p.add_argument("--hours", type=float, default=24, help="look-back window (default 24)")
    p.set_defaults(fn=cmd_sessions)
    p = sub.add_parser("repos", help="repository capacity, free space, used %%")
    _common(p)
    p.set_defaults(fn=cmd_repos)
    p = sub.add_parser("report", help="everything -> reports/veeam/<ts>/ (summary.json, report.md, raw/)")
    _common(p)
    p.add_argument("--hours", type=float, default=24, help="session look-back window (default 24)")
    p.add_argument("--out", dest="out_dir", help="output dir relative to the repo root (default reports/veeam/<ts>)")
    p.set_defaults(fn=cmd_report)
    p = sub.add_parser("selftest", help="offline check of the read-only path allowlist (no network)")
    p.set_defaults(fn=cmd_selftest)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
