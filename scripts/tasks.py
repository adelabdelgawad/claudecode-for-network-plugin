"""Ops task / finding list kept in inventory.db (table `tasks`). Never touches devices, VMs or vCenter.

Usage:
    cfn tasks list [--status open|todo|in_progress|blocked|done|wontfix|all] [--category C]
                                           [--severity crit|warn|info] [--match GLOB] [--md] [--json] [--brief]
    cfn tasks show ID
    cfn tasks add TITLE [--category C] [--severity S] [--object NAME] [--object-type T]
                                         [--detail TXT] [--action TXT] [--needs-change] [--owner O] [--due YYYY-MM-DD]
    cfn tasks set ID [ID...] [--status S] [--owner O] [--due D] [--note TXT]
    cfn tasks done|start ID [ID...] [--note TXT]      block ID [ID...] --note TXT
    cfn tasks import storage [PATH]   # reports/vsphere_storage/<ts>/ dir or summary.json (default newest)
    cfn tasks import vmtools          # from the machines table
    cfn tasks summary
    cfn tasks export [--dir DIR]      # TASKS.md + tasks.json + tasks.csv (default reports/tasks/)

Every write command (add, set, done, start, block, import) re-exports to $TASKS_EXPORT_DIR (default reports/tasks/) when done;
an export failure only warns.

Imports upsert by `key`: new -> todo; open -> detail/severity refreshed (status/owner/due/notes kept); done/wontfix that
reappears -> reopened; open tasks of the same source family no longer reported -> done ("auto-resolved").
needs_change=1 means executing the fix modifies a device/VM and must go through the approval gate (network-change skill).
"""
import argparse
import csv
import fnmatch
import json
import os
import sqlite3
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import date, timedelta
from pathlib import Path

import paths

ROOT = paths.site_root()
DB = ROOT / os.getenv("INVENTORY_DB", "inventory/inventory.db")
OPEN = ("todo", "in_progress", "blocked")
STATUSES = OPEN + ("done", "wontfix")
SEVS = ("crit", "warn", "info")
BOX = {"todo": "[ ]", "in_progress": "[~]", "blocked": "[!]", "done": "[x]", "wontfix": "[-]"}
CATS = ("storage", "snapshot", "vmware-tools", "network", "security", "lifecycle", "other")
CAT_LABEL = {"vmware-tools": "VMware Tools"}
COLS = ("id", "key", "title", "category", "severity", "status", "object_type", "object_name", "detail", "action",
        "needs_change", "source", "owner", "due", "notes", "created_at", "updated_at", "closed_at")
GATE = "[needs approval]"
EXPORT_DIR = "reports/tasks"
CSV_COLS = ("id", "status", "severity", "category", "object_name", "title", "detail", "action", "needs_change", "owner",
            "due", "notes", "updated_at", "closed_at")
WRITE_CMDS = ("add", "set", "done", "start", "block", "import")

TOOLS_ACTION = ("Upgrade VMware Tools from vCenter (Guest OS -> Upgrade VMware Tools, choose 'no reboot' where supported) "
                "or via the OS package (open-vm-tools on Linux: package update). Windows upgrades may need a reboot - "
                "schedule a window.")
TOOLS_ACTION_LINUX = ("open-vm-tools is updated through the distro package manager (e.g. apt/dnf update open-vm-tools), "
                      "not from vCenter. No reboot normally needed; restart the vmtoolsd service if required.")
TOOLS_FIX = {
    "toolsOld": ("warn", "Upgrade VMware Tools", TOOLS_ACTION),
    "toolsNotInstalled": ("crit", "Install VMware Tools",
                          "Install VMware Tools from vCenter (Guest OS -> Install VMware Tools) on Windows, or install "
                          "open-vm-tools through the distro package manager on Linux. Windows may need a reboot - "
                          "schedule a window."),
    "toolsNotRunning": ("warn", "Start/repair VMware Tools (no guest visibility)",
                        "Start the VMware Tools service in the guest (Windows: 'VMware Tools' service; Linux: systemctl "
                        "start vmtoolsd / open-vm-tools); if it will not start, repair or reinstall Tools."),
}


# --------------------------------------------------------------------------- db helpers
def ro():
    return sqlite3.connect(f"file:{DB}?mode=ro", uri=True)


def rw():
    db = sqlite3.connect(DB)
    db.execute("PRAGMA foreign_keys = ON")
    return db


def rows(db, sql, args=()):
    cur = db.execute(sql, args)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def today():
    return date.today().isoformat()


def add_note(old, text):
    line = f"[{today()}] {text}"
    return f"{old}\n{line}" if old else line


def set_status(db, tid, status, note=None):
    r = db.execute("SELECT status, notes FROM tasks WHERE id=?", (tid,)).fetchone()
    if not r:
        print(f"no task #{tid}", file=sys.stderr)
        return False
    notes = add_note(r[1], note) if note else r[1]
    closed = "datetime('now')" if status in ("done", "wontfix") else "NULL"
    if status in ("done", "wontfix") and r[0] in ("done", "wontfix"):
        closed = "COALESCE(closed_at, datetime('now'))"
    db.execute(f"UPDATE tasks SET status=?, notes=?, closed_at={closed} WHERE id=?", (status, notes, tid))
    return True


# --------------------------------------------------------------------------- rendering
def use_color():
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def paint(s, code):
    return f"\033[{code}m{s}\033[0m" if use_color() else s


SEV_COLOR = {"crit": "31;1", "warn": "33", "info": "36"}


def sevtxt(t, pad=True):
    s = (t["severity"] or "-").upper()
    return paint(s.ljust(4) if pad else s, SEV_COLOR.get(t["severity"], "0"))


def cat_label(c):
    return CAT_LABEL.get(c, (c or "other").replace("-", " ").title())


def sort_key(t):
    sv = SEVS.index(t["severity"]) if t["severity"] in SEVS else 9
    return (sv, (t["object_name"] or "").lower(), t["id"])


def group(tasks):
    g = defaultdict(list)
    for t in tasks:
        g[t["category"] or "other"].append(t)
    order = [c for c in CATS if c in g] + sorted(c for c in g if c not in CATS)
    return [(c, sorted(g[c], key=sort_key)) for c in order]


def sev_counts(ts):
    c = Counter(t["severity"] for t in ts)
    return ", ".join(f"{c[s]} {s}" for s in SEVS if c[s])


def line(t):
    who = f"{t['object_name']} — " if t["object_name"] else ""
    return f"{BOX.get(t['status'], '[?]')} #{t['id']} {sevtxt(t)}  {who}{t['title']}"


def fmt_text(ts, brief, label):
    out = []
    for c, g in group(ts):
        n_open = sum(t["status"] in OPEN for t in g)
        head = f"## {cat_label(c)} — {n_open} open" if label == "open" else f"## {cat_label(c)} — {len(g)}"
        sc = sev_counts(g if label != "open" else [t for t in g if t["status"] in OPEN])
        out.append(paint(head + (f" ({sc})" if sc else ""), "1"))
        for t in g:
            out.append(line(t))
            if not brief and t["action"]:
                extra = f"   {GATE}" if t["needs_change"] else ""
                bits = [x for x in (f"owner: {t['owner']}" if t["owner"] else "", f"due: {t['due']}" if t["due"] else "") if x]
                out.append(f"        → {t['action']}{extra}" + (f"   ({'; '.join(bits)})" if bits else ""))
        out.append("")
    nc = sum(1 for t in ts if t["needs_change"])
    out.append(f"{len(ts)} task(s) [{label}]" + (f" — {sev_counts(ts)}" if ts else "") + (f" — {nc} need approval" if nc else ""))
    return "\n".join(out)


def fmt_md(ts, label):
    st = Counter(t["status"] for t in ts)
    out = [f"# Ops tasks ({label}) — {today()}", "", "| Category | Total | crit | warn | info |", "|---|---|---|---|---|"]
    for c, g in group(ts):
        k = Counter(t["severity"] for t in g)
        out.append(f"| {cat_label(c)} | {len(g)} | {k['crit']} | {k['warn']} | {k['info']} |")
    k = Counter(t["severity"] for t in ts)
    out += [f"| **Total** | **{len(ts)}** | {k['crit']} | {k['warn']} | {k['info']} |", ""]
    out.append("Status: " + ", ".join(f"{st[s]} {s}" for s in STATUSES if st[s]) if ts else "No tasks.")
    for c, g in group(ts):
        out += ["", f"## {cat_label(c)}", ""]
        for t in g:
            box = "x" if t["status"] in ("done", "wontfix") else " "
            who = f"`{t['object_name']}` — " if t["object_name"] else ""
            tag = "" if t["status"] in ("todo", "done") else f" _({t['status']})_"
            out.append(f"- [{box}] **{(t['severity'] or '-').upper()}** #{t['id']} {who}{t['title']}{tag}")
            if t["action"]:
                out.append(f"  - Action: {t['action']}" + (" **(needs approval)**" if t["needs_change"] else ""))
            meta = [f"{k}: {t[k]}" for k in ("owner", "due") if t[k]]
            if meta:
                out.append("  - " + "; ".join(meta))
    return "\n".join(out)


# --------------------------------------------------------------------------- list / show / summary
def cmd_list(a):
    db = ro()
    where, args = [], []
    if a.status == "open":
        where.append(f"status IN ({','.join('?' * 3)})")
        args += OPEN
    elif a.status != "all":
        where.append("status=?")
        args.append(a.status)
    if a.category:
        where.append("category=?")
        args.append(a.category)
    if a.severity:
        where.append("severity=?")
        args.append(a.severity)
    ts = rows(db, "SELECT * FROM tasks" + (" WHERE " + " AND ".join(where) if where else ""), args)
    if a.match:
        ts = [t for t in ts if fnmatch.fnmatch((t["object_name"] or "").lower(), a.match.lower())]
    if a.json:
        print(json.dumps(sorted(ts, key=sort_key), indent=2))
    elif a.md:
        print(fmt_md(ts, a.status))
    else:
        print(fmt_text(ts, a.brief, a.status))


def cmd_show(a):
    t = rows(ro(), "SELECT * FROM tasks WHERE id=?", (a.id,))
    if not t:
        sys.exit(f"no task #{a.id}")
    for k in COLS:
        v = t[0][k]
        if v not in (None, ""):
            print(f"{k:13} {v}".replace("\n", "\n" + " " * 14))


def cmd_summary(a):
    ts = rows(ro(), "SELECT category, severity, status FROM tasks")
    if not ts:
        print("no tasks")
        return
    print(f"{'category':14}" + "".join(f"{s:>12}" for s in STATUSES) + f"{'total':>8}")
    cats = sorted({t["category"] or "other" for t in ts}, key=lambda c: CATS.index(c) if c in CATS else 99)
    for c in cats:
        k = Counter(t["status"] for t in ts if (t["category"] or "other") == c)
        print(f"{c:14}" + "".join(f"{k[s]:>12}" for s in STATUSES) + f"{sum(k.values()):>8}")
    k = Counter(t["status"] for t in ts)
    print(f"{'TOTAL':14}" + "".join(f"{k[s]:>12}" for s in STATUSES) + f"{len(ts):>8}")
    o = [t for t in ts if t["status"] in OPEN]
    s = Counter(t["severity"] for t in o)
    print(f"open by severity: " + ", ".join(f"{s[x]} {x}" for x in SEVS))


# --------------------------------------------------------------------------- write commands
def cmd_add(a):
    db = rw()
    with db:
        cur = db.execute(
            "INSERT INTO tasks(title, category, severity, object_name, object_type, detail, action, needs_change, owner, due, source) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,'manual')",
            (a.title, a.category, a.severity, a.object, a.object_type, a.detail, a.action, int(a.needs_change), a.owner, a.due))
        db.execute("UPDATE tasks SET key=? WHERE id=?", (f"manual:{cur.lastrowid}", cur.lastrowid))
    print(f"added #{cur.lastrowid}")


def cmd_set(a):
    db = rw()
    n = 0
    with db:
        for tid in a.ids:
            if not db.execute("SELECT 1 FROM tasks WHERE id=?", (tid,)).fetchone():
                print(f"no task #{tid}", file=sys.stderr)
                continue
            if a.status:
                set_status(db, tid, a.status)
            if a.owner is not None:
                db.execute("UPDATE tasks SET owner=? WHERE id=?", (a.owner, tid))
            if a.due is not None:
                db.execute("UPDATE tasks SET due=? WHERE id=?", (a.due, tid))
            if a.note:
                r = db.execute("SELECT notes FROM tasks WHERE id=?", (tid,)).fetchone()
                db.execute("UPDATE tasks SET notes=? WHERE id=?", (add_note(r[0], a.note), tid))
            n += 1
    print(f"updated {n} task(s)")


def cmd_shortcut(status):
    def run(a):
        if status == "blocked" and not a.note:
            sys.exit("block requires --note (why is it blocked?)")
        db = rw()
        with db:
            n = sum(set_status(db, i, status, a.note) for i in a.ids)
        print(f"{n} task(s) -> {status}")
    return run


# --------------------------------------------------------------------------- imports
def upsert(db, family, found, source):
    """found: list of dict(key,title,category,severity,object_type,object_name,detail,action,needs_change)."""
    new = upd = reo = auto = 0
    seen = set()
    for f in found:
        seen.add(f["key"])
        r = db.execute("SELECT id, status FROM tasks WHERE key=?", (f["key"],)).fetchone()
        vals = (f["title"], f["category"], f["severity"], f["object_type"], f["object_name"], f["detail"], f["action"],
                int(f["needs_change"]), source)
        if not r:
            db.execute("INSERT INTO tasks(title,category,severity,object_type,object_name,detail,action,needs_change,source,key) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?)", vals + (f["key"],))
            new += 1
        else:
            db.execute("UPDATE tasks SET title=?,category=?,severity=?,object_type=?,object_name=?,detail=?,action=?,"
                       "needs_change=?,source=?, updated_at=datetime('now') WHERE id=?", vals + (r[0],))
            if r[1] in ("done", "wontfix"):
                set_status(db, r[0], "todo", f"reopened: finding reported again {today()}")
                reo += 1
            else:
                upd += 1
    for tid, key in db.execute(f"SELECT id, key FROM tasks WHERE key LIKE ? AND status IN ({','.join('?' * 3)})",
                               (family + ":%",) + OPEN).fetchall():
        if key not in seen:
            set_status(db, tid, "done", f"auto-resolved: no longer reported by {family} {today()}")
            auto += 1
    print(f"import {family}: {new} new, {upd} updated, {reo} reopened, {auto} auto-resolved  ({len(found)} findings, source: {source})")


def storage_action(f):
    m, sug = f.get("metric"), f.get("suggestion") or ""
    change = m in ("guest_free", "snapshot_age", "datastore_free") or any(
        w in sug.lower() for w in ("extend", "consolidate", "delete", "clean", "remove"))
    return int(change)


def cmd_import_storage(a):
    base = ROOT / "reports" / "vsphere_storage"
    if a.path:
        p = Path(a.path)
        p = p if p.is_absolute() else Path.cwd() / p
    else:
        dirs = sorted(d for d in base.glob("*/") if (d / "summary.json").exists())
        if not dirs:
            sys.exit(f"no reports under {base}")
        p = dirs[-1]
    f = p / "summary.json" if p.is_dir() else p
    if not f.exists():
        sys.exit(f"not found: {f}")
    data = json.loads(f.read_text())
    found = []
    for x in data.get("findings", []):
        m, obj, det = x.get("metric") or "finding", x.get("object"), x.get("detail") or ""
        if m == "guest_blind":
            continue
        vol = ""
        title = det
        if m == "guest_free" and ": " in det:
            vol, rest = det.split(": ", 1)
            title = f"{vol} {rest}"
        key = f"storage:{m}:{obj}" + (f":{vol}" if vol else "")
        cat = "snapshot" if "snapshot" in m else "storage"
        found.append(dict(key=key, title=title, category=cat, severity=(x.get("severity") or "info").lower(),
                          object_type={"host": "esxi"}.get(x.get("kind"), x.get("kind")), object_name=obj, detail=det,
                          action=x.get("suggestion"), needs_change=storage_action(x)))
    try:
        src = str(f.relative_to(ROOT))
    except ValueError:
        src = str(f)
    db = rw()
    with db:
        upsert(db, "storage", found, src)


def cmd_import_vmtools(a):
    db = rw()
    ms = rows(db, "SELECT m.name, m.guest_os, m.os_family, m.tools_status, m.tools_version, m.primary_ip, e.hostname AS host "
                  "FROM machines m LEFT JOIN esxi_hosts e ON e.id=m.esxi_host_id "
                  "WHERE m.is_template=0 AND m.status='active' AND m.power_state='poweredOn' "
                  "AND m.tools_status IN ('toolsOld','toolsNotInstalled','toolsNotRunning')")
    found = []
    for m in ms:
        sev, title, action = TOOLS_FIX[m["tools_status"]]
        linux = (m["os_family"] or "").lower() == "linux" or "linux" in (m["guest_os"] or "").lower()
        if linux and m["tools_status"] == "toolsOld":
            action = TOOLS_ACTION_LINUX
        detail = (f"{m['tools_status']}; guest_os={m['guest_os'] or '?'}; tools_version={m['tools_version'] or '-'}; "
                  f"ip={m['primary_ip'] or '-'}; esxi={m['host'] or '?'}")
        found.append(dict(key=f"vmtools:{m['name']}", title=title, category="vmware-tools", severity=sev, object_type="vm",
                          object_name=m["name"], detail=detail, action=action, needs_change=1))
    with db:
        upsert(db, "vmtools", found, "inventory")


# --------------------------------------------------------------------------- export
def write_atomic(path, text, **kw):
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", **kw) as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def export_all(d):
    d = Path(d)
    d.mkdir(parents=True, exist_ok=True)
    ts = sorted(rows(ro(), "SELECT * FROM tasks"), key=lambda t: t["id"])
    cutoff = (date.today() - timedelta(days=30)).isoformat()
    closed = [t for t in ts if t["status"] in ("done", "wontfix") and (t["closed_at"] or "") >= cutoff]
    closed.sort(key=lambda t: t["closed_at"], reverse=True)
    md = fmt_md([t for t in ts if t["status"] in OPEN], "open") + "\n\n## Recently closed (last 30 days)\n\n"
    md += "\n".join(f"- [{'x' if t['status'] == 'done' else '-'}] #{t['id']} "
                    + (f"`{t['object_name']}` — " if t["object_name"] else "") + f"{t['title']} _({t['status']} {t['closed_at'][:10]})_"
                    for t in closed) if closed else "None."
    write_atomic(d / "TASKS.md", md + "\n")
    write_atomic(d / "tasks.json", json.dumps(ts, indent=2) + "\n")
    out = []
    w = csv.writer(type("B", (), {"write": out.append}))
    w.writerow(CSV_COLS)
    w.writerows([t[c] for c in CSV_COLS] for t in ts)
    write_atomic(d / "tasks.csv", "".join(out), newline="")
    return d / "TASKS.md"


def shown(p):
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def auto_export():
    try:
        d = Path(os.getenv("TASKS_EXPORT_DIR") or ROOT / EXPORT_DIR)
        print(f"exported → {shown(export_all(d))}")
    except Exception as e:
        print(f"warning: task export failed: {e}", file=sys.stderr)


def cmd_export(a):
    print(f"exported → {shown(export_all(Path(a.dir) if a.dir else ROOT / EXPORT_DIR))}")


# --------------------------------------------------------------------------- cli
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="checklist grouped by category")
    p.add_argument("--status", default="open", choices=("open",) + STATUSES + ("all",))
    p.add_argument("--category")
    p.add_argument("--severity", choices=SEVS)
    p.add_argument("--match", metavar="GLOB", help="glob on object_name (case-insensitive)")
    p.add_argument("--md", action="store_true", help="GitHub markdown checklist")
    p.add_argument("--json", action="store_true")
    p.add_argument("--brief", action="store_true", help="one line per task")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("show", help="all fields of a task")
    p.add_argument("id", type=int)
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("add", help="add a manual task")
    p.add_argument("title")
    p.add_argument("--category", default="other")
    p.add_argument("--severity", choices=SEVS, default="info")
    p.add_argument("--object")
    p.add_argument("--object-type", choices=("vm", "esxi", "datastore", "device", "vcenter"))
    p.add_argument("--detail")
    p.add_argument("--action")
    p.add_argument("--needs-change", action="store_true", help="executing it modifies a device/VM (approval gate)")
    p.add_argument("--owner")
    p.add_argument("--due", metavar="YYYY-MM-DD")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("set", help="change status/owner/due, append a note")
    p.add_argument("ids", type=int, nargs="+")
    p.add_argument("--status", choices=STATUSES)
    p.add_argument("--owner")
    p.add_argument("--due", metavar="YYYY-MM-DD")
    p.add_argument("--note")
    p.set_defaults(fn=cmd_set)

    for name, st, help_ in (("done", "done", "mark done"), ("start", "in_progress", "mark in progress"),
                            ("block", "blocked", "mark blocked (--note required)")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("ids", type=int, nargs="+")
        p.add_argument("--note")
        p.set_defaults(fn=cmd_shortcut(st))

    p = sub.add_parser("import", help="import findings (storage report / vmtools from inventory)")
    isub = p.add_subparsers(dest="what", required=True)
    q = isub.add_parser("storage")
    q.add_argument("path", nargs="?", help="reports/vsphere_storage/<ts>/ dir or summary.json (default newest)")
    q.set_defaults(fn=cmd_import_storage)
    q = isub.add_parser("vmtools")
    q.set_defaults(fn=cmd_import_vmtools)

    p = sub.add_parser("export", help="write TASKS.md, tasks.json, tasks.csv")
    p.add_argument("--dir", help=f"output dir (default {EXPORT_DIR}/)")
    p.set_defaults(fn=cmd_export)

    sub.add_parser("summary", help="counts by category x status").set_defaults(fn=cmd_summary)
    a = ap.parse_args()
    a.fn(a)
    if a.cmd in WRITE_CMDS:
        auto_export()


if __name__ == "__main__":
    main()
