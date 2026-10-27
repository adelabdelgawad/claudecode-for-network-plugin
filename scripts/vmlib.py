"""Shared helpers for the READ-ONLY VMware vSphere scripts (vsphere.py, vsphere_audit.py, vsphere_checklist.py).

Only property retrieval and the query methods in READONLY_METHODS are ever called; nothing here can
reconfigure, power, migrate, snapshot or otherwise change a vCenter/ESXi object.
"""
import contextlib
import os
import sqlite3
import ssl
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim, vmodl

import paths

ROOT = paths.site_root()
load_dotenv(ROOT / ".env")
DB = ROOT / os.getenv("INVENTORY_DB", "inventory/inventory.db")

# The ONLY vSphere API methods this toolset may invoke (all read-only); call_ro() enforces it.
READONLY_METHODS = frozenset({"RetrievePropertiesEx", "ContinueRetrievePropertiesEx", "CreateContainerView",
                              "DestroyView", "QueryNetworkHint", "CurrentTime",
                              # performance queries (statistics reads only), used by vsphere_checklist.py
                              "QueryPerf", "QueryPerfCounter", "QueryAvailablePerfMetric",
                              "QueryPerfProviderSummary"})


def timestamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def call_ro(obj, method, *args, **kw):
    if method not in READONLY_METHODS or method.endswith("_Task"):
        raise RuntimeError(f"refusing non-read-only vSphere method {method!r}")
    return getattr(obj, method)(*args, **kw)


def open_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def creds(ref):
    ref = (ref or "VCENTER").upper()
    uvar, pvar = f"NET_{ref}_USERNAME", f"NET_{ref}_PASSWORD"
    user, pwd = os.getenv(uvar), os.getenv(pvar)
    missing = [v for v, x in ((uvar, user), (pvar, pwd)) if not x]
    if missing:
        raise SystemExit(f"missing credentials in .env: {', '.join(missing)}")
    return user, pwd


def select_vcenters(names=None):
    db = open_db()
    rows = [dict(r) for r in db.execute("SELECT * FROM vcenters WHERE status='active' ORDER BY name")]
    db.close()
    if names:
        wanted = {n.lower() for n in names}
        missing = wanted - {r["name"].lower() for r in rows}
        if missing:
            print(f"warning: not an active vcenter: {', '.join(sorted(missing))}")
        rows = [r for r in rows if r["name"].lower() in wanted]
    return rows


@contextlib.contextmanager
def connect(vc):
    user, pwd = creds(vc.get("credential_ref"))
    ctx = ssl.create_default_context() if vc.get("verify_ssl", 1) else ssl._create_unverified_context()
    si = SmartConnect(host=vc["host"], port=int(vc.get("port") or 443), user=user, pwd=pwd, sslContext=ctx,
                      connectionPoolTimeout=60)
    try:
        yield si
    finally:
        with contextlib.suppress(Exception):
            Disconnect(si)


def mid(ref):
    """Managed object id (e.g. 'vm-12') of a reference, or None."""
    return getattr(ref, "_moId", None) if ref is not None else None


def aslist(v):
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def server_time(si):
    try:
        return call_ro(si, "CurrentTime")
    except Exception:  # noqa: BLE001
        return datetime.now(timezone.utc)


def collect(si, vimtype, props, objs=None, page=500):
    """Fetch `props` of every `vimtype` object (or just `objs`) in one PropertyCollector pass with paging.

    Returns [{'_obj': ref, '_id': moref, <prop path>: value, ...}]; properties the server omits are absent.
    """
    pc, rows, view = si.content.propertyCollector, [], None
    PC = vmodl.query.PropertyCollector
    if objs is None:
        view = call_ro(si.content.viewManager, "CreateContainerView", si.content.rootFolder, [vimtype], True)
        ospecs = [PC.ObjectSpec(obj=view, skip=True, selectSet=[
            PC.TraversalSpec(name="view", type=vim.view.ContainerView, path="view", skip=False)])]
    else:
        ospecs = [PC.ObjectSpec(obj=o, skip=False) for o in objs]
    fs = PC.FilterSpec(objectSet=ospecs, propSet=[PC.PropertySpec(type=vimtype, pathSet=list(props))])
    try:
        res = call_ro(pc, "RetrievePropertiesEx", specSet=[fs], options=PC.RetrieveOptions(maxObjects=page))
        while res:
            for oc in res.objects or []:
                row = {"_obj": oc.obj, "_id": mid(oc.obj)}
                row.update({p.name: p.val for p in oc.propSet or []})
                rows.append(row)
            res = call_ro(pc, "ContinueRetrievePropertiesEx", token=res.token) if res.token else None
    finally:
        if view is not None:
            with contextlib.suppress(Exception):
                call_ro(view, "DestroyView")
    return rows
