-- Network inventory schema (SQLite)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sites (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,          -- e.g. HQ, Hospital-A
    location    TEXT,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY,
    hostname        TEXT NOT NULL UNIQUE,
    mgmt_ip         TEXT NOT NULL UNIQUE,
    site_id         INTEGER REFERENCES sites(id),
    device_type     TEXT NOT NULL,             -- switch, router, firewall, wlc, ap, server, ...
    role            TEXT,                      -- core, distribution, access, edge, ...
    vendor          TEXT,                      -- cisco, sophos, fortinet, aruba, juniper, ...
    model           TEXT,
    os_type         TEXT,                      -- cisco_ios, cisco_xe, sophos_sfos, ... (netmiko device_type)
    os_version      TEXT,
    serial          TEXT,
    port            INTEGER DEFAULT 22,
    credential_ref  TEXT NOT NULL DEFAULT 'DEFAULT',  -- maps to NET_<ref>_USERNAME / _PASSWORD in .env
    status          TEXT NOT NULL DEFAULT 'active',   -- active, spare, decommissioned
    notes           TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS change_log (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER REFERENCES devices(id),
    action      TEXT NOT NULL,                 -- what was done
    details     TEXT,
    performed_by TEXT,
    performed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Firewall-only facts (Sophos XG / SFOS). One row per devices row with
-- device_type='firewall'; SSH console access still uses devices.mgmt_ip/port/credential_ref
-- (os_type 'sophos_sfos'). The XML API is https://<mgmt_ip>:<api_port>/webconsole/APIController:
-- <Get> is read-only; <Set>/<Remove> are CHANGES and go through the approval gate.
CREATE TABLE IF NOT EXISTS firewall_details (
    device_id           INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    api_port            INTEGER NOT NULL DEFAULT 4444,  -- SFOS webadmin / XML API port
    api_enabled         INTEGER NOT NULL DEFAULT 0,     -- 1 once API access + allowed IP are set on the box
    verify_ssl          INTEGER NOT NULL DEFAULT 0,     -- SFOS ships a self-signed cert
    api_credential_ref  TEXT NOT NULL DEFAULT 'SOPHOSAPI', -- NET_SOPHOSAPI_USERNAME / _PASSWORD
    ha_mode             TEXT,                      -- standalone, active-passive, active-active
    ha_role             TEXT,                      -- primary, auxiliary
    ha_peer_id          INTEGER REFERENCES devices(id),
    license_expiry      TEXT,                      -- earliest subscription expiry (YYYY-MM-DD)
    notes               TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_site ON devices(site_id);
CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);

CREATE TRIGGER IF NOT EXISTS trg_devices_updated
AFTER UPDATE ON devices
BEGIN
    UPDATE devices SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- ---------------------------------------------------------------------------
-- VMware vSphere inventory (servers / operating systems)
-- Kept apart from `devices` on purpose: network scripts (show/backup/change)
-- select from `devices` only, so VMs and ESXi hosts are never targeted by them.
-- Any power/config/snapshot/vMotion action against vCenter or ESXi is a CHANGE
-- (API POST/PUT/PATCH/DELETE) and goes through the approval gate.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS vcenters (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,      -- e.g. VC01
    host            TEXT NOT NULL UNIQUE,      -- FQDN or IP of vCenter (or standalone ESXi)
    port            INTEGER DEFAULT 443,
    site_id         INTEGER REFERENCES sites(id),
    version         TEXT,                      -- e.g. 8.0.3
    build           TEXT,
    verify_ssl      INTEGER NOT NULL DEFAULT 1,     -- 0 only for self-signed lab certs
    credential_ref  TEXT NOT NULL DEFAULT 'VCENTER', -- NET_VCENTER_USERNAME / _PASSWORD
    status          TEXT NOT NULL DEFAULT 'active',  -- active, decommissioned, auth_failed
    notes           TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS esxi_hosts (
    id                INTEGER PRIMARY KEY,
    hostname          TEXT NOT NULL UNIQUE,
    mgmt_ip           TEXT UNIQUE,
    vcenter_id        INTEGER REFERENCES vcenters(id),
    moref             TEXT,                    -- vSphere managed object id, e.g. host-123
    datacenter        TEXT,
    cluster           TEXT,
    site_id           INTEGER REFERENCES sites(id),
    vendor            TEXT,                    -- dell, hpe, lenovo, cisco, ...
    model             TEXT,
    serial            TEXT,
    esxi_version      TEXT,                    -- e.g. 8.0.3
    esxi_build        TEXT,
    cpu_model         TEXT,
    cpu_sockets       INTEGER,
    cpu_cores         INTEGER,
    memory_gb         REAL,
    connection_state  TEXT,                    -- connected, disconnected, notResponding
    maintenance_mode  INTEGER DEFAULT 0,
    credential_ref    TEXT NOT NULL DEFAULT 'ESXI',  -- NET_ESXI_USERNAME / _PASSWORD
    status            TEXT NOT NULL DEFAULT 'active', -- active, spare, decommissioned, auth_failed
    notes             TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- vSwitch / dvSwitch port groups: maps VM networks to VLANs on the physical switches
CREATE TABLE IF NOT EXISTS port_groups (
    id           INTEGER PRIMARY KEY,
    vcenter_id   INTEGER REFERENCES vcenters(id),
    name         TEXT NOT NULL,
    switch_name  TEXT,                         -- vSwitch0, DSwitch-Prod, ...
    switch_type  TEXT,                         -- standard, distributed, nsx
    vlan_id      TEXT,                         -- '120', '0', 'trunk:1-4094'
    notes        TEXT,
    UNIQUE (vcenter_id, switch_name, name)
);

CREATE TABLE IF NOT EXISTS machines (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,             -- VM name in vCenter
    vcenter_id      INTEGER REFERENCES vcenters(id),
    instance_uuid   TEXT UNIQUE,               -- config.instanceUuid (stable upsert key)
    bios_uuid       TEXT,
    moref           TEXT,                      -- e.g. vm-1042
    esxi_host_id    INTEGER REFERENCES esxi_hosts(id),
    datacenter      TEXT,
    cluster         TEXT,
    folder          TEXT,
    resource_pool   TEXT,
    site_id         INTEGER REFERENCES sites(id),
    is_template     INTEGER NOT NULL DEFAULT 0,
    -- operating system
    os_family       TEXT,                      -- windows, linux, other
    guest_os_id     TEXT,                      -- vSphere guestId, e.g. windows2019srv_64Guest, rhel9_64Guest
    guest_os        TEXT,                      -- full name, e.g. Microsoft Windows Server 2019 (64-bit)
    os_version      TEXT,                      -- from the guest, e.g. 10.0.17763 / 9.4
    guest_hostname  TEXT,                      -- hostname reported by VMware Tools
    domain          TEXT,                      -- AD domain / DNS suffix
    primary_ip      TEXT,
    -- sizing / state
    vcpu            INTEGER,
    memory_gb       REAL,
    disk_gb         REAL,
    power_state     TEXT,                      -- poweredOn, poweredOff, suspended
    tools_status    TEXT,                      -- toolsOk, toolsOld, toolsNotRunning, toolsNotInstalled
    tools_version   TEXT,
    hw_version      TEXT,                      -- vmx-19, vmx-21, ...
    -- ownership / access
    role            TEXT,                      -- dc, dns, db, app, web, file, his, pacs, ...
    environment     TEXT,                      -- prod, test, dev, dr
    owner           TEXT,
    mgmt_protocol   TEXT,                      -- ssh (linux), winrm (windows), none
    port            INTEGER,                   -- 22 / 5985 / 5986
    credential_ref  TEXT,                      -- WINDOWS / LINUX / ... -> NET_<REF>_* in .env
    status          TEXT NOT NULL DEFAULT 'active', -- active, spare, decommissioned, auth_failed
    notes           TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS machine_nics (
    id             INTEGER PRIMARY KEY,
    machine_id     INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    label          TEXT,                       -- Network adapter 1
    mac            TEXT,
    adapter_type   TEXT,                       -- vmxnet3, e1000e
    port_group_id  INTEGER REFERENCES port_groups(id),
    network        TEXT,                       -- port group name as reported
    connected      INTEGER,
    ip_addresses   TEXT,                       -- comma-separated, from VMware Tools
    UNIQUE (machine_id, mac)
);

CREATE INDEX IF NOT EXISTS idx_esxi_vcenter     ON esxi_hosts(vcenter_id);
CREATE INDEX IF NOT EXISTS idx_machines_vcenter ON machines(vcenter_id);
CREATE INDEX IF NOT EXISTS idx_machines_host    ON machines(esxi_host_id);
CREATE INDEX IF NOT EXISTS idx_machines_os      ON machines(os_family);
CREATE INDEX IF NOT EXISTS idx_machines_ip      ON machines(primary_ip);
CREATE INDEX IF NOT EXISTS idx_nics_mac         ON machine_nics(mac);

CREATE TRIGGER IF NOT EXISTS trg_vcenters_updated
AFTER UPDATE ON vcenters
BEGIN
    UPDATE vcenters SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_esxi_hosts_updated
AFTER UPDATE ON esxi_hosts
BEGIN
    UPDATE esxi_hosts SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_machines_updated
AFTER UPDATE ON machines
BEGIN
    UPDATE machines SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- Ops task / finding list (scripts/tasks.py). key = dedupe key, e.g. 'vmtools:VM-APP-01'.
CREATE TABLE IF NOT EXISTS tasks (
    id            INTEGER PRIMARY KEY,
    key           TEXT UNIQUE,
    title         TEXT NOT NULL,
    category      TEXT,                        -- vmware-tools, storage, snapshot, network, security, lifecycle, other
    severity      TEXT,                        -- crit, warn, info
    status        TEXT NOT NULL DEFAULT 'todo', -- todo, in_progress, blocked, done, wontfix
    object_type   TEXT,                        -- vm, esxi, datastore, device, vcenter
    object_name   TEXT,
    detail        TEXT,
    action        TEXT,                        -- suggested fix, plain text
    needs_change  INTEGER DEFAULT 0,           -- 1 = executing it modifies a device/VM -> approval gate
    source        TEXT,                        -- report path or 'inventory'
    owner         TEXT,
    due           TEXT,
    notes         TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    closed_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_status   ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_category ON tasks(category, status);

CREATE TRIGGER IF NOT EXISTS trg_tasks_updated
AFTER UPDATE ON tasks
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE tasks SET updated_at = datetime('now') WHERE id = NEW.id;
END;
