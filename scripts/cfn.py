"""cfn: run a claude-for-network script with the shared venv. Stdlib only (runs before the venv exists).

Usage: cfn <script> [args...]       e.g. cfn show -c "show version" --all,  cfn change apply CHG-...
       cfn init [DIR] [--no-venv]   set up a site workspace (same as typing `setup claude for network here`)
       cfn --help
"""
import shutil
import subprocess
import sys

import paths

RUNNABLE = {
    "inventory": "devices / VMs / ESXi from the inventory DB (read-only)",
    "inventory_edit": "add / set device facts in the inventory DB (needs APPROVE INV-EDIT)",
    "discover": "SSH sweep + show version, upserts the inventory",
    "show": "allowlisted read-only commands on targets",
    "backup": "running-config / Sophos XML backups",
    "sophos_api": "Sophos XG XML API, Get-only",
    "sophos_rename": "Sophos rule renames: check / plan (read-only), verify after apply",
    "sophos_inspect": "Sophos read-only inspection: rules, find, usage, diff of two snapshots",
    "sophos_compare": "Sophos rules across firewalls: common / specific, recommended names, order problems (read-only)",
    "sophos_xml": "Sophos XML resource templates: list / render (read-only); writes run only via cfn change apply",
    "audit": "concurrent security audit",
    "log_audit": "logging-coverage and abnormal-log audit",
    "change": "plan / show / list / apply (apply only after the user types APPROVE <ID>)",
    "vsphere": "vCenter inventory and read-only views",
    "vsphere_audit": "vSphere audit",
    "vsphere_storage": "vSphere storage risk report",
    "guest_show": "allowlisted read-only commands inside guest OSes",
    "tasks": "the task list",
    "results": "read-only analysis of a run dir: summary / grep / field / failed (no ad-hoc python)",
    "guest_security": "in-guest OS security audit (security preset, read-only)",
    "vsphere_checklist": "vSphere health/security checklist (approved items A01-H52)",
    "switch_checklist": "switch/router checklist SW01-SW34 (show-only)",
    "sophos_checklist": "Sophos XG/SFOS checklist FW01-FW27 (XML API Get-only)",
    "veeam_api": "Veeam B&R REST API, GET-only",
    "veeam_checklist": "Veeam B&R health/security checklist VB01-VB20",
}
VENV_MODULES = "import netmiko, paramiko, pyVmomi, winrm, dotenv"
NO_VENV = "Python env not set up. Run `cfn init` (or `setup claude for network here`)."


def venv_dir():
    return paths.data_dir() / "venv"


def usage():
    width = max(map(len, RUNNABLE))
    lines = [__doc__.strip(), "", "Scripts:"]
    lines += [f"  {n.ljust(width)}  {d}" for n, d in RUNNABLE.items()]
    return "\n".join(lines)


def ensure_venv(venv, requirements):
    """Create the shared venv and install requirements unless it already works. Returns 'exists' or 'created'."""
    py = paths.venv_python(venv)
    if py.exists() and subprocess.run([str(py), "-c", VENV_MODULES], capture_output=True, check=False).returncode == 0:
        return "exists"
    venv.parent.mkdir(parents=True, exist_ok=True)
    uv = shutil.which("uv")
    if uv:
        subprocess.run([uv, "venv", "--allow-existing", str(venv)], check=True)
        subprocess.run([uv, "pip", "install", "--python", str(py), "-r", str(requirements)], check=True)
    else:
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        subprocess.run([str(py), "-m", "pip", "install", "-r", str(requirements)], check=True)
    return "created"


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(usage())
        return 0
    name, rest = argv[0].replace("-", "_"), argv[1:]
    if name == "init":
        import init_workspace
        return init_workspace.main(rest)
    if name not in RUNNABLE:
        print(f"cfn: unknown script {argv[0]!r}\n\n{usage()}", file=sys.stderr)
        return 2
    py = paths.venv_python(venv_dir())
    if not py.exists():
        print(NO_VENV, file=sys.stderr)
        return 2
    return subprocess.run([str(py), str(paths.PLUGIN_ROOT / "scripts" / f"{name}.py"), *rest], check=False).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
