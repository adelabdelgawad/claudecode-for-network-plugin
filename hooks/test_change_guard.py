"""Regression test for change_guard.py, run against a throwaway project root with fake approval files.

Usage: python3 hooks/test_change_guard.py
"""
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOOK = str(Path(__file__).with_name("change_guard.py"))
INV = ("python3 -c \"import sqlite3;c=sqlite3.connect('inventory/inventory.db');"
       "c.execute('UPDATE devices SET notes=1');c.commit()\"")


PLUGIN = Path(__file__).resolve().parent.parent
MARKER = ".claude-for-network"
CID = "CHG-20261027-120000-abcd"
INV1 = INV.replace(";", " ")  # same blocked pattern, but no ';' chainer to fall back on


def run(root, tool, tin, mark=True, cwd=None):
    if mark:
        (root / MARKER).write_text("{}")
    p = subprocess.run([sys.executable, HOOK], input=json.dumps({"tool_name": tool, "tool_input": tin,
                                                                 "cwd": str(cwd or root)}),
                       capture_output=True, text=True, env={"CLAUDE_PROJECT_DIR": str(root), "PATH": "/usr/bin:/bin"}, check=False)
    # Claude Code blocks only on exit 2; any other non-zero exit lets the tool call run.
    return {0: "ALLOW", 2: "BLOCK"}.get(p.returncode, f"RC{p.returncode}")


def approve(root, name, age_min=0, status="approved"):
    d = root / ".claude" / "approvals"
    d.mkdir(parents=True, exist_ok=True)
    t = (datetime.now(timezone.utc) - timedelta(minutes=age_min)).isoformat(timespec="seconds")  # noqa: UP017
    (d / f"{name}.json").write_text(json.dumps({"id": name, "status": status, "approved_at": t}))


def main():
    cases = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cases.append(("inventory write, no INV-EDIT", run(root, "Bash", {"command": INV}), "BLOCK"))
        cases += [
            ("C2: cfn change list & <device code>", run(root, "Bash", {"command": f"cfn change list & {INV1}"}), "BLOCK"),
            ("C2: cfn change list >(<device code>)",
             run(root, "Bash", {"command": f"cfn change list > >({INV1})"}), "BLOCK"),
            ("C2: cfn change list, CR-separated", run(root, "Bash", {"command": f"cfn change list\r{INV1}"}), "BLOCK"),
            ("M6: full-path cfn change apply, single",
             run(root, "Bash", {"command": f"{PLUGIN}/bin/cfn change apply {CID}"}), "ALLOW"),
            ("M6: full-path cfn change apply, chained",
             run(root, "Bash", {"command": f"{PLUGIN}/bin/cfn change apply {CID} && echo x"}), "BLOCK"),
            ("I1: cd into hooks then sed the guard",
             run(root, "Bash", {"command": f"cd {PLUGIN}/hooks && sed -i s/a/b/ change_guard.py"}), "BLOCK"),
            ("I1: cp over the hooks dir", run(root, "Bash", {"command": f"cp /tmp/x {PLUGIN}/hooks/"}), "BLOCK"),
            ("I1: sed site_rules.py", run(root, "Bash", {"command": "sed -i s/a/b/ hooks/site_rules.py"}), "BLOCK"),
            ("I1: sed setup_trigger.py", run(root, "Bash", {"command": "sed -i s/a/b/ hooks/setup_trigger.py"}), "BLOCK"),
            ("I1: read the guard is fine", run(root, "Bash", {"command": "cat hooks/change_guard.py"}), "ALLOW"),
            ("M3: edit the vSphere read-only allowlist",
             run(root, "Edit", {"file_path": str(PLUGIN / "scripts/vmlib.py"), "new_string": "x"}), "BLOCK"),
            ("M3: edit the show allowlist",
             run(root, "Edit", {"file_path": str(PLUGIN / "scripts/show.py"), "new_string": "x"}), "BLOCK"),
            ("M3: edit the site rules", run(root, "Edit", {"file_path": str(PLUGIN / "templates/rules.md"),
                                                          "new_string": "x"}), "BLOCK"),
            ("I4: malformed tool_input fails closed", run(root, "Bash", ["not", "a", "dict"]), "BLOCK"),
        ]
        link = Path(td + "-plugin-link")
        link.symlink_to(PLUGIN)
        try:
            cases.append(("M1: edit the guard through a symlinked plugin path",
                          run(root, "Edit", {"file_path": str(link / "hooks/change_guard.py"), "new_string": "x"}),
                          "BLOCK"))
        finally:
            link.unlink()
        approve(root, "INV-EDIT", age_min=20)
        cases.append(("inventory write, INV-EDIT expired (20 min)", run(root, "Bash", {"command": INV}), "BLOCK"))
        approve(root, "INV-EDIT", status="rejected")
        cases.append(("inventory write, INV-EDIT rejected", run(root, "Bash", {"command": INV}), "BLOCK"))
        approve(root, "INV-EDIT")
        cases += [
            ("inventory write, INV-EDIT valid", run(root, "Bash", {"command": INV}), "ALLOW"),
            ("inventory write in a .py file, INV-EDIT valid",
             run(root, "Write", {"file_path": str(root / "x.py"), "content": INV}), "ALLOW"),
            ("commit + netmiko import",
             run(root, "Bash", {"command": INV.replace("import sqlite3", "import sqlite3,netmiko")}), "BLOCK"),
            ("commit + urllib", run(root, "Bash", {"command": INV.replace("import sqlite3", "import sqlite3,urllib")}), "BLOCK"),
            ("commit on another DB", run(root, "Bash", {"command": INV.replace("inventory/inventory.db", "other.db")}), "BLOCK"),
            ("inventory write + send_config_set",
             run(root, "Bash", {"command": INV.replace("UPDATE", "send_config_set UPDATE")}), "BLOCK"),
            ("plain send_config_set", run(root, "Bash", {"command": "python3 -c 'conn.send_config_set([1])'"}), "BLOCK"),
            ("curl POST", run(root, "Bash", {"command": "curl -k -X POST https://192.0.2.1/api"}), "BLOCK"),
            ("read-only inventory query", run(root, "Bash", {"command": "python3 scripts/inventory.py list"}), "ALLOW"),
            ("edit protected hook (absolute plugin path), INV-EDIT only",
             run(root, "Edit", {"file_path": str(PLUGIN / "hooks/change_guard.py"), "new_string": "x"}), "BLOCK"),
            ("write hooks.json (absolute plugin path)",
             run(root, "Write", {"file_path": str(PLUGIN / "hooks/hooks.json"), "content": "{}"}), "BLOCK"),
            ("edit bin/cfn", run(root, "Edit", {"file_path": str(PLUGIN / "bin/cfn"), "new_string": "x"}), "BLOCK"),
            ("edit the Sophos XML executor",
             run(root, "Edit", {"file_path": str(PLUGIN / "scripts/sophos_xml.py"), "new_string": "x"}), "BLOCK"),
            ("write a Sophos XML resource",
             run(root, "Write", {"file_path": str(PLUGIN / "resources/sophos/x.add.xml"), "content": "<Set/>"}),
             "BLOCK"),
            ("shell write to a Sophos XML resource",
             run(root, "Bash", {"command": f"echo x > {PLUGIN}/resources/sophos/x.add.xml"}), "BLOCK"),
            ("write the site marker", run(root, "Write", {"file_path": str(root / MARKER), "content": "{}"}), "BLOCK"),
            ("write site .claude/settings.json",
             run(root, "Write", {"file_path": str(root / ".claude/settings.json"), "content": "{}"}), "BLOCK"),
            ("sed on scripts/paths.py", run(root, "Bash", {"command": "sed -i s/a/b/ scripts/paths.py"}), "BLOCK"),
            ("cfn change apply, single", run(root, "Bash", {"command": f"cfn change apply {CID}"}), "ALLOW"),
            ("cfn change apply, chained &&", run(root, "Bash", {"command": f"cfn change apply {CID} && echo x"}), "BLOCK"),
            ("cfn change apply, chained ;", run(root, "Bash", {"command": f"cfn change apply {CID}; echo x"}), "BLOCK"),
            ("cfn change apply, piped", run(root, "Bash", {"command": f"cfn change apply {CID} | tee x"}), "BLOCK"),
            ("cfn change plan, single",
             run(root, "Bash", {"command": 'cfn change plan --title t -c "interface Gi1/0/1" SW-ACCESS-01'}), "ALLOW"),
            ("cfn show read-only", run(root, "Bash", {"command": 'cfn show -c "show version" --all'}), "ALLOW"),
        ]
        # remote-shell tools and IOS command words: blocked when used, allowed when only named or parsed
        py, sh = str(root / "x.py"), str(root / "a.sh")
        for name, tool, tin, want in [
            ("bash: telnet <ip>", "Bash", {"command": "telnet 192.0.2.1 23"}, "BLOCK"),
            ("bash: chained telnet", "Bash", {"command": "ls; telnet 192.0.2.1"}, "BLOCK"),
            ("bash: piped plink", "Bash", {"command": "echo y | plink -ssh admin@192.0.2.1"}, "BLOCK"),
            ("bash: sudo -u x telnet", "Bash", {"command": "sudo -u x telnet sw1"}, "BLOCK"),
            ("bash: timeout 5 /usr/bin/telnet", "Bash", {"command": "timeout 5 /usr/bin/telnet sw1"}, "BLOCK"),
            ("bash: sshpass", "Bash", {"command": "sshpass -p x ssh admin@sw1"}, "BLOCK"),
            ("bash: bash -c 'telnet'", "Bash", {"command": "bash -c 'telnet 192.0.2.1'"}, "BLOCK"),
            ("bash: $(telnet)", "Bash", {"command": "x=$(telnet sw1)"}, "BLOCK"),
            ("bash: python telnetlib", "Bash", {"command": "python3 -c 'import telnetlib'"}, "BLOCK"),
            ("bash: heredoc line telnet", "Bash", {"command": "cat > a.sh <<EOF\ntelnet 192.0.2.1\nEOF"}, "BLOCK"),
            ("bash: reload still blocked", "Bash", {"command": "echo reload | python3 x.py"}, "BLOCK"),
            ("bash: grep for telnet", "Bash", {"command": "grep -n \"telnet\" scripts/guest_show.py"}, "ALLOW"),
            ("file: import telnetlib", "Write", {"file_path": py, "content": "import telnetlib\n"}, "BLOCK"),
            ("file: netmiko cisco_ios_telnet", "Write",
             {"file_path": py, "content": "d = {'device_type': 'cisco_ios_telnet'}"}, "BLOCK"),
            ("file: subprocess argv", "Write", {"file_path": py, "content": "subprocess.run(['telnet', host])"}, "BLOCK"),
            ("file: os.system string", "Write", {"file_path": py, "content": "os.system('telnet 192.0.2.1')"}, "BLOCK"),
            ("file: f-string command", "Write", {"file_path": py, "content": "cmd = f\"telnet {host}\""}, "BLOCK"),
            ("file: shell=True string w/ chain", "Write",
             {"file_path": py, "content": "subprocess.run('ls; telnet 192.0.2.1', shell=True)"}, "BLOCK"),
            ("file: plink user@host string", "Write", {"file_path": py, "content": "c = 'plink admin@sw1'"}, "BLOCK"),
            ("file: .sh line", "Write", {"file_path": sh, "content": "#!/bin/sh\ntelnet 192.0.2.1\n"}, "BLOCK"),
            ("file: extensionless script line", "Write",
             {"file_path": str(root / "bin/connect"), "content": "#!/bin/sh\nexec telnet sw1\n"}, "BLOCK"),
            ("file: send_command('reload')", "Write", {"file_path": py, "content": "conn.send_command('reload')"}, "BLOCK"),
            ("file: no shutdown in a command list", "Write",
             {"file_path": py, "content": "cmds = ['interface Gi1/0/1', 'no shutdown']"}, "BLOCK"),
            ("file: ' shutdown' literal", "Write", {"file_path": py, "content": "cmds.append(' shutdown')"}, "BLOCK"),
            ("file: conf t via timing", "Write", {"file_path": py, "content": "c.send_command_timing(\"conf t\")"}, "BLOCK"),
            ("file: f-string reload in", "Write", {"file_path": py, "content": "x = f\"reload in {m}\""}, "BLOCK"),
            ("file: wr mem literal", "Write", {"file_path": py, "content": "c.send_command('write memory')"}, "BLOCK"),
            ("file: send_config_set still blocked", "Write", {"file_path": py, "content": "c.send_config_set(x)"}, "BLOCK"),
            ("file: .sh shutdown", "Write", {"file_path": sh, "content": "printf 'shutdown\\n'\n"}, "BLOCK"),
            ("file: check title naming telnet", "Write",
             {"file_path": py, "content": "TITLE = 'Risky services (SMBv1, RDP without NLA, telnet, ftp)'\n"}, "ALLOW"),
            ("file: regex alternation + port map", "Write",
             {"file_path": py, "content": "RISKY_RE = re.compile(r'(ftp|telnet|rsh)')\nPORTS = {21: 'ftp', 23: 'telnet'}\n"},
             "ALLOW"),
            ("file: reload-reason title + regex", "Write",
             {"file_path": py, "content": "TITLE = 'Uptime; last reload reason'\nRE = re.compile(r'Last reload reason: (.+)')\n"},
             "ALLOW"),
            ("file: env-state regex with shutdown", "Write",
             {"file_path": py, "content": "BAD = re.compile(r'(shutdown|critical|faulty)', re.I)  # PSU shutdown state\n"},
             "ALLOW"),
            ("file: show reload literal", "Write", {"file_path": py, "content": "conn.send_command('show reload')"}, "ALLOW"),
        ]:
            cases.append((name, run(root, tool, tin), want))
        other = root / "other-repo" / "hooks" / "change_guard.py"
        cases.append(("other repo's guard file, no GUARD-EDIT",
                      run(root, "Edit", {"file_path": str(other), "new_string": "x = 1"}), "BLOCK"))
        approve(root, "GUARD-EDIT")
        cases.append(("other repo's guard file, GUARD-EDIT valid",
                      run(root, "Edit", {"file_path": str(other), "new_string": "PUSH = ['send_config_set']"}), "ALLOW"))
        cases.append(("edit protected hook with GUARD-EDIT",
                      run(root, "Edit", {"file_path": str(PLUGIN / "hooks/change_guard.py"), "new_string": "x"}),
                      "ALLOW"))
    with tempfile.TemporaryDirectory() as td:
        cases.append(("outside a site the guard is inactive",
                      run(Path(td), "Bash", {"command": "reload"}, mark=False), "ALLOW"))
        (Path(td) / "inventory").mkdir()
        (Path(td) / "inventory" / "inventory.db").write_bytes(b"")
        cases.append(("a dir with an inventory DB (no marker) is still gated",
                      run(Path(td), "Bash", {"command": "reload"}, mark=False), "BLOCK"))
    with tempfile.TemporaryDirectory() as td:
        cases.append(("I2: outside a site, editing the plugin's guard is still blocked",
                      run(Path(td), "Edit", {"file_path": str(PLUGIN / "hooks/change_guard.py"), "new_string": "x"},
                          mark=False), "BLOCK"))
        cases.append(("I2: outside a site, sed on the guard is still blocked",
                      run(Path(td), "Bash", {"command": "sed -i s/a/b/ hooks/change_guard.py"}, mark=False), "BLOCK"))
        site = Path(td) / "site"
        site.mkdir()
        (site / MARKER).write_text("{}")
        cases.append(("I3: project dir not a site, cwd inside a site -> gated",
                      run(Path(td), "Bash", {"command": INV}, mark=False, cwd=site), "BLOCK"))
        cases.append(("I3: writing the cwd site's settings.json is blocked",
                      run(Path(td), "Write", {"file_path": str(site / ".claude/settings.json"), "content": "{}"},
                          mark=False, cwd=site), "BLOCK"))
    capture = str(Path(__file__).with_name("approval_capture.py"))
    with tempfile.TemporaryDirectory() as td:
        site = Path(td) / "site"
        site.mkdir()
        (site / MARKER).write_text("{}")
        subprocess.run([sys.executable, capture], input=json.dumps({"prompt": "APPROVE INV-EDIT", "cwd": str(site)}),
                       capture_output=True, text=True, env={"CLAUDE_PROJECT_DIR": td, "PATH": "/usr/bin:/bin"}, check=False)
        cases.append(("I3: capture records in the cwd site when the project dir is not a site",
                      (site / ".claude" / "approvals" / "INV-EDIT.json").is_file(), True))
    runpy = str(Path(__file__).with_name("run-python"))
    with tempfile.TemporaryDirectory() as td:
        site, other = Path(td) / "site", Path(td) / "other"
        (site / "sub").mkdir(parents=True)
        other.mkdir()
        (site / MARKER).write_text("{}")
        for label, flag, cwd, want in [("in a site", ["--fail-closed"], site, 2),
                                       ("in a site subdir", ["--fail-closed"], site / "sub", 2),
                                       ("outside a site", ["--fail-closed"], other, 0),
                                       ("(no flag)", [], site, 1)]:
            p = subprocess.run(["/bin/bash", runpy, *flag, "x.py"], capture_output=True, text=True, cwd=cwd,
                               env={"PATH": "/nonexistent"}, check=False)
            cases.append((f"I4: run-python {' '.join(flag)} {label} with no Python exits {want}", p.returncode, want))
    for prompt, want in [("APPROVE INV-EDIT", "approved"), ("REJECT INV-EDIT", "rejected"),
                         ("approve inv-edit please", "none")]:
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / MARKER).write_text("{}")
            subprocess.run([sys.executable, capture], input=json.dumps({"prompt": prompt, "cwd": td}),
                           capture_output=True, text=True, env={"CLAUDE_PROJECT_DIR": td, "PATH": "/usr/bin:/bin"}, check=False)
            f = Path(td) / ".claude" / "approvals" / "INV-EDIT.json"
            got = json.loads(f.read_text())["status"] if f.exists() else "none"
        cases.append((f"capture {prompt!r}", got, want))
    bad = 0
    for name, got, want in cases:
        ok = got == want
        bad += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {got:5}  {name}")
    print(f"{len(cases) - bad}/{len(cases)} passed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
