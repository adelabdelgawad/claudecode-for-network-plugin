"""Regression test for scripts/paths.py (site root / plugin root / venv resolution).

Usage: python3 tests/test_paths.py
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"
VENV_PY = REPO / ".venv" / "bin" / "python"


def py(code, cwd, env=None):
    e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"), **(env or {})}
    p = subprocess.run([sys.executable, "-c", f"import sys;sys.path.insert(0,{str(SCRIPTS)!r});{code}"],
                       cwd=cwd, env=e, capture_output=True, text=True, check=False)
    return p.returncode, (p.stdout + p.stderr).strip()


def main():
    cases = []
    with tempfile.TemporaryDirectory() as td:
        t = Path(td).resolve()
        site, other = t / "site", t / "other"
        (site / "a" / "b").mkdir(parents=True)
        other.mkdir()
        (site / ".claude-for-network").write_text("{}")

        rc, out = py("import paths;print(paths.find_site(paths.Path('a/b').resolve()))", site)
        cases.append(("find_site from a subdir returns the site", out, str(site)))
        rc, out = py("import paths;print(paths.find_site(paths.Path.cwd()))", other)
        cases.append(("find_site outside a site returns None", out, "None"))
        rc, out = py("import paths;paths.site_root()", other)
        cases.append(("site_root outside a site exits with the setup hint",
                      rc != 0 and "setup claude for network here" in out, True))
        rc, out = py("import paths;print(paths.site_root())", other, {"CLAUDE_PROJECT_DIR": str(site)})
        cases.append(("site_root uses CLAUDE_PROJECT_DIR first", out, str(site)))
        rc, out = py("import paths;print(paths.site_root())", site / "a")
        cases.append(("site_root from a subdir (no env) finds the site", out, str(site)))
        rc, out = py("import paths;print(paths.PLUGIN_ROOT)", other)
        cases.append(("PLUGIN_ROOT is the repo", out, str(REPO)))
        rc, out = py("import paths;print(paths.data_dir('nt', {'LOCALAPPDATA': 'C:/x'}).as_posix())", other)
        cases.append(("data_dir on Windows", out, "C:/x/claude-for-network"))
        rc, out = py("import paths;print(paths.data_dir('posix', {'XDG_DATA_HOME': '/d'}).as_posix())", other)
        cases.append(("data_dir on Linux with XDG_DATA_HOME", out, "/d/claude-for-network"))
        rc, out = py("import paths;print(paths.data_dir('posix', {'HOME': '/h'}).as_posix())", other)
        cases.append(("data_dir on Linux default", out, "/h/.local/share/claude-for-network"))
        rc, out = py("import paths;print(paths.venv_python(paths.Path('v'), 'nt').as_posix())", other)
        cases.append(("venv_python on Windows", out, "v/Scripts/python.exe"))
        rc, out = py("import paths;print(paths.venv_python(paths.Path('v'), 'posix').as_posix())", other)
        cases.append(("venv_python on Linux", out, "v/bin/python"))

        before = set(REPO.joinpath("inventory").iterdir())
        p = subprocess.run([str(VENV_PY), str(SCRIPTS / "inventory.py"), "counts"], cwd=other, capture_output=True,
                           text=True, env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")}, check=False)
        cases.append(("inventory.py counts outside a site refuses", p.returncode != 0, True))
        cases.append(("... and writes nothing in the dir", list(other.iterdir()), []))
        cases.append(("... and nothing in the plugin inventory/", set(REPO.joinpath("inventory").iterdir()), before))

    failed = 0
    for name, got, want in cases:
        ok = got == want
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  (got {got!r}, want {want!r})"))
    print(f"\n{len(cases) - failed}/{len(cases)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
