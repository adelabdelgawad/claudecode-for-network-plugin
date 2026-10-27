# claudecode-for-network-plugin — plugin source

This repo is the **network-ops** Claude Code plugin (marketplace `network-ops`). It holds code, skills, hooks,
templates and docs only. **It is not a site and must never hold site data** (no inventory DB, `.env`, backups,
reports, approvals or real hostnames/IPs). Sites are created anywhere with `setup claude for network here`
(`cfn init`).

## The approval gate

The gate is the core of the plugin. The rules it enforces are in `templates/rules.md` (CRITICAL section). Changes to
the gate files need extra care and their tests must stay green: `hooks/`, `bin/`, `.claude-plugin/`,
`scripts/change.py`, `scripts/netlib.py`, `scripts/paths.py`, `scripts/cfn.py`, the read-only allowlists
(`scripts/show.py`, `vmlib.py`, `guest_show.py`, `sophos_api.py`) and `templates/rules.md`. In a site, editing them
requires the user to type `APPROVE GUARD-EDIT`. The installed plugin's copies are protected everywhere; this source
repo is not, so develop here (not with `--plugin-dir` pointing at this repo, which would lock its own gate files).

## Layout

| Path | What it is |
|---|---|
| `.claude-plugin/plugin.json`, `marketplace.json` | Plugin + single-plugin marketplace (`source: "./"`) |
| `skills/*/SKILL.md` | The plugin's skills (incl. `network-workspace-init`) |
| `hooks/hooks.json` | Plugin hooks: `change_guard.py` (PreToolUse), `approval_capture.py` + `setup_trigger.py` (UserPromptSubmit), `site_rules.py` (SessionStart); all via `hooks/run-python` |
| `bin/cfn` → `scripts/cfn.py` | Launcher on the Bash PATH: `cfn <script> [args]`, `cfn init` |
| `scripts/paths.py` | Site root (marker walk-up) vs plugin root, shared venv location |
| `scripts/init_workspace.py` | The idempotent site scaffolder |
| `scripts/*.py` | The network/vSphere tools; data paths come from `netlib.ROOT` / `paths.site_root()` |
| `templates/rules.md` | Site rules injected at session start in every site |
| `templates/workspace/` | Files copied into a new site (`gitignore` is published as `.gitignore`) |
| `inventory/schema.sql` | Schema for new site DBs |
| `tests/`, `hooks/test_*.py` | Plain runnable test scripts (no pytest) |
| `tools/prepush_scan.py` | Pre-push scan for secrets and site identifiers |
| `docs/` | User docs; update them when a script or workflow changes |

## Developing

- Dev venv: `uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt`. Keep `paramiko<4`.
  Stdlib only in hooks, `cfn.py`, `paths.py`, `init_workspace.py` (they run before the venv exists).
- Try the plugin locally: `claude --plugin-dir <this repo>` in a scratch directory, then `setup claude for network here`.
- Run all tests:

  ```bash
  for t in hooks/test_change_guard.py hooks/test_site_hooks.py tests/test_paths.py tests/test_cfn.py tests/test_init_workspace.py; do python3 $t || break; done
  claude plugin validate .
  ```

- Public repo: examples use `192.0.2.x` and placeholder names (`SW-ACCESS-01`, `SW-CORE-01`). Before every push run
  `python3 tools/prepush_scan.py --history --inventory <a site>/inventory/inventory.db --deny <company>` and get the
  user's go-ahead.
- Bump `version` in `.claude-plugin/plugin.json` for each release.
