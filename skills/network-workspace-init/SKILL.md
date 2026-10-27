---
name: network-workspace-init
description: Use when the user says `setup claude for network here` (or asks to create, initialise or repair a claude-for-network site workspace in the current directory), or when a cfn script says "Not a claude-for-network site" or "Python env not set up".
---

# Set up a claude-for-network site workspace

A site is a directory holding one site's data: its own inventory DB, `.env`, backups, reports and approvals.
The code stays in the plugin. Setup is idempotent: it creates only what is missing and never overwrites a file.

## Steps

1. Run one command in the directory the user is in (or the one they named):

   ```bash
   cfn init
   ```

   First run on a machine also creates the shared Python venv (a minute or two). If `cfn` is not found, the
   plugin is not enabled in this session. Tell the user to run:

   ```
   /plugin marketplace add https://github.com/adelabdelgawad/claudecode-for-network-plugin
   /plugin install network-ops@network-ops
   ```

   then restart Claude Code in this directory and type `setup claude for network here` again.

2. Report the `created` / `exists` list in a short table. Call out anything that already existed: it was left
   untouched (e.g. an existing `CLAUDE.md` or `.claude/settings.json` without `enabledPlugins`).

3. Read `${CLAUDE_PLUGIN_ROOT}/templates/rules.md` now, so the site rules (the approval gate) apply for the rest of
   this session. New sessions in this directory load them automatically.

4. Tell the user the next steps, and do not do them yourself:
   - **Fill in `.env`** with their credentials in their own editor. Never ask them to paste credentials into the
     chat, and never print, read aloud or edit `.env` values.
   - **Add the site's subnets** to `CLAUDE.local.md`.
   - **Discover devices** with `cfn discover <subnet> [--cred REF]`. Offer to run it once `.env` is filled in.

## Do not

- Do not run `cfn init` in the plugin source repo, in a home directory, or in a directory full of unrelated
  project files without asking the user first.
- Do not delete, move or "fix" existing files to make the setup clean.
- Do not create files by hand that `cfn init` creates; rerun `cfn init` instead.
