# Change workflow (approval gate)

Every modification of a device or controller goes through one path:

```
plan  ──►  user reviews  ──►  user types  APPROVE <CHG-ID>  ──►  apply
```

Claude cannot approve its own changes. The gate is enforced by two Claude Code hooks and by
`scripts/change.py` itself.

## What counts as a change

Config mode, interface/VLAN/port/ACL/routing edits, `shutdown` / `no shutdown`,
`write memory` / `copy run start`, `reload`, `erase`, firmware or file copies, clearing state,
and any API `POST` / `PUT` / `PATCH` / `DELETE`. For vSphere: power actions, snapshots, vMotion,
reconfiguration, maintenance mode. For Sophos XG: XML API `<Set>` / `<Remove>`.

## Steps

1. **Collect current state** with read-only tools (`show.py`, `backup.py`).
2. **Write the commands** to a file, e.g. `changes/ntp-fix.txt`, plus an optional rollback file.
3. **Plan** — this does not connect to any device:

   ```bash
   cfn change plan --title "Set NTP servers on access switches" \
       --commands-file changes/ntp-fix.txt \
       --rollback-file changes/ntp-fix-rollback.txt \
       --verify "show ntp associations" --save \
       --match 'SW-*'
   ```

   The plan is written to `changes/<CHG-ID>/plan.json`.
4. **Review.** Claude shows the change ID, every target (hostname and IP), the exact commands,
   the verify commands, the rollback, and whether the config will be saved — then stops.
5. **Approve.** The user types, on its own line:

   ```
   APPROVE CHG-20261027-121415-a8f7
   ```

   or `REJECT <CHG-ID>`. "yes", "ok" or "go ahead" are not approvals.
6. **Apply:**

   ```bash
   cfn change apply CHG-20261027-121415-a8f7
   ```

   For each target, `apply` backs up the running config to `backups/<hostname>/<ts>.cfg`,
   pushes the commands, saves if `--save` was set, runs the verify commands, writes a
   `change_log` row, and stores the result in `changes/<CHG-ID>/result.json`.
7. **Rollback** of a failed change is a **new plan** with its own approval.

## How the gate is enforced

| Component | Role |
|---|---|
| `hooks/approval_capture.py` | `UserPromptSubmit` hook. Only a line typed by the user can create `.claude/approvals/<CHG-ID>.json`. |
| `cfn change apply` | Refuses unless the approval exists, matches the plan's **sha256**, is unused, and is less than **60 minutes** old. Approvals are single-use; editing the plan invalidates them. |
| `hooks/change_guard.py` | `PreToolUse` hook on Bash/Write/Edit. Blocks config-mode, save, reload and shutdown patterns, raw `ssh`/`telnet`/`sshpass`, write HTTP methods (`curl`, Postman), chained `change.py apply`, and any edit of the gate files. |

### Protected files

`hooks/`, `.claude/settings.json`, `.claude/settings.local.json`, `.claude/approvals/`,
`scripts/change.py`, `scripts/netlib.py`.

Claude can only edit these after the user types `APPROVE GUARD-EDIT`, which unlocks them for
15 minutes. The approvals directory can never be written by Claude.

## Commands

```bash
cfn change list          # all plans and their state
cfn change show <CHG-ID> # one plan in full
```

## Batching

Group devices that need identical commands into one plan. When several plans are needed, the user
can approve them in one message (one `APPROVE` line each). Dependent plans still run in order, with
the results checked between them.
