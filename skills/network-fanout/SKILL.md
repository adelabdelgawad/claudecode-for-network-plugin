---
name: network-fanout
description: Use whenever a task touches more than one network device — show collection, audits, log/config scans, backups, discovery, or applying approved changes — to run it concurrently through one Python script call instead of per-device tool calls, loops, or subagents, and to keep raw output out of the context window.
---

# Network Fan-out (concurrent, script-first, low-token)

## Safety comes first. Concurrency never relaxes a rule.

Concurrency changes *how fast* approved or read-only work runs. It never changes *what* may run:
- Every CRITICAL site rule and every step of the `network-change` skill still applies, unchanged.
- **Changes:** the only path is `cfn change apply <ID>`, and only for IDs the user typed `APPROVE` for.
  - No parallel wrapper scripts, background jobs (`&`), `xargs -P`, or threads that push config.
  - Never start a plan that depends on another plan until the first one has finished and you have checked its results.
- **Approvals stay one ID, one exact plan.** Grouping devices for efficiency happens *before* the plan is made, never by editing a plan after it has been approved.
- **Read-only scripts stay read-only.** Every command goes through `netlib.require_readonly`, and concurrency doesn't widen the allowlist.
- **Per-device safety still happens for every device:** backup before the change, `stop_on_error`, verify, and `change_log`. Faster work doesn't mean skipping steps.
- **If a hook blocks a command, stop and tell the user.** Never split, parallelise, or re-encode a command to get past it.
- **Concurrency on `change.py apply` itself:** adding it is a guard edit, which needs `APPROVE GUARD-EDIT`. It must keep the backup-first and stop-on-error behaviour.

## Core rule

**One script call covers all targets, and it runs them concurrently.** Never act on devices one at a time from the conversation.

| Do | Don't |
|---|---|
| `show.py -c "..." --match 'SW-*'` or `--all` | Make one `show.py` call per device, or loop over devices with `for h in ...; do ...; done` / `xargs` |
| Hand one subagent a whole batch | Spawn a subagent per device or per group of devices |
| Write raw output to files (`--out`), then parse it with Python | Paste whole `show` outputs into the context to read them |
| Return counts, tables and exceptions | Return every line from every device |

## Tools and their concurrency

| Tool | Workers (default) | Notes |
|---|---|---|
| `cfn show` | `--workers 16` | `--out` saves the full output. `--grep REGEX` prints only matching lines. `--quiet` (with `--out`) prints one status line per device. |
| `cfn backup` | `--workers 8` | Running configs go to `backups/<host>/<ts>.cfg` |
| `cfn discover` | `--workers 32` | Only when asked or when a device is missing (see the site rules) |
| `cfn log-audit` | `--workers 10` | Logging coverage and abnormal-log audit. Writes `summary.json` and `report.md` under `reports/log_audit/` |
| `cfn change apply` | sequential | Approval-gated (`network-change` skill). Put every target that gets the same commands in **one** plan. |

Keep workers at 32 or fewer for SSH. Old 2960s are slow to log in, so raise the timeouts, not the worker count.

## Script-first workflow

1. **Is there a script for this?** Use it with all targets in one call.
2. **Is a repeated or multi-step analysis missing a script?** Have a Sonnet subagent write a **read-only** script in `scripts/` that follows the `log_audit.py` pattern:
   - Targets come from `netlib.resolve_targets` (hostnames, `--match`, `--role`, `--all`).
   - Devices are processed with a `ThreadPoolExecutor` and `--workers`, and each device's errors are caught and recorded.
   - Raw output is saved to `<out>/raw/<host>.txt`, with parsed results in `summary.json` and a short `report.md`.
   - The console output is a compact summary only.

   It must send only allowlisted read-only commands (`netlib.require_readonly`). **A script never pushes config.** Changes only go through `change.py` (site rules, CRITICAL section).
3. **Analyse the files, not the conversation.** Query `summary.json` and `raw/` with a short `python3 -c` or script that prints aggregates: counts by status, top-N, exceptions. Read a single raw file only when you need to check a specific finding.
4. **Delegate the batch, not the device.** A Haiku subagent gets *one* instruction covering the whole target set ("run X with `--all --out`, return the summary"), and a Sonnet subagent gets the whole list of approved IDs.

## Changes

- Group devices by identical commands, which gives you identical rollback values, and make one plan per group. Don't make one plan per device.
- Ask for all the `APPROVE` lines in **one** message.
- Delegate the approved IDs to **one** Sonnet subagent.
- When one plan depends on another, for example removing old NTP servers only after the new one has been added, run them in order and check the first plan's results before running the second.

## Red flags

- A Bash command containing `for ... in` or `xargs` that calls a `scripts/*.py` device tool once per host
- Sending more than ~3 tool calls that differ only in the hostname
- A subagent prompt that names a single device when the task covers many
- Reading a raw `show` dump longer than ~100 lines into the context to find one fact. Use `--grep` or a parser instead.
