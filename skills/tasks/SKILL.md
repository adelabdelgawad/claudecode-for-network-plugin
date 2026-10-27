---
name: tasks
description: Use when the user asks for their tasks, to-do list, findings, open issues, "what's left", "what needs fixing", progress on findings, or wants to add, start, block, assign, close or re-check a task — and after any audit or report run whose findings should become tracked tasks.
---

# Task list

## Overview

Findings and follow-up work live in the `tasks` table of `inventory/inventory.db`, managed by `cfn tasks`. Each task has a severity (`crit`/`warn`/`info`), a category, a status (`todo` → `in_progress` / `blocked` → `done` / `wontfix`), the object it concerns, a suggested action, and `needs_change` (1 = doing it modifies a device or VM).

## Quick reference

```bash
cfn tasks list                     # open tasks, grouped checklist
cfn tasks list --category storage --severity crit
cfn tasks list --md                # markdown checklist (paste into Teams/email)
cfn tasks list --status all --brief
cfn tasks summary                  # counts only
cfn tasks show 12
cfn tasks start 12 | done 12 --note "extended C: to 150 GB" | block 12 --note "waiting for vendor"
cfn tasks add "Replace PSU on core switch" --category network --severity warn --object core-sw-01

# refresh from findings (dedupes, reopens, auto-resolves what disappeared)
cfn vsphere discover && cfn tasks import vmtools
cfn vsphere-storage  && cfn tasks import storage
```

## How to present tasks to the user

- When the user asks for tasks or findings, run `tasks.py list` (with filters if they named a category, severity or machine) and show the output as a checklist. Lead with the counts by severity, then the items. Run `list --md` when they want something to paste or share.
- Before showing tasks, offer to refresh them: re-run the source report and its import so the list isn't stale. Say when the data was last imported.
- Never change a task's status unless the user says so, or a re-import shows the finding is gone (auto-resolved). Tell the user what changed.

## Doing a task

- `needs_change = 1` means that carrying the task out (upgrading VMware Tools, extending a disk, removing a snapshot, cleaning up a guest, any config) is a **change** under the CRITICAL site rules, so it needs the user's `APPROVE <CHG-ID>`. vSphere and guest changes have **no `change.py` backend yet**. For those, give the user the exact steps to run themselves, then mark the task `done` once they confirm.
- Investigation tasks (read-only) can be worked directly: use `vsphere`, `network-show-collect` or `guest_show.py`, and put the findings in `--note`.
