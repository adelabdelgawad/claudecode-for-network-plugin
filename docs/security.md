# Security notes

This toolkit gives an AI agent SSH access to production network gear. The design assumes the
agent can make mistakes and puts hard stops in its way.

## Defences

1. **Read-only by default.** `show.py` enforces a command allowlist; `vmlib.call_ro()` allowlists
   vSphere API methods (property reads plus the performance queries `QueryPerf`, `QueryPerfCounter`,
   `QueryAvailablePerfMetric`, `QueryPerfProviderSummary`, which only read statistics); audit scripts send only `show` commands.
2. **Human approval for every change.** Only a line the user types (`APPROVE <CHG-ID>`) creates an
   approval, which is bound to the plan's hash, single-use, and expires after 60 minutes. See
   [change-workflow.md](change-workflow.md).
3. **Tool-call guard.** The `PreToolUse` hook blocks config/save/reload patterns, raw SSH/telnet,
   write HTTP methods, and edits to the guard itself.
4. **Backups before change.** `change.py apply` saves the running config before pushing.
5. **Audit trail.** `change_log` in the database plus `changes/<CHG-ID>/plan.json` and `result.json`.

The guard is pattern-based and is **not a sandbox**. Treat it as a seatbelt: also give the
automation account the least privilege that works (e.g. a read-only vCenter role, a Get-only
Sophos API profile) and keep `bypassPermissions` mode off on sessions that hold write credentials.

## Keeping secrets and site data out of git

| Never commit | Why |
|---|---|
| `.env` | Device credentials |
| `inventory/*.db` | Hostnames, IPs, serials |
| `backups/`, `audits/`, `outputs/`, `reports/` | Full configs, which can contain password hashes, SNMP communities and keys |
| `changes/*` | Plans and results naming real devices |
| `.claude/approvals/*` | Approval records |
| `CLAUDE.local.md` | Site-specific subnets and hostnames |

All of these are in `.gitignore`. Before publishing, check what will be committed:

```bash
git status --ignored
git ls-files | grep -Ev '^(\.claude-plugin|bin|hooks|skills|templates|tests|tools|docs|scripts|inventory/schema.sql|README|LICENSE|CLAUDE.md|requirements|\.gitignore|\.claude/settings.json)'
```

The second command should print nothing.

## Reporting a vulnerability

Please report a guard bypass or other security issue privately to the maintainers rather than
opening a public issue.
