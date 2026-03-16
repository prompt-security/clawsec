---
name: openclaw-audit-watchdog
version: 0.1.1
description: Automated daily security audits for OpenClaw agents with email reporting. Runs standard and deep audits, summarizes findings, and delivers reports. Use when setting up security audit schedules, running vulnerability scans, or configuring automated security reports for OpenClaw agents.
homepage: https://clawsec.prompt.security
metadata: {"openclaw":{"emoji":"🔭","category":"security"}}
clawdis:
  emoji: "🔭"
  requires:
    bins: [bash, curl]
---

# Prompt Security Audit (openclaw)

## Installation

Available bundled with ClawSec Suite or as a standalone installation. If you have clawsec-suite installed, you may already have this skill deployed at `~/.openclaw/skills/openclaw-audit-watchdog/`.

---

## Goal

Create (or update) a daily cron job that:

1) Runs:
- `openclaw security audit --json`
- `openclaw security audit --deep --json`

2) Summarizes findings (critical/warn/info + top findings)

3) Sends the report to:
- a user-selected DM target (channel + recipient id/handle)

Default schedule: **daily at 23:00 (11pm)** in the chosen timezone.

Delivery:
- DM to last active session

## Usage Examples

### Example 1: Quick Start (Environment Variables)

For automated/MDM deployments, set environment variables before invoking:

```bash
export PROMPTSEC_DM_CHANNEL="telegram"
export PROMPTSEC_DM_TO="@yourhandle"
export PROMPTSEC_TZ="America/New_York"
export PROMPTSEC_HOST_LABEL="prod-server-01"

# Then invoke the skill
/openclaw-audit-watchdog
```

The skill will automatically configure and create the cron job without prompts.

### Example 2: What Gets Delivered

Each day at the scheduled time, you'll receive a report like:

```
🔭 Daily Security Audit Report
Host: prod-server-01
Time: 2026-02-16 23:00:00 America/New_York

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Standard Audit: 12 checks passed, 2 warnings
✓ Deep Audit: 8 probes passed, 1 critical

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[CRIT-001] Unencrypted API Keys Detected
→ Remediation: Move credentials to encrypted vault or use environment variables

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WARNINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[WARN-003] Outdated Dependencies Found
→ Remediation: Run `openclaw security audit --fix` to update

[WARN-007] Weak Permission on Config File
→ Remediation: chmod 600 ~/.openclaw/config.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Run `openclaw security audit --deep` for full details.
```

### Example 3: Suppressing Known Findings

To suppress audit findings that have been reviewed and accepted, pass the `--enable-suppressions` flag and ensure the config file includes the `"enabledFor": ["audit"]` sentinel:

```bash
# Create or edit the suppression config
cat > ~/.openclaw/security-audit.json <<'JSON'
{
  "enabledFor": ["audit"],
  "suppressions": [
    {
      "checkId": "skills.code_safety",
      "skill": "clawsec-suite",
      "reason": "First-party security tooling — reviewed by security team",
      "suppressedAt": "2026-02-15"
    }
  ]
}
JSON

# Run with suppressions enabled
/openclaw-audit-watchdog --enable-suppressions
```

Suppressed findings still appear in the report under an informational section but are excluded from critical/warning totals.

## Suppression / Allowlist

The audit pipeline supports an opt-in suppression mechanism for managing reviewed findings. Suppression uses defense-in-depth activation: two independent gates must both be satisfied.

### Activation Requirements

1. **CLI flag:** The `--enable-suppressions` flag must be passed at invocation.
2. **Config sentinel:** The configuration file must include `"enabledFor"` with `"audit"` in the array.

If either gate is absent, all findings are reported normally and the suppression list is ignored.

### Config File Resolution (4-tier)

1. Explicit `--config <path>` argument
2. `OPENCLAW_AUDIT_CONFIG` environment variable
3. `~/.openclaw/security-audit.json`
4. `.clawsec/allowlist.json`

### Config Format

```json
{
  "enabledFor": ["audit"],
  "suppressions": [
    {
      "checkId": "skills.code_safety",
      "skill": "clawsec-suite",
      "reason": "First-party security tooling — reviewed by security team",
      "suppressedAt": "2026-02-15"
    }
  ]
}
```

For full sentinel semantics and matching rules, see the clawsec-suite skill documentation.

## Installation flow (interactive)

Provisioning (MDM-friendly): prefer environment variables (no prompts).

Required env:
- `PROMPTSEC_DM_CHANNEL` (e.g. `telegram`)
- `PROMPTSEC_DM_TO` (recipient id)

Optional env:
- `PROMPTSEC_TZ` (IANA timezone; default `UTC`)
- `PROMPTSEC_HOST_LABEL` (label included in report; default uses `hostname`)
- `PROMPTSEC_INSTALL_DIR` (stable path used by cron payload to `cd` before running runner; default: `~/.config/security-checkup`)
- `PROMPTSEC_GIT_PULL=1` (runner will `git pull --ff-only` if installed from git)

Path expansion rules (important):
- In `bash`/`zsh`, use `PROMPTSEC_INSTALL_DIR="$HOME/.config/security-checkup"` (or absolute path).
- Do not pass a single-quoted literal like `'$HOME/.config/security-checkup'`.
- On PowerShell, prefer: `$env:PROMPTSEC_INSTALL_DIR = Join-Path $HOME ".config/security-checkup"`.
- If path resolution fails, setup now exits with a clear error instead of creating a literal `$HOME` directory segment.

Interactive install is last resort if env vars or defaults are not set.

even in that case keep prompts minimalistic the watchdog tool is pretty straight up configured out of the box.

## Create the cron job

Use the `cron` tool to create a job with:

- `schedule.kind="cron"`
- `schedule.expr="0 23 * * *"`
- `schedule.tz=<installer tz>`
- `sessionTarget="isolated"`
- `wakeMode="now"`
- `payload.kind="agentTurn"`
- `payload.deliver=true`

### Payload message template (agentTurn)

Create the job with a payload message that instructs the isolated run to:

1) Run the audits

- Prefer JSON output for robust parsing:
  - `openclaw security audit --json`
  - `openclaw security audit --deep --json`

2) Render a concise text report:

Include:
- Timestamp + host identifier if available
- Summary counts
- For each CRITICAL/WARN: `checkId` + `title` + 1-line remediation
- If deep probe fails: include the probe error line

3) Deliver the report:

- DM to the chosen user target using `message` tool

### Email delivery requirement

Attempt email delivery in this priority order:

A) If an email channel plugin exists in this deployment, use:
- `message(action="send", channel="email", target="target@example.com", message=<report>)`

B) Otherwise, fallback to local sendmail if available:
- `exec` with: `printf "%s" "$REPORT" | /usr/sbin/sendmail -t` (construct To/Subject headers)

If neither path is possible, still DM the user and include a line:
- `"NOTE: could not deliver to target@example.com (email channel not configured)"`

## Idempotency / updates

Before adding a new job:

- `cron.list(includeDisabled=true)`
- If a job with name matching `"Daily security audit"` exists, update it instead of adding a duplicate:
  - adjust schedule tz/expr
  - adjust DM target

## Suggested naming

- Job name: `"Daily security audit (Prompt Security)"`

## Minimal recommended defaults (do not auto-change config)

The cron’s report should *suggest* fixes but must not apply them.

Do not run `openclaw security audit --fix` unless explicitly asked.
