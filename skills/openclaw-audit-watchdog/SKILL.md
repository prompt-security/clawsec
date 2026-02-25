---
name: openclaw-audit-watchdog
version: 0.1.1
description: Automated daily security audits for OpenClaw agents with email reporting. Runs deep audits and sends formatted reports.
homepage: https://clawsec.prompt.security
metadata: {"openclaw":{"emoji":"🔭","category":"security"}}
clawdis:
  emoji: "🔭"
  requires:
    bins: [bash, curl]
---

# Prompt Security Audit (openclaw)

## Installation Options

You can get openclaw-audit-watchdog in two ways:

### Option A: Bundled with ClawSec Suite (Recommended)

**If you've installed clawsec-suite, you may already have this!**

Openclaw-audit-watchdog is bundled alongside ClawSec Suite to provide crucial automated security audit capabilities. When you install the suite, if you don't already have the audit watchdog installed, it will be deployed from the bundled copy.

**Advantages:**
- Convenient - no separate download needed
- Standard location - installed to `~/.openclaw/skills/openclaw-audit-watchdog/`
- Preserved - if you already have audit watchdog installed, it won't be overwritten
- Single verification - integrity checked as part of suite package

### Option B: Standalone Installation (This Page)

Install openclaw-audit-watchdog independently without the full suite.

**When to use standalone:**
- You only need the audit watchdog (not other suite components)
- You want to install before installing the suite
- You prefer explicit control over audit watchdog installation

**Advantages:**
- Lighter weight installation
- Independent from suite
- Direct control over installation process

Continue below for standalone installation instructions.

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

### Example 2: Interactive Setup

If environment variables aren't set, the skill will prompt minimally:

```
User: /openclaw-audit-watchdog

Agent: Setting up daily security audit watchdog...
       What channel should I use for delivery? (e.g., telegram, slack)
User: telegram

Agent: What's the recipient ID or handle?
User: @myhandle

Agent: Which timezone for the 23:00 daily run? (default: UTC)
User: America/Los_Angeles

Agent: ✓ Created cron job "Daily security audit (Prompt Security)"
       Schedule: Daily at 23:00 America/Los_Angeles
       Delivery: telegram → @myhandle
```

### Example 3: Updating Existing Job

If a job already exists, the skill updates it instead of creating duplicates:

```
User: /openclaw-audit-watchdog

Agent: Found existing "Daily security audit (Prompt Security)" job.
       Current: Daily at 23:00 UTC → telegram:@oldhandle

       Update delivery target? (current: telegram:@oldhandle)
User: slack:#security-alerts

Agent: ✓ Updated cron job
       Schedule: Daily at 23:00 UTC
       Delivery: slack:#security-alerts
```

### Example 4: What Gets Delivered

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

### Example 5: Custom Schedule

Want a different schedule? Set it before invoking:

```bash
# Run every 6 hours instead of daily
export PROMPTSEC_SCHEDULE="0 */6 * * *"
/openclaw-audit-watchdog
```

### Example 6: Multiple Environments

For managing multiple servers, use different host labels:

```bash
# On dev server
export PROMPTSEC_HOST_LABEL="dev-01"
export PROMPTSEC_DM_TO="@dev-team"
/openclaw-audit-watchdog

# On prod server
export PROMPTSEC_HOST_LABEL="prod-01"
export PROMPTSEC_DM_TO="@oncall"
/openclaw-audit-watchdog
```

Each will send reports with clear host identification.

### Example 7: Suppressing Known Findings

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

### Sentinel Semantics

- `"enabledFor": ["audit"]` -- audit suppression active (requires `--enable-suppressions` flag too)
- `"enabledFor": ["advisory"]` -- only advisory pipeline suppression (no effect on audit)
- `"enabledFor": ["audit", "advisory"]` -- both pipelines honor suppressions
- Missing or empty `enabledFor` -- no suppression active (safe default)

### Matching Rules

- **checkId:** exact match against the audit finding's check identifier (e.g., `skills.code_safety`)
- **skill:** case-insensitive match against the skill name from the finding
- Both fields must match for a finding to be suppressed

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
