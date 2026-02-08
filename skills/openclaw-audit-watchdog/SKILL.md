---
name: openclaw-audit-watchdog
version: 0.0.4
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
