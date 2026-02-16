# OpenClaw Audit Watchdog 🔭

Automated daily security audits for OpenClaw/Clawdbot agents with email reporting.

## Overview

The Audit Watchdog provides automated security monitoring for your OpenClaw agent deployments:

- **Daily Security Scans** - Scheduled via cron for continuous monitoring
- **Deep Audit Mode** - Comprehensive analysis of agent configurations and behavior
- **Email Reporting** - Formatted reports delivered to your security team
- **Git Integration** - Optionally syncs latest configurations before audit

## Quick Start

```bash
# Install skill
mkdir -p ~/.openclaw/skills/openclaw-audit-watchdog
cd ~/.openclaw/skills/openclaw-audit-watchdog

# Download and extract
curl -sSL "https://github.com/prompt-security/clawsec/releases/download/$VERSION_TAG/openclaw-audit-watchdog.skill" -o watchdog.skill
unzip watchdog.skill

# Configure
export PROMPTSEC_EMAIL_TO="security@yourcompany.com"
export PROMPTSEC_HOST_LABEL="prod-agent-1"

# Run
./scripts/runner.sh
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `PROMPTSEC_EMAIL_TO` | Email recipient for reports | `target@example.com` |
| `PROMPTSEC_HOST_LABEL` | Host identifier in reports | hostname |
| `PROMPTSEC_GIT_PULL` | Pull latest before audit (0/1) | `0` |
| `OPENCLAW_AUDIT_CONFIG` | Path to suppression config file | Auto-detected |

## Suppression Configuration

Manage false-positive findings with the built-in suppression mechanism. Suppressed findings remain visible in reports but don't count toward critical/warning totals.

### Config File Location

The audit scanner checks these locations (in priority order):

1. `--config` flag argument
2. `OPENCLAW_AUDIT_CONFIG` environment variable
3. `~/.openclaw/security-audit.json` (primary)
4. `.clawsec/allowlist.json` (fallback)

### Example Configuration

```json
{
  "suppressions": [
    {
      "checkId": "skills.code_safety",
      "skill": "clawsec-suite",
      "reason": "First-party security tooling, reviewed 2026-02-13",
      "suppressedAt": "2026-02-13"
    },
    {
      "checkId": "skills.permissions",
      "skill": "my-internal-tool",
      "reason": "Broad permissions required for legitimate functionality",
      "suppressedAt": "2026-02-16"
    }
  ]
}
```

### Required Fields

- **checkId**: Security check identifier (e.g., `skills.code_safety`)
- **skill**: Exact skill name to suppress
- **reason**: Justification for audit trail (required)
- **suppressedAt**: ISO 8601 date (YYYY-MM-DD)

### Usage

```bash
# Use default config location
./scripts/runner.sh

# Specify custom config
./scripts/runner.sh --config /path/to/config.json

# Or set via environment
export OPENCLAW_AUDIT_CONFIG=~/.openclaw/custom-audit.json
./scripts/runner.sh
```

### Report Output

Suppressed findings appear in a separate section:

```
CRITICAL (0):
  (none)

WARNINGS (1):
  [skills.network] some-skill: Unrestricted network access

INFO - SUPPRESSED (2):
  ℹ [skills.code_safety] clawsec-suite: dangerous-exec detected
    Reason: First-party security tooling, reviewed 2026-02-13
  ℹ [skills.permissions] my-tool: Broad permission scope
    Reason: Validated by security team, suppressedAt 2026-02-16
```

**Important**: Suppressions require BOTH `checkId` AND `skill` to match. This prevents over-suppression and maintains audit integrity.

See `examples/security-audit-config.example.json` for a complete template.

## Scripts

| Script | Purpose |
|--------|---------|
| `runner.sh` | Main entry - runs full audit pipeline |
| `run_audit_and_format.sh` | Core audit execution |
| `codex_review.sh` | AI-assisted code review |
| `render_report.mjs` | HTML report generation |
| `sendmail_report.sh` | Local sendmail delivery |
| `send_smtp.mjs` | SMTP email delivery |
| `setup_cron.mjs` | Cron job configuration |

## Requirements

- bash
- curl
- Optional: node (for SMTP/rendering), jq (for JSON), sendmail (for email)

## Cron Setup

```bash
# Daily at 6 AM
0 6 * * * /path/to/scripts/runner.sh
```

Or use the setup script:

```bash
node scripts/setup_cron.mjs
```

## License

MIT - See [LICENSE](../../LICENSE) for details.

---

**Part of [ClawSec](https://github.com/prompt-security/clawsec) by [Prompt Security](https://prompt.security)**
