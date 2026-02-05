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
