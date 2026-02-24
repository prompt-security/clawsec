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

### Path Expansion and Quoting

- `PROMPTSEC_INSTALL_DIR` and `OPENCLAW_AUDIT_CONFIG` support `~`, `$HOME`, `${HOME}`, `%USERPROFILE%`, and `$env:USERPROFILE`.
- In `bash`/`zsh`, use double quotes for expandable paths:
  - `export PROMPTSEC_INSTALL_DIR="$HOME/.config/security-checkup"`
- Avoid single-quoted literals such as `'$HOME/.config/security-checkup'`.
- In PowerShell:
  - `$env:PROMPTSEC_INSTALL_DIR = Join-Path $HOME ".config/security-checkup"`

## Suppression / Allowlist

Manage false-positive findings with the built-in suppression mechanism. Suppressed findings remain visible in reports but are demoted to informational status and do not count toward critical/warning totals.

Suppression is **opt-in with defense in depth**: the audit pipeline requires BOTH a CLI flag AND a config-file sentinel before any finding is suppressed. This prevents accidental or unauthorized suppression.

### Activation (Two Gates)

Both of the following must be true for audit suppressions to take effect:

1. **CLI flag:** Pass `--enable-suppressions` when invoking the runner.
2. **Config sentinel:** The configuration file must contain `"enabledFor": ["audit"]` (or a list that includes `"audit"`).

If either gate is missing, the suppression list is ignored entirely and all findings are reported normally.

### Config File Resolution

The audit scanner resolves the suppression config file using this 4-tier priority:

1. `--config <path>` CLI argument (highest priority)
2. `OPENCLAW_AUDIT_CONFIG` environment variable
3. `~/.openclaw/security-audit.json`
4. `.clawsec/allowlist.json` (fallback)

### Example Configuration

```json
{
  "enabledFor": ["audit"],
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

The `enabledFor` array controls which pipelines honor the suppression list:

| Value | Effect |
|-------|--------|
| `["audit"]` | Only audit suppression active (still requires `--enable-suppressions` flag) |
| `["advisory"]` | Only advisory suppression active (used by clawsec-suite) |
| `["audit", "advisory"]` | Both pipelines honor suppressions |
| Missing or `[]` | No suppression in any pipeline (safe default) |

### Required Fields per Suppression Entry

| Field | Description | Example |
|-------|-------------|---------|
| `checkId` | Audit check identifier to suppress | `skills.code_safety` |
| `skill` | Skill name the suppression applies to | `clawsec-suite` |
| `reason` | Justification for audit trail (required) | `First-party tooling, reviewed by security team` |
| `suppressedAt` | ISO 8601 date (YYYY-MM-DD) | `2026-02-15` |

**Matching:** Suppression requires an exact `checkId` match and a case-insensitive `skill` name match. Both must match for a finding to be suppressed.

### Usage

```bash
# Enable suppressions with default config location
./scripts/runner.sh --enable-suppressions

# Enable suppressions with explicit config path
./scripts/runner.sh --enable-suppressions --config /path/to/config.json

# Enable suppressions with config via environment variable
export OPENCLAW_AUDIT_CONFIG=~/.openclaw/custom-audit.json
./scripts/runner.sh --enable-suppressions
```

Without `--enable-suppressions`, the config file is not consulted for suppressions:

```bash
# Suppressions NOT active (flag missing)
./scripts/runner.sh
./scripts/runner.sh --config /path/to/config.json
```

### Report Output

Suppressed findings appear in a separate informational section:

```
CRITICAL (0):
  (none)

WARNINGS (1):
  [skills.network] some-skill: Unrestricted network access

INFO - SUPPRESSED (2):
  [skills.code_safety] clawsec-suite: dangerous-exec detected
    Reason: First-party security tooling, reviewed 2026-02-13
  [skills.permissions] my-tool: Broad permission scope
    Reason: Validated by security team, suppressedAt 2026-02-16
```

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

GNU AGPL v3.0 or later - See [LICENSE](../../LICENSE) for details.

---

**Part of [ClawSec](https://github.com/prompt-security/clawsec) by [Prompt Security](https://prompt.security)**
