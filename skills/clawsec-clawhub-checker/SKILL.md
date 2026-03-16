---
name: clawsec-clawhub-checker
version: 0.0.1
description: ClawHub reputation checker for ClawSec suite. Queries VirusTotal Code Insight scores and additional safety signals before allowing skill installation. Use when installing skills, checking skill safety, verifying reputation scores, running a security scan, or when asked whether a skill is trustworthy or safe.
homepage: https://clawsec.prompt.security
clawdis:
  emoji: "🛡️"
  requires:
    bins: [clawhub, curl, jq]
  depends_on: [clawsec-suite]
---

# ClawSec ClawHub Checker

Enhances the ClawSec suite's guarded skill installer with ClawHub reputation checks. Adds a second layer of security by checking VirusTotal Code Insight scores and other reputation signals before allowing skill installation.

Wraps `clawhub install` to intercept skill installation requests, check VirusTotal reputation and advisory feeds, and require double confirmation for suspicious skills before proceeding.

## Installation

This skill must be installed **after** `clawsec-suite`:

```bash
# First install the suite
npx clawhub@latest install clawsec-suite

# Then install the checker
npx clawhub@latest install clawsec-clawhub-checker

# Run the setup script to integrate with clawsec-suite
node ~/.openclaw/skills/clawsec-clawhub-checker/scripts/setup_reputation_hook.mjs

# Restart OpenClaw gateway for changes to take effect
openclaw gateway restart
```

After setup, the checker adds `enhanced_guarded_install.mjs` and
`guarded_skill_install_wrapper.mjs` under `clawsec-suite/scripts` and updates the advisory
guardian hook. The original `guarded_skill_install.mjs` is not replaced.

## How It Works

### Enhanced Guarded Installer

After setup, run the wrapper (drop-in path) or the enhanced script directly:
```bash
# Recommended drop-in wrapper
node scripts/guarded_skill_install_wrapper.mjs --skill some-skill --version 1.0.0

# Or call the enhanced script directly
node scripts/enhanced_guarded_install.mjs --skill some-skill --version 1.0.0
```

The enhanced flow:
1. **Advisory check** (existing) - Checks clawsec advisory feed
2. **Reputation check** (new) - Queries ClawHub for VirusTotal scores
3. **Risk assessment** - Combines advisory + reputation signals
4. **Double confirmation** - If risky, requires explicit `--confirm-reputation`

### Reputation Signals Checked

1. **VirusTotal Code Insight** - Malicious code patterns, external dependencies (Docker usage, network calls, eval usage, crypto keys)
2. **Skill age & updates** - New skills vs established ones
3. **Author reputation** - Other skills by same author
4. **Download statistics** - Popularity signals

### Exit Codes

- `0` - Safe to install (no advisories, good reputation)
- `42` - Advisory match found (existing behavior)
- `43` - Reputation warning (new - requires `--confirm-reputation`)
- `1` - Error

## Configuration

Environment variables:
- `CLAWHUB_REPUTATION_THRESHOLD` - Minimum reputation score (0-100, default: 70)

## Integration with Existing Suite

The checker enhances but doesn't replace existing security:
- **Advisory feed still primary** - Known malicious skills blocked first
- **Reputation is secondary** - Unknown/suspicious skills get extra scrutiny
- **Double confirmation preserved** - Both layers require explicit user approval

## Example Usage

```bash
# Try to install a skill
node scripts/guarded_skill_install_wrapper.mjs --skill suspicious-skill --version 1.0.0

# Output might show:
# WARNING: Skill "suspicious-skill" has low reputation score (45/100)
# - Flagged by VirusTotal Code Insight: crypto keys, external APIs, eval usage
# - Author has no other published skills
# - Skill is less than 7 days old
# 
# To install despite reputation warning, run:
# node scripts/guarded_skill_install_wrapper.mjs --skill suspicious-skill --version 1.0.0 --confirm-reputation

# Install with confirmation
node scripts/guarded_skill_install_wrapper.mjs --skill suspicious-skill --version 1.0.0 --confirm-reputation
```

## Safety Notes

- This is a **defense-in-depth** layer, not a replacement for advisory feeds
- VirusTotal scores are **heuristic**, not definitive
- **False positives possible** - Legitimate skills with novel patterns might be flagged
- Always **review skill code** before installing with `--confirm-reputation`

## Current Limitations

- **OpenClaw internal check data** is not exposed via `clawhub` CLI or API, so this checker cannot access those warnings. Only VirusTotal Code Insight flags are caught.
- Heuristic checks (skill age, author reputation, downloads) provide similar risk assessment but miss specific operational warnings. Always check the ClawHub website for complete security assessment.

## Development

To modify the reputation checking logic, edit:
- `scripts/enhanced_guarded_install.mjs` - Main enhanced installer
- `scripts/check_clawhub_reputation.mjs` - Reputation checking logic
- `hooks/clawsec-advisory-guardian/lib/reputation.mjs` - Hook integration

## License

GNU AGPL v3.0 or later - Part of the ClawSec security suite
