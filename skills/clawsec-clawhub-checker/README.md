# ClawSec ClawHub Checker

A ClawSec suite skill that enhances the guarded skill installer with ClawHub reputation checks and VirusTotal Code Insight integration.

## Purpose

Adds a second layer of security to skill installation by:
1. Checking ClawHub's VirusTotal Code Insight reputation scores
2. Analyzing skill age, author reputation, and download statistics
3. Requiring double confirmation for suspicious skills
4. Integrating with existing ClawSec advisory checks

## Architecture

```
clawsec-suite (base)
└── clawsec-clawhub-checker (enhancement)
    ├── enhanced_guarded_install.mjs - Main enhanced installer
    ├── check_clawhub_reputation.mjs - Reputation checking logic
    ├── setup_reputation_hook.mjs - Integration script
    └── hooks/ - Enhanced advisory guardian hook
```

## Installation

```bash
# First install the base suite
npx clawhub install clawsec-suite

# Then install the checker
npx clawhub install clawsec-clawhub-checker

# Run setup to integrate with existing suite
node scripts/setup_reputation_hook.mjs

# Restart OpenClaw gateway
openclaw gateway restart
```

## Usage

### Enhanced Guarded Installer

```bash
# Basic usage (includes reputation checks)
node scripts/enhanced_guarded_install.mjs --skill some-skill --version 1.0.0

# With reputation confirmation override
node scripts/enhanced_guarded_install.mjs --skill suspicious-skill --version 1.0.0 --confirm-reputation

# Adjust reputation threshold (default: 70)
node scripts/enhanced_guarded_install.mjs --skill some-skill --reputation-threshold 80
```

### Reputation Check Only

```bash
# Check reputation without installation
node scripts/check_clawhub_reputation.mjs some-skill 1.0.0 70
```

## Exit Codes

- `0` - Safe to install
- `42` - Advisory match found (requires `--confirm-advisory`)
- `43` - Reputation warning (requires `--confirm-reputation`) - **NEW**
- `1` - Error

## Reputation Signals Checked

1. **VirusTotal Code Insight** - Malicious code patterns
2. **Skill Age** - New skills (<7 days) are riskier
3. **Author Reputation** - Number of published skills
4. **Update Frequency** - Stale skills (>90 days)
5. **Download Statistics** - Low download counts
6. **Version Existence** - Specified version availability

## Configuration

Environment variables:
- `CLAWHUB_REPUTATION_THRESHOLD` - Minimum score (0-100, default: 70)
- `CLAWHUB_ALLOW_SUSPICIOUS` - Skip reputation checks (not recommended)

## Integration Points

1. **Enhanced `guarded_skill_install.mjs`** - Wraps original with reputation checks
2. **Updated advisory guardian hook** - Adds reputation warnings to alerts
3. **Catalog entry in clawsec-suite** - Listed as available enhancement

## Development

### Files

- `SKILL.md` - Main documentation
- `skill.json` - Skill metadata and SBOM
- `scripts/enhanced_guarded_install.mjs` - Enhanced installer
- `scripts/check_clawhub_reputation.mjs` - Reputation logic
- `scripts/setup_reputation_hook.mjs` - Integration script
- `hooks/clawsec-advisory-guardian/lib/reputation.mjs` - Hook module

### Testing

```bash
# Test reputation check
node scripts/check_clawhub_reputation.mjs clawsec-suite

# Test enhanced installer (dry run)
node scripts/enhanced_guarded_install.mjs --skill test-skill --dry-run

# Test setup
node scripts/setup_reputation_hook.mjs
```

## Security Considerations

- Reputation checks are **heuristic**, not definitive
- **False positives** possible with legitimate novel skills
- Always **review skill code** before overriding warnings
- This is **defense-in-depth**, not replacement for advisory feeds

## License

MIT - Part of the ClawSec security suite
