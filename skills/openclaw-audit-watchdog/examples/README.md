# Security Audit Configuration Examples

## Overview

This directory contains example configuration files for the OpenClaw security audit suppression mechanism.

## Configuration File Format

The suppression configuration file must be valid JSON with the following structure:

```json
{
  "suppressions": [
    {
      "checkId": "skills.code_safety",
      "skill": "clawsec-suite",
      "reason": "First-party security tooling, reviewed 2026-02-13",
      "suppressedAt": "2026-02-13"
    }
  ]
}
```

### Required Fields

Each suppression entry must include:

- **`checkId`** (string, required): The security check identifier that flagged the finding
  - Example: `"skills.code_safety"`, `"skills.permissions"`, `"skills.network"`

- **`skill`** (string, required): The exact skill name being suppressed
  - Example: `"clawsec-suite"`, `"openclaw-audit-watchdog"`

- **`reason`** (string, required): Justification for the suppression (audit trail)
  - Example: `"First-party security tooling, reviewed 2026-02-13"`
  - Example: `"False positive - validated by security team on 2026-02-10"`

- **`suppressedAt`** (string, required): ISO 8601 date when suppression was added
  - Format: `YYYY-MM-DD`
  - Example: `"2026-02-13"`

### Configuration File Locations

The suppression config is loaded from these locations (in priority order):

1. **Custom path**: Specified via `--config` flag
2. **Environment variable**: `OPENCLAW_AUDIT_CONFIG` env var
3. **Primary default**: `~/.openclaw/security-audit.json`
4. **Fallback**: `.clawsec/allowlist.json`

If no config file is found, the audit runs normally without suppressions (backward compatible).

## Usage Examples

### Basic Setup

1. Copy the example config:
```bash
mkdir -p ~/.openclaw
cp security-audit-config.example.json ~/.openclaw/security-audit.json
```

2. Customize the suppressions for your needs

3. Run the audit:
```bash
openclaw security audit --deep
```

### Using Custom Config Path

```bash
openclaw security audit --deep --config /path/to/custom-config.json
```

### Managing False Positives

When you encounter a false positive:

1. Identify the `checkId` and `skill` name from the audit report
2. Add a suppression entry with a clear reason
3. Include the current date in ISO format
4. Re-run the audit to verify the suppression works

Example suppression entry:
```json
{
  "checkId": "skills.permissions",
  "skill": "my-internal-tool",
  "reason": "Broad permissions required for legitimate functionality, approved by security team",
  "suppressedAt": "2026-02-16"
}
```

## Important Notes

- **Transparency**: Suppressed findings remain visible in the audit report under "INFO - SUPPRESSED"
- **Matching**: Suppressions require BOTH `checkId` AND `skill` to match (prevents over-suppression)
- **Audit Trail**: Always document the reason and date for compliance
- **Validation**: The config is validated on load - malformed JSON will produce a clear error

## Example Use Case: First-Party Tools

The example config demonstrates suppressing false positives for ClawSec's own security tools:

- **clawsec-suite**: Legitimately executes CLI commands for security scanning
- **openclaw-audit-watchdog**: Legitimately accesses environment variables for auditing

These tools are flagged as "dangerous" by the security scanner but are safe first-party tools that have been reviewed.
