---
name: clawsec-analyst
version: 0.1.0
description: AI-powered security analyst using Claude API for automated advisory triage, pre-installation risk assessment, and natural language security policy parsing
homepage: https://clawsec.prompt.security
clawdis:
  emoji: "🔍"
  requires:
    bins: [node]
---

# ClawSec Analyst

AI-powered security analyst that integrates Claude API to provide intelligent, automated security analysis for the ClawSec ecosystem. This skill automates security advisory triage, performs risk assessment for skill installations, enables natural language security policy definitions, and reduces manual security review overhead for both OpenClaw and NanoClaw platforms.

## Core Capabilities

### 1. Automated Security Advisory Triage

Analyzes security advisories from the ClawSec advisory feed using Claude API to:
- Assess actual risk level (may differ from reported CVSS score)
- Identify affected components in your environment
- Recommend prioritized remediation steps
- Provide contextual threat intelligence

**Output:** JSON response with `priority` (HIGH/MEDIUM/LOW), `rationale`, `affected_components`, and `recommended_actions`.

### 2. Pre-Installation Risk Assessment

Before installing a new skill, analyzes its metadata and SBOM to:
- Identify potential security risks (filesystem access, network calls, sensitive data handling)
- Cross-reference skill dependencies against known vulnerabilities in advisory feed
- Generate risk score (0-100) with detailed explanation
- Flag high-risk behaviors for manual review

**Output:** Risk score (0-100), detailed risk report, and installation recommendation.

### 3. Natural Language Security Policy Definition

Allows users to define security policies in plain English:
- "Block any skill that accesses ~/.ssh"
- "Require manual approval for skills with HIGH severity advisories"
- "Alert when skills make network calls to non-whitelisted domains"

**Output:** Structured policy object with `type`, `condition`, `action`, and `confidence_score` (0.0-1.0).

### 4. Integration with ClawSec Advisory Feed

- Reads `advisories/feed.json` from local filesystem or remote URL
- Ed25519 signature verification for feed authenticity
- Fail-closed security model (rejects unsigned feeds in production)
- Offline resilience via 7-day result cache

## Installation

### Prerequisites

- Node.js 20+ (`node --version`)
- Valid Anthropic API key (obtain from https://console.anthropic.com/)

### Option A: Via clawhub (recommended)

```bash
npx clawhub@latest install clawsec-analyst
```

### Option B: Manual installation

```bash
set -euo pipefail

VERSION="${SKILL_VERSION:?Set SKILL_VERSION (e.g. 0.1.0)}"
INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.openclaw/skills}"
DEST="$INSTALL_ROOT/clawsec-analyst"
BASE="https://github.com/prompt-security/clawsec/releases/download/clawsec-analyst-v${VERSION}"

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Download release archive + signed checksums manifest
ZIP_NAME="clawsec-analyst-v${VERSION}.zip"
curl -fsSL "$BASE/$ZIP_NAME" -o "$TEMP_DIR/$ZIP_NAME"
curl -fsSL "$BASE/checksums.json" -o "$TEMP_DIR/checksums.json"
curl -fsSL "$BASE/checksums.sig" -o "$TEMP_DIR/checksums.sig"

# Verify checksums manifest signature (see clawsec-suite for full verification pattern)
# ... (signature verification logic omitted for brevity)

# Install verified archive
mkdir -p "$INSTALL_ROOT"
rm -rf "$DEST"
unzip -q "$TEMP_DIR/$ZIP_NAME" -d "$INSTALL_ROOT"

chmod 600 "$DEST/skill.json"
find "$DEST" -type f ! -name "skill.json" -exec chmod 644 {} \;

echo "Installed clawsec-analyst v${VERSION} to: $DEST"
```

## Configuration

### Required Environment Variables

```bash
# REQUIRED: Anthropic API key for Claude access
export ANTHROPIC_API_KEY=your-key-here  # Get from: console.anthropic.com
```

### Optional Environment Variables

```bash
# Emergency bypass for signature verification (dev/testing only)
export CLAWSEC_ALLOW_UNSIGNED_FEED=1

# Override default 300s rate limit for hook execution
export CLAWSEC_HOOK_INTERVAL_SECONDS=600

# Custom advisory feed URL (defaults to https://clawsec.prompt.security/advisories/feed.json)
export CLAWSEC_FEED_URL="https://custom.domain/feed.json"
```

## Usage

### 1. Analyze Security Advisory

Perform AI-powered triage on a specific advisory:

```bash
ANALYST_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-analyst"
node "$ANALYST_DIR/handler.ts" analyze-advisory --id CVE-2024-12345
```

**Output:**
```json
{
  "advisory_id": "CVE-2024-12345",
  "priority": "HIGH",
  "rationale": "This XSS vulnerability affects a core dependency used in skill processing...",
  "affected_components": ["skill-loader", "web-ui-renderer"],
  "recommended_actions": [
    "Update affected skills immediately",
    "Review skill isolation configurations",
    "Enable CSP headers if not already enabled"
  ],
  "ai_confidence": 0.92
}
```

### 2. Assess Skill Installation Risk

Evaluate security risks before installing a skill:

```bash
ANALYST_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-analyst"
node "$ANALYST_DIR/handler.ts" assess-skill-risk --skill-path /path/to/skill.json
```

**Output:**
```json
{
  "skill_name": "helper-plus",
  "risk_score": 45,
  "risk_level": "MEDIUM",
  "concerns": [
    "Accesses filesystem outside skill directory",
    "Makes network calls to 3rd-party APIs",
    "Dependency 'old-package@1.0.0' has known CVE (CVSS 6.5)"
  ],
  "recommendation": "REVIEW_REQUIRED",
  "mitigation_steps": [
    "Review filesystem access patterns in handler.ts",
    "Verify network call destinations are trusted",
    "Update old-package to 1.2.3+"
  ]
}
```

### 3. Define Security Policy

Create enforceable security policies from natural language:

```bash
ANALYST_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-analyst"
node "$ANALYST_DIR/handler.ts" define-policy --statement "Block any skill that writes to home directory outside .openclaw folder"
```

**Output:**
```json
{
  "policy": {
    "type": "filesystem_access",
    "condition": {
      "operation": "write",
      "path_pattern": "^$HOME/(?!.openclaw/).*",
      "scope": "skill_execution"
    },
    "action": "BLOCK",
    "severity": "HIGH"
  },
  "confidence": 0.88,
  "ambiguities": [],
  "enforceable": true
}
```

**Note:** If confidence < 0.7, the skill will prompt for clarification before creating the policy.

## OpenClaw Hook Integration

ClawSec Analyst can run automatically as an OpenClaw hook on specific events.

### Enable Hook

```bash
ANALYST_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-analyst"
# Hook setup script (to be implemented in future version)
# node "$ANALYST_DIR/scripts/setup_analyst_hook.mjs"
```

### Hook Behavior

- **Event triggers:** `agent:bootstrap`, `command:new`
- **Rate limit:** 300 seconds (configurable via `CLAWSEC_HOOK_INTERVAL_SECONDS`)
- **Actions:**
  - Scan advisory feed for new HIGH/CRITICAL advisories
  - Cross-reference against installed skills
  - Notify user of new security risks
  - Provide AI-generated remediation guidance

### Restart OpenClaw Gateway

After enabling the hook:

```bash
# Restart your OpenClaw gateway to load the new hook
# (specific restart command depends on your OpenClaw setup)
```

## API Integration Details

### Claude API Model

- **Model:** `claude-sonnet-4-5-20250929`
- **Max tokens:** 2048 (configurable per use case)
- **Retry strategy:** Exponential backoff (1s → 2s → 4s)
- **Max retries:** 3 attempts
- **Rate limit handling:** Automatic retry on 429 errors

### Advisory Feed Schema

Consumes ClawSec advisory feed format:

```json
{
  "advisories": [
    {
      "id": "CVE-2024-12345",
      "severity": "HIGH",
      "type": "vulnerability",
      "nvd_category_id": "CWE-79",
      "affected": ["package@1.0.0", "cpe:2.3:a:vendor:product:1.0.0"],
      "action": "update",
      "cvss_score": 7.5,
      "platforms": ["npm", "pip"],
      "description": "XSS vulnerability...",
      "references": ["https://..."]
    }
  ],
  "metadata": {
    "last_updated": "2026-02-27T00:00:00Z",
    "feed_version": "1.0"
  }
}
```

### Caching Behavior

- **Cache location:** `~/.openclaw/clawsec-analyst-cache/`
- **Cache TTL:** 7 days
- **Cache invalidation:** Automatic on stale entries
- **Offline mode:** Falls back to cache if Claude API unavailable

### State Persistence

- **State file:** `~/.openclaw/clawsec-analyst-state.json`
- **Purpose:** Rate limiting, deduplication, last-seen advisory tracking
- **Format:** JSON with `last_execution`, `analyzed_advisories`, `policy_version`

## Error Handling

### Missing API Key

```bash
$ node handler.ts analyze-advisory --id CVE-2024-12345
ERROR: ANTHROPIC_API_KEY environment variable not set
Please obtain an API key from https://console.anthropic.com/ and set:
  export ANTHROPIC_API_KEY=your-key-here  # Get from: console.anthropic.com
```

### Claude API Rate Limit

```bash
Claude API rate limit hit (attempt 1/3), retrying in 1000ms...
Claude API rate limit hit (attempt 2/3), retrying in 2000ms...
Successfully completed analysis after 2 retries
```

### Signature Verification Failure

```bash
ERROR: Advisory feed signature verification failed
Feed: /Users/user/.openclaw/skills/clawsec-suite/advisories/feed.json
Signature: /Users/user/.openclaw/skills/clawsec-suite/advisories/feed.json.sig

The feed may have been tampered with. Aborting analysis.

Emergency bypass (dev only): export CLAWSEC_ALLOW_UNSIGNED_FEED=1
```

### Network Failure with Cache Fallback

```bash
WARNING: Claude API unavailable (network error), checking cache...
Using cached analysis for CVE-2024-12345 (cached 2 days ago)
Note: Analysis may be outdated. Retry when network is restored.
```

## Security Considerations

### Fail-Closed Design

- **No API key:** Fails immediately with clear error message
- **Unsigned feed:** Rejects feed in production (unless emergency bypass enabled)
- **Low confidence policy:** Rejects ambiguous policies (threshold: 0.7)
- **Signature verification:** Uses Ed25519 with pinned public key

### Data Privacy

- **Advisory data sent to Claude API:** Only advisory metadata (ID, severity, description, CVE references)
- **NOT sent to Claude API:** User-specific paths, installed skill lists (unless explicitly part of risk assessment), API keys, credentials
- **Cache security:** Cache files stored with 600 permissions, contain only analysis results

### Emergency Bypass

`CLAWSEC_ALLOW_UNSIGNED_FEED=1` is provided for:
- Development and testing
- Emergency feed updates when signature service is down
- Migration periods during key rotation

**WARNING:** Do NOT use in production environments. This bypass defeats the entire signature verification security model.

## Troubleshooting

### Issue: "Module not found: @anthropic-ai/sdk"

**Cause:** Dependencies not installed.

**Solution:**
```bash
cd "${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-analyst"
npm install
```

### Issue: "Advisory feed not found"

**Cause:** ClawSec advisory feed not accessible.

**Solution:**
1. Check if `clawsec-suite` is installed (contains embedded feed)
2. Verify network access to `https://clawsec.prompt.security/advisories/feed.json`
3. Check custom `CLAWSEC_FEED_URL` if set

### Issue: "Policy confidence too low (0.45)"

**Cause:** Natural language policy statement is ambiguous.

**Solution:**
Rephrase the policy with more specific terms:
- ❌ Bad: "Block risky skills"
- ✅ Good: "Block skills that access ~/.ssh or make network calls to non-whitelisted domains"

### Issue: "Rate limit exceeded after 3 retries"

**Cause:** Anthropic API rate limit hit, retries exhausted.

**Solution:**
1. Wait 60 seconds before retrying
2. Check your API tier at https://console.anthropic.com/
3. Use cache fallback if available (will warn about staleness)

## Development

### Running Tests

```bash
cd skills/clawsec-analyst

# Unit tests
node test/claude-client.test.mjs
node test/feed-reader.test.mjs
node test/analyzer.test.mjs
node test/risk-assessor.test.mjs
node test/policy-engine.test.mjs

# Integration tests
node test/integration-triage.test.mjs
node test/integration-risk.test.mjs
node test/integration-policy.test.mjs
```

### Linting

```bash
# TypeScript compilation check
npx tsc --noEmit

# ESLint
npx eslint . --ext .ts --max-warnings 0
```

### Skill Structure Validation

```bash
python utils/validate_skill.py skills/clawsec-analyst
```

## Compatibility

- **Platforms:** Linux, macOS (Darwin)
- **Node.js:** 20.0.0+
- **Compatible with:** OpenClaw, NanoClaw, MoltBot, ClawdBot
- **Advisory feed version:** 1.0
- **Claude API model:** claude-sonnet-4-5-20250929

## License

AGPL-3.0-or-later

## Support

- **Homepage:** https://clawsec.prompt.security
- **Issues:** https://github.com/prompt-security/clawsec/issues
- **Documentation:** https://clawsec.prompt.security/docs/analyst
- **Security contact:** security@prompt.security
