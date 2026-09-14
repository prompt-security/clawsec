---
name: clawsec-analyst
description: AI-powered security analyst that provides automated advisory triage, pre-installation risk assessment, and natural language security policy parsing using Claude API.
metadata: { "openclaw": { "events": ["agent:bootstrap", "command:new"] } }
---

# ClawSec Analyst Hook

This hook integrates Claude API to provide intelligent, automated security analysis for OpenClaw agents on:

- `agent:bootstrap`
- `command:new`

When triggered, it analyzes the ClawSec advisory feed and provides AI-generated security insights, risk assessments, and actionable remediation guidance.

## Safety Contract

- The hook does not delete or modify skills without explicit user approval.
- It only reports security findings and recommendations.
- All analysis results are advisory—users make final decisions on remediation actions.
- Alerts are deduplicated using `~/.openclaw/clawsec-analyst-state.json`.

## Required Environment Variables

- `ANTHROPIC_API_KEY`: **REQUIRED** - Anthropic API key for Claude access. Obtain from https://console.anthropic.com/.

## Optional Environment Variables

- `CLAWSEC_FEED_URL`: override remote advisory feed URL.
- `CLAWSEC_FEED_SIG_URL`: override detached remote feed signature URL (default `${CLAWSEC_FEED_URL}.sig`).
- `CLAWSEC_FEED_CHECKSUMS_URL`: override remote checksum manifest URL (default sibling `checksums.json`).
- `CLAWSEC_FEED_CHECKSUMS_SIG_URL`: override detached remote checksum manifest signature URL.
- `CLAWSEC_FEED_PUBLIC_KEY`: path to pinned feed-signing public key PEM.
- `CLAWSEC_LOCAL_FEED`: override local fallback feed file.
- `CLAWSEC_LOCAL_FEED_SIG`: override local detached feed signature path.
- `CLAWSEC_LOCAL_FEED_CHECKSUMS`: override local checksum manifest path.
- `CLAWSEC_LOCAL_FEED_CHECKSUMS_SIG`: override local checksum manifest signature path.
- `CLAWSEC_VERIFY_CHECKSUM_MANIFEST`: set to `0` only for emergency troubleshooting (default verifies checksums).
- `CLAWSEC_ALLOW_UNSIGNED_FEED`: set to `1` only for temporary migration compatibility; bypasses signature/checksum verification.
- `CLAWSEC_ANALYST_STATE_FILE`: override state file path (default `~/.openclaw/clawsec-analyst-state.json`).
- `CLAWSEC_ANALYST_CACHE_DIR`: override analysis cache directory (default `~/.openclaw/clawsec-analyst-cache`).
- `CLAWSEC_HOOK_INTERVAL_SECONDS`: minimum interval between hook scans (default `300`).

## Analysis Features

### Automated Advisory Triage

- Assesses actual risk level (may differ from reported CVSS score)
- Identifies affected components in the user's environment
- Recommends prioritized remediation steps
- Provides contextual threat intelligence

### Pre-Installation Risk Assessment

- Analyzes skill metadata and SBOM before installation
- Identifies potential security risks (filesystem access, network calls)
- Cross-references dependencies against known vulnerabilities
- Generates risk score (0-100) with detailed explanation

### Natural Language Policy Parsing

- Translates plain English security policies into structured, enforceable rules
- Returns confidence score (0.0-1.0) for policy clarity
- Rejects ambiguous policies (threshold: 0.7)

## Error Handling

- **Missing API key:** Fails fast with clear error message directing user to set `ANTHROPIC_API_KEY`.
- **Rate limits:** Implements exponential backoff (1s → 2s → 4s) with max 3 retries.
- **Network failures:** Falls back to 7-day cache if Claude API is unavailable.
- **Signature verification failure:** Fails closed if advisory feed signature is invalid (unless emergency bypass enabled).

## Offline Resilience

Analysis results are cached to `~/.openclaw/clawsec-analyst-cache/` with a 7-day TTL. If Claude API is unavailable, the hook will use cached results and warn users about potential staleness.
