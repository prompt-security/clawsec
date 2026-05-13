---
name: picoclaw-security-guardian
version: 0.0.2
description: Picoclaw security posture skill with advisory awareness, configuration drift detection, and supply-chain verification guidance.
homepage: https://clawsec.prompt.security
author: prompt-security
license: AGPL-3.0-or-later
picoclaw:
  emoji: "🦐"
  category: "security"
  requires:
    bins: [node]
  test_requires:
    bins: [bash, docker, python3, node, openssl, zip]
---

# Picoclaw Security Guardian

Detailed architecture/operator docs: `wiki/modules/picoclaw-security-guardian.md`.

## Goal

Provide Picoclaw with the same support-matrix security capabilities ClawSec tracks for mature platform modules:

| Skill name | supported platform | security feed | config drift | agent posture-review lane | chain of supply verification |
|---|---|---|---|---|---|
| picoclaw-security-guardian | Picoclaw | Yes | Yes | Separate package | Yes |

## Threat model

Picoclaw is a lightweight AI gateway that can expose chat channels, a Web UI, tool execution, MCP servers, credentials, schedulers, and embedded/router deployments. This skill focuses on the trust boundaries where those features become security-sensitive.

## Default safety posture

- Read-only by default.
- No scheduler creation in v0.0.1.
- No outbound network by default.
- Writes only explicit report/profile outputs under `$PICOCLAW_HOME/security/clawsec/` unless the operator supplies test-local temporary paths.
- Advisory checks fail closed when verification state is not verified unless the operator passes `--allow-unsigned` for a documented emergency/offline window.

## Security advisory awareness

Use `scripts/check_advisories.mjs` with a local feed/cache and verification state:

```bash
node scripts/check_advisories.mjs   --feed ~/.picoclaw/security/clawsec/feed.json   --state ~/.picoclaw/security/clawsec/feed-verification-state.json
```

The script filters advisories for `picoclaw`, `ai-gateway`, empty/all-platform advisories, or affected package entries containing `picoclaw`.

## Drift protection

Generate a deterministic profile:

```bash
node scripts/generate_profile.mjs   --output ~/.picoclaw/security/clawsec/current-profile.json
```

Compare against an approved baseline:

```bash
node scripts/check_drift.mjs   --baseline ~/.picoclaw/security/clawsec/baseline-profile.json   --current ~/.picoclaw/security/clawsec/current-profile.json   --fail-on critical
```

Critical drift includes public Web UI enablement, Web UI auth disablement, workspace restriction disablement, unsigned/insecure verification mode, verified-feed regression, and watched-file/release-artifact fingerprint changes.

## Chain-of-supply verification

Verify a Picoclaw release artifact against a checksum manifest plus detached signature. Signed manifest verification is required for a passing supply-chain verdict:

```bash
node scripts/verify_supply_chain.mjs \
  --artifact ./picoclaw \
  --checksums ./checksums.json \
  --signature ./checksums.json.sig \
  --public-key ./feed-signing-public.pem
```

Checksum-only mode is integrity-only, not provenance. Use `--allow-unsigned-checksums` only for short, documented offline triage windows; it should not satisfy production install verification.

## Operator review notes

- Treat public UI binding (`0.0.0.0`, `-public`) as a critical review item until auth and network allowlists are proven.
- Treat MCP servers as separate trust boundaries; review each server's filesystem, network, and credential access.
- Treat third-party OpenWrt/LuCI wrappers as separate supply-chain artifacts. Verify provenance before installing them on routers.
- Never leave unsigned advisory mode enabled in recurring or production checks.

## Validation

```bash
python utils/validate_skill.py skills/picoclaw-security-guardian
node skills/picoclaw-security-guardian/test/profile.test.mjs
node skills/picoclaw-security-guardian/test/drift.test.mjs
node skills/picoclaw-security-guardian/test/supply_chain.test.mjs
bash -n skills/picoclaw-security-guardian/test/picoclaw_security_guardian_sandbox_regression.sh
```

## Pre-release install regression

Before publishing v0.0.1 release artifacts, run the isolated install lane from the repo root:

```bash
skills/picoclaw-security-guardian/test/picoclaw_security_guardian_sandbox_regression.sh
```

The regression installs the skill through Picoclaw's own `find_skills` / `install_skill` path from a local ClawHub-compatible registry into an isolated Docker-hosted Picoclaw workspace with isolated `HOME`, `PICOCLAW_HOME`, and `PICOCLAW_WORKSPACE`. It verifies signed release-artifact preflight inputs, confirms Picoclaw's skill loader can list/load the installed skill, then runs the installed copy's profile, drift, advisory fail-closed, advisory filtering, and supply-chain verification paths against Picoclaw-style `config.json` and `launcher-config.json` files.

