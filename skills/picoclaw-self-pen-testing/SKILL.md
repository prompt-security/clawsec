---
name: picoclaw-self-pen-testing
version: 0.0.2
description: Picoclaw-only local posture-review skill focused on read-only findings and safe operator remediation guidance.
homepage: https://clawsec.prompt.security
author: prompt-security
license: AGPL-3.0-or-later
picoclaw:
  emoji: "🦐"
  category: "security"
  requires:
    bins: [node]
  test_requires:
    bins: [node]
---

# Picoclaw Posture Review (separate package)

Purpose: keep Picoclaw posture-review checks isolated from the broader guardian package so moderation-sensitive checks can be versioned/published independently.

## Scope

This skill only performs local, read-only posture-review analysis against an existing Picoclaw posture profile.

It flags:
- public Web UI exposure
- disabled UI auth
- unrestricted workspace/tooling
- unsigned verification mode
- MCP trust-boundary review needs
- scheduler persistence review
- plaintext secret markers
- multi-channel auth review

## Usage

```bash
node scripts/self_pen_test.mjs --profile ~/.picoclaw/security/clawsec/current-profile.json
```

## Validation

```bash
python utils/validate_skill.py skills/picoclaw-self-pen-testing
node skills/picoclaw-self-pen-testing/test/self_pen_test.test.mjs
```
