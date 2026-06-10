# picoclaw-security-guardian

Picoclaw security posture skill for ClawSec.

Status: implemented (v0.0.1), Picoclaw-specific.

Detailed architecture/operator docs: `wiki/modules/picoclaw-security-guardian.md`.

## Vercel Skills Installation

Install with the Vercel Skills CLI for this harness:

```bash
npx skills add prompt-security/clawsec --skill picoclaw-security-guardian -a openclaw -y
```

## Support matrix mapping

| Skill name | supported platform | security feed | config drift | agent posture-review lane | chain of supply verification |
|---|---|---|---|---|---|
| picoclaw-security-guardian | Picoclaw | Yes | Yes | Separate package | Yes |

## Capabilities

- Picoclaw-aware advisory filtering from a verified ClawSec feed/cache.
- Deterministic local posture profile generation for configs, gateway exposure, tools, MCP, credentials/security files, and release artifacts.
- Baseline drift comparison with critical/high/medium/low/info findings.
- Supply-chain verification for release artifacts using SHA-256 manifests plus required Ed25519 detached signatures for passing provenance verdicts.

## Quickstart

```bash
node scripts/generate_profile.mjs --output ~/.picoclaw/security/clawsec/current-profile.json
node scripts/check_drift.mjs --baseline ~/.picoclaw/security/clawsec/baseline-profile.json --current ~/.picoclaw/security/clawsec/current-profile.json
node scripts/verify_supply_chain.mjs --artifact ./picoclaw --checksums ./checksums.json --signature ./checksums.json.sig --public-key ./feed-signing-public.pem
node scripts/check_advisories.mjs --feed ~/.picoclaw/security/clawsec/feed.json --state ~/.picoclaw/security/clawsec/feed-verification-state.json
```

All scripts are read-only except profile/report outputs explicitly requested by `--output`.

## Tests

```bash
node test/profile.test.mjs
node test/drift.test.mjs
node test/supply_chain.test.mjs
bash -n test/picoclaw_security_guardian_sandbox_regression.sh
```

## Pre-release install regression

Run this before cutting v0.0.1 release artifacts:

```bash
test/picoclaw_security_guardian_sandbox_regression.sh
```

It uses Docker to publish the skill through a local ClawHub-compatible registry, installs it with Picoclaw's own `find_skills` / `install_skill` flow into an isolated Picoclaw workspace, confirms Picoclaw's skill loader can list/load it, then verifies the installed copy's profile, drift, advisory, and supply-chain paths.
