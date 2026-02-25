# Security

## Security Model Overview
- ClawSec secures both content distribution (signed artifacts) and runtime behavior (advisory gating, integrity monitoring).
- Trust anchors are pinned public keys committed in repo and verified against workflow-generated outputs.
- Runtime consumers default to verification-first behavior with explicit migration bypass flags.

## Cryptographic Controls
| Control | Mechanism | Location |
| --- | --- | --- |
| Feed authenticity | Ed25519 detached signatures (`feed.json.sig`) | Advisory workflows + consumer verification libs. |
| Artifact integrity | SHA-256 checksum manifests (`checksums.json`) | Skill release and pages deploy workflows. |
| Key consistency | Fingerprint comparison across docs + canonical PEMs | `scripts/ci/verify_signing_key_consistency.sh`. |
| Signature verification action | Composite sign+verify action in CI | `.github/actions/sign-and-verify/action.yml`. |

## Runtime Enforcement Controls
| Control | Component | Effect |
| --- | --- | --- |
| Advisory hook gating | `clawsec-advisory-guardian` | Alerts and cautious guidance based on matched advisories. |
| Double-confirmation installer | `guarded_skill_install.mjs` | Exit `42` until explicit confirmation for matched advisories. |
| Reputation extension | `clawsec-clawhub-checker` | Additional risk scoring before install. |
| NanoClaw signature gate | `skill-signature-handler.ts` + MCP tool | Blocks tampered/unsigned package installs by policy. |
| Integrity baseline monitor | `soul-guardian` + NanoClaw integrity monitor | Drift detection, quarantine, restore, auditable history. |

## Supply-Chain and CI Controls
- CI runs Trivy, npm audit, gitleaks, CodeQL, and Scorecard workflows.
- Release workflows validate SBOM file existence before packaging.
- Deploy workflow verifies generated signing key fingerprint against canonical key material.
- Release docs include manual verification commands for downstream consumers.

## Incident and Rotation Playbooks
- `docs/SECURITY-SIGNING.md` defines key generation, custody, rotation, and incident phases.
- `docs/MIGRATION-SIGNED-FEED.md` defines staged enforcement and rollback levels.
- Rollback paths prioritize preserving signed publishing where possible and time-boxing any bypass.

## Example Snippets
```bash
# verify canonical public key fingerprint
openssl pkey -pubin -in clawsec-signing-public.pem -outform DER | shasum -a 256
```

```bash
# run repo key-consistency guardrail used in CI
./scripts/ci/verify_signing_key_consistency.sh
```

## Known Security Tradeoffs
- Unsigned compatibility mode can reduce assurance and should be disabled once migration completes.
- Some deploy paths tolerate unsigned legacy checksum assets for backward compatibility.
- Reputation checks rely on external tooling output and may include heuristic false positives/negatives.
- Local scripts inherit environment trust; compromised local shells can still subvert operator workflows.

## Hardening Opportunities
- Remove unsigned compatibility flags after migration stabilization.
- Expand deterministic checksum/signature verification for all mirrored release files.
- Add explicit tests for workflow-level signature failure scenarios.
- Increase runtime telemetry for advisory fetch/verification failures to simplify incident triage.

## Source References
- SECURITY.md
- docs/SECURITY-SIGNING.md
- docs/MIGRATION-SIGNED-FEED.md
- scripts/ci/verify_signing_key_consistency.sh
- .github/actions/sign-and-verify/action.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs
- skills/clawsec-suite/scripts/guarded_skill_install.mjs
- skills/clawsec-clawhub-checker/scripts/enhanced_guarded_install.mjs
- skills/soul-guardian/scripts/soul_guardian.py
- skills/clawsec-nanoclaw/host-services/skill-signature-handler.ts
- skills/clawsec-nanoclaw/guardian/integrity-monitor.ts
