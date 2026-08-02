# Skill Feature Matrix

This page preserves the package-by-package capability comparison for ClawSec. The English page is canonical; localized versions keep the same package order and status meaning.

The platform summary rolls up coverage across the current package family. A capability may require a separate skill rather than being included in the platform's primary entry point.

## Platform Summary

| Platform | Advisory and feed handling | Integrity and drift | Audit and posture | Install risk gate | Candidate install-artifact verification | Community reporting | Runtime traffic |
| --- | --- | --- | --- | --- | --- | --- | --- |
| OpenClaw | Signed verification and external lookups | Via optional `soul-guardian` package | Available | Advisory and reputation gates | No integrated candidate verifier; installation delegated to ClawHub | Opt-in | Specification only |
| NanoClaw | Signed, fail-closed verification | Built in | Advisory and vulnerability audit | Advisory preflight | Implemented NanoClaw integration; pinned-key candidate signatures | Opt-in | Specification only |
| Hermes | Signed, fail-closed verification | Built in | Attestation and posture verification | Advisory preflight only | No candidate-artifact verification | Opt-in | Specification only |
| Picoclaw | Consumes upstream-verified feed state | Built in | Built-in posture profiling + separate read-only review | No install gate | Executable release-artifact verification; caller-trusted key | Opt-in | Specification only |

Every released ClawSec package documents a manual signed-manifest preflight for its own standalone archive. That shared release-integrity baseline is not repeated in every row below. `claw-release` additionally guides production of those signed releases. The candidate-verification column is reserved for install artifacts beyond a package's own archive.

## Package-by-Package Coverage

<!-- skill-feature-matrix:start -->
| Skill name | Platform | Advisory and feed handling | Integrity and drift | Audit and posture | Install risk gate | Candidate install-artifact verification | Community reporting | Runtime traffic |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `claw-release` | OpenClaw | No | No | No | No | No candidate-artifact verification | No | No |
| `clawsec-clawhub-checker` | OpenClaw + `clawsec-suite` integration | Suite advisory gate | No | No | ClawHub reputation + suite advisory gate | No candidate-artifact verification | No | No |
| `clawsec-feed` | OpenClaw | Advisory data package; polling is suite/operator-managed; no feed-signature verification | No | No | No | No candidate-artifact verification | No | No |
| `clawsec-nanoclaw` | NanoClaw | Signed, fail-closed verification | File baselines + optional restore | Advisory/vulnerability audit; no active testing | Advisory preflight | Implemented NanoClaw integration; pinned-key candidate package-signature verification | No | No |
| `clawsec-scanner` | OpenClaw | External CVE lookup; no signed-feed verification | No | Dependency, SAST, and static-hook audit; no active exploitation | No | No candidate-artifact verification | No | No |
| `clawsec-suite` | OpenClaw | Signed feed + checksum-manifest verification | Via optional `soul-guardian`; not built in | No | Advisory gate + explicit confirmation | No integrated candidate verifier; generic detached-signature utility only; installation delegated to ClawHub | No | No |
| `clawtributor` | All core platforms | No | No | No | No | No | Approval-gated local drafting + manual submission | No |
| `hermes-attestation-guardian` | Hermes | Signed, fail-closed verification | Attestation, configuration, and trust-anchor drift | Attestation and posture verification | Advisory preflight only | No candidate-artifact verification | No | No |
| `hermes-traffic-guardian` | Hermes | No | Planned posture export only | No | No | No | No | Specification only; no runtime proxy |
| `nanoclaw-traffic-guardian` | NanoClaw | No | No | No | No | No | No | Specification only; no runtime proxy |
| `openclaw-audit-watchdog` | OpenClaw | No | No | Automated audit with deep mode; no active exploitation | No | No | No | No |
| `openclaw-traffic-guardian` | OpenClaw | No | No | No | No | No | No | Specification only; no runtime proxy |
| `picoclaw-security-guardian` | Picoclaw | Consumes verified feed state; cryptographic verification is upstream | Deterministic profile and configuration drift | Read-only posture checks | No | Executable Picoclaw release-artifact checksum + signed-manifest verification; caller-trusted key | No | No |
| `picoclaw-self-pen-testing` | Picoclaw | No | No | Read-only self-pen posture review; no active exploitation | No | No | No | No |
| `picoclaw-traffic-guardian` | Picoclaw | No | Planned profile export only | No | No | No | No | Specification only; no runtime proxy |
| `soul-guardian` | OpenClaw | No | Workspace-file baseline, drift detection, and optional restore | No | No | No | No | No |
<!-- skill-feature-matrix:end -->

## Status Definitions

- **Signed verification** means the package verifies signed trust material itself. **Monitoring**, **external lookup**, and **upstream-verified state** are intentionally listed separately.
- **Install risk gate** describes advisory or reputation checks before installation. It is not the same as verifying the candidate artifact's provenance.
- The shared **own-package preflight** covers each package's release archive only. The candidate-verification column records verification of other install artifacts.
- **Audit and posture** includes static, dependency, advisory, attestation, and read-only posture checks. The matrix explicitly says when no active exploitation occurs.
- **Via optional add-on** means the primary package can discover or coordinate a separate skill, but does not ship that capability itself.
- **Specification only** means the skill folder, metadata, frontmatter, and implementation contract exist, but no runtime proxy is shipped.
- **Planned posture/profile export only** describes an integration contract in a traffic-guardian specification, not a shipped drift monitor.

`clawtributor` is a cross-platform incident-reporting package. Its `No` values mean the matrix's other protection capabilities are outside its reporting scope, not that the package is inactive.

## Maintenance

The 16 package rows were recovered from the former README matrix. The capability axes were split where the legacy binary values conflated monitoring with verification, audits with active testing, add-ons with built-ins, or advisory gates with artifact provenance.

The matrix must stay aligned with the directories under `skills/`. Translation QA verifies that every localized matrix keeps the same 16 package identifiers, order, and nine-column structure.

## Source References

- `skills/*/skill.json`
- `skills/*/SKILL.md`
- [ClawSec Suite Core](modules/clawsec-suite.md)
- [ClawSec Scanner](modules/clawsec-scanner.md)
- [NanoClaw Integration](modules/nanoclaw-integration.md)
- [Hermes Attestation Guardian](modules/hermes-attestation-guardian.md)
- [Picoclaw Security Guardian](modules/picoclaw-security-guardian.md)
- [Picoclaw Self Pen Testing](modules/picoclaw-self-pen-testing.md)
- [Runtime Traffic Guardian Baseline](modules/runtime-traffic-guardian-baseline.md)
