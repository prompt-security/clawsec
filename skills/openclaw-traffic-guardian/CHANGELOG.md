# Changelog

## [0.0.1-beta5] - 2026-06-23

### Changed

- Re-released skill metadata to run through the corrected normal tag publish pipeline without runtime changes.

## [0.0.1-beta4] - 2026-06-22

### Changed

- Re-released skill metadata to publish through the updated ClawHub pipeline without runtime changes.

## [0.0.1-beta3] - 2026-06-10

### Security
- Added the `POLICY_REVIEW` scope for approval-sensitive social-account mutation requests, contributed by @kriptoburak.
- Defined required JSONL metadata for social-account mutation findings, including source type, mutation category, approval-marker presence, and execution context.

### Changed
- Clarified that persistent social monitor and webhook configuration changes are review findings, while read-only social research should remain covered by no-false-positive tests.
- Re-released skill package with updated marketplace grouping and signed release trust artifacts for Vercel-compatible skill installation.

## [0.0.1-beta2] - 2026-05-13

### Security
- Added explicit signed release artifact verification instructions for standalone installs, including `checksums.json`, `checksums.sig`, `signing-public.pem`, archive hash verification, and `SKILL.md`/`skill.json` checksum checks.

### Changed
- Re-release skill payload metadata after excluding test-only files from release SBOMs and archives.

## [0.0.1-beta1] - 2026-05-10

- Added baseline skill metadata, frontmatter, and implementation specification.
- Reserved folder structure for OpenClaw traffic-monitoring runtime code, hook integration, and tests.
- Beta release notes: this release is a scaffold/spec baseline and does not yet ship active runtime proxy interception.
- Beta release notes: defaults remain non-invasive (no automatic traffic mutation or enforcement enabled by default).
