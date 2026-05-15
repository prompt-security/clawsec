# Changelog

## [0.1.2] - 2026-05-15

### Fixed
- Included `lib/semver.mjs` and `lib/cron.mjs` in the release SBOM so signed archives contain every runtime library imported by shipped scripts.

## [0.1.1] - 2026-05-13

### Security
- Added explicit signed release artifact verification instructions for standalone installs, including `checksums.json`, `checksums.sig`, `signing-public.pem`, archive hash verification, and `SKILL.md`/`skill.json` checksum checks.

### Changed
- Re-release skill payload metadata after excluding test-only files from release SBOMs and archives.

## [0.1.0] - 2026-04-21

- Added mandatory release verification gate guidance before install: `checksums.json`, `checksums.sig`, and pinned signing public-key fingerprint.
- Added explicit Hermes guard trust-policy note for signature-aware trust (trusted signer fingerprint allowlist) over source-name-only trust.
- Moved sandbox regression harness into the skill test surface (`test/hermes_attestation_sandbox_regression.sh`) and fixed in-skill default path resolution.
- Tightened advisory feed verification to require checksum-manifest artifacts when checksum-manifest verification is enabled (fail-closed when missing).
- Added feed regression coverage for missing local/remote checksum-manifest artifacts under strict verification mode.
- Refactored cron setup scripts to share managed-block helpers from `lib/cron.mjs`, reducing drift risk.
- Added explicit `.mjs` scan/test coverage guidance so Hermes-side scanner scope and regression harness context stay aligned with `scripts/*.mjs`, `lib/*.mjs`, and `test/*.test.mjs`.
- Clarified fresh-node first-run edge-case documentation.
- Clarified Hermes runtime metadata/frontmatter and README capability coverage for ClawHub publishing.
- Removed compatibility-report wiki page references in favor of README capability matrix as the primary compatibility surface.
- Updated skill metadata/docs to v0.1.0 and aligned README quickstart with fail-closed verification expectations.

## [0.0.1] - 2026-04-15

- Implemented deterministic Hermes attestation generator CLI (`scripts/generate_attestation.mjs`).
- Implemented fail-closed verifier CLI with schema, canonical digest, expected checksum, and optional detached signature checks (`scripts/verify_attestation.mjs`).
- Implemented meaningful baseline diff engine with stable severity mapping for risky toggle regressions, feed verification regressions, trust anchor drift, and watched file drift (`lib/diff.mjs`).
- Implemented Hermes-only cron setup helper with print-only default and managed-block apply mode (`scripts/setup_attestation_cron.mjs`).
- Added shared attestation library for canonicalization, schema validation, digest generation, and policy parsing (`lib/attestation.mjs`).
- Expanded tests for schema determinism, diff behavior, generator/verifier fail-closed behavior, and cron helper Hermes-only output.
- Updated metadata/docs to match actual implemented behavior and ClawSec release pipeline expectations.
