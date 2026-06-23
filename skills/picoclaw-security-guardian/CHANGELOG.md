# Changelog

## [0.0.6] - 2026-06-23

### Changed

- Re-released skill metadata to run through the corrected normal tag publish pipeline without runtime changes.

## [0.0.5] - 2026-06-22

### Changed

- Re-released skill metadata to publish through the updated ClawHub pipeline without runtime changes.

## [0.0.4] - 2026-06-10

### Changed

- Re-released skill package with updated marketplace grouping and signed release trust artifacts for Vercel-compatible skill installation.

## [0.0.3] - 2026-05-24

### Changed
- Documented that Picoclaw advisory checks consume the consolidated signed advisory feed, including NVD CVEs, approved community advisories, and provisional GHSA-without-CVE records.

## [0.0.2] - 2026-05-13

### Security
- Added explicit signed release artifact verification instructions for standalone installs, including `checksums.json`, `checksums.sig`, `signing-public.pem`, archive hash verification, and `SKILL.md`/`skill.json` checksum checks.

### Changed
- Re-release skill payload metadata after excluding test-only files from release SBOMs and archives.

## [0.0.1] - 2026-04-26

### Added
- Initial Picoclaw-specific ClawSec skill package for advisory awareness, deterministic profile generation, drift detection, and supply-chain verification.
- Picoclaw-native Docker pre-release install regression harness using `find_skills` / `install_skill` and skill-loader validation.

### Changed
- Split optional posture-review checks into separate `picoclaw-self-pen-testing` package so this package remains the core public guardian lane.
- Updated metadata/docs/regression expectations to keep this package focused on advisory, drift, and supply-chain checks.
