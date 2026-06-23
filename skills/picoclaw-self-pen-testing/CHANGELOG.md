# Changelog

## [0.0.5] - 2026-06-23

### Changed

- Re-released skill metadata to run through the corrected normal tag publish pipeline without runtime changes.

## [0.0.4] - 2026-06-22

### Changed

- Re-released skill metadata to publish through the updated ClawHub pipeline without runtime changes.

## [0.0.3] - 2026-06-10

### Changed

- Re-released skill package with updated marketplace grouping and signed release trust artifacts for Vercel-compatible skill installation.

## [0.0.2] - 2026-05-13

### Security
- Added explicit signed release artifact verification instructions for standalone installs, including `checksums.json`, `checksums.sig`, `signing-public.pem`, archive hash verification, and `SKILL.md`/`skill.json` checksum checks.

### Changed
- Re-release skill payload metadata after excluding test-only files from release SBOMs and archives.

## [0.0.1] - 2026-04-26

### Added
- Initial extraction from `picoclaw-security-guardian` to isolate self-pen-testing checks as a standalone Picoclaw skill.
- Local read-only finding engine (`lib/self_pen_test.mjs`).
- CLI runner (`scripts/self_pen_test.mjs`) and unit test (`test/self_pen_test.test.mjs`).
