# Changelog

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
