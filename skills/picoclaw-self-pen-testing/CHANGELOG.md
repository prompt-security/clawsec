# Changelog

## [0.0.2] - 2026-05-13

### Changed
- Re-release skill payload metadata after excluding test-only files from release SBOMs and archives.

## [0.0.1] - 2026-04-26

### Added
- Initial extraction from `picoclaw-security-guardian` to isolate self-pen-testing checks as a standalone Picoclaw skill.
- Local read-only finding engine (`lib/self_pen_test.mjs`).
- CLI runner (`scripts/self_pen_test.mjs`) and unit test (`test/self_pen_test.test.mjs`).
