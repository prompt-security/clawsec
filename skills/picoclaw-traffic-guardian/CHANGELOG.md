# Changelog

## [0.0.1-beta2] - 2026-05-13

### Security
- Added explicit signed release artifact verification instructions for standalone installs, including `checksums.json`, `checksums.sig`, `signing-public.pem`, archive hash verification, and `SKILL.md`/`skill.json` checksum checks.

### Changed
- Re-release skill payload metadata after excluding test-only files from release SBOMs and archives.

## [0.0.1-beta1] - 2026-05-10

- Added baseline skill metadata, frontmatter, and implementation specification.
- Reserved folder structure for Picoclaw traffic-monitoring runtime code, profile export, and tests.
- Beta release notes: this release is a scaffold/spec baseline and does not yet ship active runtime proxy interception.
- Beta release notes: defaults remain non-invasive (no automatic traffic mutation or enforcement enabled by default).
