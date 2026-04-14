# Changelog

All notable changes to soul-guardian will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] - 2026-04-14

### Added

- Operational notes that describe restore behavior, state-directory sensitivity, and optional scheduling integrations.
- Metadata for persistence, network posture, and operator review expectations.

### Changed

- Declared optional integration runtimes used by the documented workflows (`clawdbot`, `launchctl`, `bash`) alongside the required `python3` runtime.

### Security

- Made it explicit that restore mode can overwrite protected files back to baseline and that guardian state directories may contain sensitive snapshots, diffs, and quarantined content.
