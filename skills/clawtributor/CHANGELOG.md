# Changelog

All notable changes to Clawtributor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.4] - 2026-04-14

### Added

- Operational notes that describe the standalone install runtime and the external GitHub submission target.
- Metadata that records opt-in reporting, local state persistence, and approval-gated network egress.

### Changed

- Corrected the skill homepage in `SKILL.md` to the canonical `clawsec.prompt.security` domain.
- Declared the full standalone install/reporting toolchain (`bash`, `curl`, `jq`, `shasum`, `unzip`, `gh`) in metadata.

### Security

- Made the off-host reporting trust model explicit: every submission stays approval-gated and evidence must be sanitized before it is sent to GitHub.
