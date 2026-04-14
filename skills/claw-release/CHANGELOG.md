# Changelog

All notable changes to the Claw Release skill will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.2] - 2026-04-14

### Added

- Operational notes that make the required maintainer credentials, runtime, and git/GitHub side effects explicit.

### Changed

- Declared `bash` alongside the existing `git`, `jq`, and `gh` runtime requirements in skill metadata.
- Replaced the documented destructive rollback example with a softer rollback flow that preserves release changes for review.

### Security

- Clarified that this internal skill mutates git state, pushes to remotes, and publishes GitHub Releases, so it should only be run from a trusted checkout by maintainers.
