# Changelog

All notable changes to the ClawSec ClawHub Checker will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] - 2026-04-16

### Changed

- Converted setup flow to non-mutating preflight validation; the skill no longer rewrites or copies files into installed `clawsec-suite` directories.
- Updated reputation collection to rely on `clawhub inspect --json` security metadata instead of probing `clawhub install` output.
- Updated documentation and metadata to describe standalone wrapper usage for guarded install checks.
- Added explicit documentation for optional manual advisory-hook wiring when operators want `reputationWarning` fields in advisory alert rendering.

### Security

- Removed in-place cross-skill source mutation behavior from setup.
- Removed install-output scraping behavior used only to infer VirusTotal status.
- Reputation scoring now fails closed when scanner metadata is missing, and hook-level reputation subprocess execution failures are treated as unsafe results.

## [0.0.2] - 2026-04-14

### Added

- Runtime and operator-review metadata describing the suite dependency, ClawHub lookups, and in-place integration behavior.
- Preflight disclosure in `scripts/setup_reputation_hook.mjs` before the installed suite is modified.
- Regression coverage for setup disclosure in `test/setup_reputation_hook.test.mjs`.

### Changed

- Declared `node` and `openclaw` as required runtimes alongside `clawhub` because the integration flow depends on all three.
- Documented that setup rewrites installed `clawsec-suite` files rather than operating on a detached copy.

### Security

- Made the string-based `handler.ts` rewrite and the remote ClawHub reputation-query behavior explicit so operators can review the mutation and network trust model before enabling it.
