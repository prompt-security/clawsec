# Changelog

All notable changes to the ClawSec ClawHub Checker will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
