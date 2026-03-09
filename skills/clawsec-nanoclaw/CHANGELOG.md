# Changelog

All notable changes to the ClawSec NanoClaw compatibility skill will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] - 2026-03-09

### Security

- Removed runtime public-key override from host-side package signature verification; verification now always uses the pinned ClawSec key.
- Removed unsigned-package override path in host-side verification flow.
- Added strict package/signature path policy for signature verification (`/tmp`, `/var/tmp`, `/workspace/ipc`, `/workspace/project/data`, `/workspace/project/tmp`, `/workspace/project/downloads`) with absolute-path, extension, symlink, and realpath boundary checks.
- Added policy-bound path enforcement for integrity approvals: approvals now require normalized paths that are explicitly present in non-ignored integrity policy targets.

### Changed

- Updated MCP signature verification tool docs and behavior to align with bounded path policy and pinned-key-only verification.
- Added regression tests for signature-verification and integrity-approval hardening invariants.

## [0.0.2] - 2026-02-28

### Added

- Exploitability-aware advisory output in NanoClaw MCP tools (`exploitability_score`, `exploitability_rationale`).
- Exploitability filtering (`exploitabilityScore`) for `clawsec_list_advisories`.

### Changed

- Updated NanoClaw advisory sorting and pre-install safety recommendation logic to prioritize exploitability context.
- Updated NanoClaw integration docs to match current host/container integration points (`src/ipc.ts`, `src/index.ts`) and current cache schema.
- Removed duplicate exploitability normalization logic from MCP advisory tools and now reuse `normalizeExploitabilityScore` from `lib/risk.ts`.
- Reused `matchesAffectedSpecifier` from `lib/advisories.ts` in MCP advisory tools to keep skill/version matching logic centralized and consistent.
