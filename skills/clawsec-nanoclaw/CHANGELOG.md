# Changelog

All notable changes to the ClawSec NanoClaw compatibility skill will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] - 2026-03-01

### Changed

- Removed duplicate exploitability normalization logic from MCP advisory tools and now reuse `normalizeExploitabilityScore` from `lib/risk.ts`.
- Kept advisory risk classification logic centralized so host-service and MCP tool safety outputs stay aligned.

## [0.0.2] - 2026-02-28

### Added

- Exploitability-aware advisory output in NanoClaw MCP tools (`exploitability_score`, `exploitability_rationale`).
- Exploitability filtering (`exploitabilityScore`) for `clawsec_list_advisories`.

### Changed

- Updated NanoClaw advisory sorting and pre-install safety recommendation logic to prioritize exploitability context.
- Updated NanoClaw integration docs to match current host/container integration points (`src/ipc.ts`, `src/index.ts`) and current cache schema.
