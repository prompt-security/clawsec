# Changelog

All notable changes to `clawsec-ps-fuzz` are documented here.

## [0.1.0] - 2026-08-18

### Added

- Public, harness-neutral wrapper for the reviewed `ps-fuzz` v2.1.0 release.
- Authorization-gated wheel/source provisioning, direct-model runs, isolated runtime state, and redacted aggregate reports.
- Pinned upstream manifest, hash-locked dependency set, capability snapshot, third-party notice, and offline boundary tests.

### Security

- Requires a fresh authorization confirmation for provisioning and every active run.
- Rejects unapproved endpoint URLs and excludes generic agent HTTP, MCP, tool execution, scheduling, remediation, and real vector-store operations.
