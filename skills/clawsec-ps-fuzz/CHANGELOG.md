# Changelog

All notable changes to `clawsec-ps-fuzz` are documented here.

## [0.1.0] - 2026-08-18

### Added

- Public, harness-neutral wrapper for the reviewed `ps-fuzz` v2.1.0 release.
- Authorization-gated wheel/source provisioning, direct-model runs, isolated runtime state, and redacted aggregate reports.
- Pinned upstream manifest, hash-locked dependency set, capability snapshot, third-party notice, and offline boundary tests.
- Standalone, confirmation-gated signed-release verifier using Python's standard library and the system OpenSSL executable.

### Security

- Requires a fresh authorization confirmation for provisioning and every active run.
- Rejects unapproved endpoint URLs and excludes generic agent HTTP, MCP, tool execution, scheduling, remediation, and real vector-store operations.
- Pins the canonical ClawSec Ed25519 public-key fingerprint, verifies the signed release manifest before trusting identity or hashes, rejects unsafe ZIP layouts and incomplete SBOM payloads, and publishes only through a no-clobber atomic install.
- Documents that first-install trust must come from an out-of-band verifier source; candidate instructions, candidate keys, convenience registries, and the optional suite cannot attest the candidate package.
