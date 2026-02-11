# Changelog

All notable changes to the ClawSec Suite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.10] - 2026-02-11

### Security

#### Transport Security Hardening
- **TLS Version Enforcement**: Eliminated support for TLS 1.0 and TLS 1.1, enforcing minimum TLS 1.2 for all HTTPS connections
- **Certificate Validation**: Enabled strict certificate validation (`rejectUnauthorized: true`) to prevent MITM attacks
- **Domain Allowlist**: Restricted advisory feed connections to approved domains only:
  - `clawsec.prompt.security` (official ClawSec feed host)
  - `prompt.security` (parent domain)
  - `raw.githubusercontent.com` (GitHub raw content)
  - `github.com` (GitHub releases)
- **Strong Cipher Suites**: Configured modern cipher suites (AES-GCM, ChaCha20-Poly1305) for secure connections

#### Signature Verification & Checksum Validation
- **Fixed unverified file publication**: Refactored `deploy-pages.yml` workflow to download release assets to temporary directory before signature verification, ensuring unverified files never reach public directory
- **Fixed schema mismatch**: Updated `deploy-pages.yml` to generate `checksums.json` with proper `schema_version` and `algorithm` fields that match parser expectations
- **Fixed missing checksums abort**: Updated `loadRemoteFeed` to gracefully skip checksum verification when `checksums.json` is missing (e.g., GitHub raw content), while still enforcing fail-closed signature verification
- **Fixed parser strictness**: Enhanced `parseChecksumsManifest` to accept legacy manifest formats through a fallback chain:
  1. `schema_version` (new standard)
  2. `version` (skill-release.yml format)
  3. `generated_at` (old deploy-pages.yml format)
  4. `"1"` (ultimate fallback)

### Changed
- Advisory feed loader now uses `secureFetch` wrapper with TLS 1.2+ enforcement and domain validation
- Checksum verification is now graceful: feeds load successfully from sources without checksums (e.g., GitHub raw) while maintaining fail-closed signature verification
- Workflow release mirroring flow changed from `download → verify → skip` to `download to temp → verify → mirror` (fail = delete temp)

### Fixed
- Unverified skill releases no longer published to public directory on signature verification failure
- Schema mismatch between generated and expected checksums manifest fields
- Feed loading failures when checksums.json missing from upstream sources
- Parser rejection of valid legacy manifest formats

### Security Impact
- **Fail-closed security maintained**: All feed signatures still verified; invalid signatures reject feed loading
- **No backward compatibility break**: Legacy manifests continue working through fallback chain
- **Enhanced transport security**: Connections protected against downgrade attacks and MITM
- **Defense in depth**: Multiple layers of verification (domain, TLS, certificate, signature, checksum)

---

## Release Notes Template

When creating a new release, copy this template to the GitHub release notes:

```markdown
## Security Improvements

### Transport Security
✅ TLS 1.2+ enforcement (eliminated TLS 1.0, 1.1)
✅ Strict certificate validation
✅ Domain allowlist (prompt.security, github.com only)
✅ Modern cipher suites (AES-GCM, ChaCha20-Poly1305)

### Signature & Checksum Verification
✅ Unverified files never published (temp directory workflow)
✅ Proper schema fields in generated checksums.json
✅ Graceful fallback when checksums missing (GitHub raw)
✅ Legacy manifest format support (backward compatible)

### Testing
All verification tests passed:
- ✅ Unit tests: 14/14 passed
- ✅ Parser lenience: 3/3 legacy formats accepted
- ✅ Remote loading: Gracefully handles missing checksums
- ✅ Workflow security: Temp directory prevents unverified publication
```
