# Glossary

## Terms
| Term | Definition |
| --- | --- |
| Advisory Feed | JSON document (`feed.json`) containing security advisories for skills/platforms. |
| Affected Specifier | Skill selector such as `skill@1.2.3`, wildcard, or range used in matching logic. |
| Guarded Install | Two-step installer behavior that requires explicit confirmation when advisories match. |
| SBOM Files | Skill-declared artifact list in `skill.json` used for packaging and validation. |
| Detached Signature | Base64 signature file (`.sig`) stored separately from signed payload. |
| Checksum Manifest | File hash map (`checksums.json`) used to verify payload integrity. |

## Skill Packaging Terms
| Term | Definition |
| --- | --- |
| Skill Tag | Git tag formatted as `<skill>-v<semver>` used by release automation. |
| Release Assets | Files attached to GitHub release (zip, `skill.json`, checksums, signatures). |
| Catalog Index | `public/skills/index.json`, generated list consumed by web catalog. |
| Embedded Components | Capability bundle from one skill included in another (for example feed embedded in suite). |

## Advisory and Security Terms
| Term | Definition |
| --- | --- |
| Fail-Closed Verification | Reject payload if signature or checksum validation fails. |
| Unsigned Compatibility Mode | Temporary bypass path enabled via `CLAWSEC_ALLOW_UNSIGNED_FEED=1`. |
| Suppression Rule | Config entry matching `checkId` and `skill` to suppress known/accepted findings. |
| Key Fingerprint | SHA-256 digest of DER-encoded public key used for key consistency checks. |

## Runtime and Platform Terms
| Term | Definition |
| --- | --- |
| OpenClaw Hook | Runtime event handler (`clawsec-advisory-guardian`) that checks advisories. |
| NanoClaw IPC | Host/container task exchange for advisory refresh, signature verification, integrity checks. |
| Integrity Baseline | Stored approved hashes/snapshots for protected files. |
| Hash-Chained Audit Log | Append-only audit log where each entry depends on prior hash. |

## CI/CD Terms
| Term | Definition |
| --- | --- |
| Poll NVD CVEs Workflow | Scheduled workflow that fetches and transforms NVD CVEs into advisories. |
| Community Advisory Workflow | Issue-label-triggered workflow that publishes approved community advisories. |
| Skill Release Workflow | Tag-triggered packaging/signing/publishing pipeline for skills. |
| Deploy Pages Workflow | Workflow that builds site assets and mirrors release/advisory artifacts. |

## Source References
- types.ts
- skills/clawsec-suite/skill.json
- skills/clawsec-nanoclaw/skill.json
- skills/clawsec-suite/scripts/guarded_skill_install.mjs
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/suppression.mjs
- skills/clawsec-nanoclaw/guardian/integrity-monitor.ts
- scripts/populate-local-feed.sh
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
