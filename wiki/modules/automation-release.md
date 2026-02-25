# Module: Automation and Release Pipelines

## Responsibilities
- Enforce repository quality/security checks before merge and deployment.
- Generate and maintain advisory feed updates from automated and community sources.
- Package, sign, and publish skill release artifacts from tag events.
- Build and deploy static website outputs and mirrored release/advisory assets.

## Key Files
- `.github/workflows/ci.yml`: lint/type/build/security/test matrix.
- `.github/workflows/poll-nvd-cves.yml`: daily NVD advisory ingestion.
- `.github/workflows/community-advisory.yml`: issue-label-driven advisory publishing.
- `.github/workflows/skill-release.yml`: release validation, packaging, signing, and publishing.
- `.github/workflows/deploy-pages.yml`: site build + asset mirroring to GitHub Pages.
- `.github/actions/sign-and-verify/action.yml`: shared Ed25519 sign/verify composite action.
- `scripts/prepare-to-push.sh`: local CI-like quality gate.
- `scripts/release-skill.sh`: manual helper for version bump + tag workflow.

## Public Interfaces
| Interface | Trigger | Outcome |
| --- | --- | --- |
| CI workflow | Push/PR on `main` | Fails fast on lint/type/build/test/security regressions. |
| NVD poll workflow | Cron + dispatch | Updates advisory feed with deduped, normalized CVEs. |
| Community advisory workflow | Issue labeled `advisory-approved` | Opens PR adding signed advisory records. |
| Skill release workflow | Tag `<skill>-v*` | Creates GitHub release assets and signatures. |
| Deploy pages workflow | Successful CI/release run | Publishes site + mirrored artifacts to Pages. |

## Inputs and Outputs
Inputs/outputs are summarized in the table below.

| Type | Name | Location | Description |
| --- | --- | --- | --- |
| Input | Git refs/events | GitHub Actions event payloads | Determines which workflow path runs. |
| Input | Skill metadata/SBOM | `skills/*/skill.json` | Drives release asset assembly and validation. |
| Input | NVD API data | External API responses | Source CVEs for advisory feed generation. |
| Input | Signing secrets | GitHub Secrets | Private key material for signing artifacts. |
| Output | Signed advisories | `advisories/feed.json(.sig)` + mirrored public files | Consumable signed feed channel. |
| Output | Skill release assets | `release-assets/*` and GitHub release attachments | Installable and verifiable skill artifacts. |
| Output | Website build | `dist/` deployment artifact | Public web frontend and mirrors. |

## Configuration
| Config Point | Location | Notes |
| --- | --- | --- |
| Workflow schedules | `poll-nvd-cves.yml`, `codeql.yml`, `scorecard.yml` | Daily/weekly security automation cadence. |
| Concurrency groups | Workflow `concurrency` blocks | Prevents destructive overlap in key pipelines. |
| Signing key checks | `scripts/ci/verify_signing_key_consistency.sh` | Ensures docs and canonical PEM files align. |
| Local pre-push gating | `scripts/prepare-to-push.sh` | Mirrors CI checks with optional auto-fix. |

## Example Snippets
```yaml
# skill release trigger pattern
on:
  push:
    tags:
      - '*-v[0-9]*.[0-9]*.[0-9]*'
```

```bash
# local all-in-one pre-push gate
./scripts/prepare-to-push.sh
# optional auto-fix
./scripts/prepare-to-push.sh --fix
```

## Edge Cases
- NVD API rate limiting (`403`/`429`) is handled with retry/backoff and can fail workflow on persistent errors.
- Release pipeline blocks on version mismatch between `skill.json` and `SKILL.md` frontmatter.
- Key fingerprint drift between canonical PEM files and docs hard-fails signing-related workflows.
- Deploy workflow intentionally allows unsigned legacy checksums for backward compatibility in some branches.
- Manual helper script has safety checks but includes destructive rollback logic in error branches; use carefully.

## Tests
| Validation Layer | Location |
| --- | --- |
| Workflow execution tests | CI jobs in `.github/workflows/ci.yml` |
| Skill-level unit/property tests | `skills/*/test/*.test.mjs` invoked by CI |
| Local deterministic checks | `scripts/prepare-to-push.sh` |
| Release link checks | `scripts/validate-release-links.sh` |

## Source References
- .github/workflows/ci.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/actions/sign-and-verify/action.yml
- scripts/prepare-to-push.sh
- scripts/release-skill.sh
- scripts/validate-release-links.sh
- scripts/ci/verify_signing_key_consistency.sh
