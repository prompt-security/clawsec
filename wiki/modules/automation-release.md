# Module: Automation and Release Pipelines

## Responsibilities
- Enforce repository quality/security checks before merge and deployment.
- Generate and maintain advisory feed updates from automated and community sources.
- Package, sign, and publish skill release artifacts from tag events.
- Build and deploy static website outputs and mirrored release/advisory assets.

## CI/CD Summary (migrated from README)

### Automated workflows
The canonical CI/CD workflow matrix (triggers + responsibilities) is maintained in `CLAUDE.md` under "CI Workflows".

This module intentionally focuses on automation/release-specific workflow behavior and operational details. Additional module-relevant workflows not listed in the core matrix include:
- `pages-verify.yml` (PR-only Pages build/signing verification without publish)
- `wiki-sync.yml` (syncs repository `wiki/` content to GitHub Wiki)

### Skill release pipeline behavior
When a skill is tagged (for example, `soul-guardian-v1.0.0`), the pipeline:
1. Validates `skill.json` version/tag alignment.
2. Enforces signing-key consistency against canonical repo key material.
3. Stages the release payload from SBOM-scoped files and root skill docs.
4. Generates release trust packet files, install instructions, and a SkillSpector security report.
5. Generates `checksums.json` for the archive and release assets.
6. Signs and verifies release checksum artifacts.
7. Publishes GitHub Release assets.
8. Publishes the verified release payload to ClawHub when configured, then compares every expected registry file hash and size with the signed package.
9. Supersedes older releases within the same major version (tags remain).
10. Triggers website catalog refresh.

### PR dry-run behavior
PRs that touch skill packages run the release workflow in validation mode:
- `validate-pr-version-sync` checks changed skill metadata and documentation parity.
- Released stable skills must advance by at least one SemVer patch version; equal or lower versions fail validation.
- `release` builds dry-run release assets for changed release-relevant skill files.
- `comment-skillspector-report` posts a sanitized SkillSpector summary back to the PR when reports are available.
- `simulate-tag-release-build` exercises the tag-release builder across skills, verifies signed ClawHub staging through the patched pinned client, and does not publish.

The PR path exists to catch packaging, signing, and release-evidence regressions before a maintainer pushes a real release tag.

### SkillSpector release evidence
The pipeline installs [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) inside GitHub Actions and runs:

```bash
skillspector scan <staged-release-payload> --no-llm --format markdown --output skillspector-report.md
```

The scan target is the staged payload, not the raw `skills/<name>/` source directory. That matters because release evidence should describe what users install, while source-only tests and fixtures stay outside the packaged payload.

SkillSpector output is used in three places:
- PR dry-run artifact: `skillspector-pr-reports`
- GitHub release asset: `skillspector-report.md`
- Signed checksum manifest: `checksums.json` includes the SkillSpector report hash

PR comments intentionally use a sanitized summary. Raw code blocks, inline snippets, emails, and token-like values are omitted from the comment body, and reviewers can download the workflow artifact when they need the full report.

### Signing-key consistency guardrails
Guardrail script:
- `scripts/ci/verify_signing_key_consistency.sh`

Enforced in:
- `.github/workflows/skill-release.yml`
- `.github/workflows/deploy-pages.yml`

### Release versioning and superseding
- Changes to an already released stable skill must increment its version by at least one patch version (for example, `0.1.14` to `0.1.15`).
- New patch/minor release: previous releases in same major line are removed.
- New major release: latest release from previous major line is retained for compatibility.
- Git tags are preserved and can be used to recreate releases when needed.

### ClawHub package parity
- ClawHub publication uses the package extracted from the signed GitHub release archive, not `skills/<name>/` directly.
- The pinned ClawHub client is patched to accept `.sig` and `.pem` text trust artifacts before upload.
- Publication is a blocking release job for configured skills.
- After publish, `clawhub inspect` must report the exact expected publishable paths, SHA-256 hashes, and sizes. Missing or extra files fail the job.
- SBOM-declared optional `.gitkeep` placeholders are the only allowed release/archive omission because ClawHub intentionally ignores dotfiles. Any other client-unsupported package file blocks publication.
- For Suite releases, package preparation verifies the embedded feed signature, checksum signature, signing-key fingerprint, and all required local fallback artifacts before upload.

### Release artifacts
Each skill release includes:
- `<skill>-v<version>.zip`
- `checksums.json`
- `checksums.sig`
- `signing-public.pem`
- `skill.json`
- `SKILL.md`
- `skill-card.md`
- `permissions.json`
- `install.md`
- `skillspector-report.md`
- Additional SBOM-scoped files

Operational docs:
- `wiki/security-signing-runbook.md`
- `wiki/migration-signed-feed.md`

## Key Files
- `.github/workflows/ci.yml`: lint/type/build/security/test matrix.
- `.github/workflows/pages-verify.yml`: PR-only Pages build/signing verification (no publish).
- `.github/workflows/poll-nvd-cves.yml`: daily NVD advisory ingestion.
- `.github/workflows/community-advisory.yml`: issue-label-driven advisory publishing.
- `.github/workflows/skill-release.yml`: release validation, packaging, signing, and publishing.
- `.github/workflows/deploy-pages.yml`: site build + asset mirroring to GitHub Pages.
- `.github/workflows/wiki-sync.yml`: syncs repository `wiki/` into GitHub Wiki.
- `.github/actions/sign-and-verify/action.yml`: shared Ed25519 sign/verify composite action.
- `https://github.com/NVIDIA/SkillSpector`: upstream SkillSpector scanner installed by the release workflow.
- `scripts/prepare-to-push.sh`: local CI-like quality gate.
- `scripts/release-skill.sh`: manual helper for version bump + tag workflow.

## Public Interfaces
| Interface | Trigger | Outcome |
| --- | --- | --- |
| CI workflow | Push/PR on `main` | Fails fast on lint/type/build/test/security regressions. |
| Pages Verify workflow | PR on `main` | Validates Pages build/signing artifacts without production deploy. |
| NVD poll workflow | Cron + dispatch | Updates advisory feed with deduped, normalized CVEs. |
| Community advisory workflow | Issue labeled `advisory-approved` | Opens PR adding signed advisory records. |
| Skill release workflow | Metadata PR changes + tag `<skill>-v*` | PR dry-run/version checks and tagged release publishing. |
| Deploy pages workflow | Successful CI/release run | Publishes site + mirrored artifacts to Pages. |
| Sync wiki workflow | Push `wiki/**` on `main` | Publishes repository wiki content into GitHub Wiki remote. |

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
- Release pipeline blocks equal or decreasing versions for changed, previously released skills.
- ClawHub may silently omit unsupported file extensions; the workflow patches the pinned client and verifies the published registry file list to detect this.
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
- .github/workflows/pages-verify.yml
- .github/workflows/wiki-sync.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/actions/sign-and-verify/action.yml
- scripts/prepare-to-push.sh
- scripts/release-skill.sh
- scripts/validate-release-links.sh
- scripts/ci/verify_signing_key_consistency.sh
