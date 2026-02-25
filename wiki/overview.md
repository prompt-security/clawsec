# Overview

## Purpose
- ClawSec is a security-focused repository that combines a public web catalog with installable security skills for OpenClaw and NanoClaw environments.
- The codebase supports three delivery paths at once: static website publishing, signed advisory distribution, and per-skill GitHub release packaging.
- Primary users are agent operators, skill developers, and maintainers running CI-based security automation.

![Prompt Security Logo](assets/overview_img_01_prompt-security-logo.png)
![ClawSec Mascot](assets/overview_img_02_clawsec-mascot.png)

## Repo Layout
| Path | Role | Notes |
| --- | --- | --- |
| `pages/`, `components/`, `App.tsx`, `index.tsx` | Vite + React UI | Skill catalog, advisory feed, and detail pages. |
| `skills/` | Security skill packages | Each skill has `skill.json`, `SKILL.md`, optional scripts/tests/docs. |
| `advisories/` | Repository advisory channel | Signed `feed.json` + `feed.json.sig` and key material. |
| `scripts/` | Local automation | Populate feed/skills, pre-push checks, release helpers. |
| `.github/workflows/` | CI/CD pipelines | CI, releases, NVD polling, community advisory ingestion, pages deploy. |
| `utils/` | Python utilities | Skill validation and checksum packaging helpers. |
| `public/` | Published static assets | Site media, mirrored advisories, and generated skill artifacts. |
| `docs/` | Operational docs | Signing runbooks, migration plans, compatibility and verification guides. |

## Entry Points
| Entry | Type | Purpose |
| --- | --- | --- |
| `index.tsx` | Frontend bootstrap | Mounts React app into `#root`. |
| `App.tsx` | Frontend router | Defines route map for home, skills, and feed pages. |
| `scripts/prepare-to-push.sh` | Dev workflow | Runs lint/type/build/security checks before push. |
| `scripts/populate-local-feed.sh` | Data bootstrap | Pulls CVEs from NVD and updates local advisory feeds. |
| `scripts/populate-local-skills.sh` | Data bootstrap | Builds `public/skills/index.json` and per-skill checksums. |
| `.github/workflows/skill-release.yml` | Release entry | Handles tag-based skill packaging/signing/release. |
| `.github/workflows/poll-nvd-cves.yml` | Scheduled feed updates | Polls NVD and updates advisories. |

## Key Artifacts
| Artifact | Produced By | Consumed By |
| --- | --- | --- |
| `advisories/feed.json` | NVD poll + community advisory workflows | Web UI, clawsec-suite hook, installers. |
| `advisories/feed.json.sig` | Signing workflow steps | Signature verification in suite/nanoclaw tooling. |
| `public/skills/index.json` | Deploy workflow / local populate script | `pages/SkillsCatalog.tsx` and `pages/SkillDetail.tsx`. |
| `public/checksums.json` + `public/checksums.sig` | Deploy workflow | Client-side integrity verification flows. |
| `release-assets/checksums.json` | Skill release workflow | Release consumers verifying zip integrity. |
| `skills/*/skill.json` | Skill authors | Site catalog generation, validators, and release pipelines. |

## Key Workflows
- Local web development: `npm install` then `npm run dev`.
- Local security data preview: run `./scripts/populate-local-skills.sh` and `./scripts/populate-local-feed.sh` before loading `/skills` and `/feed` pages.
- Pre-push quality gate: run `./scripts/prepare-to-push.sh` (optionally `--fix`).
- Skill lifecycle: edit `skills/<name>/`, validate with `python utils/validate_skill.py`, then tag `<skill>-vX.Y.Z` to trigger release workflow.
- Advisory lifecycle: scheduled NVD poll and issue-label-based community ingestion both merge into the same signed feed.

## Example Snippets
```bash
# local UI + locally populated data
npm install
./scripts/populate-local-skills.sh
./scripts/populate-local-feed.sh --days 120
npm run dev
```

```bash
# canonical TypeScript quality checks used by CI
npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0
npx tsc --noEmit
npm run build
```

## Where to Start
- Read `README.md` for product positioning and install paths.
- Open `App.tsx` and `pages/` to understand user-facing behavior.
- Open `skills/clawsec-suite/skill.json` to understand the suite contract and embedded components.
- Review `.github/workflows/ci.yml`, `.github/workflows/skill-release.yml`, and `.github/workflows/deploy-pages.yml` for production behavior.

## How to Navigate
- UI behavior is centered in `pages/`; visual wrappers sit in `components/`.
- Skill-specific logic is isolated by folder under `skills/`; each folder includes its own scripts/tests/docs.
- Feed handling appears in three layers: repository feed files, workflow updates, and runtime consumers (`clawsec-suite`/`clawsec-nanoclaw`).
- Operational quality gates live in `scripts/` and workflow YAML files.
- For generation traces and update baselines, start from `wiki/GENERATION.md` and then branch into module pages.

## Common Pitfalls
- Using literal home tokens (for example `\$HOME`) in config path env vars can trigger path validation failures.
- Fetching JSON from SPA routes can return HTML with status 200; pages guard for this and treat it as empty-state.
- Unsigned feed bypass mode (`CLAWSEC_ALLOW_UNSIGNED_FEED=1`) exists for migration compatibility and should not be used in steady state.
- Skill release automation expects version parity between `skill.json` and `SKILL.md` frontmatter.
- Some scripts are POSIX shell oriented; Windows users should prefer PowerShell equivalents or WSL.

## Source References
- README.md
- package.json
- App.tsx
- index.tsx
- pages/Home.tsx
- pages/SkillsCatalog.tsx
- pages/SkillDetail.tsx
- pages/FeedSetup.tsx
- scripts/prepare-to-push.sh
- scripts/populate-local-feed.sh
- scripts/populate-local-skills.sh
- skills/clawsec-suite/skill.json
- .github/workflows/ci.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
