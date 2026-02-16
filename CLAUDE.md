# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Setup

```bash
npm install              # install JS dependencies
npm run dev              # start Vite dev server on http://localhost:3000
npm run build            # production build to dist/
```

Python environment (use `uv`, not raw `pip`):

```bash
uv venv                  # create .venv in repo root
source .venv/bin/activate
uv pip install ruff bandit   # linters configured in pyproject.toml
```

Required tools: Node 20+, Python 3.10+, openssl, jq, shellcheck (`brew install shellcheck`).

## Common Commands

**Pre-push validation** (mirrors CI — run before pushing):

```bash
./scripts/prepare-to-push.sh         # lint, typecheck, build, security scans
./scripts/prepare-to-push.sh --fix   # auto-fix where possible
```

**Lint:**

```bash
npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0   # JS/TS
ruff check utils/                                             # Python
bandit -r utils/ -ll                                          # Python security
```

**Tests** (vanilla Node.js — no framework, no npm test script):

```bash
node skills/clawsec-suite/test/feed_verification.test.mjs
node skills/clawsec-suite/test/guarded_install.test.mjs
node skills/clawsec-suite/test/skill_catalog_discovery.test.mjs
```

**Validate a skill's structure:**

```bash
python utils/validate_skill.py skills/<skill-name>
```

**Signing key consistency check:**

```bash
./scripts/ci/verify_signing_key_consistency.sh
```

**Populate local dev data:**

```bash
./scripts/populate-local-skills.sh           # build public/skills/index.json from local skills/
./scripts/populate-local-feed.sh --days 120  # fetch real NVD CVE data for local advisory feed
```

## Releasing a Skill

```bash
./scripts/release-skill.sh <skill-name> <version> [--force-tag]
# Example: ./scripts/release-skill.sh clawsec-feed 0.0.5
```

- **Feature branch:** bumps version in skill.json + SKILL.md frontmatter, commits. No tag.
- **Main branch:** same + creates annotated git tag + GitHub release with changelog.
- Tag format: `<skill-name>-v<semver>` (e.g., `clawsec-suite-v0.1.0`).
- Pushing the tag triggers the `skill-release.yml` workflow (sign, package, publish).

## Architecture

**Frontend:** React 19 + TypeScript + Vite, deployed to GitHub Pages. Hash-based routing. Tailwind via CDN.

**Skills:** Each skill lives in `skills/<name>/` with:
- `skill.json` — metadata, SBOM (file manifest), OpenClaw config (emoji, triggers, required bins)
- `SKILL.md` — YAML frontmatter (`name`, `version`, `description`) + agent-readable markdown
- Version in `skill.json` and `SKILL.md` frontmatter must match (CI enforced)

**clawsec-suite** is the meta-skill ("skill-of-skills") that installs and manages other skills. It embeds:
- Advisory feed with Ed25519 signature verification (`hooks/clawsec-advisory-guardian/`)
- Guarded skill installer with two-stage approval for advisory-flagged skills
- Dynamic catalog discovery from `https://clawsec.prompt.security/skills/index.json` with local fallback

**Signing:** Single Ed25519 keypair for everything (feed + releases).
- Private key lives only in GitHub secret `CLAWSEC_SIGNING_PRIVATE_KEY` — never committed.
- Public key committed in three canonical locations: `clawsec-signing-public.pem`, `advisories/feed-signing-public.pem`, `skills/clawsec-suite/advisories/feed-signing-public.pem`.
- `SKILL.md` embeds the same key inline for offline installation verification.
- Drift guard: `scripts/ci/verify_signing_key_consistency.sh` enforces all references resolve to the same fingerprint. Runs on every PR and tag push.

## CI Workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | PR / push to main | Lint (TS, Python, shell), Trivy security scan, npm audit, tests, build |
| `skill-release.yml` | Tag `*-v*.*.*` or PR touching skill files | Sign checksums, publish to GitHub Releases, supersede old versions |
| `deploy-pages.yml` | After CI or release succeeds | Build web frontend + skills catalog, deploy to GitHub Pages |
| `poll-nvd-cves.yml` | Daily 06:00 UTC | Poll NVD for CVEs, update `advisories/feed.json` + signature |
| `community-advisory.yml` | Issue labeled `advisory-approved` | Process community report into `CLAW-YYYY-NNNN` advisory |

## Key Conventions

- **ESLint:** flat config (`eslint.config.js`), zero warnings policy
- **Python:** ruff + bandit, configured in `pyproject.toml`, line-length 120
- **Shell:** shellcheck on `scripts/*.sh`
- **Tests:** each `.test.mjs` is a standalone Node.js script with its own pass/fail counters and `process.exit(1)` on failure. Tests generate ephemeral Ed25519 keys — they don't use the repo signing keys.
- **Advisory feed:** fail-closed signature verification by default. `CLAWSEC_ALLOW_UNSIGNED_FEED=1` is a temporary migration bypass only.
- **Hook event model:** hooks mutate `event.messages` array in-place (not return values). Rate-limited to 300s by default (`CLAWSEC_HOOK_INTERVAL_SECONDS`).
