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

Required tools: Node 20+, Python 3.10+, openssl, jq, shellcheck, gitleaks,
trufflehog (`brew install shellcheck gitleaks trufflehog`). The pre-commit hook
exits 1 without gitleaks.

`npm install` points `core.hooksPath` at `.githooks/` via the `prepare` script,
which enables the secret-scanning pre-commit hook. See **Secret Scanning** below.

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

**Secret scanning** (same engine as the hooks and CI):

```bash
gitleaks protect --staged --redact          # staged blobs, as pre-commit sees them
gitleaks git --redact                       # every commit
trufflehog git "file://$(pwd)" --results=verified,unknown --fail
git config core.hooksPath .githooks         # (re)enable the hook
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
| `ci.yml` | PR to main / manual | Lint (TS, Python, shell), Trivy security scan, TruffleHog secret scan, npm audit, tests, build. No `push` trigger, so direct commits to main are not CI-scanned — accepted risk: the only direct-to-main writer is the NVD/GHSA poller, whose input is public advisory data. |
| `skill-release.yml` | Tag `*-v*.*.*` or PR touching skill files | Sign checksums, publish to GitHub Releases, supersede old versions |
| `deploy-pages.yml` | After CI or release succeeds | Build web frontend + skills catalog, deploy to GitHub Pages |
| `poll-nvd-cves.yml` | Daily 06:00 UTC | Poll NVD for CVEs, update `advisories/feed.json` + signature |
| `community-advisory.yml` | Issue labeled `advisory-approved` | Process community report into `CLAW-YYYY-NNNN` advisory |

## Secret Scanning

Two tools, split by what each is actually good at.

| Gate | Runs | Tool | Scope |
|---|---|---|---|
| `.githooks/pre-commit` | on commit | `gitleaks protect --staged` | staged blobs |
| `.githooks/pre-push` | on push | gitleaks **+** TruffleHog | the commits being pushed |
| `ci.yml` / `secret-scan` | on PR | TruffleHog Action + gitleaks | the PR's commit range |

**Dead or alive.** pre-push and CI both pass `unverified` in `--results`, so a
rotated or already-dead credential still fails — a leaked key is a leak whether
or not it still works. CI's default (`verified,unknown`) would let it through.

What makes that policy usable is that **every gate scans a range, never full
history**. Over the whole repo this filter reports 140 findings — the advisory
feed cites upstream fix commits as 40-char hex SHAs, which read as legacy GitHub
PATs — but a range scan sees only the diff, so an ordinary push or PR reports 0.
Never widen a gate to full history without re-checking that.

But TruffleHog only emits a **PrivateKey** finding when it can verify the key
against a provider. An unverifiable key produces no output at all — confirmed
against RSA-2048, EC prime256v1, PKCS#8 Ed25519 and OpenSSH Ed25519. That is
exactly the shape of `CLAWSEC_SIGNING_PRIVATE_KEY`, so gitleaks covers it: its
built-in `private-key` rule matches on pattern and needs no network.

**Why gitleaks in the hooks.** Staged content is not in git yet, and
`trufflehog git file://.` only reads committed objects — it reports nothing for
a staged key. `gitleaks protect --staged` reads the staged blobs directly. At
pre-push both run: gitleaks is offline and ~0.3s, TruffleHog adds its detector
set for ~5s on a 20-commit range. `CLAWSEC_SKIP_TRUFFLEHOG=1` drops the slow
half when you are offline; `CLAWSEC_SKIP_SECRET_SCAN=1` skips both.

**Tuning.** Use each tool's native mechanism — `trufflehog:ignore` on the line,
or `--exclude-paths` / `--exclude-detectors`; `gitleaks:allow` on the line, or
`.gitleaksignore`. Do not add a custom suppression layer.

**`--no-verify` cannot be disabled.** It is built into git's CLI. Client-side
hooks are a fast feedback loop, not a boundary; CI is the backstop.

**Worktrees that pin `core.hooksPath` get no hooks.** `prepare` sets
`core.hooksPath=.githooks` in local scope, which every checkout inherits — the
relative path resolves per worktree, so the main checkout and ordinary linked
worktrees are all covered (verified). But worktree scope outranks local scope,
so a worktree carrying its own `core.hooksPath` in `config.worktree` silently
wins and no hook runs. Today that is 2 of 19 checkouts here, both agent
sandboxes created by tooling that pins it. Check with
`git config --get core.hooksPath` — anything other than `.githooks` means the
local gates are off in that checkout and only CI is protecting you.

**The control worth more than all of the above** is GitHub secret scanning
**push protection** — it rejects the push itself, so the secret never lands on
any branch. Free for public repositories, and currently **disabled** on this
repo. Enable it at Settings → Code security.

Note that TruffleHog verifies by calling the provider's API, so the CI scan
makes outbound network requests.

## Key Conventions

- **ESLint:** flat config (`eslint.config.js`), zero warnings policy
- **Python:** ruff + bandit, configured in `pyproject.toml`, line-length 120
- **Shell:** shellcheck on `scripts/*.sh`
- **Tests:** each `.test.mjs` is a standalone Node.js script with its own pass/fail counters and `process.exit(1)` on failure. Tests generate ephemeral Ed25519 keys — they don't use the repo signing keys.
- **Secret scanning:** suppress a false positive with the scanner's own mechanism (`trufflehog:ignore` / `gitleaks:allow` on the line), scoped to that value. Never add a custom suppression layer.
- **Advisory feed:** fail-closed signature verification by default. `CLAWSEC_ALLOW_UNSIGNED_FEED=1` is a temporary migration bypass only.
- **Hook event model:** hooks mutate `event.messages` array in-place (not return values). Rate-limited to 300s by default (`CLAWSEC_HOOK_INTERVAL_SECONDS`).
