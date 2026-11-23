# Repository Guidelines

## Project Structure & Module Organization
ClawSec combines a Vite + React frontend with security skill packages and release tooling.
- Frontend entrypoints: `index.tsx`, `App.tsx`
- UI and routes: `components/`, `pages/`
- Shared types/constants: `types.ts`, `constants.ts`
- Wiki source docs: `wiki/` (synced to GitHub Wiki by `.github/workflows/wiki-sync.yml`)
- Generated wiki exports: `public/wiki/` (`llms.txt` outputs; generated locally/CI and gitignored)
- Skills: `skills/<skill-name>/` (`skill.json`, `SKILL.md`, optional `scripts/`, `test/`)
- Advisory feed: `advisories/feed.json`, `advisories/feed.json.sig`
- Automation: `scripts/`, `.github/workflows/`
- Python utilities: `utils/validate_skill.py`, `utils/package_skill.py`

## Build, Test, and Development Commands
- `npm install`: install dependencies.
- `npm run dev`: run local Vite server.
- `npm run build`: create production build (CI gate).
- `npm run preview`: preview built app.
- `npm run gen:wiki-llms`: generate wiki `llms.txt` exports from `wiki/` into `public/wiki/`.
- `./scripts/prepare-to-push.sh [--fix]`: run lint, types, build, and security checks.
- `./scripts/populate-local-wiki.sh`: regenerate local wiki `llms.txt` exports for preview.
- `npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0`: lint JS/TS.
- `npx tsc --noEmit`: type-check TypeScript.
- `node skills/clawsec-suite/test/feed_verification.test.mjs`: run a skill-local Node test.
- `python utils/validate_skill.py skills/<skill-name>`: validate skill schema/metadata.

## Coding Style & Naming Conventions
- Use TypeScript/TSX for frontend code and ESM for scripts.
- Follow `eslint.config.js`; prefix intentionally unused vars/args with `_`.
- Python under `utils/` follows `pyproject.toml` Ruff/Bandit rules (line length 120).
- Name React files in PascalCase (for example, `SkillCard.tsx`), skill directories in kebab-case (for example, `skills/clawsec-feed`), and tests as `*.test.mjs`.

## Testing Guidelines
There is no root `npm test`; tests are mostly skill-local.
- Run changed tests directly: `node skills/<skill>/test/<name>.test.mjs`.
- For frontend/config changes, run ESLint, `npx tsc --noEmit`, and `npm run build`.
- For wiki rendering/export changes, run `npm run gen:wiki-llms` and `npm run build`.
- For Python utility updates, run `ruff check utils/` and `bandit -r utils/ -ll`.

## Skill Release Lifecycle

- Use Semantic Versioning prereleases in this order: `0.x.y-beta.N`, `0.x.y-rc.N`, then `0.x.y`. Never use or publish forms such as `0.x.yrcN`.
- Once the monotonic signed lifecycle-policy cutover serial is active, beta and RC artifacts plus stable-intent candidate identity, lab manifests, and receipts are private and lab-only. Reject every public prerelease ref not in the cutover policy's frozen legacy-ref/digest allowlist. Preserve allowlisted historical refs as legacy, non-authorized history; they remain fetchable and must not be deleted or rewritten.
- Deploy each candidate to a matching non-production harness lab. Use only an SSH endpoint explicitly named by the operator; never infer or substitute a hostname or alias.
- Treat `scp` only as transport. Copy into a fresh quarantine path, authenticate a signed private candidate manifest with the separate lab trust root, verify the exact candidate digest before and after transfer, and install verified local bytes through the production-equivalent path. There is no unsigned lab mode.
- Where a harness has no native local installer, use the reviewed standalone verifier to safe-extract, check preimages and conflicts, atomically activate the exact verified tree, and issue a receipt; never make an unverified direct copy into the final skill directory.
- Never relabel beta or RC bytes as stable. Qualify a private payload with the final stable version already embedded, then require release CI to rebuild the exact qualified commit and match its unsigned archive and install-tree digests. Those identical payload bytes may become public only through that stable pipeline after promotion verification; the private candidate identity and lab evidence do not.
- Do not advance beta to RC, or RC to stable-intent, without a passing required lab receipt set. Any payload or governed-input change creates a new candidate and repeats the affected lab matrix.
- Any source, version metadata, lockfile, generator, build definition/toolchain, bundled trust-asset, or allowed-transformation change invalidates prior qualification. Digest mismatch fails closed and cannot be waived.
- Release only an exact qualified commit that remains on protected `main`. Use package-qualified immutable stable tags; never reuse, move, overwrite, or delete a public stable version or tag. Failed private stable-intent attempts may retain the same intended version only under a new candidate ID.
- Bind promotion to one durable release-attempt ID. A retry may resume only the exact matching published tag/assets after re-verifying them; reject foreign or mismatched public refs.
- The reviewed stable release pipeline is the only path that may use production signing keys, create a public stable release, publish stores, or activate the signed catalog.
- Require append-only build, per-harness deployment, qualification, promotion-authorization, promotion, channel-publication, and catalog-activation records. Bind exact digests and policy evidence without secrets.
- Keep production signing and store credentials out of lab hosts and agent-writable paths. Catalog activation requires fresh qualification and promotion evidence, final required channel receipts with parity plus clean native-store installs, and private projection validation. Controlled discovery follows only the successfully activated serial.

## Pull Request Guidelines
- Follow Conventional Commits: `feat(scope): ...`, `fix(scope): ...`, `chore(scope): ...`.
- Use skill branches like `skill/<name>-...`.
- Keep PRs focused and include summary, security benefit, and testing performed.
- Use one PR per bounded change class. Each new skill gets its own PR; each existing skill change gets its own PR; documentation/policy changes get a separate PR; release or CI pipeline changes get a separate PR.
- Do not combine multiple skills, a skill with repository-wide docs, or a skill with pipeline work merely because they share a project milestone. Use explicit dependencies or stacked PRs, and let maintainers decide later whether any PRs should be collated.
- Skill-owned metadata, tests, `SKILL.md`, `REMOVE.md`, and changelog entries required to make one skill internally consistent stay with that skill PR. Cross-skill matrices, wiki architecture, and release-policy documentation remain documentation PRs.
- Keep versions aligned between `skills/<skill>/skill.json` and `skills/<skill>/SKILL.md`.
- Do not push release tags from PR branches; releases are tagged from `main`.
- Do not commit generated `public/wiki/` artifacts; edit `wiki/` source files instead.

## Agent Collaboration & Git Safety
- Delete unused or obsolete files only when your changes make them irrelevant; revert files only when the change is yours or explicitly requested. If a git operation creates uncertainty about another agent’s in-flight work, stop and coordinate instead of deleting.
- Before deleting any file to fix local type/lint failures, stop and ask the user.
- Never edit `.env` or any environment variable files.
- Coordinate with other agents before removing their in-progress edits; do not revert or delete work you did not author unless everyone agrees.
- Moving, renaming, and restoring files is allowed when done safely.
- Never run destructive git operations without explicit written instruction in this conversation: `git reset --hard`, `rm`, `git checkout`/`git restore` to older commits. Treat these as catastrophic; if unsure, stop and ask. In Cursor or Codex Web, use platform tooling as applicable.
- Never use `git restore` (or similar revert commands) on files you did not author.
- Always run `git status` before committing.
- Keep commits atomic and commit only touched files with explicit paths.
- For tracked files: `git commit -m "<scoped message>" -- path/to/file1 path/to/file2`.
- For new files: `git restore --staged :/ && git add "path/to/file1" "path/to/file2" && git commit -m "<scoped message>" -- path/to/file1 path/to/file2`.
- Quote any git path containing brackets or parentheses when staging/committing (for example, `"src/app/[candidate]/**"`).
- For rebases, avoid editors: `GIT_EDITOR=:` and `GIT_SEQUENCE_EDITOR=:` (or `--no-edit`).
- Never amend commits without explicit written approval in this task thread.
