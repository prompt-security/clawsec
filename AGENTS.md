# Repository Guidelines

## Project Structure & Module Organization
ClawSec combines a Vite + React frontend with security skill packages and release tooling.
- Frontend entrypoints: `index.tsx`, `App.tsx`
- UI and routes: `components/`, `pages/`
- Shared types/constants: `types.ts`, `constants.ts`
- Skills: `skills/<skill-name>/` (`skill.json`, `SKILL.md`, optional `scripts/`, `test/`)
- Advisory feed: `advisories/feed.json`, `advisories/feed.json.sig`
- Automation: `scripts/`, `.github/workflows/`
- Python utilities: `utils/validate_skill.py`, `utils/package_skill.py`

## Build, Test, and Development Commands
- `npm install`: install dependencies.
- `npm run dev`: run local Vite server.
- `npm run build`: create production build (CI gate).
- `npm run preview`: preview built app.
- `./scripts/prepare-to-push.sh [--fix]`: run lint, types, build, and security checks.
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
- For Python utility updates, run `ruff check utils/` and `bandit -r utils/ -ll`.

## Pull Request Guidelines
- Follow Conventional Commits: `feat(scope): ...`, `fix(scope): ...`, `chore(scope): ...`.
- Use skill branches like `skill/<name>-...`.
- Keep PRs focused and include summary, security benefit, and testing performed.
- Keep versions aligned between `skills/<skill>/skill.json` and `skills/<skill>/SKILL.md`.
- Do not push release tags from PR branches; releases are tagged from `main`.

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
