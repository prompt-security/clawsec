# Cross-Platform Compatibility Report

## 1) Executive Summary

### Overall status by OS
- Linux: **Good**, primary workflows validated; still some POSIX-only scripts/docs.
- macOS: **Good**, with caveats around POSIX tool availability and Homebrew-specific assumptions.
- Windows: **Partial**, Node/Python pieces work, but many shell-first install/release workflows still require WSL/Git Bash.

### Highest-risk incompatibilities
1. **(Fixed)** Literal `$HOME` path creation risk in audit watchdog cron setup payload generation.
2. **(Fixed)** Path env vars accepted as raw strings in multiple Node entrypoints without expansion/validation.
3. **(Open)** Large portions of manual install/release guidance remain POSIX-only (`bash`, `jq`, `curl`, `unzip`, `chmod`, `find -exec`).

### SKILLS install path-expansion root cause
Root cause was a combination of:
- shell-side literal env assignment (for example, `PROMPTSEC_INSTALL_DIR='$HOME/...')`
- Node scripts not expanding home tokens
- cron payload construction escaping `$` (`\$HOME`), forcing literal interpretation in downstream shell execution

This could produce paths like `~/.openclaw/workspace/$HOME/...`.

---

## 2) Findings Table

| ID | Severity | OS Impact | Component | Description | Proposed Fix | Status |
|---|---|---|---|---|---|---|
| CP-001 | Blocker | Linux/macOS/Windows | `skills/openclaw-audit-watchdog/scripts/setup_cron.mjs` | Literal `$HOME` could be propagated into cron payload, creating wrong runtime paths. | Expand/normalize home tokens and reject unresolved escaped tokens before job creation. | **Fixed** |
| CP-002 | High | Linux/macOS/Windows | `skills/clawsec-suite/hooks/.../handler.ts`, `.../scripts/guarded_skill_install.mjs`, `.../lib/suppression.mjs`, `skills/openclaw-audit-watchdog/scripts/load_suppression_config.mjs` | Env path vars treated as opaque strings; `~`, `$HOME` not consistently handled. | Shared/consistent path resolution + fail-fast validation. | **Fixed** |
| CP-003 | Medium | macOS/Windows | `skills/openclaw-audit-watchdog/test/render_report_suppression.test.mjs`, `.../scripts/codex_review.sh` | Hardcoded `/opt/homebrew` and `which` assumptions. | Use `process.execPath` for tests; PATH-first Codex discovery. | **Fixed** |
| CP-004 | Medium | Windows (+ CI) | repo-wide line endings | Missing `.gitattributes` could introduce CRLF script breakage (`env bash^M`). | Add `.gitattributes` with LF enforcement for scripts/config/text. | **Fixed** |
| CP-005 | Medium | macOS/Windows | `.github/workflows/ci.yml` | TS/lint/build checks were Linux-only. | Add OS matrix for Node checks (`ubuntu`, `macos`, `windows`). | **Fixed** |
| CP-006 | High | Windows | Multiple SKILL docs and shell scripts | Install/maintenance flow is still heavily POSIX-shell based. | Add PowerShell equivalents or Node wrappers for critical flows. | Open |
| CP-007 | Medium | Linux/macOS/Windows | `skills/soul-guardian/scripts/soul_guardian.py` | `Path(...).expanduser()` handles `~` but not `$HOME`/`%USERPROFILE%`. | Add explicit env-token expansion + validation for `--state-dir`. | Open |
| CP-008 | Medium | Windows | `scripts/release-skill.sh`, `scripts/populate-local-*.sh` | GNU/BSD shell toolchain assumptions block native Windows usage. | Provide cross-platform Node/Python replacements or PowerShell equivalents. | Open |
| CP-009 | Low | Windows | docs + scripts using `chmod 600/644` | POSIX permission semantics are partial/non-portable on Windows. | Document best-effort behavior and Windows ACL alternatives. | Open |
| CP-010 | Low | macOS/Windows | CI non-Node jobs | Shell/Python/security scan jobs remain Ubuntu-only. | Add scoped matrix or dedicated non-Linux smoke jobs where practical. | Open |

---

## 3) Detailed Findings

## Paths
- Fixed: centralized home-token expansion and suspicious token rejection for critical runtime/install path env vars.
- Fixed: path normalization before filesystem access and before cron payload construction.
- Open: `soul_guardian.py` still expands only `~`, not `$HOME`/Windows env tokens.

## Shell / Command Dependencies
- Confirmed extensive POSIX dependencies (`bash`, `curl`, `jq`, `mktemp`, `chmod`, `find`, `unzip`, `openssl`, `shasum/sha256sum`).
- Fixed minor hardcoded binary path assumptions.
- Open: no full native PowerShell parity for core shell workflows.

## Permissions / Filesystem Semantics
- Confirmed many scripts rely on POSIX permission commands.
- Existing `state.ts` already handles `chmod` failures on unsupported filesystems.
- Open: docs still mostly assume POSIX permissions.

## Line Endings
- Fixed by adding `.gitattributes` with LF rules for scripts and key text/config files.

## Runtime Dependencies
- Node scripts generally portable.
- Python utilities are portable.
- OpenSSL usage in docs/workflows remains shell/toolchain dependent.

## CI / Automation
- Fixed: TS/lint/build matrix now runs on Linux/macOS/Windows.
- Open: remaining security/shell/python jobs are Linux-only by design.

---

## 4) SKILLS Install Investigation

### Reproduction (pre-fix)
1. Set install dir with literal token (common quoting mistake):
   - `export PROMPTSEC_INSTALL_DIR='$HOME/.config/security-checkup'`
2. Run:
   - `node skills/openclaw-audit-watchdog/scripts/setup_cron.mjs`
3. The generated payload command used escaped `$` in `cd` path, resulting in literal token usage at execution time (`cd "\$HOME/..."`), which can resolve under current working directory (for example, `~/.openclaw/workspace/$HOME/...`).

### Root cause analysis
- POSIX single quotes prevent variable expansion.
- Node does not auto-expand env vars inside strings.
- Existing payload escaping converted `$` to literal in shell command text.

### Fix implemented
- Added explicit path resolution (supports `~`, `$HOME`, `${HOME}`, `%USERPROFILE%`, `$env:USERPROFILE`) and normalization.
- Added fail-fast validation for unresolved/escaped home tokens.
- Applied to watchdog cron setup, watchdog suppression config loader, suite hook handler, suite advisory suppression loader, and suite guarded installer.
- Added tests covering expansion and escaped-token rejection.

### Validation targets
- `bash` / `zsh`: expanded env values and reject literal escaped home tokens.
- `sh` (where scripts are invoked through Node entrypoints): same path behavior in Node layer.
- Windows PowerShell: `%USERPROFILE%` / `$env:USERPROFILE` expansion and path normalization validated in Node tests.

