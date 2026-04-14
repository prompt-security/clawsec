# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-04-14

### Added

- Registry/runtime metadata now declares the actual required runtimes (`openclaw`, `node`) plus the DM/email environment variables and operator review notes.
- `scripts/setup_cron.mjs` now prints a preflight review summarizing recipients, persistence, and required runtime before creating or updating the cron job.
- Coverage for cron setup disclosure behavior (`test/setup_cron.test.mjs`) and case-insensitive suppression matching regression.

### Changed

- Email delivery is now explicit and opt-in: `scripts/runner.sh` only attempts email delivery when `PROMPTSEC_EMAIL_TO` is configured.
- `scripts/setup_cron.mjs` now carries configured runtime/delivery environment variables into the cron payload so the scheduled job is more self-describing and less dependent on ambient host state.
- Suppression matching in `scripts/render_report.mjs` is now case-insensitive for skill names, matching the documented behavior and normalized config loader.
- Documentation now consistently refers to the current OpenClaw product name.

### Security

- Removed the placeholder email recipient from the default cron payload to avoid implicitly sending audit output to an unreviewed address.
- Cron setup now surfaces the unattended delivery model before enabling persistence, making external recipients and runtime assumptions explicit to the operator.

## [0.1.1]

### Added

- Contributor credit: portability and path-hardening improvements in this release were contributed by [@aldodelgado](https://github.com/aldodelgado) in PR #62.
- Cross-shell home-path expansion support in watchdog path inputs (`~`, `$HOME`, `${HOME}`, `%USERPROFILE%`, `$env:HOME`).
- Regression coverage for suppression-config home-token expansion and escaped-token rejection (`test/suppression_config.test.mjs`).

### Changed

- `scripts/codex_review.sh` now resolves the Codex CLI from `CODEX_BIN`, then `PATH`, then Homebrew fallback for improved portability.
- `scripts/setup_cron.mjs` now normalizes and validates install-dir/home-derived paths before job creation.
- `scripts/load_suppression_config.mjs` now resolves/normalizes configured file paths consistently across shell styles.

### Security

- Escaped or unresolved home tokens in suppression config paths now fail fast to avoid silently using unintended literal paths.

## [0.1.0]

### Added

- Suppression/allowlist mechanism with explicit opt-in gating (defense in depth).
- `--enable-suppressions` CLI flag for `run_audit_and_format.sh`, `render_report.mjs`, and `runner.sh`.
- `enabledFor` config sentinel -- config must declare `"enabledFor": ["audit"]` for audit suppression to activate.
- 4-tier config file resolution: explicit `--config` path > `OPENCLAW_AUDIT_CONFIG` env var > `~/.openclaw/security-audit.json` > `.clawsec/allowlist.json`.
- `INFO-SUPPRESSED` section in report output showing suppressed findings with metadata.
- Integration tests for suppression behavior (11 tests in `render_report_suppression.test.mjs`).
- Unit tests for config loading and opt-in gating (15 tests in `suppression_config.test.mjs`).
- Test fixtures: `empty-suppressions.json`, `invalid-json.json`, `malformed-config.json`.

### Changed

- `load_suppression_config.mjs` now requires explicit `{ enabled: true }` parameter -- returns empty suppressions by default.
- `render_report.mjs` passes suppression enabled state to config loader.
- Summary counts in report output are recalculated after filtering suppressed findings.

### Security

- Suppression is never active by default -- requires BOTH CLI flag AND config sentinel (defense in depth).
- Environment variables alone cannot activate suppression (prevents ambient attack vector).
