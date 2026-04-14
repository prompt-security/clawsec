# Changelog

All notable changes to soul-guardian will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.5] - 2026-04-14

### Added

- Regression coverage for launchd label migration so the installer documents and cleans up the previous Clawdbot-era label before starting the new default label.

### Changed

- `scripts/install_launchd_plist.py` now documents the legacy launchd label/plist in dry-run output and attempts a best-effort disable/bootout of `com.clawdbot.soul-guardian.<agentId>` before installing `com.openclaw.soul-guardian.<agentId>`.
- The `--label` help now explains that non-legacy labels trigger legacy-job cleanup, while explicitly selecting the legacy label skips that migration path.

### Security

- Reduced the chance of duplicate launchd jobs or split monitoring state by making the old-label cleanup path explicit and warning the operator when manual launchd cleanup is still required.

## [0.0.4] - 2026-04-14

### Added

- Regression coverage for launchd state-directory selection so existing legacy installs keep using their current guardian state unless the operator explicitly chooses a new location.

### Changed

- `scripts/install_launchd_plist.py` now reuses `~/.clawdbot/soul-guardian/<agentId>/` when that legacy state directory already exists and otherwise keeps the new `~/.openclaw/...` default.
- The launchd installer now prints an explicit migration warning with the `--state-dir` value to use when switching an existing install to the new OpenClaw path.

### Security

- Prevented silent state-directory drift for existing launchd-based installs that would otherwise create a second guardian state tree and lose visibility into the approved baselines they were already enforcing.

## [0.0.3] - 2026-04-14

### Added

- Operational notes that describe restore behavior, state-directory sensitivity, and optional scheduling integrations.
- Metadata for persistence, network posture, and operator review expectations.

### Changed

- Declared optional integration runtimes used by the documented workflows (`openclaw`, `launchctl`, `bash`) alongside the required `python3` runtime.
- Normalized the documented product/runtime naming to OpenClaw, including cron examples, default external state paths, and launchd labels.

### Security

- Made it explicit that restore mode can overwrite protected files back to baseline and that guardian state directories may contain sensitive snapshots, diffs, and quarantined content.
