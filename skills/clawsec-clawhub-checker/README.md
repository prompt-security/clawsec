# ClawSec ClawHub Checker

A `clawsec-suite` companion skill that adds a standalone reputation gate before guarded installs.

## Operational Notes

- Required runtime: `node`, `clawhub`, `openclaw`
- Dependency: installed `clawsec-suite`
- No in-place mutation of other skills
- Advisory-hook wiring is optional and manual in this release
- Reputation checks query ClawHub metadata and remain confirmation-gated

## Purpose

Adds a second risk signal before install by:

1. Reading ClawHub inspect/security metadata
2. Applying reputation heuristics (age, updates, author activity, downloads)
3. Requiring `--confirm-reputation` for low-score installs

## Installation

```bash
npx clawhub install clawsec-suite
npx clawhub install clawsec-clawhub-checker
```

Optional preflight helper:

```bash
node ~/.openclaw/skills/clawsec-clawhub-checker/scripts/setup_reputation_hook.mjs
```

## Usage

```bash
node ~/.openclaw/skills/clawsec-clawhub-checker/scripts/enhanced_guarded_install.mjs \
  --skill some-skill \
  --version 1.0.0
```

Override only after manual review:

```bash
node ~/.openclaw/skills/clawsec-clawhub-checker/scripts/enhanced_guarded_install.mjs \
  --skill some-skill \
  --version 1.0.0 \
  --confirm-reputation
```

## Optional Advisory-Hook Wiring

If you need advisory alerts to include `reputationWarning` / `reputationWarnings`, wire the checker module manually into the installed suite hook:

- Source: `~/.openclaw/skills/clawsec-clawhub-checker/hooks/clawsec-advisory-guardian/lib/reputation.mjs`
- Target: `~/.openclaw/skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`

The setup helper validates paths only and does not patch these files automatically.

## Exit Codes

- `0` safe to install
- `42` advisory confirmation required
- `43` reputation confirmation required
- `1` error

## Configuration

- `CLAWHUB_REPUTATION_THRESHOLD` (default: 70)

## Security Considerations

- Reputation is heuristic, not authoritative
- False positives are possible
- Always inspect code before confirming installation

## License

GNU AGPL v3.0 or later - Part of the ClawSec security suite
