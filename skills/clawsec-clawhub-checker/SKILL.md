---
name: clawsec-clawhub-checker
version: 0.0.3
description: ClawHub reputation checker for clawsec-suite. Adds a standalone reputation gate before guarded skill installation.
homepage: https://clawsec.prompt.security
clawdis:
  emoji: "🛡️"
  requires:
    bins: [node, clawhub, openclaw]
  depends_on: [clawsec-suite]
---

# ClawSec ClawHub Checker

Adds a reputation gate on top of the `clawsec-suite` guarded installer.

## Operational Notes

- Required runtime: `node`, `clawhub`, `openclaw`
- Depends on: installed `clawsec-suite`
- Side effects: none on other skills; this package does not rewrite installed suite files
- Advisory-hook wiring is optional and manual in this release
- Network behavior: reputation checks call ClawHub inspect/search endpoints
- Trust model: scores are heuristic and confirmation-gated

## What It Does

1. Reads skill metadata from ClawHub (`inspect --json`)
2. Evaluates scanner status (including VirusTotal summary when present)
3. Applies additional reputation heuristics (age, updates, author history, downloads)
4. Requires explicit `--confirm-reputation` when score is below threshold

## Installation

Install after `clawsec-suite`:

```bash
npx clawhub@latest install clawsec-suite
npx clawhub@latest install clawsec-clawhub-checker
```

Optional preflight check (validates local paths and prints recommended command):

```bash
node ~/.openclaw/skills/clawsec-clawhub-checker/scripts/setup_reputation_hook.mjs
```

## Usage

Run the enhanced installer directly from this skill:

```bash
node ~/.openclaw/skills/clawsec-clawhub-checker/scripts/enhanced_guarded_install.mjs \
  --skill some-skill \
  --version 1.0.0
```

If a skill is below threshold, rerun only with explicit approval:

```bash
node ~/.openclaw/skills/clawsec-clawhub-checker/scripts/enhanced_guarded_install.mjs \
  --skill some-skill \
  --version 1.0.0 \
  --confirm-reputation
```

## Optional Advisory-Hook Wiring (Manual)

This release does not auto-patch `clawsec-suite` hook files.  
If you rely on advisory alerts that include `reputationWarning` / `reputationWarnings`, wire the checker module manually:

- Source module: `~/.openclaw/skills/clawsec-clawhub-checker/hooks/clawsec-advisory-guardian/lib/reputation.mjs`
- Target hook file: `~/.openclaw/skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`

Treat that wiring as a deliberate local customization and review it before enabling.

## Exit Codes

- `0` safe to install
- `42` advisory confirmation required (from clawsec-suite)
- `43` reputation confirmation required
- `1` error

## Configuration

Environment variables:

- `CLAWHUB_REPUTATION_THRESHOLD` - Minimum score (0-100, default: 70)

## Safety Notes

- This is defense-in-depth, not a replacement for advisory matching
- Scanner outputs can produce false positives and false negatives
- Always review skill code before overriding warnings

## Development

Key files:

- `scripts/enhanced_guarded_install.mjs`
- `scripts/check_clawhub_reputation.mjs`
- `scripts/setup_reputation_hook.mjs`
- `hooks/clawsec-advisory-guardian/lib/reputation.mjs`

## License

GNU AGPL v3.0 or later - Part of the ClawSec security suite
