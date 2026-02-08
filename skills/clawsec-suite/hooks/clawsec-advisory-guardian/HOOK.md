---
name: clawsec-advisory-guardian
description: Detect advisory matches for installed skills and require explicit user approval before any removal action.
metadata: { "openclaw": { "events": ["agent:bootstrap", "command:new"] } }
---

# ClawSec Advisory Guardian Hook

This hook checks the ClawSec advisory feed against locally installed skills on:

- `agent:bootstrap`
- `command:new`

When it detects an advisory affecting an installed skill, it posts an alert message.
If the advisory looks malicious or removal-oriented, it explicitly recommends removal
and asks for user approval first.

## Safety Contract

- The hook does not delete or modify skills.
- It only reports findings and requests explicit approval before removal.
- Alerts are deduplicated using `~/.openclaw/clawsec-suite-feed-state.json`.

## Optional Environment Variables

- `CLAWSEC_FEED_URL`: override remote feed URL.
- `CLAWSEC_LOCAL_FEED`: override local fallback feed file.
- `CLAWSEC_SUITE_STATE_FILE`: override state file path.
- `CLAWSEC_INSTALL_ROOT`: override installed skills root.
- `CLAWSEC_SUITE_DIR`: override clawsec-suite install path.
- `CLAWSEC_HOOK_INTERVAL_SECONDS`: minimum interval between hook scans (default `300`).
