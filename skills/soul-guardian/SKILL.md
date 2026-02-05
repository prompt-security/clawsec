---
name: soul-guardian
version: 0.0.1
description: Drift detection + baseline integrity guard for an agent workspace's auto-loaded prompt/instruction markdown files (SOUL.md, AGENTS.md, etc.), with per-file policies, tamper-evident audit logging, and optional auto-restore.
homepage: https://clawsec.prompt.security
metadata: {"openclaw":{"emoji":"👻","category":"security"}}
clawdis:
  emoji: "👻"
  requires:
    bins: [python3]
---

# soul-guardian

Use this skill to detect and respond to unexpected edits in the workspace files that the agent auto-loads.

## Installation Options

You can get soul-guardian in two ways:

### Option A: Bundled with ClawSec Suite (Recommended)

**If you've installed clawsec-suite, you may already have this!**

Soul-guardian is bundled alongside ClawSec Suite to provide file integrity and drift detection capabilities. When you install the suite, if you don't already have soul-guardian installed, it will be deployed from the bundled copy.

**Advantages:**
- Convenient - no separate download needed
- Standard location - installed to `~/.openclaw/skills/soul-guardian/`
- Preserved - if you already have soul-guardian installed, it won't be overwritten
- Single verification - integrity checked as part of suite package

### Option B: Standalone Installation (This Page)

Install soul-guardian independently without the full suite.

**When to use standalone:**
- You only need file integrity monitoring (not other suite components)
- You want to install before installing the suite
- You prefer explicit control over soul-guardian installation

**Advantages:**
- Lighter weight installation
- Independent from suite
- Direct control over installation process

Continue below for standalone installation instructions.

---

## What it protects (default policy)

- **Auto-restore + alert:** `SOUL.md`, `AGENTS.md`
- **Alert-only:** `USER.md`, `TOOLS.md`, `IDENTITY.md`, `HEARTBEAT.md`, `MEMORY.md`
- **Ignored by default:** `memory/*.md` (daily notes)

Policy is stored in the guardian state directory as `policy.json`.

## Quick start (first run)

Recommended: onboard an **external** state dir, then initialize baselines there.

```bash
python3 skills/soul-guardian/scripts/onboard_state_dir.py --agent-id <agentId>
python3 skills/soul-guardian/scripts/soul_guardian.py --state-dir ~/.clawdbot/soul-guardian/<agentId> init --actor sam --note "first baseline"
```

(Full step-by-step + scheduling options are in `README.md`.)

## Commands

Run from the agent workspace root:

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py status
python3 skills/soul-guardian/scripts/soul_guardian.py check
python3 skills/soul-guardian/scripts/soul_guardian.py check --no-restore
python3 skills/soul-guardian/scripts/soul_guardian.py approve --file SOUL.md
python3 skills/soul-guardian/scripts/soul_guardian.py restore --file SOUL.md
python3 skills/soul-guardian/scripts/soul_guardian.py verify-audit
```

### State directory

- Default (backward compatible): `memory/soul-guardian/`
- Recommended external override:

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py --state-dir ~/.clawdbot/soul-guardian/<agentId> check
```

## Cron pattern

Keep the existing gateway cron pattern: run `check` every N minutes and notify only when drift is detected.

For onboarding/migration to an external state directory, see `README.md` and:

```bash
python3 skills/soul-guardian/scripts/onboard_state_dir.py
```
