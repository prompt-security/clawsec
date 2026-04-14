---
name: soul-guardian
version: 0.0.5
description: Drift detection + baseline integrity guard for agent workspace files with automatic alerting support
homepage: https://clawsec.prompt.security
metadata: {"openclaw":{"emoji":"👻","category":"security"}}
clawdis:
  emoji: "👻"
  requires:
    bins: [python3]
---

# soul-guardian 👻

Protects your agent's core files (SOUL.md, AGENTS.md, etc.) from unauthorized changes with automatic detection, restoration, and **user alerting**.

## Operational Notes

- Required runtime: `python3`
- Optional runtime: `openclaw` for cron integration, `launchctl` for macOS scheduling, `bash` for the demo helper
- Side effects: can auto-restore protected files to their approved baseline and writes audit/quarantine state locally
- Network behavior: none by default
- Trust model: any scheduling is opt-in, but restore mode intentionally overwrites drifted files

## Quick Start (3 Steps)

### Step 1: Initialize baselines
```bash
cd ~/.openclaw/workspace
python3 skills/soul-guardian/scripts/soul_guardian.py init --actor setup --note "initial baseline"
```

### Step 2: Enable monitoring
```bash
python3 skills/soul-guardian/scripts/soul_guardian.py enable-monitoring
```
This shows you how to add monitoring to your workflow.

### Step 3: Add to HEARTBEAT.md (Recommended)

Add this to your HEARTBEAT.md for automatic monitoring:

```markdown
## Soul Guardian Check
- Run `python3 skills/soul-guardian/scripts/soul_guardian.py check --actor heartbeat --output-format alert`
- If any output is produced, relay it to the user immediately as a security alert
```

That's it! Soul Guardian will now:
- ✅ Detect unauthorized changes to protected files
- ✅ Auto-restore SOUL.md and AGENTS.md to approved baseline
- ✅ Alert you when drift is detected and handled

---

## What it protects (default policy)

| File | Mode | Action on drift |
|------|------|-----------------|
| SOUL.md | restore | Auto-restore + alert |
| AGENTS.md | restore | Auto-restore + alert |
| USER.md | alert | Alert only |
| TOOLS.md | alert | Alert only |
| IDENTITY.md | alert | Alert only |
| HEARTBEAT.md | alert | Alert only |
| MEMORY.md | alert | Alert only |
| memory/*.md | ignore | Ignored |

## Commands

### Check for drift (with alert output)
```bash
python3 skills/soul-guardian/scripts/soul_guardian.py check --output-format alert
```
- Silent if no drift
- Outputs human-readable alert if drift detected
- Perfect for heartbeat integration

### Watch mode (continuous monitoring)
```bash
python3 skills/soul-guardian/scripts/soul_guardian.py watch --interval 30
```
Runs continuously, checking every 30 seconds.

### Approve intentional changes
```bash
python3 skills/soul-guardian/scripts/soul_guardian.py approve --file SOUL.md --actor user --note "intentional update"
```

### View status
```bash
python3 skills/soul-guardian/scripts/soul_guardian.py status
```

### Verify audit log integrity
```bash
python3 skills/soul-guardian/scripts/soul_guardian.py verify-audit
```

---

## Alert Format

When drift is detected, the `--output-format alert` produces output like:

```
==================================================
🚨 SOUL GUARDIAN SECURITY ALERT
==================================================

📄 FILE: SOUL.md
   Mode: restore
   Status: ✅ RESTORED to approved baseline
   Expected hash: abc123def456...
   Found hash:    789xyz000111...
   Diff saved: /path/to/patches/drift.patch

==================================================
Review changes and investigate the source of drift.
If intentional, run: soul_guardian.py approve --file <path>
==================================================
```

This output is designed to be relayed directly to the user in TUI/chat.

---

## Security Model

**What it does:**
- Detects filesystem drift vs approved baseline (sha256)
- Produces unified diffs for review
- Maintains tamper-evident audit log with hash chaining
- Refuses to operate on symlinks
- Uses atomic writes for restores

**What it doesn't do:**
- Cannot prove WHO made a change (actor is best-effort metadata)
- Cannot protect if attacker controls both workspace AND state directory
- Is not a substitute for backups

**Recommendation:** Store state directory outside workspace for better resilience.

---

## Demo

Run the full demo flow to see soul-guardian in action:

```bash
bash skills/soul-guardian/scripts/demo.sh
```

This will:
1. Verify clean state (silent check)
2. Inject malicious content into SOUL.md
3. Run heartbeat check (produces alert)
4. Show SOUL.md was restored

---

## Troubleshooting

**"Not initialized" error:**
Run `init` first to set up baselines.

**Drift keeps happening:**
Check what's modifying your files. Review the audit log and patches.

**Want to approve a change:**
Run `approve --file <path>` after reviewing the change.
