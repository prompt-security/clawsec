# soul-guardian

A small, dependency-free integrity guard for Clawdbot agent workspaces.

It helps you detect (and optionally auto-undo) unexpected edits to the workspace markdown files that an agent auto-loads (e.g., `SOUL.md`, `AGENTS.md`). It also records a **tamper-evident** audit trail of changes.

## Why this exists

In many Clawdbot setups, the agent reads certain markdown files every session (identity, instructions, memory, tools, etc.). If those files drift unexpectedly (accidental edits, bad merges, unwanted automation, etc.), you want:

- detection (sha256 mismatch)
- a diff/patch artifact for review
- a record of what happened (audit log)
- optionally: an automatic restore to a known-good baseline for critical files

## What it protects (default policy)

Default `policy.json` protects:

- **Auto-restore + alert:** `SOUL.md`, `AGENTS.md`
- **Alert-only:** `USER.md`, `TOOLS.md`, `IDENTITY.md`, `HEARTBEAT.md`, `MEMORY.md`
- **Ignored by default:** `memory/*.md` (daily notes)

You can customize this by editing the policy file in the guardian state directory.

## Security model (and limitations)

What it does well:
- Detects filesystem drift vs an approved baseline.
- Produces unified diffs (patch files) for review.
- Maintains an **append-only JSONL audit log** with **hash chaining** so log tampering is detectable.
- Refuses to operate on **symlinks** (reduces link attacks).
- Uses **atomic writes** for restores and baseline updates (`os.replace`).

What it does *not* do:
- It cannot prove *who* changed a file. `--actor` is best-effort metadata.
- It cannot protect you if an attacker can modify both the workspace and the guardian state directory.
- It is not a substitute for backups.

Recommendation (not enforced):
- Mirror/back up your guardian state directory (and/or workspace) using git and/or offsite backups.

## State directory

By default, state is stored inside the workspace:

- `memory/soul-guardian/`
  - `policy.json` (what to monitor)
  - `baselines.json` (approved sha256 per file)
  - `approved/<path>` (approved snapshots)
  - `audit.jsonl` (append-only log with hash chain)
  - `patches/*.patch` (unified diffs)
  - `quarantine/*` (copies of drifted files before restore)

For better resilience, you can move this **outside** the workspace (recommended).

## Install / usage

From the agent workspace root.

### First run / Initialize baselines (recommended)

For resilience, create your guardian **state directory outside** the workspace first, then initialize baselines.

1) Onboard an external state dir (creates policy, copies any existing state, prints paths/snippets):

```bash
python3 skills/soul-guardian/scripts/onboard_state_dir.py --agent-id <agentId>
```

2) Initialize baselines **in that external state dir**:

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py \
  --state-dir ~/.clawdbot/soul-guardian/<agentId> \
  init --actor sam --note "first baseline"
```

3) Run a check once (should be silent on OK; prints a single-line summary on drift):

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py \
  --state-dir ~/.clawdbot/soul-guardian/<agentId> \
  check --actor system --note "first check"
```

### Common commands

Status (summary):

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py \
  --state-dir ~/.clawdbot/soul-guardian/<agentId> \
  status
```

Check for drift (default: restores restore-mode files):

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py \
  --state-dir ~/.clawdbot/soul-guardian/<agentId> \
  check --actor system --note cron
```

Alert-only check (never restore):

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py \
  --state-dir ~/.clawdbot/soul-guardian/<agentId> \
  check --no-restore
```

Approve intentional edits (one file):

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py \
  --state-dir ~/.clawdbot/soul-guardian/<agentId> \
  approve --file SOUL.md --actor sam --note "intentional update"
```

Approve all policy targets (except ignored ones):

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py \
  --state-dir ~/.clawdbot/soul-guardian/<agentId> \
  approve --all --actor sam --note "bulk approve"
```

Restore (only restore-mode files):

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py \
  --state-dir ~/.clawdbot/soul-guardian/<agentId> \
  restore --file SOUL.md --actor system --note "manual restore"
```

Verify audit log tamper-evidence:

```bash
python3 skills/soul-guardian/scripts/soul_guardian.py \
  --state-dir ~/.clawdbot/soul-guardian/<agentId> \
  verify-audit
```

## Policy format (`policy.json`)

Example:

```json
{
  "version": 1,
  "workspaceRoot": "/path/to/workspace",
  "targets": [
    {"path": "SOUL.md", "mode": "restore"},
    {"path": "AGENTS.md", "mode": "restore"},
    {"path": "USER.md", "mode": "alert"},
    {"pattern": "memory/*.md", "mode": "ignore"}
  ]
}
```

- `mode`:
  - `restore`: drift triggers audit + patch + (by default) restore + quarantine copy
  - `alert`: drift triggers audit + patch, but does not restore
  - `ignore`: excluded

## Onboarding: move state outside the workspace

Run the helper:

```bash
python3 skills/soul-guardian/scripts/onboard_state_dir.py
```

It will:
- create an external state dir (**recommended default:** `~/.clawdbot/soul-guardian/<agentId>/`)
- copy (or move with `--move`) existing state from `memory/soul-guardian/`
- write a default `policy.json` if missing
- print scheduling snippets

Notes:
- `<agentId>` should be **stable and unique per workspace** (don’t point multiple workspaces at the same state dir).
- WARNING: `--move` deletes the old in-workspace state dir after copying.
- The external state dir can contain **approved snapshots, patches, and quarantined copies** of sensitive prompt/instruction/memory files. Keep permissions restrictive (e.g., `chmod 700 <dir>`; `chmod go-rwx <dir>`).

Then include `--state-dir` in all commands (run from the workspace root), e.g.:

```bash
cd <workspace> && python3 skills/soul-guardian/scripts/soul_guardian.py --state-dir ~/.clawdbot/soul-guardian/<agentId> check
```

## Scheduling (cron)

### A) Clawdbot Gateway Cron (recommended)

This is the default pattern when you want drift notifications to flow through Clawdbot.

Note: even when there is **no drift**, Clawdbot cron runs typically show an **OK summary** in the main session.

Example (edit paths + schedule):

```bash
clawdbot cron add \
  --name "soul-guardian: check workspace" \
  --description "Run soul-guardian check; alert when drift detected." \
  --session isolated \
  --wake now \
  --cron "*/10 * * * *" \
  --tz UTC \
  --message "Run:\ncd '<workspace>'\npython3 skills/soul-guardian/scripts/soul_guardian.py --state-dir ~/.clawdbot/soul-guardian/<agentId> check --actor cron --note 'gateway-cron'\n\nIf the command prints a line starting with 'SOUL_GUARDIAN_DRIFT', treat it as an alert. If it prints nothing, reply HEARTBEAT_OK." \
  --post-prefix "[soul-guardian]" \
  --post-mode summary
```

### B) macOS launchd (optional, silent-on-OK)

If you want **system scheduling** without Clawdbot posting OK summaries, use `launchd`.

Because `soul_guardian.py check` prints **nothing** on OK and prints a single-line `SOUL_GUARDIAN_DRIFT ...` summary on drift, this tends to be silent unless something changed.

Generate + (optionally) install a LaunchAgent plist (run from the workspace root, or pass `--workspace-root`):

```bash
python3 skills/soul-guardian/scripts/install_launchd_plist.py \
  --state-dir ~/.clawdbot/soul-guardian/<agentId> \
  --interval-seconds 600 \
  --install
```

The generated plist includes `WorkingDirectory` set to your workspace root (recommended), so relative paths behave as expected.

The script writes drift output to log files under `<state-dir>/logs/`.
You can tail them with the commands it prints.

## Development / tests

A minimal test script is included:

```bash
python3 skills/soul-guardian/scripts/test_soul_guardian.py
```

It simulates a workspace in a temp directory and validates drift detection, approve/restore flow, and audit hash chain verification.
