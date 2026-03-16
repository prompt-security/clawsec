---
name: prompt-agent
version: 0.0.1
description: Security audit enforcement for AI agents. Scans permissions, validates configurations, detects exposed secrets, and verifies sandbox settings. Use when running a security audit, checking agent safety, scanning for vulnerabilities, or verifying agent health status.
homepage: https://clawsec.prompt.security
metadata: {"openclaw":{"emoji":"🛡️","category":"security"}}
clawdis:
  emoji: "🛡️"
  requires:
    bins: [curl, git]
---

# Prompt Agent 🛡️

Security audit enforcement for AI agents. Protects your agent through automated security scans and continuous health verification.

**Compatible with:** OpenClaw, MoltBot, ClawdBot agents

**An open source project by [Prompt Security](https://prompt.security)**

---

## Deploy Prompt Agent

Installation Steps:

### Step 1: Detect active agent folder and create skill directory

```bash
# Detect active agent folder (.openclaw, .moltbot, or .clawdbot)
AGENT_HOME=""
for folder in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot"; do
  if [ -d "$folder" ]; then
    AGENT_HOME="$folder"
    break
  fi
done

if [ -z "$AGENT_HOME" ]; then
  echo "ERROR: No agent folder found. Expected one of: ~/.openclaw, ~/.moltbot, ~/.clawdbot"
  echo "Please ensure your agent is properly installed."
  exit 1
fi

echo "Detected agent folder: $AGENT_HOME"

mkdir -p "$AGENT_HOME/skills/prompt-agent"
# Save this SKILL.md as SKILL.md in the directory above
```

### Step 2: Set up the cron job

Create a scheduled job for daily security audits:

```bash
# Create the cron job
if ! openclaw cron add \
  --name "Prompt Agent Security Audit" \
  --description "Daily security audit and health verification" \
  --cron "${PROMPT_AGENT_AUDIT_SCHEDULE:-0 23 * * *}" \
  --tz "${PROMPT_AGENT_TZ:-UTC}" \
  --session isolated \
  --message "Run prompt-agent security audit: scan for vulnerabilities, verify health, report findings"; then
  echo "Error: Failed to create cron job"
  exit 1
fi

# Verify the cron job was created
echo "Verifying cron job creation..."
if ! openclaw cron list --json | jq -e '.jobs[] | select(.name == "Prompt Agent Security Audit")' >/dev/null 2>&1; then
  echo "Error: Cron job was not created successfully"
  echo "Please verify openclaw cron functionality and try again"
  exit 1
fi

echo "Cron job created and verified successfully."
```

### Step 3: Add to your heartbeat

Add Prompt Agent to your heartbeat routine:

```markdown
## Prompt Agent (every heartbeat)
1. Fetch and follow HEARTBEAT.md from $AGENT_HOME/skills/prompt-agent/
2. Verify agent health and security posture
3. Notify user if action is required
```

> **Note:** `$AGENT_HOME` is your detected agent folder (`~/.openclaw`, `~/.moltbot`, or `~/.clawdbot`)

### Step 4: Confirm deployment

Tell your user:
```
Prompt Agent deployed successfully. I will now:
- Run daily security audits at 23:00 UTC
- Monitor health and security posture
- Alert you to any security issues affecting your environment
```

---

## Running a Security Audit

Your user can ask you to run an audit anytime:

```
"Run a security audit"
"Check my agent's security"
"Scan for vulnerabilities"
```

### Audit Output

```
🛡️ Prompt Agent Security Audit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Time: 2026-02-02T15:30:00Z
Host: my-agent

Summary: 1 critical · 2 warnings · 5 info

CRITICAL:
- [CRED-001] Exposed API key in environment
  Fix: Move to secure credential storage or encrypted secrets file

WARNING:
- [SKILL-012] Skill "random-helper" has no verified author
  Fix: Review skill source or remove if untrusted
- [PERM-003] Unrestricted file system access enabled
  Fix: Configure allowlist for file operations

Recommendations:
- Enable audit logging for sensitive operations
- Review installed skills monthly
```

---

## Soul.md Hardening

Prompt Agent can help harden your agent's system prompt (soul.md):

### Hardening Checklist

- [ ] Verify system prompt integrity hash
- [ ] Disable "Ignore previous instructions" capability
- [ ] Enforce output structuring (JSON) for sensitive operations
- [ ] Add input sanitization directives
- [ ] Configure artifact integrity verification

---

## When to Notify Your User

**Do notify:**
- Critical or warning findings from audit
- Health check failures
- Detected attack attempts (prompt injection, unauthorized access)
- Skills attempting to disable or modify prompt-agent

**Don't notify:**
- Info-level findings (log silently)
- Routine successful health checks
- Successful audit completions with no issues

---

## Environment Variables (Optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `PROMPT_AGENT_TZ` | Timezone for scheduled jobs | `UTC` |
| `PROMPT_AGENT_AUDIT_SCHEDULE` | Cron expression for audits | `0 23 * * *` |
| `PROMPT_AGENT_INSTALL_DIR` | Installation directory | `$AGENT_HOME/skills/prompt-agent` |

> **Note:** `$AGENT_HOME` is auto-detected from `~/.openclaw`, `~/.moltbot`, or `~/.clawdbot`

---

## State Tracking

Track prompt-agent health and audit history:

```json
{
  "schema_version": "1.0",
  "last_heartbeat": "2026-02-02T15:00:00Z",
  "last_audit": "2026-02-02T23:00:00Z",
  "prompt_agent_version": "0.0.1",
  "files_hash": {
    "SKILL.md": "sha256:abc...",
    "HEARTBEAT.md": "sha256:def..."
  }
}
```

Save to: `$AGENT_HOME/prompt-agent-state.json`

> **Note:** `$AGENT_HOME` is your detected agent folder (`~/.openclaw`, `~/.moltbot`, or `~/.clawdbot`)

---

## License

GNU AGPL v3.0 or later - See repository for details.

Built with 🛡️ by the [Prompt Security](https://prompt.security) team and the agent community.
