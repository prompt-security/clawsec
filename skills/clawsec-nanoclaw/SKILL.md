---
name: clawsec-nanoclaw
version: 0.0.1
description: Use when checking for security vulnerabilities in NanoClaw skills, before installing new skills, or when asked about security advisories affecting the bot
---

# ClawSec for NanoClaw

Security advisory monitoring that protects your WhatsApp bot from known vulnerabilities in skills and dependencies.

## Overview

ClawSec provides MCP tools that check installed skills against a curated feed of security advisories. It prevents installation of vulnerable skills and alerts you to issues in existing ones.

**Core principle:** Check before you install. Monitor what's running.

## When to Use

Use ClawSec tools when:
- Installing a new skill (check safety first)
- User asks "are my skills secure?"
- Investigating suspicious behavior
- Regular security audits
- After receiving security notifications

Do NOT use for:
- Code review (use other tools)
- Performance issues (different concern)
- General debugging

## MCP Tools Available

### Pre-Installation Check

```typescript
// Before installing any skill
const safety = await tools.clawsec_check_skill_safety({
  skillName: 'new-skill',
  version: '1.0.0'  // optional
});

if (!safety.safe) {
  // Show user the risks before proceeding
  console.warn(`Security issues: ${safety.advisories.map(a => a.id)}`);
}
```

### Security Audit

```typescript
// Check all installed skills
const result = await tools.clawsec_check_advisories({
  skillsRoot: '/workspace/project/skills'  // optional
});

if (result.criticalCount > 0) {
  // Alert user immediately
  console.error('CRITICAL vulnerabilities found!');
}
```

### Browse Advisories

```typescript
// List advisories with filters
const advisories = await tools.clawsec_list_advisories({
  platform: 'nanoclaw',    // optional: nanoclaw, openclaw, or both
  severity: 'critical'     // optional: critical, high, medium, low
});
```

## Quick Reference

| Task | Tool | Key Parameter |
|------|------|---------------|
| Pre-install check | `clawsec_check_skill_safety` | `skillName` |
| Audit all skills | `clawsec_check_advisories` | `installRoot` (optional) |
| Browse feed | `clawsec_list_advisories` | `severity`, `type` (optional) |
| Verify package signature | `clawsec_verify_skill_package` | `packagePath` |
| Refresh advisory cache | `clawsec_refresh_cache` | (none) |
| Check file integrity | `clawsec_check_integrity` | `mode`, `autoRestore` (optional) |
| Approve file change | `clawsec_approve_change` | `path` |
| View baseline status | `clawsec_integrity_status` | `path` (optional) |
| Verify audit log | `clawsec_verify_audit` | (none) |

## Common Patterns

### Pattern 1: Safe Skill Installation

```typescript
// ALWAYS check before installing
const safety = await tools.clawsec_check_skill_safety({
  skillName: userRequestedSkill
});

if (safety.safe) {
  // Proceed with installation
  await installSkill(userRequestedSkill);
} else {
  // Show user the risks and get confirmation
  await showSecurityWarning(safety.advisories);
  if (await getUserConfirmation()) {
    await installSkill(userRequestedSkill);
  }
}
```

### Pattern 2: Periodic Security Check

```typescript
// Add to scheduled tasks
schedule_task({
  prompt: "Check for security advisories using clawsec_check_advisories and alert if any critical issues found",
  schedule_type: "cron",
  schedule_value: "0 9 * * *"  // Daily at 9am
});
```

### Pattern 3: User Security Query

```
User: "Are my skills secure?"

You: I'll check installed skills for known vulnerabilities.
[Use clawsec_check_advisories]

Response:
✅ No critical issues found.
- 2 low-severity advisories (not urgent)
- All skills up to date
```

## Common Mistakes

### ❌ Installing without checking
```typescript
// DON'T
await installSkill('untrusted-skill');
```

```typescript
// DO
const safety = await tools.clawsec_check_skill_safety({
  skillName: 'untrusted-skill'
});
if (safety.safe) await installSkill('untrusted-skill');
```

### ❌ Ignoring platform filters
```typescript
// DON'T: Check OpenClaw advisories on NanoClaw
const advisories = await tools.clawsec_list_advisories({
  platform: 'openclaw'  // Wrong platform!
});
```

```typescript
// DO: Use correct platform or let it auto-filter
const advisories = await tools.clawsec_list_advisories({
  platform: 'nanoclaw'  // Correct
});
```

### ❌ Skipping critical severity
```typescript
// DON'T: Only check low severity
if (result.lowCount > 0) alert();
```

```typescript
// DO: Prioritize critical and high
if (result.criticalCount > 0 || result.highCount > 0) {
  // Alert immediately
}
```

## Implementation Details

**Feed Source**: https://clawsec.prompt.security/advisories/feed.json

**Update Frequency**: Every 6 hours (automatic)

**Signature Verification**: Ed25519 signed feeds

**Cache Location**: `/workspace/project/data/clawsec-cache.json`

See [INSTALL.md](./INSTALL.md) for setup and [docs/](./docs/) for advanced usage.

## Real-World Impact

- Prevents installation of skills with known RCE vulnerabilities
- Alerts to supply chain attacks in dependencies
- Provides actionable remediation steps
- Zero false positives (curated feed only)
