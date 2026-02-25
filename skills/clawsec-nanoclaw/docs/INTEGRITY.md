# File Integrity Monitoring for NanoClaw

ClawSec's file integrity monitoring protects critical NanoClaw configuration files from unauthorized modification.

## What It Does

**Protects Critical Files:**
- `registered_groups.json` - Prevents unauthorized group access
- `CLAUDE.md` files - Protects agent instructions
- Container/host code - Alerts on unexpected changes

**How It Works:**
1. **Baseline**: Stores SHA-256 hashes of approved file states
2. **Monitoring**: Periodically checks files for changes (drift)
3. **Restore**: Automatically reverts critical files to approved versions
4. **Audit**: Maintains tamper-evident log of all operations

## Quick Start

### Step 1: Verify Installation

Check that integrity monitoring is available:

```bash
# From container
ls /workspace/project/skills/clawsec-nanoclaw/guardian/
# Should show: policy.json, integrity-monitor.ts
```

### Step 2: Initialize Baselines

The first time integrity monitoring runs, it creates baselines automatically:

```typescript
// Agent calls this (happens automatically on first integrity check)
await tools.clawsec_check_integrity();
```

This creates:
```
/workspace/project/data/soul-guardian/
├── baselines.json       # SHA-256 hashes
├── approved/            # File snapshots
│   ├── registered_groups.json
│   └── CLAUDE.md
├── patches/             # Diffs (empty initially)
├── quarantine/          # Tampered files (empty initially)
└── audit.jsonl          # Event log
```

### Step 3: Enable Scheduled Monitoring

Add to main group's scheduled tasks:

```typescript
schedule_task({
  prompt: `
    Check file integrity with clawsec_check_integrity.
    If drift detected and files restored, send WhatsApp message:
    "⚠️ SECURITY ALERT

    Unauthorized changes detected and automatically reverted:
    [list files that were restored]

    Review details: /workspace/project/data/soul-guardian/patches/"
  `,
  schedule_type: 'cron',
  schedule_value: '*/30 * * * *',  // Every 30 minutes
  context_mode: 'isolated'
});
```

That's it! Integrity monitoring is now active.

## MCP Tools Reference

### 1. `clawsec_check_integrity`

Check all protected files for unauthorized changes.

**Parameters:**
- `mode` (optional): `'check'` (default) or `'status'`
  - `check`: Detect drift and auto-restore
  - `status`: View baselines only (no drift detection)
- `autoRestore` (optional): `true` (default) or `false`
  - If `false`, drift is detected but not auto-fixed

**Output:**
```json
{
  "success": true,
  "timestamp": "2026-02-25T12:00:00Z",
  "drift_detected": false,
  "files": [
    {
      "path": "/workspace/project/data/registered_groups.json",
      "status": "ok",
      "mode": "restore",
      "expected_sha": "abc123...",
      "found_sha": "abc123..."
    }
  ],
  "summary": {
    "total": 3,
    "ok": 3,
    "drifted": 0,
    "restored": 0,
    "alerted": 0,
    "errors": 0
  }
}
```

**Example:**
```typescript
const result = await tools.clawsec_check_integrity();

if (result.drift_detected) {
  console.log('⚠️ Drift detected!');
  for (const file of result.files) {
    if (file.status === 'restored') {
      console.log(`✅ Restored: ${file.path}`);
      console.log(`  Diff: ${file.patch_path}`);
    } else if (file.status === 'drifted') {
      console.log(`⚠️ Changed: ${file.path} (alert only)`);
    }
  }
}
```

### 2. `clawsec_approve_change`

Approve an intentional file modification as the new baseline.

**When to use:**
- After legitimately updating CLAUDE.md
- After adding/removing groups in registered_groups.json
- After any intentional change to protected files

**Parameters:**
- `path` (required): Absolute path to file
- `note` (optional): Explanation for audit log

**Output:**
```json
{
  "success": true,
  "path": "/workspace/group/CLAUDE.md",
  "approved_at": "2026-02-25T12:00:00Z",
  "approved_by": "agent",
  "note": "Added new skill instructions"
}
```

**Example:**
```typescript
// After editing CLAUDE.md
await tools.clawsec_approve_change({
  path: '/workspace/group/CLAUDE.md',
  note: 'Updated agent instructions for new skill'
});

console.log('✅ Change approved - new baseline created');
```

### 3. `clawsec_integrity_status`

View current baseline status without checking for drift.

**Parameters:**
- `path` (optional): Specific file, or all if omitted

**Output:**
```json
{
  "success": true,
  "baseline_age": "2026-02-25T10:00:00Z",
  "files": [
    {
      "path": "/workspace/project/data/registered_groups.json",
      "mode": "restore",
      "priority": "critical",
      "has_baseline": true,
      "baseline_sha": "abc123...",
      "approved_at": "2026-02-25T10:00:00Z",
      "snapshot_exists": true
    }
  ]
}
```

**Example:**
```typescript
const status = await tools.clawsec_integrity_status();

console.log('Protected files:');
for (const file of status.files) {
  console.log(`- ${file.path} (${file.mode}, ${file.priority})`);
  console.log(`  Last approved: ${file.approved_at}`);
}
```

### 4. `clawsec_verify_audit`

Verify audit log hash chain integrity.

**No parameters.**

**Output:**
```json
{
  "success": true,
  "valid": true,
  "entries": 42,
  "errors": []
}
```

**Example:**
```typescript
const verification = await tools.clawsec_verify_audit();

if (!verification.valid) {
  console.log('🚨 CRITICAL: Audit log has been tampered with!');
  console.log('Errors:', verification.errors);
} else {
  console.log(`✅ Audit log verified (${verification.entries} entries)`);
}
```

## Protected Files Policy

### Critical Priority (Auto-Restore)

**`/workspace/project/data/registered_groups.json`**
- **Risk**: Tampering grants unauthorized group access
- **Action**: Immediate auto-restore + alert

**`/workspace/group/CLAUDE.md`**
- **Risk**: Modifies agent behavior
- **Action**: Immediate auto-restore + alert

**`/workspace/project/groups/global/CLAUDE.md`**
- **Risk**: Affects all groups
- **Action**: Immediate auto-restore + alert

### Medium Priority (Alert Only)

**Container code** (`/workspace/project/container/**/*.ts`)
- **Risk**: Unexpected code changes
- **Action**: Alert for review (no auto-restore)

**Host code** (`/workspace/project/host/**/*.ts`)
- **Risk**: Unexpected code changes
- **Action**: Alert for review (no auto-restore)

### Ignored

**IPC files** (`/workspace/ipc/**/*`)
- Changes are expected and frequent

**Conversations** (`/workspace/group/conversations/**/*`)
- Changes are expected and frequent

## Workflow Examples

### Scenario 1: Scheduled Monitoring

**Setup:**
```typescript
schedule_task({
  prompt: 'Run clawsec_check_integrity and alert on drift',
  schedule_type: 'cron',
  schedule_value: '*/30 * * * *'
});
```

**What happens:**
1. Every 30 minutes, agent checks integrity
2. If drift detected in critical files:
   - Files auto-restored to baseline
   - Tampered versions quarantined
   - Diff patch generated
   - User alerted via WhatsApp
3. If drift in non-critical files:
   - Alert only, no auto-restore

### Scenario 2: Updating Agent Instructions

**Workflow:**
```typescript
// 1. Edit CLAUDE.md
fs.writeFileSync('/workspace/group/CLAUDE.md', newInstructions);

// 2. Test changes
// ... verify agent behaves correctly ...

// 3. Approve changes
await tools.clawsec_approve_change({
  path: '/workspace/group/CLAUDE.md',
  note: 'Added instructions for new weather skill'
});

// 4. Future integrity checks will use this new baseline
```

### Scenario 3: Adding a New Group

**Workflow:**
```typescript
// 1. Add group to registered_groups.json
const groups = JSON.parse(fs.readFileSync('/workspace/project/data/registered_groups.json'));
groups['new-jid'] = { name: 'Family', folder: 'family', trigger: '@Andy' };
fs.writeFileSync('/workspace/project/data/registered_groups.json', JSON.stringify(groups, null, 2));

// 2. Approve the change
await tools.clawsec_approve_change({
  path: '/workspace/project/data/registered_groups.json',
  note: 'Added family group'
});
```

### Scenario 4: Investigating Drift

**When drift is detected:**
```typescript
const result = await tools.clawsec_check_integrity();

if (result.drift_detected) {
  for (const file of result.files) {
    if (file.status === 'restored') {
      // Critical file was auto-restored
      console.log(`🔧 Auto-restored: ${file.path}`);
      console.log(`📄 Diff: ${file.patch_path}`);
      console.log(`📦 Quarantine: ${file.quarantine_path}`);

      // Review the diff
      const diff = fs.readFileSync(file.patch_path, 'utf-8');
      console.log('Changes that were reverted:');
      console.log(diff);
    }
  }
}
```

## Security Model

### Threat Model

**Protects Against:**
- Unauthorized file modifications
- Group hijacking (via registered_groups.json tampering)
- Agent instruction poisoning (via CLAUDE.md changes)
- Accidental file corruption

**Does NOT Protect Against:**
- Attacker with full host access (can modify baselines)
- Simultaneous baseline + file modification
- Malicious scheduled tasks that approve their own changes

### Baseline Storage

**Location:** `/workspace/project/data/soul-guardian/`

**Access Control:**
- Baselines written only by host process
- Containers access via IPC only
- No container can modify its own baselines

**Integrity:**
- SHA-256 hashes (industry standard)
- Hash-chained audit log (tamper-evident)
- Atomic file operations (safe restores)

### Audit Log

**Format:** JSONL with hash chaining

**Each entry includes:**
```json
{
  "ts": "2026-02-25T12:00:00Z",
  "event": "drift",
  "actor": "agent",
  "path": "/workspace/group/CLAUDE.md",
  "expected_sha": "abc123...",
  "found_sha": "def456...",
  "chain": {
    "prev": "previous_entry_hash",
    "hash": "this_entry_hash"
  }
}
```

**Chain calculation:**
```
hash = SHA-256(prev_hash + '\n' + canonical_json(entry_without_chain))
```

This makes tampering detectable: changing any entry breaks the chain.

## Troubleshooting

### Integrity Check Fails

**Symptom:** `clawsec_check_integrity` returns `success: false`

**Causes:**
1. IntegrityService not initialized
2. Policy file missing
3. Baselines corrupted

**Solution:**
```bash
# Check service status
ls /workspace/project/data/soul-guardian/

# If missing, reinitialize
rm -rf /workspace/project/data/soul-guardian/
# Next integrity check will recreate baselines
```

### False Positives (Legitimate Changes Flagged)

**Symptom:** File keeps getting restored even though changes are legitimate

**Cause:** Baseline not updated after intentional changes

**Solution:**
```typescript
await tools.clawsec_approve_change({
  path: '/path/to/file',
  note: 'Legitimate change'
});
```

### Audit Chain Broken

**Symptom:** `clawsec_verify_audit` returns `valid: false`

**Causes:**
1. Audit log manually edited
2. Filesystem corruption
3. Security breach

**Solution:**
```typescript
const verification = await tools.clawsec_verify_audit();
console.log('Errors:', verification.errors);

// If corruption, backup and reset
cp /workspace/project/data/soul-guardian/audit.jsonl /tmp/audit-backup.jsonl
rm /workspace/project/data/soul-guardian/audit.jsonl
// Audit log will restart on next operation
```

### High Disk Usage

**Symptom:** `/workspace/project/data/soul-guardian/` grows large

**Causes:**
- Many drift events generate patches
- Quarantine files accumulate

**Solution:**
```bash
# Clean old patches (older than 30 days)
find /workspace/project/data/soul-guardian/patches/ -mtime +30 -delete

# Clean quarantine (after review)
rm /workspace/project/data/soul-guardian/quarantine/*
```

## Performance

**Overhead:**
- Baseline check: ~10ms per file
- SHA-256 computation: ~1ms per KB
- Restore operation: ~20ms per file

**Typical deployment:**
- 3-5 protected files
- 30-minute check interval
- < 0.1% CPU usage
- < 5MB disk usage

## Advanced Topics

### Custom Policy

While the default policy is pinned by the skill, you can fork it:

```bash
cp /workspace/project/skills/clawsec-nanoclaw/guardian/policy.json /workspace/project/data/custom-policy.json
```

Edit and reinitialize:
```typescript
// Update IntegrityMonitor initialization
new IntegrityMonitor({
  policyPath: '/workspace/project/data/custom-policy.json',
  stateDir: '/workspace/project/data/soul-guardian'
});
```

### Manual Baseline Export

```bash
# Export current baselines
cp /workspace/project/data/soul-guardian/baselines.json /tmp/baselines-backup.json

# Export approved snapshots
tar -czf /tmp/approved-snapshots.tar.gz /workspace/project/data/soul-guardian/approved/
```

### Baseline Import (Disaster Recovery)

```bash
# Restore baselines
cp /tmp/baselines-backup.json /workspace/project/data/soul-guardian/baselines.json

# Restore snapshots
tar -xzf /tmp/approved-snapshots.tar.gz -C /workspace/project/data/soul-guardian/
```

## FAQ

**Q: Can I disable auto-restore for testing?**

A: Yes, use `autoRestore: false`:
```typescript
await tools.clawsec_check_integrity({ autoRestore: false });
```

**Q: How do I protect additional files?**

A: Edit `policy.json` and add targets:
```json
{
  "path": "/workspace/group/my-config.json",
  "mode": "restore",
  "priority": "high",
  "description": "My custom config"
}
```

**Q: What happens if both baseline and file are modified?**

A: The most recent baseline wins. Always approve legitimate changes immediately.

**Q: Can I run integrity checks on-demand?**

A: Yes, just call `clawsec_check_integrity` from any agent.

**Q: Is the audit log encrypted?**

A: No, but it's hash-chained for tamper detection. Encryption can be added in Phase 3.

## Support

- **Documentation**: https://clawsec.prompt.security/
- **Issues**: https://github.com/prompt-security/clawsec/issues
- **Security Reports**: security@prompt.security

---

**Ready to protect your NanoClaw deployment? Start with the [Quick Start](#quick-start) guide above.**
