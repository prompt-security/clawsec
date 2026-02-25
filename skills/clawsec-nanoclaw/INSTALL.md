# ClawSec for NanoClaw - Installation Guide

This guide shows how to add ClawSec security monitoring to your NanoClaw deployment.

## Overview

ClawSec provides security advisory monitoring for NanoClaw through:
- **MCP Tools**: Agents can check for vulnerabilities via `clawsec_check_advisories`
- **Advisory Feed**: Automatic monitoring of https://clawsec.prompt.security/advisories/feed.json
- **Signature Verification**: Ed25519-signed feeds ensure integrity
- **Platform Targeting**: Advisories can be NanoClaw-specific or cross-platform

## Prerequisites

- NanoClaw >= 0.1.0
- Node.js >= 18.0.0
- Write access to NanoClaw installation directory

## Installation Steps

### 1. Copy Skill Files

Copy the `clawsec-nanoclaw` skill directory to your NanoClaw installation:

```bash
# From the ClawSec repository
cp -r skills/clawsec-nanoclaw /path/to/your/nanoclaw/skills/
```

### 2. Integrate MCP Tools

Add the ClawSec MCP tools to your NanoClaw container agent runner.

**File**: `container/agent-runner/src/ipc-mcp-stdio.ts`

```typescript
// Add these imports at the top to register all ClawSec MCP tools:

// Advisory tools: clawsec_check_advisories, clawsec_check_skill_safety,
//                 clawsec_list_advisories, clawsec_refresh_cache
import '../../../skills/clawsec-nanoclaw/mcp-tools/advisory-tools.js';

// Signature verification: clawsec_verify_skill_package
import '../../../skills/clawsec-nanoclaw/mcp-tools/signature-verification.js';

// Integrity monitoring: clawsec_check_integrity, clawsec_approve_change,
//                       clawsec_integrity_status, clawsec_verify_audit
import '../../../skills/clawsec-nanoclaw/mcp-tools/integrity-tools.js';
```

Each file calls `server.tool()` directly to register its tools. The `server`,
`writeIpcFile`, `TASKS_DIR`, and `groupFolder` variables must be available in
the scope where these files are imported (they are declared as ambient globals
in each tool file).

### 3. Integrate IPC Handlers

Add the host-side IPC handlers for ClawSec operations.

**File**: `host/ipc-handler.ts`

```typescript
// Add this import at the top
import { registerClawSecHandlers } from '../skills/clawsec-nanoclaw/host-services/ipc-handlers.js';

// In your IPC handler setup function
export function setupIpcHandlers() {
  // ... your existing handlers ...

  // Register ClawSec handlers
  registerClawSecHandlers();
}
```

### 4. Start Advisory Cache Service

Add the advisory cache manager to your host services.

**File**: `host/index.ts` (or your main entry point)

```typescript
// Add this import
import { startAdvisoryCache } from '../skills/clawsec-nanoclaw/host-services/advisory-cache.js';

// Start the service when your host process starts
async function main() {
  // ... your existing initialization ...

  // Start ClawSec advisory cache (fetches feed every 6 hours)
  startAdvisoryCache({
    cacheFile: '/workspace/project/data/clawsec-advisory-cache.json',
    feedUrl: 'https://clawsec.prompt.security/advisories/feed.json',
    publicKeyPath: '/workspace/project/skills/clawsec-nanoclaw/advisories/feed-signing-public.pem',
    refreshInterval: 6 * 60 * 60 * 1000, // 6 hours
  });

  // ... rest of your startup ...
}
```

### 5. Restart NanoClaw

Restart your NanoClaw instance to load the new MCP tools and services:

```bash
# Stop NanoClaw
docker-compose down

# Start with new configuration
docker-compose up -d
```

## Verification

Test that ClawSec is working:

### 1. Check MCP Tools Available

From within a NanoClaw agent session, the following tools should be available:

**Advisory Tools** (mcp-tools/advisory-tools.ts):
- `clawsec_check_advisories` - Scan installed skills for vulnerabilities
- `clawsec_check_skill_safety` - Pre-installation safety check
- `clawsec_list_advisories` - List all advisories with filtering
- `clawsec_refresh_cache` - Request immediate advisory cache refresh

**Signature Verification** (mcp-tools/signature-verification.ts):
- `clawsec_verify_skill_package` - Verify Ed25519 signature on skill packages

**Integrity Monitoring** (mcp-tools/integrity-tools.ts):
- `clawsec_check_integrity` - Check protected files for unauthorized changes
- `clawsec_approve_change` - Approve intentional file modification as new baseline
- `clawsec_integrity_status` - View current baseline status
- `clawsec_verify_audit` - Verify audit log hash chain integrity

### 2. Test Advisory Checking

Ask your NanoClaw agent:
```
Check if any of my installed skills have security advisories
```

The agent should use the `clawsec_check_advisories` tool and report results.

### 3. Check Advisory Cache

Verify the cache file was created:
```bash
cat /workspace/project/data/clawsec-advisory-cache.json
```

You should see:
- `feed`: Array of advisories
- `signature`: Ed25519 signature
- `lastFetch`: Timestamp of last update
- `verified`: Should be `true`

## Usage Examples

### Agent Commands

Once installed, your NanoClaw agents can:

**Check for vulnerabilities:**
```
Scan my installed skills for security issues
```

**Pre-installation check:**
```
Is it safe to install skill-name@1.0.0?
```

**List all advisories:**
```
Show me all ClawSec security advisories
```

### Manual Tool Invocation

You can also call the MCP tools directly from agent code:

```typescript
// Check all installed skills
const result = await tools.clawsec_check_advisories({
  skillsRoot: '/workspace/project/skills'
});

// Check specific skill before installation
const safetyCheck = await tools.clawsec_check_skill_safety({
  skillName: 'risky-skill',
  version: '1.0.0'
});
```

## Configuration

### Cache Location

Default: `/workspace/project/data/clawsec-advisory-cache.json`

To change, update the `cacheFile` parameter in `startAdvisoryCache()`.

### Refresh Interval

Default: 6 hours

To change, update the `refreshInterval` parameter (in milliseconds).

### Feed URL

Default: `https://clawsec.prompt.security/advisories/feed.json`

To use a mirror or custom feed, update the `feedUrl` parameter.

## Platform-Specific Advisories

ClawSec advisories can target specific platforms:

- **`platforms: ["nanoclaw"]`**: Only affects NanoClaw
- **`platforms: ["openclaw"]`**: Only affects OpenClaw/MoltBot
- **`platforms: ["openclaw", "nanoclaw"]`**: Affects both
- **No `platforms` field**: Applies to all platforms

The MCP tools automatically filter advisories based on your platform.

## Security

### Signature Verification

All advisory feeds are Ed25519 signed. The public key is pinned in:
```
skills/clawsec-nanoclaw/advisories/feed-signing-public.pem
```

Feeds failing signature verification are rejected.

### Cache Integrity

The advisory cache includes:
- Cryptographic signature of feed contents
- Verification status
- Timestamp of last successful fetch

Never manually edit the cache file - it will break signature verification.

## Troubleshooting

### Tools Not Appearing

**Problem**: MCP tools not showing up in agent

**Solution**:
1. Check that you added the import and registration in `ipc-mcp-stdio.ts`
2. Restart the container
3. Check container logs for import errors

### Cache Not Updating

**Problem**: Advisory cache is empty or stale

**Solution**:
1. Check that `startAdvisoryCache()` is called in your host entry point
2. Verify network access to `clawsec.prompt.security`
3. Check host logs for fetch errors
4. Manually trigger: `curl https://clawsec.prompt.security/advisories/feed.json`

### Signature Verification Failing

**Problem**: Cache shows `"verified": false`

**Solution**:
1. Ensure public key file exists at correct path
2. Check file permissions (should be readable)
3. Verify feed URL is correct (not using HTTP instead of HTTPS)
4. Check for corrupted downloads (try clearing cache and refetching)

### IPC Communication Issues

**Problem**: Tools return errors about IPC

**Solution**:
1. Verify IPC handlers are registered in `host/ipc-handler.ts`
2. Check that IPC directory exists and is writable
3. Ensure host process is running
4. Check host logs for handler errors

## Uninstallation

To remove ClawSec from NanoClaw:

1. Remove MCP tool registration from `ipc-mcp-stdio.ts`
2. Remove IPC handler registration from `host/ipc-handler.ts`
3. Remove `startAdvisoryCache()` call from host entry point
4. Delete the skill directory: `rm -rf skills/clawsec-nanoclaw`
5. Delete the cache file: `rm /workspace/project/data/clawsec-advisory-cache.json`
6. Restart NanoClaw

## Support

- **Documentation**: https://clawsec.prompt.security/
- **Issues**: https://github.com/prompt-security/clawsec/issues
- **Security**: security@prompt.security

## License

AGPL-3.0-or-later

---

**Questions?** Open an issue or check the main ClawSec documentation.
