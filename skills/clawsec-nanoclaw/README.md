# ClawSec for NanoClaw v1 (Legacy Adapter)

This package preserves the original ClawSec integration for pre-v2 NanoClaw deployments.

## Compatibility

- Supported NanoClaw range: `>=0.1.0 <2.0.0`.
- NanoClaw v2 (`>=2.0.0`): **incompatible; do not install or activate this adapter**.
- The bundled IPC, cache, scheduler, and integrity examples describe the v1 layout only.
- NanoClaw v2 needs a separate adapter for its current host, container, SQLite IPC, and extension surfaces.

This package remains available for legacy users and migration evidence. It is not a NanoClaw v2 installation path.

## What Changed

### Advisory Feed Monitoring
- **NVD CVE Pipeline**: Now monitors for NanoClaw-specific keywords
  - "NanoClaw", "WhatsApp-bot", "baileys" (WhatsApp library)
  - Container-related vulnerabilities
- **Platform Targeting**: Advisories can specify `platforms: ["nanoclaw"]` for NanoClaw-specific issues

### Keywords Added
The CVE monitoring now includes:
- `NanoClaw` - Direct product name
- `WhatsApp-bot` - Core functionality
- `baileys` - WhatsApp client library dependency

## Advisory Schema

Advisories now support optional `platforms` field:

```json
{
  "id": "CVE-2026-XXXXX",
  "platforms": ["openclaw", "nanoclaw"],
  "severity": "critical",
  "type": "prompt_injection",
  "affected": ["skill-name@1.0.0"],
  "action": "Update to version 1.0.1"
}
```

**Platform values:**
- `"openclaw"` - Affects OpenClaw/ClawdBot/MoltBot only
- `"nanoclaw"` - Affects NanoClaw only
- `["openclaw", "nanoclaw"]` - Affects both platforms
- (empty/missing) - Applies to all platforms (backward compatible)

## Legacy ClawSec NanoClaw Skill

ClawSec provides a legacy adapter for compatible pre-v2 NanoClaw deployments:

**Location**: `skills/clawsec-nanoclaw/`

### Features

- **9 MCP Tools** for agents to manage security:
  - `clawsec_check_advisories` - Scan installed skills for vulnerabilities
  - `clawsec_check_skill_safety` - Pre-installation safety checks
  - `clawsec_list_advisories` - Browse advisory feed with filtering
  - `clawsec_refresh_cache` - Request immediate advisory cache refresh
  - `clawsec_verify_skill_package` - Verify Ed25519 signatures on skill packages
  - `clawsec_check_integrity` - Check protected files for unauthorized changes
  - `clawsec_approve_change` - Approve intentional file modifications
  - `clawsec_integrity_status` - View file baseline status
  - `clawsec_verify_audit` - Verify audit log hash chain

- **Advisory Cache Service**: Host-managed feed fetching with signature validation
- **Signature Verification**: Ed25519-signed feeds ensure integrity
- **Exploitability Context**: Surfaces `exploitability_score` and rationale to reduce alert fatigue
- **IPC Communication**: Container-safe host communication

### Legacy v1 Integration Map

Only operators who have confirmed a target version in `>=0.1.0 <2.0.0` should use the detailed [legacy installation guide](./INSTALL.md). Do not raw-copy or import these files into NanoClaw v2.

The v1 adapter historically integrates into three v1 locations:

**1. MCP Tools** (container):
```typescript
// container/agent-runner/src/ipc-mcp-stdio.ts
import '../../../skills/clawsec-nanoclaw/mcp-tools/advisory-tools.js';
```

**2. IPC Handlers** (host):
```typescript
// src/ipc.ts
import { handleAdvisoryIpc } from '../skills/clawsec-nanoclaw/host-services/ipc-handlers.js';
```

**3. Cache Service** (host):
```typescript
// src/index.ts
import { AdvisoryCacheManager } from '../skills/clawsec-nanoclaw/host-services/advisory-cache.js';
```

### Advisory Feed

NanoClaw consumes the same feed as OpenClaw:
```
https://clawsec.prompt.security/advisories/feed.json
```

The feed is Ed25519 signed. A v1 operator must explicitly wire and start the cache service; this package does not install an automatic scheduler.

## Legacy Implementation Status

The MCP tools, host services, IPC handlers, and integrity code are frozen v1 implementation and migration evidence. They are not a starting point for claiming NanoClaw v2 support. A future v2 core, suite, and drift guardian must use the v2-native workflow and land in separate packages and PRs.

## Documentation

- [Skill Documentation](./SKILL.md) - Legacy v1 behavior and compatibility boundary
- [Installation Guide](./INSTALL.md) - Legacy v1 integration instructions
- [ClawSec Main README](../../README.md) - Overall ClawSec documentation
- [Security & Signing](../../wiki/security-signing-runbook.md) - Signature verification details

## Support

- **Issues**: https://github.com/prompt-security/clawsec/issues
- **Security**: security@prompt.security
- NanoClaw Repository: https://github.com/qwibitai/nanoclaw
