# ClawSec for NanoClaw

ClawSec now supports NanoClaw, a containerized WhatsApp bot powered by Claude agents.

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

## ClawSec NanoClaw Skill

ClawSec provides a complete security skill for NanoClaw deployments:

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

- **Advisory Cache Service**: Automatic feed fetching every 6 hours
- **Signature Verification**: Ed25519-signed feeds ensure integrity
- **Platform Filtering**: Shows only relevant advisories for NanoClaw
- **IPC Communication**: Container-safe host communication

### Installation

1. Copy the skill to your NanoClaw deployment:
   ```bash
   cp -r skills/clawsec-nanoclaw /path/to/nanoclaw/skills/
   ```

2. Follow the detailed guide at `skills/clawsec-nanoclaw/INSTALL.md`

### Quick Integration

The skill integrates into three places:

**1. MCP Tools** (container):
```typescript
// container/agent-runner/src/ipc-mcp-stdio.ts
import { clawsecTools } from '../../../skills/clawsec-nanoclaw/mcp-tools/advisory-tools.js';
```

**2. IPC Handlers** (host):
```typescript
// host/ipc-handler.ts
import { registerClawSecHandlers } from '../skills/clawsec-nanoclaw/host-services/ipc-handlers.js';
```

**3. Cache Service** (host):
```typescript
// host/index.ts
import { startAdvisoryCache } from '../skills/clawsec-nanoclaw/host-services/advisory-cache.js';
```

### Advisory Feed

NanoClaw consumes the same feed as OpenClaw:
```
https://clawsec.prompt.security/advisories/feed.json
```

The feed is Ed25519 signed and automatically fetched by the cache service.

## Team Credits

This integration was developed by a team of 8 specialized agents coordinated to adapt ClawSec for NanoClaw:

- **pioneer-repo-scout** - ClawSec architecture analysis
- **pioneer-nanoclaw-scout** - NanoClaw architecture analysis
- **architect** - Integration design and coordination
- **advisory-specialist** - Advisory feed integration
- **integrity-specialist** - File integrity design
- **installer-specialist** - Signature verification implementation
- **tester** - Test infrastructure and validation
- **documenter** - Documentation

Total contribution: 3000+ lines of code and comprehensive design documents.

## What's Included

The `clawsec-nanoclaw` skill provides:

- **1,730 lines** of production-ready TypeScript code
- **MCP Tools** (350 lines): Agent-facing vulnerability checking
- **Advisory Cache** (492 lines): Automatic feed fetching and caching
- **Signature Verification** (387 lines): Ed25519 signature validation
- **Advisory Matching** (289 lines): Skill-to-vulnerability correlation
- **IPC Handlers** (212 lines): Container-to-host communication
- **Complete Documentation**: Installation guide, usage examples, troubleshooting

## Future Enhancements

Planned features for future releases:
- File integrity monitoring (soul-guardian adaptation for containers)
- Real-time advisory alerts via WebSocket
- WhatsApp-native security alert formatting
- Behavioral analysis and anomaly detection
- Custom/private advisory feed support

## Documentation

- [Skill Documentation](skills/clawsec-nanoclaw/SKILL.md) - Features and architecture
- [Installation Guide](skills/clawsec-nanoclaw/INSTALL.md) - Detailed setup instructions
- [ClawSec Main README](README.md) - Overall ClawSec documentation
- [Security & Signing](SECURITY-SIGNING.md) - Signature verification details

## Support

- **Issues**: https://github.com/prompt-security/clawsec/issues
- **Security**: security@prompt.security
- NanoClaw Repository: (link TBD)
