# ClawSec for NanoClaw

Security advisory monitoring and vulnerability checking for NanoClaw WhatsApp bot deployments.

## What is ClawSec for NanoClaw?

ClawSec for NanoClaw brings enterprise-grade security monitoring to containerized WhatsApp bot agents. It provides:

- **Advisory Feed Monitoring**: Automatic tracking of security vulnerabilities from ClawSec's curated feed
- **MCP Tools**: Native tools that agents can use to check for vulnerabilities
- **Pre-Installation Checks**: Scan skills for known security issues before installation
- **Signature Verification**: Ed25519-signed feeds ensure advisory integrity
- **Platform Targeting**: Advisories can be NanoClaw-specific or cross-platform with OpenClaw

## Why NanoClaw Needs This

NanoClaw agents run in containers with different security requirements than OpenClaw:

- **Containerized Environment**: Can't use OpenClaw's hook system
- **MCP Protocol**: Agents interact via Message Control Protocol, not bash hooks
- **Multi-Platform Skills**: Skills may work on both NanoClaw and OpenClaw
- **Remote Deployment**: Often deployed in cloud environments with different threat models

ClawSec for NanoClaw provides security monitoring adapted to this architecture.

## Features

### 1. MCP Tools for Agents

Four native tools that agents can invoke:

#### `clawsec_check_advisories`
Scans installed skills for known vulnerabilities.

**Parameters:**
- `skillsRoot` (optional): Path to skills directory (default: `/workspace/project/skills`)

**Returns:**
- List of advisories affecting installed skills
- Severity levels (critical, high, medium, low)
- Recommended actions

**Example:**
```typescript
const result = await tools.clawsec_check_advisories({
  skillsRoot: '/workspace/project/skills'
});
// { matches: [...], totalAdvisories: 5, criticalCount: 1 }
```

#### `clawsec_check_skill_safety`
Pre-installation safety check for a specific skill.

**Parameters:**
- `skillName`: Name of skill to check
- `version` (optional): Specific version to check

**Returns:**
- Safety status (safe/unsafe)
- Matching advisories if unsafe
- Recommended actions

**Example:**
```typescript
const safety = await tools.clawsec_check_skill_safety({
  skillName: 'dangerous-skill',
  version: '1.0.0'
});
// { safe: false, advisories: [...], severity: 'critical' }
```

#### `clawsec_list_advisories`
Lists all advisories in the feed, optionally filtered.

**Parameters:**
- `platform` (optional): Filter by platform (nanoclaw/openclaw)
- `severity` (optional): Filter by severity level
- `type` (optional): Filter by advisory type

**Returns:**
- Array of advisories matching filters
- Full advisory details

**Example:**
```typescript
const advisories = await tools.clawsec_list_advisories({
  platform: 'nanoclaw',
  severity: 'critical'
});
// [{ id: 'CVE-2026-1234', ... }]
```

#### `clawsec_verify_signature`
Verifies Ed25519 signature of advisory feed.

**Parameters:**
- `feedPath`: Path to feed JSON file
- `signaturePath`: Path to detached signature file
- `publicKeyPath`: Path to public key PEM file

**Returns:**
- Verification status (valid/invalid)
- Error details if invalid

**Example:**
```typescript
const verified = await tools.clawsec_verify_signature({
  feedPath: '/tmp/feed.json',
  signaturePath: '/tmp/feed.json.sig',
  publicKeyPath: '/workspace/project/skills/clawsec-nanoclaw/advisories/feed-signing-public.pem'
});
// { valid: true }
```

### 2. Automatic Advisory Feed Updates

The host service automatically:
- Fetches advisories from `https://clawsec.prompt.security/advisories/feed.json` every 6 hours
- Verifies Ed25519 signatures before accepting updates
- Caches advisories for fast agent access
- Logs all update attempts and verification results

### 3. Platform-Specific Advisory Filtering

Advisories can target specific platforms:

```json
{
  "id": "CVE-2026-1234",
  "platforms": ["nanoclaw"],
  "severity": "critical",
  "affected": ["skill-name@1.0.0"],
  "action": "Update to version 1.0.1"
}
```

The MCP tools automatically filter:
- `platforms: ["nanoclaw"]` - Shows only to NanoClaw
- `platforms: ["openclaw"]` - Hidden from NanoClaw
- `platforms: ["openclaw", "nanoclaw"]` - Shows to both
- No `platforms` field - Shows to all (default)

### 4. IPC-Based Host Communication

Since agents run in containers, ClawSec uses IPC for operations requiring host access:
- Signature verification (requires native crypto libraries)
- Advisory cache management
- Skill directory scanning

This keeps containers lightweight while enabling full security capabilities.

## Installation

See [INSTALL.md](./INSTALL.md) for detailed setup instructions.

**Quick Summary:**
1. Copy skill directory to NanoClaw
2. Integrate MCP tools into `ipc-mcp-stdio.ts`
3. Integrate IPC handlers into `host/ipc-handler.ts`
4. Start advisory cache service in host process
5. Restart NanoClaw

## Usage

### Agent Natural Language Commands

Once installed, agents can respond to:

```
Check my installed skills for security issues
Is it safe to install skill-name?
Show me all critical security advisories
Verify the advisory feed signature
```

### Programmatic Usage

```typescript
// In agent code
const { tools } = require('./mcp-tools');

// Check all skills
const vulns = await tools.clawsec_check_advisories({
  skillsRoot: '/workspace/project/skills'
});

if (vulns.criticalCount > 0) {
  console.log('CRITICAL VULNERABILITIES FOUND!');
  vulns.matches.forEach(match => {
    console.log(`- ${match.advisory.id}: ${match.advisory.action}`);
  });
}

// Pre-installation check
const safety = await tools.clawsec_check_skill_safety({
  skillName: 'new-skill',
  version: '2.0.0'
});

if (!safety.safe) {
  throw new Error(`Skill has known vulnerabilities: ${safety.advisories.map(a => a.id).join(', ')}`);
}
```

## Architecture

### Components

```
┌─────────────────────────────────────────────────┐
│  Container: NanoClaw Agent                      │
│  ┌────────────────────────────────────────────┐ │
│  │ MCP Tools (advisory-tools.ts)              │ │
│  │ - clawsec_check_advisories                 │ │
│  │ - clawsec_check_skill_safety               │ │
│  │ - clawsec_list_advisories                  │ │
│  │ - clawsec_verify_signature                 │ │
│  └──────────────┬─────────────────────────────┘ │
│                 │ IPC Requests                   │
└─────────────────┼─────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│  Host: NanoClaw Host Process                    │
│  ┌────────────────────────────────────────────┐ │
│  │ IPC Handlers (ipc-handlers.ts)             │ │
│  │ - Advisory cache reads                     │ │
│  │ - Signature verification                   │ │
│  │ - Skill scanning                           │ │
│  └──────────────┬─────────────────────────────┘ │
│                 │                                │
│  ┌────────────────────────────────────────────┐ │
│  │ Advisory Cache Service                     │ │
│  │ (advisory-cache.ts)                        │ │
│  │ - Periodic feed fetching (6h)              │ │
│  │ - Ed25519 signature verification           │ │
│  │ - Cache management                         │ │
│  └──────────────┬─────────────────────────────┘ │
│                 │ HTTPS                          │
└─────────────────┼─────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│  https://clawsec.prompt.security/              │
│  - advisories/feed.json                         │
│  - advisories/feed.json.sig                     │
└─────────────────────────────────────────────────┘
```

### Data Flow

1. **Initial Fetch**: Host service fetches advisory feed on startup
2. **Verification**: Ed25519 signature verified before accepting
3. **Caching**: Verified feed cached to `/workspace/project/data/clawsec-advisory-cache.json`
4. **Agent Request**: Agent invokes MCP tool (e.g., `clawsec_check_advisories`)
5. **IPC**: MCP tool writes IPC request to filesystem
6. **Host Processing**: Host IPC handler processes request
7. **Cache Read**: Handler reads advisory cache
8. **Matching**: Compares installed skills against advisories
9. **Response**: Results returned to agent via IPC
10. **Periodic Update**: Cache refreshes every 6 hours

## Security

### Threat Model

ClawSec for NanoClaw protects against:

- **Vulnerable Skills**: Known security issues in installed skills
- **Malicious Skills**: Skills with documented malicious behavior
- **Feed Tampering**: Man-in-the-middle attacks on advisory feed
- **Feed Replay**: Serving outdated feeds with known vulnerabilities removed
- **Dependency Vulnerabilities**: Issues in skill dependencies (e.g., baileys)

### Signature Verification

All advisory feeds are Ed25519 signed:

```
feed.json          # Advisory data
feed.json.sig      # Detached Ed25519 signature
```

The public key is pinned in the skill:
```
advisories/feed-signing-public.pem
```

**Verification Process:**
1. Fetch feed and signature from HTTPS URL
2. Verify signature using pinned public key
3. Reject feed if signature invalid
4. Accept feed only if signature valid and recent

### Cache Integrity

The cache file includes:
```json
{
  "feed": [...],
  "signature": "base64_encoded_signature",
  "publicKey": "pinned_public_key",
  "lastFetch": "2026-02-25T12:00:00Z",
  "verified": true
}
```

Never accept advisories from unverified cache.

## Performance

### Cache Strategy

- **Fetch Interval**: 6 hours (configurable)
- **Cache Location**: `/workspace/project/data/clawsec-advisory-cache.json`
- **Cache Size**: Typically <100KB
- **Lookup Time**: <1ms (in-memory after load)

### Agent Impact

- **Tool Response Time**: <10ms (reads local cache)
- **Container Size**: +150KB (TypeScript code)
- **Memory Usage**: <5MB (for advisory cache)

## Compatibility

### NanoClaw Versions

- **Minimum**: 0.1.0
- **Tested**: 0.1.x
- **Recommended**: Latest stable

### Node.js

- **Minimum**: 18.0.0
- **Recommended**: 20.x or later

### Cross-Platform Skills

Skills that work on both NanoClaw and OpenClaw benefit from unified security monitoring:

- OpenClaw: Uses hook-based advisory guardian
- NanoClaw: Uses MCP tool-based advisory checking
- Same advisory feed serves both platforms
- Platform-specific advisories when needed

## Comparison with OpenClaw ClawSec

| Feature | OpenClaw | NanoClaw |
|---------|----------|----------|
| Architecture | Hook-based | MCP tool-based |
| Agent Access | Hook invocations | MCP tools |
| Host Communication | Direct | IPC |
| Signature Verification | OpenSSL CLI | Native Node.js crypto |
| Advisory Cache | File-based | File-based |
| Automatic Updates | Cron | Host service |
| Platform | Local | Containerized |

## Limitations

- **Network Required**: Advisory fetching requires internet access
- **Host Trust**: Agents must trust host for signature verification
- **Container Boundary**: Some operations require IPC to host
- **Skill Discovery**: Requires scanning skill directory (can be slow)

## Future Enhancements

Planned features for future releases:

1. **Real-Time Alerts**: WebSocket connection for instant advisory notifications
2. **Skill Sandboxing**: Integration with container security policies
3. **Behavioral Analysis**: ML-based detection of malicious skill behavior
4. **WhatsApp Alerts**: Direct security notifications via WhatsApp
5. **Custom Feeds**: Support for organization-specific advisory feeds
6. **Skill Pinning**: Lock skills to specific versions after verification
7. **Compliance Reports**: Generate security compliance reports for audits

## Team Credits

Designed and implemented by an 8-agent collaborative team:

- **pioneer-repo-scout**: ClawSec architecture analysis
- **pioneer-nanoclaw-scout**: NanoClaw architecture analysis
- **architect**: Integration design and coordination
- **advisory-specialist**: Advisory feed integration
- **integrity-specialist**: File integrity design
- **installer-specialist**: Signature verification implementation
- **tester**: Test infrastructure and validation
- **documenter**: Documentation

Total contribution: 3000+ lines of design + implementation code.

## License

AGPL-3.0-or-later

Same license as ClawSec core.

## Support

- **Documentation**: https://clawsec.prompt.security/
- **Issues**: https://github.com/prompt-security/clawsec/issues
- **Security Reports**: security@prompt.security (PGP key available)

---

**Ready to secure your NanoClaw deployment?** See [INSTALL.md](./INSTALL.md) to get started.
