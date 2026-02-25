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

## How NanoClaw Uses ClawSec

NanoClaw can consume the advisory feed at:
```
https://clawsec.prompt.security/advisories/feed.json
```

The feed is Ed25519 signed for integrity verification.

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

## Future Enhancements

Planned features for deeper NanoClaw integration:
- MCP tools for advisory checking in containers
- File integrity monitoring (soul-guardian adaptation)
- Automated skill safety gates
- WhatsApp-native alert formatting

## More Information

- [ClawSec Main README](README.md)
- [Security & Signing](SECURITY-SIGNING.md)
- NanoClaw Repository: (link TBD)
