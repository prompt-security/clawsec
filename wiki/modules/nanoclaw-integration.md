# Module: NanoClaw Integration

## Responsibilities
- Port ClawSec advisory/signature logic into NanoClaw host+container architecture.
- Provide MCP tools that expose advisory checks, signature verification, and integrity monitoring.
- Maintain host-side cached advisory state with TLS/signature enforcement and IPC-triggered refresh.
- Protect critical NanoClaw files with baseline drift detection and hash-chained audit trails.

## Key Files
- `skills/clawsec-nanoclaw/skill.json`: NanoClaw package contract and MCP tool registry.
- `skills/clawsec-nanoclaw/lib/signatures.ts`: secure fetch and Ed25519 verification primitives.
- `skills/clawsec-nanoclaw/lib/advisories.ts`: feed load and advisory matching helpers.
- `skills/clawsec-nanoclaw/host-services/advisory-cache.ts`: host cache manager.
- `skills/clawsec-nanoclaw/host-services/ipc-handlers.ts`: IPC request dispatch for advisory/signature tasks.
- `skills/clawsec-nanoclaw/host-services/skill-signature-handler.ts`: package signature verification service.
- `skills/clawsec-nanoclaw/guardian/integrity-monitor.ts`: baseline/diff/restore/audit engine.
- `skills/clawsec-nanoclaw/mcp-tools/*.ts`: container-side tool definitions.

## Public Interfaces
| Interface | Context | Notes |
| --- | --- | --- |
| `clawsec_check_advisories` | MCP tool | Lists advisories affecting installed skills. |
| `clawsec_check_skill_safety` | MCP tool | Returns install recommendation for a specific skill. |
| `clawsec_verify_skill_package` | MCP tool | Verifies detached package signature through host IPC. |
| `clawsec_check_integrity` | MCP tool | Runs integrity check, optional auto-restore for critical targets. |
| IPC task `verify_skill_signature` | Host service | Returns structured verification response with error codes. |
| IPC task `refresh_advisory_cache` | Host service | Refreshes signed advisory cache on demand. |

## Inputs and Outputs
Inputs/outputs are summarized in the table below.

| Type | Name | Location | Description |
| --- | --- | --- | --- |
| Input | Signed advisory feed | `https://clawsec.prompt.security/advisories/feed.json(.sig)` | Threat intelligence source for cache refresh. |
| Input | Package + signature files | Host filesystem paths | Pre-install package authenticity checks. |
| Input | Integrity policy | `guardian/policy.json` | Per-path mode and priority controls. |
| Output | Advisory cache | `/workspace/project/data/clawsec-advisory-cache.json` | Host-managed verified advisory data. |
| Output | Verification results | `/workspace/ipc/clawsec_results/*.json` | IPC response payload for tool calls. |
| Output | Integrity state | `.../soul-guardian/` | Baselines, snapshots, patches, quarantine, audit logs. |

## Configuration
| Setting | Default | Effect |
| --- | --- | --- |
| Feed URL | Hosted ClawSec advisory endpoint | Primary remote source for advisory cache manager. |
| Cache TTL | `5 minutes` | Controls staleness threshold before requiring refresh. |
| Fetch timeout | `10 seconds` | Limits host network wait time. |
| Allowed domains | `clawsec.prompt.security`, `prompt.security`, `raw.githubusercontent.com`, `github.com` | Restricts remote fetch targets. |
| Integrity policy modes | `restore`, `alert`, `ignore` | Controls automatic restoration and alert-only behavior. |

## Example Snippets
```ts
// host-side signature verification dispatch
const result = await deps.signatureVerifier.verify({
  packagePath,
  signaturePath,
  publicKeyPem,
  allowUnsigned: allowUnsigned || false,
});
```

```ts
// integrity monitor drift handling
if (baseline.mode === 'restore' && autoRestore) {
  // quarantine modified file, restore approved snapshot, append audit event
}
```

## Edge Cases
- Disallowed domains or non-HTTPS URLs are blocked by security policy wrappers.
- Missing signature files can be tolerated only when `allowUnsigned` is explicitly set.
- IPC result waits can timeout, causing conservative block recommendations.
- Integrity engine refuses symlink operations to reduce path-redirection attacks.
- Audit-chain validation can detect tampering or corruption in historical records.

## Tests
| Test Scope | File/Path | Notes |
| --- | --- | --- |
| Type contracts | `skills/clawsec-nanoclaw/lib/types.ts` | Defines tool/IPC DB payload contracts. |
| Operational docs | `docs/SKILL_SIGNING.md`, `docs/INTEGRITY.md` | Describes verification/integrity usage patterns. |
| Cross-module behavior | Reuses suite verification patterns | Signature/checksum primitives ported from suite logic. |

## Source References
- skills/clawsec-nanoclaw/skill.json
- skills/clawsec-nanoclaw/lib/types.ts
- skills/clawsec-nanoclaw/lib/signatures.ts
- skills/clawsec-nanoclaw/lib/advisories.ts
- skills/clawsec-nanoclaw/host-services/advisory-cache.ts
- skills/clawsec-nanoclaw/host-services/ipc-handlers.ts
- skills/clawsec-nanoclaw/host-services/skill-signature-handler.ts
- skills/clawsec-nanoclaw/host-services/integrity-handler.ts
- skills/clawsec-nanoclaw/guardian/integrity-monitor.ts
- skills/clawsec-nanoclaw/guardian/policy.json
- skills/clawsec-nanoclaw/mcp-tools/advisory-tools.ts
- skills/clawsec-nanoclaw/mcp-tools/signature-verification.ts
- skills/clawsec-nanoclaw/mcp-tools/integrity-tools.ts
- skills/clawsec-nanoclaw/docs/SKILL_SIGNING.md
- skills/clawsec-nanoclaw/docs/INTEGRITY.md
