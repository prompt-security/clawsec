# Runtime Traffic Guardian Baseline

## Summary

This module defines the baseline for a new platform-specific runtime traffic monitoring family:

- `skills/openclaw-traffic-guardian/`
- `skills/hermes-traffic-guardian/`
- `skills/nanoclaw-traffic-guardian/`
- `skills/picoclaw-traffic-guardian/`

These packages are intentionally specification scaffolds. They reserve the skill names, platform metadata, SBOM entries, frontmatter, folder structure, and safety contracts so platform builders can add implementations without changing the architectural decision.

## Capability Gap

The existing ClawSec matrix covers advisory verification, config drift, self-pen-testing/posture review, and supply-chain verification. It does not currently provide live runtime traffic monitoring:

- HTTP request/response inspection
- optional HTTPS inspection with explicit CA trust
- outbound secret exfiltration detection
- inbound command-injection detection
- redacted local threat logging
- platform-specific status/profile/attestation surfaces

## Architecture Decision

Runtime traffic monitoring is a separate skill family, not an extension of existing posture or scanner skills.

Reasoning:

- `clawsec-scanner` is periodic report-only vulnerability scanning and OpenClaw hook DAST.
- `hermes-attestation-guardian` produces and verifies deterministic posture artifacts; it should attest monitor state, not run a proxy.
- `clawsec-nanoclaw` owns advisory/signature/integrity MCP tools; traffic interception requires host-side network ownership and stricter container boundaries.
- `picoclaw-security-guardian` is read-only posture/drift/supply-chain logic; proxy runtime would violate that safety posture.

## Shared Safety Contract

All traffic guardian implementations must preserve these constraints:

1. Opt-in only.
2. Detect-and-log by default.
3. No automatic system CA installation.
4. No global `HTTP_PROXY` or `HTTPS_PROXY` mutation.
5. No blocking in the first implementation.
6. Redact secret snippets before persistence or surfaced output.
7. Bound scan bytes and log retention.
8. Keep platform adapter state under platform-specific ClawSec security directories.

## Platform Ownership

| Skill | Runtime owner | Integration point |
|---|---|---|
| `openclaw-traffic-guardian` | OpenClaw adapter | Optional `clawsec-suite` add-on and optional OpenClaw hook/status integration |
| `hermes-traffic-guardian` | Hermes adapter | Posture export watched by `hermes-attestation-guardian` |
| `nanoclaw-traffic-guardian` | NanoClaw host service | Container-safe MCP tools and IPC result channel |
| `picoclaw-traffic-guardian` | Picoclaw adapter | Profile fragment consumed by `picoclaw-security-guardian` |

## Shared Finding Schema

Builders should use the common schema described in each skill's `SPEC.md`:

```json
{
  "schema_version": "clawsec-traffic-finding/v1",
  "platform": "openclaw",
  "direction": "outbound",
  "protocol": "http",
  "threat_type": "EXFIL",
  "pattern": "ai_api_key",
  "severity": "high",
  "source": "127.0.0.1",
  "dest": "api.example.com:443",
  "snippet": "[REDACTED]",
  "timestamp": "2026-04-26T00:00:00.000Z"
}
```

## Minimum Detection Families

Outbound EXFIL:

- AI API keys
- AWS access key IDs
- private key PEM markers
- SSH key file paths
- sensitive Unix file paths
- dotenv and cloud credential paths

Inbound INJECTION:

- pipe-to-shell commands
- shell exec flags
- reverse shell command shapes
- destructive remove commands
- SSH authorized-key injection shapes

Platform builders may add stable platform-specific markers, such as NanoClaw WhatsApp session paths or Picoclaw gateway token paths, once those names are verified.

## Source References

- skills/openclaw-traffic-guardian/SKILL.md
- skills/openclaw-traffic-guardian/SPEC.md
- skills/hermes-traffic-guardian/SKILL.md
- skills/hermes-traffic-guardian/SPEC.md
- skills/nanoclaw-traffic-guardian/SKILL.md
- skills/nanoclaw-traffic-guardian/SPEC.md
- skills/picoclaw-traffic-guardian/SKILL.md
- skills/picoclaw-traffic-guardian/SPEC.md
