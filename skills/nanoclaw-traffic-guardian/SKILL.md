---
name: nanoclaw-traffic-guardian
version: 0.0.1-beta1
description: NanoClaw runtime traffic monitoring baseline for host-side proxy inspection with container-safe MCP and IPC status surfaces.
homepage: https://clawsec.prompt.security
author: prompt-security
license: AGPL-3.0-or-later
nanoclaw:
  requires:
    node: ">=18.0.0"
---

# NanoClaw Traffic Guardian

This is a baseline specification skill. It intentionally does not ship a proxy or runtime implementation yet.

## Scope

Builders should use this skill as the NanoClaw landing zone for runtime traffic monitoring:

- host-side HTTP proxy inspection
- optional HTTPS inspection with host-held CA material
- outbound exfiltration detection
- inbound injection detection
- redacted local threat logs
- MCP tools for status, findings, and config checks
- IPC handlers for container-safe host communication

Prefer this as an optional companion to `clawsec-nanoclaw`, not as a mandatory extension of the existing advisory/signature/integrity suite.

## Safety Contract

- Opt-in only.
- Detect-and-log by default.
- No automatic system CA installation.
- No CA private key access from the container.
- No blocking in the first implementation.
- Redact secrets before logs or MCP responses.
- Keep all state under `NANOCLAW_TRAFFIC_GUARDIAN_HOME` or the host-managed NanoClaw security data directory.

## Builder Entry Points

Read `SPEC.md` before implementing. Use the placeholder folders as follows:

| Path | Intended use |
|---|---|
| `lib/` | Detector rules, redaction, types, report formatting |
| `host-services/` | Host-side proxy lifecycle, log access, IPC handlers |
| `mcp-tools/` | Container-side MCP tools for status and findings |
| `test/` | Unit tests, host/container IPC tests, redaction tests |

## Required First Implementation Behavior

1. Validate config without starting the proxy.
2. Start monitor through a host-managed lifecycle path.
3. Keep CA key material on the host side.
4. Inspect HTTP request/response text up to a bounded byte limit.
5. Support optional HTTPS MITM only when the operator supplies per-runtime trust configuration.
6. Emit JSONL findings with redacted snippets.
7. Expose MCP tools that return status and redacted findings only.

## Out of Scope for v0.0.1 Implementation

- automatic system trust-store mutation
- transparent network interception
- default blocking
- sending traffic to external services
- exposing raw request/response bodies to the container

