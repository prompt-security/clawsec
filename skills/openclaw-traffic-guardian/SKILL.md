---
name: openclaw-traffic-guardian
version: 0.0.1-beta1
description: OpenClaw runtime traffic monitoring baseline for opt-in HTTP/HTTPS proxy inspection, egress detection, and inbound injection detection.
homepage: https://clawsec.prompt.security
author: prompt-security
license: AGPL-3.0-or-later
clawdis:
  emoji: "TG"
  requires:
    bins: [node, python3]
---

# OpenClaw Traffic Guardian

This is a baseline specification skill. It intentionally does not ship a proxy or runtime implementation yet.

## Scope

Builders should use this skill as the OpenClaw landing zone for runtime traffic monitoring:

- operator-scoped HTTP proxy inspection
- optional HTTPS inspection with per-process CA trust
- outbound exfiltration detection
- inbound injection detection
- redacted local threat logs
- optional OpenClaw hook/status integration

Do not merge this capability into `clawsec-scanner`, `openclaw-audit-watchdog`, or `soul-guardian`. Those skills have different trust boundaries and safety contracts.

## Safety Contract

- Opt-in only.
- Detect-and-log by default.
- No automatic system CA installation.
- No global `HTTP_PROXY` or `HTTPS_PROXY` changes.
- No blocking in the first implementation.
- Redact secrets before logs or conversation alerts.
- Keep all state under `OPENCLAW_TRAFFIC_GUARDIAN_HOME` or `~/.openclaw/security/clawsec/traffic-guardian`.

## Builder Entry Points

Read `SPEC.md` before implementing. Use the placeholder folders as follows:

| Path | Intended use |
|---|---|
| `lib/` | Detector rules, redaction, event schema, report formatting |
| `scripts/` | Start, stop, status, config validation, log query helpers |
| `hooks/openclaw-traffic-guardian-hook/` | Optional OpenClaw hook/status integration |
| `test/` | Unit tests, proxy fixture tests, redaction tests, process-scope tests |

## Required First Implementation Behavior

1. Validate config without starting the proxy.
2. Start monitor in foreground or explicit background mode.
3. Scope proxy environment variables to the target OpenClaw process.
4. Inspect HTTP request/response text up to a bounded byte limit.
5. Support optional HTTPS MITM only when the operator supplies per-process trust configuration.
6. Emit JSONL findings with redacted snippets.
7. Provide a `status` command that reports mode, listener, CA fingerprint if present, and last findings.

## Out of Scope for v0.0.1 Implementation

- automatic system trust-store mutation
- transparent network interception
- default blocking
- sending traffic to external services
- collecting full request/response bodies

