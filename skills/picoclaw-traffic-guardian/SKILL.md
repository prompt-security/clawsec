---
name: picoclaw-traffic-guardian
version: 0.0.1-beta2
description: Picoclaw runtime traffic monitoring baseline for lightweight AI gateway proxy inspection, egress detection, and posture integration.
homepage: https://clawsec.prompt.security
author: prompt-security
license: AGPL-3.0-or-later
picoclaw:
  emoji: "TG"
  requires:
    bins: [node, python3]
---

# Picoclaw Traffic Guardian

This is a baseline specification skill. It intentionally does not ship a proxy or runtime implementation yet.

## Scope

Builders should use this skill as the Picoclaw landing zone for runtime traffic monitoring:

- lightweight AI gateway HTTP proxy inspection
- optional HTTPS inspection with per-process CA trust
- outbound exfiltration detection
- inbound injection detection
- redacted local threat logs
- profile export for `picoclaw-security-guardian`

Do not add proxy runtime ownership to `picoclaw-security-guardian` or `picoclaw-self-pen-testing`. Those skills should profile, drift-check, or review this monitor's status, not run it.

## Safety Contract

- Opt-in only.
- Detect-and-log by default.
- No automatic system CA installation.
- No global proxy environment changes.
- No blocking in the first implementation.
- Redact secrets before logs, summaries, or profile outputs.
- Keep all state under `PICOCLAW_TRAFFIC_GUARDIAN_HOME` or `$PICOCLAW_HOME/security/clawsec/traffic-guardian`.

## Builder Entry Points

Read `SPEC.md` before implementing. Use the placeholder folders as follows:

| Path | Intended use |
|---|---|
| `lib/` | Detector rules, redaction, profile export, report formatting |
| `scripts/` | Start, stop, status, config validation, log query, profile export helpers |
| `test/` | Unit tests, proxy fixture tests, redaction tests, profile integration tests |

## Required First Implementation Behavior

1. Validate config without starting the proxy.
2. Start monitor in foreground or explicit background mode.
3. Scope proxy environment variables to the target Picoclaw gateway process.
4. Inspect HTTP request/response text up to a bounded byte limit.
5. Support optional HTTPS MITM only when the operator supplies per-process trust configuration.
6. Emit JSONL findings with redacted snippets.
7. Export a small profile fragment that `picoclaw-security-guardian` can include in deterministic posture profiles.

## Out of Scope for v0.0.1 Implementation

- automatic system trust-store mutation
- transparent network interception
- default blocking
- sending traffic to external services
- collecting full request/response bodies

