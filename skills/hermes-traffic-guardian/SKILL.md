---
name: hermes-traffic-guardian
version: 0.0.1
description: Hermes runtime traffic monitoring baseline for opt-in proxy inspection, egress detection, and attestation-aware traffic posture.
homepage: https://clawsec.prompt.security
author: prompt-security
license: AGPL-3.0-or-later
hermes:
  emoji: "TG"
  requires:
    bins: [node, python3]
---

# Hermes Traffic Guardian

This is a baseline specification skill. It intentionally does not ship a proxy or runtime implementation yet.

## Scope

Builders should use this skill as the Hermes landing zone for runtime traffic monitoring:

- operator-scoped HTTP proxy inspection
- optional HTTPS inspection with per-process CA trust
- outbound exfiltration detection
- inbound injection detection
- redacted local threat logs
- status export for `hermes-attestation-guardian`

Do not add proxy runtime ownership to `hermes-attestation-guardian`. That skill should attest this monitor's status and configuration, not run it.

## Safety Contract

- Opt-in only.
- Detect-and-log by default.
- No automatic system CA installation.
- No global proxy environment changes.
- No blocking in the first implementation.
- Redact secrets before logs, summaries, or attestation-linked outputs.
- Keep all state under `HERMES_TRAFFIC_GUARDIAN_HOME` or `$HERMES_HOME/security/traffic-guardian`.

## Builder Entry Points

Read `SPEC.md` before implementing. Use the placeholder folders as follows:

| Path | Intended use |
|---|---|
| `lib/` | Detector rules, redaction, posture export, report formatting |
| `scripts/` | Start, stop, status, config validation, log query, attestation export helpers |
| `test/` | Unit tests, proxy fixture tests, redaction tests, attestation export tests |

## Required First Implementation Behavior

1. Validate config without starting the proxy.
2. Start monitor in foreground or explicit background mode.
3. Scope proxy environment variables to the target Hermes service or CLI process.
4. Inspect HTTP request/response text up to a bounded byte limit.
5. Support optional HTTPS MITM only when the operator supplies per-process trust configuration.
6. Emit JSONL findings with redacted snippets.
7. Export a small posture JSON file that `hermes-attestation-guardian` can include as a trust anchor or watched file.

## Out of Scope for v0.0.1 Implementation

- automatic system trust-store mutation
- transparent network interception
- default blocking
- sending traffic to external services
- collecting full request/response bodies

