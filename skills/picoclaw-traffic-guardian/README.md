# Picoclaw Traffic Guardian

Baseline skill for Picoclaw runtime traffic monitoring.

This package is intentionally a spec scaffold. Builders should add the Picoclaw-specific monitor implementation here while preserving the safety contract in `SKILL.md` and `SPEC.md`.

## Intended Capability

- detect outbound secret exfiltration in Picoclaw gateway HTTP/HTTPS traffic
- detect inbound command-injection and tool-abuse payloads
- write redacted local JSONL findings
- export monitor posture for `picoclaw-security-guardian`
- provide explicit start, stop, status, and log-query commands

## Builder Notes

Keep runtime ownership in this skill. `picoclaw-security-guardian` should only profile and drift-check this skill's state, config, and output fingerprints.

