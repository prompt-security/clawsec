# Hermes Traffic Guardian

Baseline skill for Hermes runtime traffic monitoring.

This package is intentionally a spec scaffold. Builders should add the Hermes-specific monitor implementation here while preserving the safety contract in `SKILL.md` and `SPEC.md`.

## Intended Capability

- detect outbound secret exfiltration in Hermes HTTP/HTTPS traffic
- detect inbound command-injection and tool-abuse payloads
- write redacted local JSONL findings
- export monitor posture for `hermes-attestation-guardian`
- provide explicit start, stop, status, and log-query commands

## Builder Notes

Keep runtime ownership in this skill. `hermes-attestation-guardian` should only attest this skill's state, config, and output fingerprints.

