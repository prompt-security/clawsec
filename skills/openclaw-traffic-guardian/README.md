# OpenClaw Traffic Guardian

Baseline skill for OpenClaw runtime traffic monitoring.

This package is intentionally a spec scaffold. Builders should add the OpenClaw-specific monitor implementation here while preserving the safety contract in `SKILL.md` and `SPEC.md`.

## Intended Capability

- detect outbound secret exfiltration in agent HTTP/HTTPS traffic
- detect inbound command-injection and tool-abuse payloads
- write redacted local JSONL findings
- provide explicit start, stop, status, and log-query commands
- integrate with `clawsec-suite` as an optional add-on

## Builder Notes

Use `SPEC.md` as the implementation contract. Keep runtime changes opt-in and scoped to the OpenClaw process being monitored.

