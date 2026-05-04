# NanoClaw Traffic Guardian

Baseline skill for NanoClaw runtime traffic monitoring.

This package is intentionally a spec scaffold. Builders should add the NanoClaw-specific host-service, IPC, and MCP implementation here while preserving the safety contract in `SKILL.md` and `SPEC.md`.

## Intended Capability

- detect outbound secret exfiltration in NanoClaw host-managed traffic
- detect inbound command-injection and tool-abuse payloads
- keep CA private key material outside the container
- expose redacted status/findings through MCP tools
- provide explicit host-side lifecycle controls

## Builder Notes

Follow the existing `clawsec-nanoclaw` pattern: host services own privileged operations, while MCP tools expose bounded requests and redacted responses.

