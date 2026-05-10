# NanoClaw Traffic Guardian Specification

## Goal

Provide NanoClaw with opt-in runtime traffic monitoring that observes host-managed NanoClaw traffic for exfiltration and injection signals while preserving container isolation.

## Required Architecture

Implement four layers:

1. Detector core
   - normalized finding schema
   - pattern registry
   - snippet redaction
   - deduplication
   - JSONL report writer

2. Host service
   - proxy lifecycle
   - CA key ownership
   - log storage
   - config validation
   - IPC task handling

3. MCP tool surface
   - `clawsec_traffic_status`
   - `clawsec_traffic_findings`
   - `clawsec_traffic_check_config`

4. Operator interface
   - safe setup text
   - explicit host/container proxy wiring guidance
   - CA fingerprint display when HTTPS inspection is enabled

## Finding Schema

Findings must be JSON objects with these fields:

```json
{
  "schema_version": "clawsec-traffic-finding/v1",
  "platform": "nanoclaw",
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

## Minimum Detection Set

Outbound EXFIL:

- AI API keys
- AWS access key IDs
- private key PEM markers
- SSH key file paths
- sensitive Unix file paths
- dotenv and cloud credential paths
- WhatsApp session or credential path markers when NanoClaw exposes stable names

Inbound INJECTION:

- pipe-to-shell commands
- shell exec flags
- reverse shell command shapes
- destructive remove commands
- SSH authorized-key injection shapes

## Safety Requirements

- Default mode is detect-and-log.
- Blocking mode must not exist in the first implementation.
- Snippets must be redacted before persistence and before MCP responses.
- Maximum scan bytes must be configurable and bounded.
- CA private key material must stay host-side.
- System trust-store instructions must require explicit operator confirmation and must never run automatically.

## Tests Required Before Release

- detector unit tests for each pattern
- redaction tests proving secrets are not persisted or returned through MCP
- host-service lifecycle tests
- IPC timeout and malformed-task tests
- MCP schema tests
- proxy fixture tests for HTTP request and response inspection
- no-false-positive tests for common benign traffic

