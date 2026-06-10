# OpenClaw Traffic Guardian Specification

## Goal

Provide OpenClaw with opt-in runtime traffic monitoring that observes agent HTTP/HTTPS traffic for exfiltration and injection signals without changing global host networking.

## Required Architecture

Implement three layers:

1. Detector core
   - normalized finding schema
   - pattern registry
   - snippet redaction
   - deduplication
   - JSONL report writer

2. OpenClaw adapter
   - lifecycle commands for start, stop, status, and threats
   - process-scoped proxy environment guidance
   - optional hook/status integration under `hooks/openclaw-traffic-guardian-hook/`

3. Operator interface
   - safe setup text
   - explicit per-process proxy export commands
   - CA fingerprint display when HTTPS inspection is enabled

## Finding Schema

Findings must be JSON objects with these fields:

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

`POLICY_REVIEW` findings must keep the same base schema and add these fields:

```json
{
  "threat_type": "POLICY_REVIEW",
  "pattern": "social_account_mutation",
  "source_type": "openclaw_tool_request",
  "mutation_category": "post",
  "approval_marker_present": false,
  "execution_context": "background_runner"
}
```

- `source_type`: `http_request`, `openclaw_tool_request`, or `unknown`.
- `mutation_category`: `post`, `reply`, `repost`, `like`, `follow`, `unfollow`, `dm`, `media_upload`, `persistent_monitor`, `webhook_config`, `giveaway_draw`, or `other_social_account_mutation`.
- `approval_marker_present`: boolean; do not persist marker secrets or full approval tokens.
- `execution_context`: `direct_operator`, `scheduler`, `background_runner`, or `unknown`.

## Minimum Detection Set

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

Outbound POLICY_REVIEW:

- social-account write requests such as post, reply, repost, like, follow, unfollow, DM, media upload, persistent monitor creation/update, webhook configuration changes, or giveaway draw actions
- OpenClaw plugin/tool requests that invoke TweetClaw or another X/Twitter automation plugin for account mutation
- scheduler or background-runner requests that would repeat social-account mutations without a fresh operator approval

## Safety Requirements

- Default mode is detect-and-log.
- Blocking mode must not exist in the first implementation.
- Snippets must be redacted before persistence.
- Maximum scan bytes must be configurable and bounded.
- CA trust must be per-process by default.
- System trust-store instructions must require explicit operator confirmation and must never run automatically.
- POLICY_REVIEW findings must create an operator-review record only; they must not auto-block, auto-approve, or rewrite the requested action.

## Tests Required Before Release

- detector unit tests for each pattern
- redaction tests proving secrets are not persisted
- proxy fixture tests for HTTP request and response inspection
- no-false-positive tests for common benign traffic
- policy-review fixture tests for TweetClaw/social-account mutation examples and benign read-only social research requests
- lifecycle tests for stale PID/state cleanup
- status output tests
- OpenClaw hook integration tests if hook files are added
