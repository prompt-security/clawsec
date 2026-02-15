#!/usr/bin/env bash
set -euo pipefail

# Run a Codex CLI code review for this skill.
# Safe by default: read-only sandbox.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CODEX_BIN="/opt/homebrew/bin/codex"
if [[ ! -x "$CODEX_BIN" ]]; then
  echo "codex not found at $CODEX_BIN" >&2
  exit 127
fi

# Use GPT-5.1 Codex Max (high reasoning). Note: some models (e.g. o3) may be blocked
# depending on the account type.
exec "$CODEX_BIN" review -s read-only -m gpt-5.1-codex-max \
  "Review this skill for security/reliability issues. Focus on: shell quoting, command injection, sendmail header injection, dependency checks, cron payload safety, and failure modes. Provide concrete patch suggestions (with diffs if possible)." \
  -c "workdir=\"$ROOT_DIR\"" \
  -c "reasoning_effort=\"xhigh\""
