#!/usr/bin/env bash
set -euo pipefail

# Runner for Prompt Security daily audit job.
# - Optionally git-pulls repo (if PROMPTSEC_GIT_PULL=1)
# - Runs openclaw security audit + deep audit
# - Emails report to target@example.com via local sendmail
# - Prints the report to stdout (so cron delivery can DM it)

COMPANY_EMAIL="${PROMPTSEC_EMAIL_TO:-target@example.com}"
HOST_LABEL="${PROMPTSEC_HOST_LABEL:-}"
DO_PULL="${PROMPTSEC_GIT_PULL:-0}"
ENABLE_SUPPRESSIONS=0
AUDIT_CONFIG=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --enable-suppressions)
      ENABLE_SUPPRESSIONS=1; shift ;;
    --config)
      AUDIT_CONFIG="${2:-}"; shift 2 ;;
    *)
      shift ;;
  esac
done

if [[ "$DO_PULL" == "1" ]]; then
  if command -v git >/dev/null 2>&1 && [[ -d "$ROOT_DIR/.git" ]]; then
    git -C "$ROOT_DIR" pull --ff-only >/dev/null 2>&1 || true
  fi
fi

args=( )
if [[ -n "$HOST_LABEL" ]]; then
  args+=(--label "$HOST_LABEL")
fi
if [[ "$ENABLE_SUPPRESSIONS" -eq 1 ]]; then
  args+=(--enable-suppressions)
fi
if [[ -n "$AUDIT_CONFIG" ]]; then
  args+=(--config "$AUDIT_CONFIG")
fi
REPORT="$($SCRIPT_DIR/run_audit_and_format.sh "${args[@]}")"

SUBJECT_HOST="${HOST_LABEL:-$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown-host)}"
EMAIL_OK=1

# Prefer sendmail-compatible delivery if available; otherwise fallback to local SMTP (localhost:25 by default).
if printf '%s\n' "$REPORT" | "$SCRIPT_DIR/sendmail_report.sh" --to "$COMPANY_EMAIL" --subject "[$SUBJECT_HOST] openclaw daily security audit"; then
  EMAIL_OK=1
else
  if command -v node >/dev/null 2>&1; then
    if printf '%s\n' "$REPORT" | node "$SCRIPT_DIR/send_smtp.mjs" --to "$COMPANY_EMAIL" --subject "[$SUBJECT_HOST] openclaw daily security audit"; then
      EMAIL_OK=1
    else
      EMAIL_OK=0
    fi
  else
    EMAIL_OK=0
  fi
fi

if [[ "$EMAIL_OK" -eq 0 ]]; then
  printf '%s\n\n' "$REPORT"
  echo "NOTE: could not deliver email to ${COMPANY_EMAIL} via local sendmail"
else
  printf '%s\n' "$REPORT"
fi
