#!/usr/bin/env bash
set -euo pipefail

# Sends report text (stdin) via local sendmail.
#
# Usage:
#   ./sendmail_report.sh --to target@example.com [--subject "..."]

TO=""
SUBJECT="openclaw daily security audit"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --to)
      TO="${2:-}"; shift 2 ;;
    --subject)
      SUBJECT="${2:-}"; shift 2 ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$TO" ]]; then
  echo "--to is required" >&2
  exit 2
fi

# Resolve sendmail:
# - explicit override via PROMPTSEC_SENDMAIL_BIN
# - macOS default /usr/sbin/sendmail (often not in PATH for non-login shells)
# - fallback to PATH lookup
SENDMAIL_BIN="${PROMPTSEC_SENDMAIL_BIN:-}"
if [[ -z "$SENDMAIL_BIN" ]] && [[ -x "/usr/sbin/sendmail" ]]; then
  SENDMAIL_BIN="/usr/sbin/sendmail"
fi
if [[ -z "$SENDMAIL_BIN" ]]; then
  SENDMAIL_BIN="$(command -v sendmail || true)"
fi
if [[ -z "$SENDMAIL_BIN" ]] || [[ ! -x "$SENDMAIL_BIN" ]]; then
  echo "sendmail not found (tried PROMPTSEC_SENDMAIL_BIN, /usr/sbin/sendmail, and sendmail in PATH)" >&2
  exit 1
fi

# Prevent header injection: strip CR/LF from header fields
TO_CLEAN="$(printf '%s' "$TO" | tr -d '\r\n')"
SUBJECT_CLEAN="$(printf '%s' "$SUBJECT" | tr -d '\r\n')"

# Basic RFC2822
{
  echo "To: ${TO_CLEAN}"
  echo "Subject: ${SUBJECT_CLEAN}"
  echo "Content-Type: text/plain; charset=UTF-8"
  echo
  cat
} | "$SENDMAIL_BIN" -oi -oem -t
