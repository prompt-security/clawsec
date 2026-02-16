#!/usr/bin/env bash
set -euo pipefail

# Runs openclaw security audits and prints a formatted report to stdout.
#
# Usage:
#   ./run_audit_and_format.sh [--label "custom label"] [--config <path>]

show_help() {
  cat <<EOF
Usage: run_audit_and_format.sh [OPTIONS]

Options:
  --label <text>              Custom label for the report
  --config <path>             Path to config file (e.g., allowlist.json)
  --enable-suppressions       Explicitly enable the suppression mechanism
  --help                      Show this help message

EOF
  exit 0
}

LABEL=""
CONFIG=""
ENABLE_SUPPRESSIONS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      LABEL="${2:-}"; shift 2 ;;
    --config)
      CONFIG="${2:-}"; shift 2 ;;
    --enable-suppressions)
      ENABLE_SUPPRESSIONS=1; shift ;;
    --help)
      show_help ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

TMPDIR="${TMPDIR:-/tmp}"
AUDIT_JSON="$(mktemp "${TMPDIR%/}/openclaw_audit.XXXXXX.audit.json")"
DEEP_JSON="$(mktemp "${TMPDIR%/}/openclaw_audit.XXXXXX.deep.json")"

cleanup() {
  rm -f "$AUDIT_JSON" "$DEEP_JSON" 2>/dev/null || true
}
trap cleanup EXIT

command -v openclaw >/dev/null 2>&1 || { echo "openclaw not found in PATH" >&2; exit 127; }
command -v node >/dev/null 2>&1 || { echo "node not found in PATH" >&2; exit 127; }

run_audit() {
  local kind="$1" outfile="$2"
  local errfile
  errfile="$(mktemp "${TMPDIR%/}/openclaw_audit.XXXXXX.err")"

  local config_args=()
  if [[ -n "$CONFIG" ]]; then
    config_args=(--config "$CONFIG")
  fi

  # kind is either: "audit" or "deep"
  if [[ "$kind" == "audit" ]]; then
    if ! openclaw security audit --json "${config_args[@]}" >"$outfile" 2>"$errfile"; then
      printf '{"findings":[],"summary":{"critical":0,"warn":0,"info":0},"error":"audit failed: %s"}\n' \
        "$(head -n 20 "$errfile" | tr '\n' ' ')" >"$outfile"
    fi
  else
    if ! openclaw security audit --deep --json "${config_args[@]}" >"$outfile" 2>"$errfile"; then
      printf '{"findings":[],"summary":{"critical":0,"warn":0,"info":0},"error":"deep failed: %s"}\n' \
        "$(head -n 20 "$errfile" | tr '\n' ' ')" >"$outfile"
    fi
  fi

  rm -f "$errfile" 2>/dev/null || true
}

run_audit "audit" "$AUDIT_JSON"
run_audit "deep" "$DEEP_JSON"

# Host id: prefer short hostname; fall back to full hostname
HOST_ID="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown-host)"

if [[ -z "$LABEL" ]]; then
  LABEL="$HOST_ID"
else
  LABEL="$LABEL ($HOST_ID)"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build args for render_report
RENDER_ARGS=(--audit "$AUDIT_JSON" --deep "$DEEP_JSON" --label "$LABEL")
if [[ "$ENABLE_SUPPRESSIONS" -eq 1 ]]; then
  RENDER_ARGS+=(--enable-suppressions)
fi
if [[ -n "$CONFIG" ]]; then
  RENDER_ARGS+=(--config "$CONFIG")
fi

node "$SCRIPT_DIR/render_report.mjs" "${RENDER_ARGS[@]}"
