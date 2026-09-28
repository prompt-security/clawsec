#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

FEED_URL="${CLAWSEC_FEED_URL:-https://clawsec.prompt.security/advisories/feed.json}"
FEED_SIG_URL="${CLAWSEC_FEED_SIG_URL:-${FEED_URL}.sig}"
FEED_PUBLIC_KEY="${CLAWSEC_FEED_PUBLIC_KEY:-$SKILL_DIR/advisories/feed-signing-public.pem}"
EXPECTED_PUBLIC_KEY_SHA256="711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8"

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

curl -fsSL --retry 3 --retry-delay 1 "$FEED_URL" -o "$TEMP_DIR/feed.json"
curl -fsSL --retry 3 --retry-delay 1 "$FEED_SIG_URL" -o "$TEMP_DIR/feed.json.sig"

if [ ! -f "$FEED_PUBLIC_KEY" ]; then
  echo "ERROR: Pinned feed public key not found: $FEED_PUBLIC_KEY" >&2
  exit 1
fi

ACTUAL_PUBLIC_KEY_SHA256="$({
  openssl pkey -pubin -in "$FEED_PUBLIC_KEY" -outform DER
} | shasum -a 256 | awk '{print $1}')"
if [ "$ACTUAL_PUBLIC_KEY_SHA256" != "$EXPECTED_PUBLIC_KEY_SHA256" ]; then
  echo "ERROR: Feed public key fingerprint mismatch" >&2
  exit 1
fi

openssl base64 -d -A -in "$TEMP_DIR/feed.json.sig" -out "$TEMP_DIR/feed.json.sig.bin"
if ! openssl pkeyutl -verify -rawin -pubin \
  -inkey "$FEED_PUBLIC_KEY" \
  -sigfile "$TEMP_DIR/feed.json.sig.bin" \
  -in "$TEMP_DIR/feed.json" >/dev/null 2>&1; then
  echo "ERROR: Advisory feed signature verification failed" >&2
  exit 1
fi

if ! jq -e '
  type == "object"
  and (.version | type == "string" and length > 0)
  and (.updated | type == "string" and length > 0)
  and (.advisories | type == "array" and length > 0)
' "$TEMP_DIR/feed.json" >/dev/null; then
  echo "ERROR: Advisory feed structure is invalid" >&2
  exit 1
fi

cat "$TEMP_DIR/feed.json"
