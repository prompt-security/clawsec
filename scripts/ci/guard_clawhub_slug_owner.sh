#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <target-clawhub-slug>" >&2
}

if [ "$#" -ne 1 ]; then
  usage
  exit 2
fi

TARGET_SLUG="$1"
SITE="${CLAWHUB_SITE:-https://clawhub.ai}"
REGISTRY="${CLAWHUB_REGISTRY:-$SITE}"
CONFIG_PATH="${CLAWHUB_CONFIG_PATH:-$HOME/.clawhub-ci/config.json}"

if [[ ! "$TARGET_SLUG" =~ ^[a-z0-9-]+$ ]]; then
  echo "::error::Invalid ClawHub slug for ownership guard: ${TARGET_SLUG}"
  exit 1
fi

if [ ! -f "$CONFIG_PATH" ]; then
  echo "::error::ClawHub config not found at ${CONFIG_PATH}. Run clawhub login before ownership guard."
  exit 1
fi

TOKEN="$(jq -r '.token // empty' "$CONFIG_PATH")"
if [ -z "$TOKEN" ]; then
  echo "::error::ClawHub token missing from ${CONFIG_PATH}. Run clawhub login before ownership guard."
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

api_get() {
  local path="$1"
  local output_path="$2"
  local url="${REGISTRY%/}${path}"
  local http_status
  local curl_status

  set +e
  http_status="$(
    curl --silent --show-error --location --max-time 15 \
      --header "Accept: application/json" \
      --header "Authorization: Bearer ${TOKEN}" \
      --output "$output_path" \
      --write-out "%{http_code}" \
      "$url"
  )"
  curl_status=$?
  set -e

  if [ "$curl_status" -ne 0 ]; then
    echo "::error::Failed to call ClawHub API: ${url}"
    return 1
  fi

  printf '%s\n' "$http_status"
}

whoami_json="$TMP_DIR/whoami.json"
whoami_status="$(api_get "/api/v1/whoami" "$whoami_json")"
if [ "$whoami_status" != "200" ]; then
  echo "::error::Failed to verify authenticated ClawHub publisher. HTTP ${whoami_status}."
  cat "$whoami_json"
  exit 1
fi

publisher_handle="$(jq -r '.user.handle // empty' "$whoami_json")"
if [ -z "$publisher_handle" ]; then
  echo "::error::Could not determine authenticated ClawHub publisher handle."
  cat "$whoami_json"
  exit 1
fi

target_json="$TMP_DIR/target.json"
target_status="$(api_get "/api/v1/skills/${TARGET_SLUG}" "$target_json")"
if [ "$target_status" = "404" ]; then
  echo "Target ClawHub slug ${TARGET_SLUG} is not currently published; authenticated publisher ${publisher_handle} may create it."
  exit 0
fi

if [ "$target_status" != "200" ]; then
  echo "::error::Failed to inspect target ClawHub slug ${TARGET_SLUG}. HTTP ${target_status}."
  cat "$target_json"
  exit 1
fi

target_owner="$(jq -r '.owner.handle // .owner.displayName // empty' "$target_json")"
if [ -z "$target_owner" ]; then
  echo "::error::Could not determine owner for existing ClawHub slug ${TARGET_SLUG}."
  echo "target owner: ${target_owner:-unknown}"
  exit 1
fi

if [ "$target_owner" != "$publisher_handle" ]; then
  echo "::error::Resolved ClawHub slug ${TARGET_SLUG} is already owned by ${target_owner}, but the authenticated publisher is ${publisher_handle}. Transfer or alias the registry slug before publishing."
  exit 1
fi

echo "ClawHub slug ownership guard passed: ${TARGET_SLUG} owned by authenticated publisher ${publisher_handle}."
