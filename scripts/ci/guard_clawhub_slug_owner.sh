#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <source-skill-slug> <target-clawhub-slug>" >&2
}

if [ "$#" -ne 2 ]; then
  usage
  exit 2
fi

SOURCE_SLUG="$1"
TARGET_SLUG="$2"
SITE="${CLAWHUB_SITE:-https://clawhub.ai}"
REGISTRY="${CLAWHUB_REGISTRY:-$SITE}"

if [ "$SOURCE_SLUG" = "$TARGET_SLUG" ]; then
  echo "ClawHub slug ownership guard skipped; source and target are both ${TARGET_SLUG}."
  exit 0
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

inspect_slug() {
  local slug="$1"
  local json_path="$2"
  local err_path="$3"

  set +e
  CLAWHUB_DISABLE_TELEMETRY=1 CLAWHUB_SITE="$SITE" CLAWHUB_REGISTRY="$REGISTRY" \
    clawhub inspect "$slug" --json > "$json_path" 2> "$err_path"
  local status=$?
  set -e

  return "$status"
}

target_json="$TMP_DIR/target.json"
target_err="$TMP_DIR/target.err"
if ! inspect_slug "$TARGET_SLUG" "$target_json" "$target_err"; then
  if grep -Eqi "Skill not found|not found" "$target_err"; then
    echo "Target ClawHub slug ${TARGET_SLUG} is not currently published; publish may create it."
    exit 0
  fi

  echo "::error::Failed to inspect target ClawHub slug ${TARGET_SLUG}."
  cat "$target_err"
  exit 1
fi

source_json="$TMP_DIR/source.json"
source_err="$TMP_DIR/source.err"
if ! inspect_slug "$SOURCE_SLUG" "$source_json" "$source_err"; then
  echo "::error::Target ClawHub slug ${TARGET_SLUG} already exists, but source slug ${SOURCE_SLUG} could not be inspected. Refusing to publish without proving ownership continuity."
  cat "$source_err"
  exit 1
fi

target_owner="$(jq -r '.owner.handle // .owner.displayName // empty' "$target_json")"
source_owner="$(jq -r '.owner.handle // .owner.displayName // empty' "$source_json")"

if [ -z "$target_owner" ] || [ -z "$source_owner" ]; then
  echo "::error::Could not determine ClawHub slug owners for ${SOURCE_SLUG} -> ${TARGET_SLUG}."
  echo "source owner: ${source_owner:-unknown}"
  echo "target owner: ${target_owner:-unknown}"
  exit 1
fi

if [ "$target_owner" != "$source_owner" ]; then
  echo "::error::Resolved ClawHub slug ${TARGET_SLUG} is already owned by ${target_owner}, while source slug ${SOURCE_SLUG} is owned by ${source_owner}. Transfer or alias the registry slug before publishing."
  exit 1
fi

echo "ClawHub slug ownership guard passed: ${SOURCE_SLUG} -> ${TARGET_SLUG} owned by ${source_owner}."
