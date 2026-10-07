#!/bin/bash
# feed-utils.sh
# Shared advisory feed path and sync helpers for local/maintenance scripts.

init_feed_paths() {
  local project_root="$1"

  : "${FEED_PATH:=$project_root/advisories/feed.json}"
  : "${SKILL_FEED_PATH:=$project_root/skills/clawsec-feed/advisories/feed.json}"
  : "${SUITE_FEED_PATH:=$project_root/skills/clawsec-suite/advisories/feed.json}"
  : "${PUBLIC_FEED_PATH:=$project_root/public/advisories/feed.json}"
}

sync_feed_to_mirrors() {
  local source_feed="$1"
  local mode="${2:-create}"

  local target
  for target in "$SKILL_FEED_PATH" "$SUITE_FEED_PATH" "$PUBLIC_FEED_PATH"; do
    case "$mode" in
      create)
        mkdir -p "$(dirname "$target")"
        cp "$source_feed" "$target"
        echo "✓ Updated: $target"
        ;;
      existing-only)
        if [ -f "$target" ]; then
          cp "$source_feed" "$target"
          echo "✓ Updated: $target"
        fi
        ;;
      *)
        echo "Error: unsupported mirror sync mode: $mode" >&2
        return 1
        ;;
    esac
  done
}

nvd_query_specs() {
  # Keyword searches are discovery-only. Publication requires an allowlisted CPE
  # with an explicit version scope in scripts/nvd-advisory-transform.jq.
  # Hermes Agent stays keyword-only until NVD assigns an authoritative product CPE.
  cat <<'EOF'
keyword|OpenClaw
keyword|clawdbot
keyword|Moltbot
keyword|NanoClaw
keyword|WhatsApp-bot
keyword|baileys
keyword|hermes-agent
keyword|Picoclaw
keyword|NemoClaw
keyword|NVIDIA OpenShell
virtualMatchString|cpe:2.3:a:openclaw:openclaw
virtualMatchString|cpe:2.3:a:nanoco:nanoclaw
virtualMatchString|cpe:2.3:a:sipeed:picoclaw
virtualMatchString|cpe:2.3:a:nvidia:nemoclaw
virtualMatchString|cpe:2.3:a:nvidia:openshell
EOF
}

nvd_incremental_query_specs() {
  # Retraction detection must see every NVD record modified in the overlap
  # window. A record that lost its old keyword and CPE identity will no longer
  # appear in the allowlisted discovery queries used by full rebuilds.
  echo 'modified|all'
}

nvd_query_specs_for_scan() {
  local force_full_scan="$1"

  case "$force_full_scan" in
    true)
      nvd_query_specs
      ;;
    false|'')
      nvd_incremental_query_specs
      ;;
    *)
      echo "Error: force_full_scan must be true or false" >&2
      return 1
      ;;
  esac
}

nvd_drop_review_limit() {
  # A batch this large is unusual enough to require explicit operator review,
  # even when it is a small fraction of a very large feed.
  echo '20'
}

nvd_is_material_drop() {
  local dropped_count="$1"
  local existing_count="$2"
  local limit

  if ! [[ "$dropped_count" =~ ^[0-9]+$ ]] || ! [[ "$existing_count" =~ ^[0-9]+$ ]]; then
    echo "Error: dropped_count and existing_count must be non-negative integers" >&2
    return 2
  fi

  limit="$(nvd_drop_review_limit)"
  [ "$dropped_count" -gt 0 ] && {
    [ "$dropped_count" -ge "$limit" ] ||
      { [ "$existing_count" -gt 0 ] && [ "$((dropped_count * 4))" -ge "$existing_count" ]; }
  }
}

nvd_summary_components() {
  echo 'openclaw, nanoclaw, hermes, picoclaw, nemoclaw, openshell'
}

nvd_assert_no_conflicting_duplicates() {
  local input_file="$1"
  local conflicting_ids

  conflicting_ids="$(jq -r '
    .vulnerabilities
    | group_by(.cve.id)[]
    | select(length > 1)
    | select((map(.cve) | unique | length) > 1)
    | .[0].cve.id
  ' "$input_file")" || return 1

  if [ -n "$conflicting_ids" ]; then
    echo "Error: NVD returned conflicting snapshots for duplicate CVE IDs:" >&2
    printf '%s\n' "$conflicting_ids" | sed 's/^/  - /' >&2
    return 1
  fi
}

nvd_query_slug() {
  local kind="$1"
  local value="$2"
  printf '%s__%s' "$kind" "$value" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/_/g'
}

nvd_build_url() {
  local kind="$1"
  local value="$2"
  local suffix="${3:-}"
  local encoded

  encoded=$(jq -nr --arg v "$value" '$v|@uri')

  case "$kind" in
    keyword)
      printf 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s%s' "$encoded" "$suffix"
      ;;
    virtualMatchString)
      printf 'https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=%s%s' "$encoded" "$suffix"
      ;;
    modified)
      if [ "$value" != "all" ] || [[ "$suffix" != *lastModStartDate=* ]] || [[ "$suffix" != *lastModEndDate=* ]]; then
        echo "Error: modified NVD inventory requires the all marker and a bounded modification window" >&2
        return 1
      fi
      printf 'https://services.nvd.nist.gov/rest/json/cves/2.0?%s' "${suffix#&}"
      ;;
    *)
      echo "Error: unsupported NVD query kind: $kind" >&2
      return 1
      ;;
  esac
}
