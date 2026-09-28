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
  cat <<'EOF'
keyword|OpenClaw
keyword|clawdbot
keyword|Moltbot
keyword|NanoClaw
keyword|WhatsApp-bot
keyword|baileys
keyword|hermes workflow
keyword|hermes-agent
keyword|Picoclaw
keyword|NemoClaw
keyword|NVIDIA OpenShell
virtualMatchString|cpe:2.3:a:openclaw:openclaw
virtualMatchString|cpe:2.3:a:nanoco:nanoclaw
virtualMatchString|cpe:2.3:a:qwibitai:nanoclaw
virtualMatchString|cpe:2.3:a:software-metadata.pub:hermes
virtualMatchString|cpe:2.3:a:nousresearch:hermes_agent
virtualMatchString|cpe:2.3:a:picoclaw:picoclaw
virtualMatchString|cpe:2.3:a:sipeed:picoclaw
virtualMatchString|cpe:2.3:a:nvidia:nemoclaw
virtualMatchString|cpe:2.3:a:nvidia:openshell
EOF
}

nvd_summary_keywords() {
  echo 'openclaw, nanoclaw, hermes, picoclaw, nemoclaw, openshell'
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
    *)
      echo "Error: unsupported NVD query kind: $kind" >&2
      return 1
      ;;
  esac
}
