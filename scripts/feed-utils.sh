#!/bin/bash
# feed-utils.sh
# Shared advisory feed path and sync helpers for local/maintenance scripts.

init_feed_paths() {
  local project_root="$1"

  : "${FEED_PATH:=$project_root/advisories/feed.json}"
  : "${SKILL_FEED_PATH:=$project_root/skills/clawsec-feed/advisories/feed.json}"
  : "${PUBLIC_FEED_PATH:=$project_root/public/advisories/feed.json}"
}

sync_feed_to_mirrors() {
  local source_feed="$1"
  local mode="${2:-create}"

  local target
  for target in "$SKILL_FEED_PATH" "$PUBLIC_FEED_PATH"; do
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
  cat <<'EOF'
keyword|OpenClaw
keyword|clawdbot
keyword|Moltbot
keyword|NanoClaw
keyword|WhatsApp-bot
keyword|baileys
keyword|hermes workflow
virtualMatchString|cpe:2.3:a:software-metadata.pub:hermes
EOF
}

nvd_keyword_pattern() {
  echo 'OpenClaw|clawdbot|Moltbot|openclaw|NanoClaw|nanoclaw|WhatsApp-bot|baileys|HERMES workflow|software publication with rich metadata'
}

nvd_github_ref_pattern() {
  echo 'github\.com/openclaw/openclaw|github\.com/qwibitai/nanoclaw|github\.com/softwarepub/hermes'
}

nvd_cpe_pattern() {
  echo 'cpe:2\.3:a:software-metadata\.pub:hermes(?::|$)'
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
