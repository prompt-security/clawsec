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
