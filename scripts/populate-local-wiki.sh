#!/bin/bash
# populate-local-wiki.sh
# Generates wiki-derived public assets for local preview and CI parity.
#
# Usage: ./scripts/populate-local-wiki.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WIKI_DIR="$PROJECT_ROOT/wiki"
PUBLIC_WIKI_DIR="$PROJECT_ROOT/public/wiki"

if [ ! -d "$WIKI_DIR" ]; then
  echo "Error: wiki directory not found at $WIKI_DIR"
  exit 1
fi

echo "=== ClawSec Local Wiki Populator ==="
echo "Project root: $PROJECT_ROOT"

node "$PROJECT_ROOT/scripts/generate-wiki-llms.mjs"

PAGE_COUNT=0
if [ -d "$PUBLIC_WIKI_DIR" ]; then
  PAGE_COUNT=$(find "$PUBLIC_WIKI_DIR" -type f -path '*/llms.txt' ! -path "$PUBLIC_WIKI_DIR/llms.txt" | wc -l | tr -d ' ')
fi

echo "Wiki llms index: $PUBLIC_WIKI_DIR/llms.txt"
echo "Wiki llms pages: $PAGE_COUNT files under $PUBLIC_WIKI_DIR/<page>/llms.txt"
