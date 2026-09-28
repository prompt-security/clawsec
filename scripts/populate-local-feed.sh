#!/bin/bash
# populate-local-feed.sh
# Polls NVD API for real CVE data and populates local advisory feed for development preview.
# This mirrors the GitHub Actions pipeline logic exactly.
#
# Usage: ./scripts/populate-local-feed.sh [--days N] [--force]
#   --days N   Look back N days (default: 120)
#   --force    Ignore existing advisories and fetch all

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=./feed-utils.sh
source "$SCRIPT_DIR/feed-utils.sh"

# Configuration - same as pipeline
init_feed_paths "$PROJECT_ROOT"
NVD_QUERY_SPECS="$(nvd_query_specs)"
ENRICH_SCRIPT="$PROJECT_ROOT/scripts/ci/enrich_exploitability.sh"

# Parse args
DAYS_BACK=120
FORCE=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --days)
      DAYS_BACK="$2"
      shift 2
      ;;
    --force)
      FORCE=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo "=== ClawSec Local Feed Populator ==="
echo "Project root: $PROJECT_ROOT"
echo "Days back: $DAYS_BACK"
echo "Force mode: $FORCE"
echo ""

# Verify enrichment helper exists (it validates Python/analyzer prerequisites internally).
if [ ! -x "$ENRICH_SCRIPT" ]; then
  echo "Error: Exploitability enrichment helper not found or not executable: $ENRICH_SCRIPT"
  exit 1
fi

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# The consolidated feed timestamp also advances for community and GHSA-only
# changes, so it is not a valid NVD cursor. Re-read a rolling overlap window;
# downstream identity deduplication makes that safe.
if date -v-1d > /dev/null 2>&1; then
  START_DATE=$(date -u -v-"${DAYS_BACK}"d +%Y-%m-%dT%H:%M:%S.000Z)
else
  START_DATE=$(date -u -d "${DAYS_BACK} days ago" +%Y-%m-%dT%H:%M:%S.000Z)
fi
echo "Using rolling NVD overlap start: $START_DATE"

END_DATE=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "End date: $END_DATE"
echo ""

# URL encode dates
START_ENC=${START_DATE//:/%3A}
END_ENC=${END_DATE//:/%3A}

echo "=== Fetching CVEs from NVD ==="

fetch_nvd_response() {
  local url="$1"
  local output_file="$2"
  local label="$3"
  local attempt http_code retry_delay

  for attempt in 1 2 3; do
    if ! http_code=$(curl -sS -w "%{http_code}" -o "$output_file" "$url"); then
      http_code="000"
    fi

    if [ "$http_code" = "200" ]; then
      if jq -e '
        type == "object"
        and (.vulnerabilities | type) == "array"
        and (.totalResults | type == "number" and . >= 0 and . == floor)
        and (.startIndex | type == "number" and . >= 0 and . == floor)
        and (.resultsPerPage | type == "number" and . >= 0 and . == floor)
        and all(.vulnerabilities[]; (.cve.id | type) == "string")
      ' "$output_file" > /dev/null 2>&1; then
        return 0
      fi
      echo "  Invalid NVD response for $label, retry $attempt..." >&2
      retry_delay=5
    elif [ "$http_code" = "403" ] || [ "$http_code" = "429" ]; then
      echo "  Rate limited for $label, waiting before retry $attempt..." >&2
      retry_delay=30
    else
      echo "  HTTP $http_code for $label, retry $attempt..." >&2
      retry_delay=5
    fi

    if [ "$attempt" -lt 3 ]; then
      sleep "$retry_delay"
    fi
  done

  return 1
}

while IFS='|' read -r QUERY_KIND QUERY_VALUE; do
  [ -n "$QUERY_KIND" ] || continue

  QUERY_SLUG=$(nvd_query_slug "$QUERY_KIND" "$QUERY_VALUE")
  echo "Fetching $QUERY_KIND query: $QUERY_VALUE"

  QUERY_FILE="$TEMP_DIR/nvd_${QUERY_SLUG}.json"

  if [ "$FORCE" = "true" ]; then
    echo "  Full scan: paginating complete NVD history"
    QUERY_WINDOW_SUFFIX=""
  else
    echo "  Incremental scan: paginating NVD date window"
    QUERY_WINDOW_SUFFIX="&lastModStartDate=${START_ENC}&lastModEndDate=${END_ENC}"
  fi

  echo '{"vulnerabilities":[]}' > "$QUERY_FILE"
  START_INDEX=0
  RESULTS_PER_PAGE=2000
  EXPECTED_TOTAL_RESULTS=""

  while true; do
    URL=$(nvd_build_url "$QUERY_KIND" "$QUERY_VALUE" "${QUERY_WINDOW_SUFFIX}&startIndex=${START_INDEX}&resultsPerPage=${RESULTS_PER_PAGE}")
    PAGE_FILE="$TEMP_DIR/nvd_${QUERY_SLUG}_${START_INDEX}.json"

    if ! fetch_nvd_response "$URL" "$PAGE_FILE" "$QUERY_KIND:$QUERY_VALUE page $START_INDEX"; then
      echo "Error: failed to fetch a valid NVD response for $QUERY_KIND:$QUERY_VALUE page $START_INDEX" >&2
      exit 1
    fi

    RETURNED_START_INDEX=$(jq -r '.startIndex' "$PAGE_FILE")
    if [ "$RETURNED_START_INDEX" -ne "$START_INDEX" ]; then
      echo "Error: NVD returned startIndex=$RETURNED_START_INDEX for requested page $START_INDEX ($QUERY_KIND:$QUERY_VALUE)" >&2
      exit 1
    fi

    PAGE_COUNT=$(jq '.vulnerabilities | length' "$PAGE_FILE")
    TOTAL_RESULTS=$(jq '.totalResults' "$PAGE_FILE")
    if [ -z "$EXPECTED_TOTAL_RESULTS" ]; then
      EXPECTED_TOTAL_RESULTS="$TOTAL_RESULTS"
    elif [ "$TOTAL_RESULTS" -ne "$EXPECTED_TOTAL_RESULTS" ]; then
      echo "Error: NVD totalResults changed from $EXPECTED_TOTAL_RESULTS to $TOTAL_RESULTS while paginating $QUERY_KIND:$QUERY_VALUE" >&2
      exit 1
    fi

    if [ "$PAGE_COUNT" -eq 0 ] && [ "$START_INDEX" -lt "$EXPECTED_TOTAL_RESULTS" ]; then
      echo "Error: NVD returned an empty page at startIndex=$START_INDEX before advertised totalResults=$EXPECTED_TOTAL_RESULTS ($QUERY_KIND:$QUERY_VALUE)" >&2
      exit 1
    fi

    jq -s '.[0].vulnerabilities += .[1].vulnerabilities | .[0]' \
      "$QUERY_FILE" "$PAGE_FILE" > "$TEMP_DIR/nvd_${QUERY_SLUG}_merged.json"
    mv "$TEMP_DIR/nvd_${QUERY_SLUG}_merged.json" "$QUERY_FILE"

    echo "  ✓ Fetched $PAGE_COUNT CVEs at startIndex=$START_INDEX (totalResults=$EXPECTED_TOTAL_RESULTS)"

    START_INDEX=$((START_INDEX + PAGE_COUNT))
    if [ "$START_INDEX" -eq "$EXPECTED_TOTAL_RESULTS" ]; then
      break
    fi
    if [ "$START_INDEX" -gt "$EXPECTED_TOTAL_RESULTS" ]; then
      echo "Error: fetched $START_INDEX CVEs, exceeding advertised totalResults=$EXPECTED_TOTAL_RESULTS ($QUERY_KIND:$QUERY_VALUE)" >&2
      exit 1
    fi

    echo "  Waiting 6s (NVD rate limit)..."
    sleep 6
  done

  MERGED_COUNT=$(jq '.vulnerabilities | length' "$QUERY_FILE")
  if [ "$MERGED_COUNT" -ne "$EXPECTED_TOTAL_RESULTS" ]; then
    echo "Error: merged $MERGED_COUNT CVEs but NVD advertised totalResults=$EXPECTED_TOTAL_RESULTS ($QUERY_KIND:$QUERY_VALUE)" >&2
    exit 1
  fi
  
  # NVD recommends 6 second delay between requests
  echo "  Waiting 6s (NVD rate limit)..."
  sleep 6
done <<< "$NVD_QUERY_SPECS"

echo ""
echo "=== Processing CVEs ==="

# Combine all fetched CVEs
echo '{"vulnerabilities":[]}' > "$TEMP_DIR/combined.json"

while IFS='|' read -r QUERY_KIND QUERY_VALUE; do
  [ -n "$QUERY_KIND" ] || continue
  QUERY_SLUG=$(nvd_query_slug "$QUERY_KIND" "$QUERY_VALUE")
  FILE="$TEMP_DIR/nvd_${QUERY_SLUG}.json"
  if [ ! -s "$FILE" ] || ! jq -e '(.vulnerabilities | type) == "array"' "$FILE" > /dev/null 2>&1; then
    echo "Error: missing or invalid fetched NVD data for $QUERY_KIND:$QUERY_VALUE" >&2
    exit 1
  fi

  jq -s '.[0].vulnerabilities += .[1].vulnerabilities | .[0]' \
    "$TEMP_DIR/combined.json" "$FILE" > "$TEMP_DIR/combined_new.json"
  mv "$TEMP_DIR/combined_new.json" "$TEMP_DIR/combined.json"
done <<< "$NVD_QUERY_SPECS"

# Deduplicate by CVE ID
jq '.vulnerabilities | unique_by(.cve.id)' "$TEMP_DIR/combined.json" > "$TEMP_DIR/unique_cves.json"
TOTAL=$(jq 'length' "$TEMP_DIR/unique_cves.json")
echo "Total unique CVEs from NVD: $TOTAL"

# Discovery queries are intentionally broad. Publication is strict: require an
# allowlisted product CPE and an explicit machine-readable affected version scope.
jq -L "$SCRIPT_DIR" '
  include "nvd-advisory-transform";
  [.[] | select(has_supported_scoped_target)]
' "$TEMP_DIR/unique_cves.json" > "$TEMP_DIR/filtered_cves.json"

FILTERED=$(jq 'length' "$TEMP_DIR/filtered_cves.json")
echo "Filtered CVEs (matching criteria): $FILTERED"

if [ "$FORCE" = "true" ] && [ "$FILTERED" -eq 0 ]; then
  echo "Error: refusing full rebuild because strict NVD scoping produced zero advisories." >&2
  exit 1
fi

# Get existing advisory IDs (unless force mode)
if [ "$FORCE" = "true" ]; then
  echo "Force mode: ignoring existing advisory IDs during transform"
  echo '[]' > "$TEMP_DIR/existing_ids.json"
elif [ -f "$FEED_PATH" ]; then
  jq -r '.advisories[]?.id // empty' "$FEED_PATH" | sort -u | \
    jq -R -s 'split("\n") | map(select(length > 0))' > "$TEMP_DIR/existing_ids.json"
else
  echo '[]' > "$TEMP_DIR/existing_ids.json"
fi

# Transform CVEs with the same canonical logic used by CI.
jq -L "$SCRIPT_DIR" --slurpfile existing "$TEMP_DIR/existing_ids.json" '
  include "nvd-advisory-transform";
  [.[] |
    select(.cve.id as $id | (($existing[0] // []) | index($id) | not)) |
    nvd_advisory
  ]
' "$TEMP_DIR/filtered_cves.json" > "$TEMP_DIR/new_advisories.json"

NEW_COUNT=$(jq 'length' "$TEMP_DIR/new_advisories.json")
echo "New advisories to add: $NEW_COUNT"

if [ "$FORCE" = "true" ] && [ "$NEW_COUNT" -ne "$FILTERED" ]; then
  echo "Error: full rebuild transform mismatch (filtered=$FILTERED, transformed=$NEW_COUNT)"
  exit 1
fi

if [ "$NEW_COUNT" -eq 0 ] && [ "$FORCE" = "false" ]; then
  echo ""
  echo "No new CVEs found. Feed is up to date."
  echo "Use --force to re-fetch all CVEs regardless of existing entries."
  exit 0
fi

echo ""
echo "=== Analyzing Exploitability ==="

# Build CVSS vector lookup for enriched analysis inputs.
jq '
  [.[] | {
    id: .cve.id,
    cvss_vector: (
      .cve.metrics.cvssMetricV40[0]?.cvssData.vectorString //
      .cve.metrics.cvssMetricV31[0]?.cvssData.vectorString //
      .cve.metrics.cvssMetricV30[0]?.cvssData.vectorString //
      .cve.metrics.cvssMetricV2[0]?.vectorString //
      ""
    )
  }] | map({(.id): .cvss_vector}) | add
' "$TEMP_DIR/filtered_cves.json" > "$TEMP_DIR/cvss_vectors.json"

"$ENRICH_SCRIPT" \
  --mode batch \
  --input "$TEMP_DIR/new_advisories.json" \
  --output "$TEMP_DIR/new_advisories.json" \
  --cvss-vectors "$TEMP_DIR/cvss_vectors.json"

echo ""
echo "=== New Advisories ==="
jq -r '.[] | "  \(.id) [\(.severity)] - \(.title)"' "$TEMP_DIR/new_advisories.json"

echo ""
echo "=== Updating Feeds ==="

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Merge new advisories into existing feed
if [ -f "$FEED_PATH" ]; then
  jq --slurpfile new "$TEMP_DIR/new_advisories.json" --arg now "$NOW" --argjson force "$FORCE" '
    .updated = $now |
    # Full scans replace NVD CVEs, matching CI; incremental scans merge by ID.
    .advisories = (
      (if $force
       then ((.advisories // []) | map(select(((.id // "") | startswith("CVE-")) | not)))
       else (.advisories // [])
       end) as $base
      | reduce ($base + ($new[0] // []))[] as $adv
        ({};
          if ($adv.id // "") == "" then
            .
          else
            .[$adv.id] = $adv
          end
        )
      | [.[]]
      | sort_by(.published)
      | reverse
    )
  ' "$FEED_PATH" > "$TEMP_DIR/updated_feed.json"
else
  jq -n --slurpfile advisories "$TEMP_DIR/new_advisories.json" --arg now "$NOW" '{
    version: "1.0.0",
    updated: $now,
    description: "Community-driven security advisory feed for ClawSec. Automatically updated with explicitly scoped OpenClaw, NanoClaw, Hermes, PicoClaw, NemoClaw, and OpenShell CVEs from NVD.",
    advisories: (($advisories[0] // []) | sort_by(.published) | reverse)
  }' > "$TEMP_DIR/updated_feed.json"
fi

# Validate and save
if jq empty "$TEMP_DIR/updated_feed.json" 2>/dev/null; then
  node "$PROJECT_ROOT/scripts/ci/validate_advisory_feed.mjs" "$TEMP_DIR/updated_feed.json"
  # Update main feed
  cp "$TEMP_DIR/updated_feed.json" "$FEED_PATH"
  echo "✓ Updated: $FEED_PATH"

  # Sync feed mirrors for local skill/public consumers.
  sync_feed_to_mirrors "$FEED_PATH" "create"
  
  echo ""
  TOTAL_ADVISORIES=$(jq '.advisories | length' "$FEED_PATH")
  echo "=== Summary ==="
  echo "Total advisories in feed: $TOTAL_ADVISORIES"
  echo "New advisories added: $NEW_COUNT"
  echo ""
  echo "Run 'npm run dev' to preview the feed in the local site."
else
  echo "Error: Generated invalid JSON"
  exit 1
fi
