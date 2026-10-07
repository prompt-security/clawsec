#!/bin/bash
# populate-local-feed.sh
# Polls NVD API for real CVE data and populates local advisory feed for development preview.
# This uses the same strict fetch, scope, retraction, and rebuild safety rules
# as CI. The GitHub Actions workflow remains the publishing path.
#
# Usage: ./scripts/populate-local-feed.sh [--days N] [--force] [--allow-large-drop]
#   --days N            Look back 1-119 days (default: 119; NVD maximum is 120)
#   --force             Ignore existing advisories and fetch all
#   --allow-large-drop  Permit a reviewed full-rebuild or incremental removal
#                       of 20+ records or 25% of existing CVE identities

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=./feed-utils.sh
source "$SCRIPT_DIR/feed-utils.sh"

# Configuration - same as pipeline
init_feed_paths "$PROJECT_ROOT"
ENRICH_SCRIPT="$PROJECT_ROOT/scripts/ci/enrich_exploitability.sh"

# Parse args
DAYS_BACK=119
FORCE=false
ALLOW_LARGE_DROP=false

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
    --allow-large-drop)
      ALLOW_LARGE_DROP=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if ! [[ "$DAYS_BACK" =~ ^[0-9]+$ ]] || [ "$DAYS_BACK" -lt 1 ] || [ "$DAYS_BACK" -gt 119 ]; then
  echo "Error: --days must be an integer from 1 through 119 to stay below NVD's 120-day maximum" >&2
  exit 1
fi

echo "=== ClawSec Local Feed Populator ==="
echo "Project root: $PROJECT_ROOT"
echo "Days back: $DAYS_BACK"
echo "Force mode: $FORCE"
echo "Allow large advisory drop: $ALLOW_LARGE_DROP"
echo ""

# Verify enrichment helper exists (it validates Python/analyzer prerequisites internally).
if [ ! -x "$ENRICH_SCRIPT" ]; then
  echo "Error: Exploitability enrichment helper not found or not executable: $ENRICH_SCRIPT"
  exit 1
fi

# Incremental generation is a stateful merge. Without the canonical baseline it
# cannot distinguish new records from retained history. Only an explicit full
# scan may bootstrap a missing feed, and an existing malformed feed is never
# safe to overwrite implicitly.
if [ -f "$FEED_PATH" ]; then
  if ! jq -e 'type == "object" and (.advisories | type == "array" and length > 0)' "$FEED_PATH" >/dev/null; then
    echo "Error: existing advisory feed is malformed or empty: $FEED_PATH" >&2
    exit 1
  fi
elif [ "$FORCE" != "true" ]; then
  echo "Error: canonical advisory feed is missing. Incremental generation cannot safely reconstruct history; rerun with --force only for an intentional bootstrap." >&2
  exit 1
else
  echo "Explicit full-scan bootstrap: no existing canonical feed found."
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

NVD_QUERY_SPECS="$(nvd_query_specs_for_scan "$FORCE")"

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
    echo "  Incremental scan: paginating the broad rolling NVD modification inventory"
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

    MERGED_COUNT=$(jq '.vulnerabilities | length' "$QUERY_FILE")
    UNIQUE_MERGED_COUNT=$(jq '[.vulnerabilities[].cve.id] | unique | length' "$QUERY_FILE")
    if [ "$UNIQUE_MERGED_COUNT" -ne "$MERGED_COUNT" ]; then
      echo "Error: NVD returned duplicate CVE IDs while paginating $QUERY_KIND:$QUERY_VALUE" >&2
      exit 1
    fi

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

# Exact duplicates are expected across overlapping discovery queries. Conflicting
# payloads mean NVD changed mid-scan, so do not choose an arbitrary snapshot.
nvd_assert_no_conflicting_duplicates "$TEMP_DIR/combined.json"

# Deduplicate identical CVE payloads by ID.
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

if [ -f "$FEED_PATH" ]; then
  jq '.advisories // []' "$FEED_PATH" > "$TEMP_DIR/existing_advisories.json"
else
  echo '[]' > "$TEMP_DIR/existing_advisories.json"
fi

if [ "$FORCE" = "false" ]; then
  jq -n \
    --slurpfile existing "$TEMP_DIR/existing_advisories.json" \
    --slurpfile fetched "$TEMP_DIR/unique_cves.json" \
    --slurpfile scoped "$TEMP_DIR/filtered_cves.json" '
    ($fetched[0] | map(.cve.id) | unique) as $fetched_ids |
    ($scoped[0] | map(.cve.id) | unique) as $scoped_ids |
    [
      $existing[0][] |
      select((.id // "") | startswith("CVE-")) |
      .id as $id |
      select(($fetched_ids | index($id)) != null) |
      select(($scoped_ids | index($id)) == null) |
      $id
    ] | unique
  ' > "$TEMP_DIR/retracted_advisory_ids.json"
else
  echo '[]' > "$TEMP_DIR/retracted_advisory_ids.json"
fi

# Compare the current NVD representation of every scoped CVE in the overlap
# window with the canonical feed. Existing IDs are not "already handled": NVD
# may correct their risk, scope, taxonomy, timestamps, text, or references.
# Keep this field list in parity with the CI workflow's current-state update
# contract, and merge only these NVD-owned fields so local enrichment survives.
if [ "$FORCE" = "false" ]; then
  jq -L "$SCRIPT_DIR" '
    include "nvd-advisory-transform";
    [.[] | nvd_advisory_current_state]
  ' "$TEMP_DIR/filtered_cves.json" > "$TEMP_DIR/nvd_current_state.json"

  jq -n \
    --slurpfile existing "$TEMP_DIR/existing_advisories.json" \
    --slurpfile nvd "$TEMP_DIR/nvd_current_state.json" '
    ($existing[0] | map(select((.id // "") | startswith("CVE-")))) as $cve_advisories |
    [
      $nvd[0][] |
      . as $nvd_entry |
      ($cve_advisories | map(select(.id == $nvd_entry.id)) | first) as $existing_entry |
      select(
        $existing_entry != null and (
          ($existing_entry.severity != $nvd_entry.severity) or
          ($existing_entry.type != $nvd_entry.type) or
          ($existing_entry.nvd_category_id != $nvd_entry.nvd_category_id) or
          ($existing_entry.cvss_score != $nvd_entry.cvss_score) or
          ($existing_entry.cvss_vector != $nvd_entry.cvss_vector) or
          ($existing_entry.published != $nvd_entry.published) or
          ($existing_entry.updated != $nvd_entry.updated) or
          ($existing_entry.authoritative_nvd_affected != $nvd_entry.authoritative_nvd_affected) or
          ($existing_entry.synthesized_from_ghsa != $nvd_entry.synthesized_from_ghsa) or
          ($existing_entry.authoritative_canonical_platforms != $nvd_entry.authoritative_canonical_platforms) or
          ($existing_entry.authoritative_canonical_cwe_ids != $nvd_entry.authoritative_canonical_cwe_ids) or
          ($existing_entry.description != $nvd_entry.description) or
          ($existing_entry.title != $nvd_entry.title) or
          ($existing_entry.references != $nvd_entry.references)
        )
      ) |
      {
        id: $nvd_entry.id,
        updated_fields: {
          severity: $nvd_entry.severity,
          type: $nvd_entry.type,
          nvd_category_id: $nvd_entry.nvd_category_id,
          cvss_score: $nvd_entry.cvss_score,
          cvss_vector: $nvd_entry.cvss_vector,
          published: $nvd_entry.published,
          updated: $nvd_entry.updated,
          affected: $nvd_entry.affected,
          authoritative_nvd_affected: $nvd_entry.authoritative_nvd_affected,
          synthesized_from_ghsa: $nvd_entry.synthesized_from_ghsa,
          platforms: $nvd_entry.platforms,
          authoritative_canonical_platforms: $nvd_entry.authoritative_canonical_platforms,
          cwe_ids: $nvd_entry.cwe_ids,
          authoritative_canonical_cwe_ids: $nvd_entry.authoritative_canonical_cwe_ids,
          description: $nvd_entry.description,
          title: $nvd_entry.title,
          references: $nvd_entry.references
        }
      }
    ]
  ' > "$TEMP_DIR/updated_advisories.json"
else
  echo '[]' > "$TEMP_DIR/nvd_current_state.json"
  echo '[]' > "$TEMP_DIR/updated_advisories.json"
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
UPDATED_COUNT=$(jq 'length' "$TEMP_DIR/updated_advisories.json")
RETRACTED_COUNT=$(jq 'length' "$TEMP_DIR/retracted_advisory_ids.json")
echo "New advisories to add: $NEW_COUNT"
echo "Updated advisories: $UPDATED_COUNT"
echo "Advisories no longer carrying publishable NVD scope: $RETRACTED_COUNT"

EXISTING_CVE_COUNT=$(jq '[.[] | select((.id // "") | startswith("CVE-"))] | length' "$TEMP_DIR/existing_advisories.json")
if [ "$FORCE" = "false" ]; then
  RETRACTION_LIMIT="$(nvd_drop_review_limit)"
  echo "Incremental retraction safety check: $RETRACTED_COUNT of $EXISTING_CVE_COUNT existing CVEs (review at $RETRACTION_LIMIT records or 25% of the current CVE feed)"
  if nvd_is_material_drop "$RETRACTED_COUNT" "$EXISTING_CVE_COUNT" && [ "$ALLOW_LARGE_DROP" != "true" ]; then
    echo "Error: refusing incremental update because it would retract $RETRACTED_COUNT of $EXISTING_CVE_COUNT existing CVEs (review threshold: $RETRACTION_LIMIT records or 25% of the current CVE feed). Review the broad NVD inventory, then rerun with --allow-large-drop if intentional." >&2
    exit 1
  fi
fi

if [ "$FORCE" = "true" ] && [ "$NEW_COUNT" -ne "$FILTERED" ]; then
  echo "Error: full rebuild transform mismatch (filtered=$FILTERED, transformed=$NEW_COUNT)"
  exit 1
fi

if [ "$FORCE" = "true" ]; then
  jq -n --slurpfile existing "$TEMP_DIR/existing_advisories.json" --slurpfile rebuilt "$TEMP_DIR/new_advisories.json" '
    ($rebuilt[0] | map(.id) | unique) as $rebuilt_ids |
    [
      $existing[0][] |
      select((.id // "") | startswith("CVE-")) |
      .id as $id |
      select(($rebuilt_ids | index($id)) == null) |
      $id
    ] | unique
  ' > "$TEMP_DIR/full_rebuild_removed_ids.json"
  FULL_REBUILD_REMOVED_COUNT=$(jq 'length' "$TEMP_DIR/full_rebuild_removed_ids.json")
  DROP_REVIEW_LIMIT="$(nvd_drop_review_limit)"
  echo "Full rebuild identity safety check: $FULL_REBUILD_REMOVED_COUNT of $EXISTING_CVE_COUNT existing CVE IDs absent (review at $DROP_REVIEW_LIMIT records or 25% of the current CVE feed)"
  if nvd_is_material_drop "$FULL_REBUILD_REMOVED_COUNT" "$EXISTING_CVE_COUNT" && [ "$ALLOW_LARGE_DROP" != "true" ]; then
    echo "Error: refusing full rebuild because it would remove $FULL_REBUILD_REMOVED_COUNT of $EXISTING_CVE_COUNT existing CVE IDs (review threshold: $DROP_REVIEW_LIMIT records or 25% of the current CVE feed). Review the counts and IDs, then rerun with --allow-large-drop if intentional." >&2
    jq -r '.[] | "- \(.)"' "$TEMP_DIR/full_rebuild_removed_ids.json" >&2
    exit 1
  fi
fi

if [ "$NEW_COUNT" -eq 0 ] && [ "$UPDATED_COUNT" -eq 0 ] && [ "$RETRACTED_COUNT" -eq 0 ] && [ "$FORCE" = "false" ]; then
  echo ""
  echo "No new, corrected, or retracted CVEs found. Feed is up to date."
  echo "Use --force to re-fetch all CVEs regardless of existing entries."
  exit 0
fi

if [ "$NEW_COUNT" -gt 0 ]; then
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
        .cve.metrics.cvssMetricV2[0]?.cvssData.vectorString //
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
fi

echo ""
echo "=== Updating Feeds ==="

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Merge new advisories into existing feed
if [ -f "$FEED_PATH" ]; then
  jq --slurpfile new "$TEMP_DIR/new_advisories.json" \
    --slurpfile updates "$TEMP_DIR/updated_advisories.json" \
    --slurpfile retracted "$TEMP_DIR/retracted_advisory_ids.json" \
    --arg now "$NOW" --argjson force "$FORCE" '
    .updated = $now |
    # Full scans replace NVD CVEs, matching CI; incremental scans merge by ID.
    .advisories = (
      (if $force
       then ((.advisories // []) | map(select(((.id // "") | startswith("CVE-")) | not)))
       else (
         (.advisories // []) |
         map(
           . as $adv |
           select(($adv.id as $id | (($retracted[0] // []) | index($id))) == null) |
           ($updates[0] | map(select(.id == $adv.id)) | first) as $update |
           if $update then
             ($adv * $update.updated_fields)
             | .affected = (
                 ($update.updated_fields.affected + ($adv.authoritative_ghsa_affected // []))
                 | unique
               )
             | .platforms = (
                 ($update.updated_fields.platforms + ($adv.authoritative_ghsa_platforms // []))
                 | unique
               )
             | .cwe_ids = (
                 ($update.updated_fields.cwe_ids + ($adv.authoritative_ghsa_cwe_ids // []))
                 | unique
               )
             | .references = (
                 $update.updated_fields.references
                 + [
                     $adv.references[]? |
                     select(type == "string" and test("GHSA-"; "i"))
                   ]
                 | unique
               )
           else
             $adv
           end
         )
       )
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
  echo "Existing advisories corrected: $UPDATED_COUNT"
  echo "Advisories retracted: $RETRACTED_COUNT"
  echo ""
  echo "Run 'npm run dev' to preview the feed in the local site."
else
  echo "Error: Generated invalid JSON"
  exit 1
fi
