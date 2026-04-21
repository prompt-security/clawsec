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
KEYWORDS_PATTERN="$(nvd_keyword_pattern)"
GITHUB_REF_PATTERN="$(nvd_github_ref_pattern)"
CPE_PATTERN="$(nvd_cpe_pattern)"
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

# Determine date window
if [ -f "$FEED_PATH" ] && [ "$FORCE" = "false" ]; then
  LAST_UPDATED=$(jq -r '.updated // empty' "$FEED_PATH")
  if [ -n "$LAST_UPDATED" ]; then
    START_DATE="$LAST_UPDATED"
    echo "Using last updated from feed: $START_DATE"
  fi
fi

if [ -z "${START_DATE:-}" ]; then
  # macOS vs Linux date compatibility
  if date -v-1d > /dev/null 2>&1; then
    START_DATE=$(date -u -v-"${DAYS_BACK}"d +%Y-%m-%dT%H:%M:%S.000Z)
  else
    START_DATE=$(date -u -d "${DAYS_BACK} days ago" +%Y-%m-%dT%H:%M:%S.000Z)
  fi
  echo "Using default start date: $START_DATE"
fi

END_DATE=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "End date: $END_DATE"
echo ""

# URL encode dates
START_ENC=${START_DATE//:/%3A}
END_ENC=${END_DATE//:/%3A}

echo "=== Fetching CVEs from NVD ==="

while IFS='|' read -r QUERY_KIND QUERY_VALUE; do
  [ -n "$QUERY_KIND" ] || continue

  QUERY_SLUG=$(nvd_query_slug "$QUERY_KIND" "$QUERY_VALUE")
  echo "Fetching $QUERY_KIND query: $QUERY_VALUE"

  URL=$(nvd_build_url "$QUERY_KIND" "$QUERY_VALUE" "&lastModStartDate=${START_ENC}&lastModEndDate=${END_ENC}")

  # Fetch with retry logic
  for i in 1 2 3; do
    HTTP_CODE=$(curl -s -w "%{http_code}" -o "$TEMP_DIR/nvd_${QUERY_SLUG}.json" "$URL")
    if [ "$HTTP_CODE" = "200" ]; then
      COUNT=$(jq '.vulnerabilities | length // 0' "$TEMP_DIR/nvd_${QUERY_SLUG}.json" 2>/dev/null || echo 0)
      echo "  ✓ Found $COUNT CVEs"
      break
    elif [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "429" ]; then
      echo "  Rate limited, waiting 30s before retry $i..."
      sleep 30
    else
      echo "  HTTP $HTTP_CODE, retry $i..."
      sleep 5
    fi
  done
  
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
  if [ -f "$FILE" ] && [ -s "$FILE" ]; then
    if jq -e '.vulnerabilities' "$FILE" > /dev/null 2>&1; then
      jq -s '.[0].vulnerabilities += .[1].vulnerabilities | .[0]' \
        "$TEMP_DIR/combined.json" "$FILE" > "$TEMP_DIR/combined_new.json"
      mv "$TEMP_DIR/combined_new.json" "$TEMP_DIR/combined.json"
    fi
  fi
done <<< "$NVD_QUERY_SPECS"

# Deduplicate by CVE ID
jq '.vulnerabilities | unique_by(.cve.id)' "$TEMP_DIR/combined.json" > "$TEMP_DIR/unique_cves.json"
TOTAL=$(jq 'length' "$TEMP_DIR/unique_cves.json")
echo "Total unique CVEs from NVD: $TOTAL"

# Post-filter: keep only CVEs matching our criteria
jq --arg kw "$KEYWORDS_PATTERN" --arg gh "$GITHUB_REF_PATTERN" --arg cpe "$CPE_PATTERN" '
  [.[] | select(
    (.cve.descriptions[]? | select(.lang == "en") | .value | test($kw; "i"))
    or
    (.cve.references[]? | .url | test($gh; "i"))
    or
    ([.cve.configurations[]? | .. | objects | .criteria? | strings | test($cpe; "i")] | any)
  )]
' "$TEMP_DIR/unique_cves.json" > "$TEMP_DIR/filtered_cves.json"

FILTERED=$(jq 'length' "$TEMP_DIR/filtered_cves.json")
echo "Filtered CVEs (matching criteria): $FILTERED"

# Get existing advisory IDs (unless force mode)
if [ "$FORCE" = "true" ]; then
  echo "Force mode: ignoring existing advisory IDs during transform"
  EXISTING_IDS=""
elif [ -f "$FEED_PATH" ]; then
  EXISTING_IDS=$(jq -r '.advisories[]?.id // empty' "$FEED_PATH" | sort -u)
else
  EXISTING_IDS=""
fi

# Transform CVEs to our advisory format (same logic as pipeline)
EXISTING_JSON=$(echo "$EXISTING_IDS" | jq -R -s 'split("\n") | map(select(length > 0))')

jq --argjson existing "$EXISTING_JSON" '
  def map_severity:
    if . == null then "medium"
    elif . >= 9.0 then "critical"
    elif . >= 7.0 then "high"
    elif . >= 4.0 then "medium"
    else "low"
    end;
  
  def get_cvss_score:
    .cve.metrics.cvssMetricV31[0]?.cvssData.baseScore //
    .cve.metrics.cvssMetricV30[0]?.cvssData.baseScore //
    .cve.metrics.cvssMetricV2[0]?.cvssData.baseScore //
    null;

  def nvd_category_raw:
    (
      [.cve.weaknesses[]?.description[]? | select(.lang == "en") | .value | strings | select(length > 0)]
      | unique
      | map(select(. != "NVD-CWE-noinfo" and . != "NVD-CWE-Other"))
      | .[0]
    );

  def cwe_id:
    (
      nvd_category_raw
      | if . == null then null
        else (try (capture("^CWE-(?<id>[0-9]+)$").id) catch null)
        end
    );

  def cwe_name_map($id):
    ({
      "20": "improper_input_validation",
      "22": "path_traversal",
      "77": "command_injection",
      "78": "os_command_injection",
      "79": "cross_site_scripting",
      "89": "sql_injection",
      "94": "code_injection",
      "119": "memory_buffer_bounds_violation",
      "120": "classic_buffer_overflow",
      "125": "out_of_bounds_read",
      "134": "format_string_vulnerability",
      "200": "exposure_of_sensitive_information",
      "250": "execution_with_unnecessary_privileges",
      "269": "improper_privilege_management",
      "284": "improper_access_control",
      "285": "improper_authorization",
      "287": "improper_authentication",
      "295": "improper_certificate_validation",
      "306": "missing_authentication_for_critical_function",
      "319": "cleartext_transmission_of_sensitive_information",
      "326": "inadequate_encryption_strength",
      "327": "risky_cryptographic_algorithm",
      "352": "cross_site_request_forgery",
      "362": "race_condition",
      "400": "uncontrolled_resource_consumption",
      "416": "use_after_free",
      "434": "unrestricted_file_upload",
      "502": "deserialization_of_untrusted_data",
      "601": "open_redirect",
      "611": "xml_external_entity_injection",
      "639": "insecure_direct_object_reference",
      "668": "exposure_of_resource_to_wrong_sphere",
      "669": "incorrect_resource_transfer_between_spheres",
      "732": "incorrect_permission_assignment",
      "787": "out_of_bounds_write",
      "798": "hard_coded_credentials",
      "862": "missing_authorization",
      "863": "incorrect_authorization",
      "918": "server_side_request_forgery",
      "922": "insecure_storage_of_sensitive_information"
    }[$id]);

  def nvd_category_name:
    (
      cwe_id as $id
      | if $id == null then "unspecified_weakness"
        else (cwe_name_map($id) // ("unknown_cwe_" + $id))
        end
    );

  def cpe_criteria:
    (
      [.cve.configurations[]? | .. | objects | .criteria? | strings | select(startswith("cpe:2.3:"))]
      | unique
    );

  def inferred_targets:
    (
      (
        [
          (.cve.descriptions[]? | select(.lang == "en") | .value),
          (.cve.references[]?.url // empty),
          (.cve.configurations[]? | .. | objects | .criteria? // empty)
        ]
        | map(strings | ascii_downcase)
        | join(" ")
      ) as $blob
      | (
          (if ($blob | test("github\\.com/openclaw/openclaw|\\bopenclaw\\b|\\bclawdbot\\b|\\bmoltbot\\b")) then ["openclaw@*"] else [] end)
          + (if ($blob | test("github\\.com/qwibitai/nanoclaw|\\bnanoclaw\\b|whatsapp-bot|\\bbaileys\\b")) then ["nanoclaw@*"] else [] end)
          + (if ($blob | test("github\\.com/softwarepub/hermes|cpe:2\\.3:a:software-metadata\\.pub:hermes|\\bhermes workflow\\b|software publication with rich metadata")) then ["hermes@*"] else [] end)
        )
    );

  def matched_targets:
    (
      (cpe_criteria + inferred_targets)
      | unique
      | .[0:5]
    );

  def platforms_from_targets($targets):
    (
      [
        (if ($targets | map(strings | ascii_downcase | select(startswith("openclaw@") or test("^cpe:2\\.3:[aho]:openclaw:openclaw(?::|$)"))) | length > 0) then "openclaw" else empty end),
        (if ($targets | map(strings | ascii_downcase | select(startswith("nanoclaw@") or test("^cpe:2\\.3:[aho]:[^:]*:nanoclaw(?::|$)"))) | length > 0) then "nanoclaw" else empty end),
        (if ($targets | map(strings | ascii_downcase | select(startswith("hermes@") or test("^cpe:2\\.3:[aho]:software-metadata\\.pub:hermes(?::|$)"))) | length > 0) then "hermes" else empty end)
      ]
    );

  def normalized_affected:
    (
      matched_targets
      | if length == 0 then ["openclaw@*", "nanoclaw@*", "hermes@*"] else . end
    );

  def normalized_platforms:
    (
      inferred_targets as $inferred
      | platforms_from_targets($inferred) as $from_inferred
      | if ($from_inferred | length) > 0 then $from_inferred
        else
          matched_targets as $targets
          | platforms_from_targets($targets) as $from_targets
          | if ($from_targets | length) > 0 then $from_targets else ["openclaw", "nanoclaw", "hermes"] end
        end
    );
  
  [.[] |
    select(.cve.id as $id | $existing | index($id) | not) |
    {
      id: .cve.id,
      severity: (get_cvss_score | map_severity),
      type: nvd_category_name,
      nvd_category_id: nvd_category_raw,
      title: (.cve.descriptions[] | select(.lang == "en") | .value | .[0:100] + (if length > 100 then "..." else "" end)),
      description: (.cve.descriptions[] | select(.lang == "en") | .value),
      affected: normalized_affected,
      platforms: normalized_platforms,
      action: "Review and update affected components. See NVD for remediation details.",
      published: .cve.published,
      references: [.cve.references[]?.url // empty] | unique | .[0:3],
      cvss_score: get_cvss_score,
      nvd_url: ("https://nvd.nist.gov/vuln/detail/" + .cve.id),
      exploitability_score: null,
      exploitability_rationale: null
    }
  ]
' "$TEMP_DIR/filtered_cves.json" > "$TEMP_DIR/new_advisories.json"

NEW_COUNT=$(jq 'length' "$TEMP_DIR/new_advisories.json")
echo "New advisories to add: $NEW_COUNT"

if [ "$NEW_COUNT" -eq 0 ]; then
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
  jq --argjson new "$(cat "$TEMP_DIR/new_advisories.json")" --arg now "$NOW" '
    .updated = $now |
    # Merge by advisory ID so force mode can refresh existing CVEs without duplicates
    .advisories = (
      reduce (.advisories + $new)[] as $adv
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
  jq -n --argjson advisories "$(cat "$TEMP_DIR/new_advisories.json")" --arg now "$NOW" '{
    version: "1.0.0",
    updated: $now,
    description: "Community-driven security advisory feed for ClawSec. Automatically updated with OpenClaw, NanoClaw, and Hermes-related CVEs from NVD.",
    advisories: ($advisories | sort_by(.published) | reverse)
  }' > "$TEMP_DIR/updated_feed.json"
fi

# Validate and save
if jq empty "$TEMP_DIR/updated_feed.json" 2>/dev/null; then
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
