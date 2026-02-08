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

# Configuration - same as pipeline
FEED_PATH="$PROJECT_ROOT/advisories/feed.json"
SKILL_FEED_PATH="$PROJECT_ROOT/skills/clawsec-feed/advisories/feed.json"
PUBLIC_FEED_PATH="$PROJECT_ROOT/public/advisories/feed.json"
KEYWORDS="OpenClaw clawdbot Moltbot"
GITHUB_REF_PATTERN="github.com/openclaw/openclaw"

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
    START_DATE=$(date -u -v-${DAYS_BACK}d +%Y-%m-%dT%H:%M:%S.000Z)
  else
    START_DATE=$(date -u -d "${DAYS_BACK} days ago" +%Y-%m-%dT%H:%M:%S.000Z)
  fi
  echo "Using default start date: $START_DATE"
fi

END_DATE=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "End date: $END_DATE"
echo ""

# URL encode dates
START_ENC=$(echo "$START_DATE" | sed 's/:/%3A/g')
END_ENC=$(echo "$END_DATE" | sed 's/:/%3A/g')

echo "=== Fetching CVEs from NVD ==="

for KEYWORD in $KEYWORDS; do
  echo "Fetching keyword: $KEYWORD"
  
  URL="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${KEYWORD}&lastModStartDate=${START_ENC}&lastModEndDate=${END_ENC}"
  
  # Fetch with retry logic
  for i in 1 2 3; do
    HTTP_CODE=$(curl -s -w "%{http_code}" -o "$TEMP_DIR/nvd_${KEYWORD}.json" "$URL")
    if [ "$HTTP_CODE" = "200" ]; then
      COUNT=$(jq '.vulnerabilities | length // 0' "$TEMP_DIR/nvd_${KEYWORD}.json" 2>/dev/null || echo 0)
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
done

echo ""
echo "=== Processing CVEs ==="

# Combine all fetched CVEs
echo '{"vulnerabilities":[]}' > "$TEMP_DIR/combined.json"

for KEYWORD in $KEYWORDS; do
  FILE="$TEMP_DIR/nvd_${KEYWORD}.json"
  if [ -f "$FILE" ] && [ -s "$FILE" ]; then
    if jq -e '.vulnerabilities' "$FILE" > /dev/null 2>&1; then
      jq -s '.[0].vulnerabilities += .[1].vulnerabilities | .[0]' \
        "$TEMP_DIR/combined.json" "$FILE" > "$TEMP_DIR/combined_new.json"
      mv "$TEMP_DIR/combined_new.json" "$TEMP_DIR/combined.json"
    fi
  fi
done

# Deduplicate by CVE ID
jq '.vulnerabilities | unique_by(.cve.id)' "$TEMP_DIR/combined.json" > "$TEMP_DIR/unique_cves.json"
TOTAL=$(jq 'length' "$TEMP_DIR/unique_cves.json")
echo "Total unique CVEs from NVD: $TOTAL"

# Post-filter: keep only CVEs matching our criteria
KEYWORDS_PATTERN="OpenClaw|clawdbot|Moltbot|openclaw"

jq --arg kw "$KEYWORDS_PATTERN" --arg gh "$GITHUB_REF_PATTERN" '
  [.[] | select(
    (.cve.descriptions[]? | select(.lang == "en") | .value | test($kw; "i"))
    or
    (.cve.references[]? | .url | test($gh; "i"))
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
  
  [.[] | 
    select(.cve.id as $id | $existing | index($id) | not) |
    {
      id: .cve.id,
      severity: (get_cvss_score | map_severity),
      type: nvd_category_name,
      nvd_category_id: nvd_category_raw,
      title: (.cve.descriptions[] | select(.lang == "en") | .value | .[0:100] + (if length > 100 then "..." else "" end)),
      description: (.cve.descriptions[] | select(.lang == "en") | .value),
      affected: [.cve.configurations[]?.nodes[]?.cpeMatch[]?.criteria // empty] | unique | .[0:5],
      action: "Review and update affected components. See NVD for remediation details.",
      published: .cve.published,
      references: [.cve.references[]?.url // empty] | unique | .[0:3],
      cvss_score: get_cvss_score,
      nvd_url: ("https://nvd.nist.gov/vuln/detail/" + .cve.id)
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
    description: "Community-driven security advisory feed for ClawSec. Automatically updated with OpenClaw-related CVEs from NVD.",
    advisories: ($advisories | sort_by(.published) | reverse)
  }' > "$TEMP_DIR/updated_feed.json"
fi

# Validate and save
if jq empty "$TEMP_DIR/updated_feed.json" 2>/dev/null; then
  # Update main feed
  cp "$TEMP_DIR/updated_feed.json" "$FEED_PATH"
  echo "✓ Updated: $FEED_PATH"
  
  # Update skill feed
  mkdir -p "$(dirname "$SKILL_FEED_PATH")"
  cp "$FEED_PATH" "$SKILL_FEED_PATH"
  echo "✓ Updated: $SKILL_FEED_PATH"
  
  # Update public feed for local dev
  mkdir -p "$(dirname "$PUBLIC_FEED_PATH")"
  cp "$FEED_PATH" "$PUBLIC_FEED_PATH"
  echo "✓ Updated: $PUBLIC_FEED_PATH"
  
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
