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

# NVD rejects lastModStartDate..lastModEndDate ranges longer than 120 days,
# with or without an API key. A daily poll only needs a 90-day ceiling, which
# stays inside that cap when a feed timestamp goes stale.
NVD_MAX_LOOKBACK_DAYS=90
NVD_RESULTS_PER_PAGE=2000
NVD_FETCH_ATTEMPTS=5
# Authenticated budget is about 50 requests per rolling 30s. One second leaves
# room for retries. Without a key the public budget is 5 per 30s (6s spacing).
NVD_AUTH_REQUEST_INTERVAL_SECONDS=1
NVD_PUBLIC_REQUEST_INTERVAL_SECONDS=6
NVD_RETRY_PASS_DELAY_SECONDS=30

# 1 when NVD_API_KEY is non-empty after trimming. Callers must read this flag
# instead of expanding the key, so xtrace cannot print the secret.
NVD_API_KEY_IS_SET=0
NVD_LAST_HTTP_CODE=""
NVD_FAILED_QUERIES=()
# Paths for the in-flight NVD request. A signal trap removes them so a killed
# curl cannot leave the API key behind in the temp directory.
NVD_CURL_CONFIG_FILE=""
NVD_CURL_CODE_FILE=""
NVD_SAVED_EXIT_TRAP=""
NVD_SAVED_INT_TRAP=""
NVD_SAVED_TERM_TRAP=""

nvd_remove_request_temps() {
  if [ -n "${NVD_CURL_CONFIG_FILE:-}" ]; then
    rm -f "$NVD_CURL_CONFIG_FILE"
    NVD_CURL_CONFIG_FILE=""
  fi
  if [ -n "${NVD_CURL_CODE_FILE:-}" ]; then
    rm -f "$NVD_CURL_CODE_FILE"
    NVD_CURL_CODE_FILE=""
  fi
}

# trap -p output is itself a trap command. Re-eval it to restore the caller.
nvd_restore_one_trap() {
  local saved="$1"
  local signal="$2"
  if [ -n "$saved" ]; then
    # shellcheck disable=SC2294
    eval "$saved"
  else
    trap - "$signal"
  fi
}

nvd_run_saved_exit_trap() {
  local saved="$1"
  local quoted=""
  local command=""
  [ -n "$saved" ] || return 0
  quoted="${saved#trap -- }"
  quoted="${quoted% EXIT}"
  # trap -p stores the action as one shell-quoted word. Decode it, then run it.
  # shellcheck disable=SC2086
  command="$(eval "printf '%s' ${quoted}")"
  # shellcheck disable=SC2294
  eval "$command"
}

nvd_install_request_traps() {
  NVD_SAVED_EXIT_TRAP="$(trap -p EXIT || true)"
  NVD_SAVED_INT_TRAP="$(trap -p INT || true)"
  NVD_SAVED_TERM_TRAP="$(trap -p TERM || true)"
  trap 'nvd_request_exit_cleanup' EXIT
  trap 'nvd_request_interrupted INT' INT
  trap 'nvd_request_interrupted TERM' TERM
}

nvd_restore_request_traps() {
  local saved_exit="${NVD_SAVED_EXIT_TRAP:-}"
  local saved_int="${NVD_SAVED_INT_TRAP:-}"
  local saved_term="${NVD_SAVED_TERM_TRAP:-}"
  NVD_SAVED_EXIT_TRAP=""
  NVD_SAVED_INT_TRAP=""
  NVD_SAVED_TERM_TRAP=""
  nvd_remove_request_temps
  nvd_restore_one_trap "$saved_int" INT
  nvd_restore_one_trap "$saved_term" TERM
  nvd_restore_one_trap "$saved_exit" EXIT
}

# Command-substitution subshells inherit this trap. They must not delete the
# parent's temp files or run the parent's EXIT action. The shell's own exit
# status is left alone: an EXIT trap does not replace it unless it calls exit.
nvd_request_exit_cleanup() {
  # Do not return from an EXIT trap: bash can drop the function context and
  # replace the shell's exit status. Falling off the end leaves that status.
  if [ "${BASH_SUBSHELL:-0}" -eq 0 ]; then
    local saved_exit="${NVD_SAVED_EXIT_TRAP:-}"
    local saved_int="${NVD_SAVED_INT_TRAP:-}"
    local saved_term="${NVD_SAVED_TERM_TRAP:-}"
    NVD_SAVED_EXIT_TRAP=""
    NVD_SAVED_INT_TRAP=""
    NVD_SAVED_TERM_TRAP=""
    nvd_remove_request_temps
    trap - EXIT INT TERM
    nvd_restore_one_trap "$saved_int" INT
    nvd_restore_one_trap "$saved_term" TERM
    nvd_run_saved_exit_trap "$saved_exit"
  fi
}

nvd_request_interrupted() {
  local signal="$1"
  if [ "${BASH_SUBSHELL:-0}" -eq 0 ]; then
    local saved_exit="${NVD_SAVED_EXIT_TRAP:-}"
    local saved_int="${NVD_SAVED_INT_TRAP:-}"
    local saved_term="${NVD_SAVED_TERM_TRAP:-}"
    NVD_SAVED_EXIT_TRAP=""
    NVD_SAVED_INT_TRAP=""
    NVD_SAVED_TERM_TRAP=""
    nvd_remove_request_temps
    trap - EXIT INT TERM
    nvd_restore_one_trap "$saved_int" INT
    nvd_restore_one_trap "$saved_term" TERM
    # Restoring EXIT makes the caller's handler run once as the process dies.
    nvd_restore_one_trap "$saved_exit" EXIT
    kill -s "$signal" "$$"
  fi
}

nvd_prepare_api_key() {
  local tracing=0
  case $- in
    *x*)
      tracing=1
      set +x
      ;;
  esac

  if [ -n "${NVD_API_KEY+x}" ]; then
    NVD_API_KEY="${NVD_API_KEY//$'\r'/}"
    NVD_API_KEY="${NVD_API_KEY//$'\n'/}"
    NVD_API_KEY="${NVD_API_KEY#"${NVD_API_KEY%%[![:space:]]*}"}"
    NVD_API_KEY="${NVD_API_KEY%"${NVD_API_KEY##*[![:space:]]}"}"
  fi

  if [ -n "${NVD_API_KEY:-}" ]; then
    NVD_API_KEY_IS_SET=1
  else
    NVD_API_KEY_IS_SET=0
  fi

  if [ "$tracing" -eq 1 ]; then
    set -x
  fi
}

nvd_api_key_present() {
  nvd_prepare_api_key
  [ "$NVD_API_KEY_IS_SET" -eq 1 ]
}

nvd_warn_if_unauthenticated() {
  if nvd_api_key_present; then
    echo "NVD API key is set. Requests send it in the apiKey header and not the URL."
    echo "Inter-request delay: ${NVD_AUTH_REQUEST_INTERVAL_SECONDS}s (authenticated limit is about 50 requests per 30s)."
    return 0
  fi

  echo "::warning::NVD_API_KEY is empty. Falling back to unauthenticated NVD requests (about 5 requests per 30s)."
  echo "Inter-request delay: ${NVD_PUBLIC_REQUEST_INTERVAL_SECONDS}s."
}

nvd_inter_request_sleep() {
  if nvd_api_key_present; then
    sleep "$NVD_AUTH_REQUEST_INTERVAL_SECONDS"
  else
    sleep "$NVD_PUBLIC_REQUEST_INTERVAL_SECONDS"
  fi
}

nvd_is_transient_status() {
  local code="$1"
  case "$code" in
    000 | 5[0-9][0-9])
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

# attempt is 1-based and counts the failure just observed.
# Transient failures wait 10/30/60/120s. Rate limits wait at least 30s.
nvd_retry_backoff_seconds() {
  local attempt="$1"
  local http_code="${2:-}"
  local seconds=120

  case "$attempt" in
    1) seconds=10 ;;
    2) seconds=30 ;;
    3) seconds=60 ;;
    *) seconds=120 ;;
  esac

  if [ "$http_code" = "403" ] || [ "$http_code" = "429" ]; then
    if [ "$seconds" -lt 30 ]; then
      seconds=30
    fi
  fi

  printf '%s\n' "$seconds"
}

nvd_date_to_epoch() {
  local value="$1"
  local epoch=""
  local trimmed=""

  epoch="$(date -u -d "$value" +%s 2>/dev/null || true)"
  if [ -z "$epoch" ]; then
    trimmed="${value%Z}"
    trimmed="${trimmed%.*}"
    epoch="$(date -u -j -f "%Y-%m-%dT%H:%M:%S" "$trimmed" +%s 2>/dev/null || true)"
  fi

  if [[ ! "$epoch" =~ ^[0-9]+$ ]]; then
    echo "Error: unable to parse NVD date: ${value}" >&2
    return 1
  fi

  printf '%s\n' "$epoch"
}

nvd_epoch_to_date() {
  local epoch="$1"
  local formatted=""

  formatted="$(date -u -d "@${epoch}" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u -r "$epoch" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || true)"
  if [ -z "$formatted" ]; then
    echo "Error: unable to format NVD epoch: ${epoch}" >&2
    return 1
  fi

  printf '%s\n' "$formatted"
}

# Print the lastMod start to use. Missing or too-old timestamps clamp to
# end minus NVD_MAX_LOOKBACK_DAYS. Output is always a canonical UTC timestamp.
nvd_clamp_start_date() {
  local start_date="${1:-}"
  local end_date="$2"
  local end_epoch=""
  local start_epoch=""
  local floor_epoch=0

  end_epoch="$(nvd_date_to_epoch "$end_date")"
  floor_epoch=$((end_epoch - NVD_MAX_LOOKBACK_DAYS * 86400))

  if [ -z "$start_date" ]; then
    echo "Warning: no last poll date; using ${NVD_MAX_LOOKBACK_DAYS} days before ${end_date}. NVD rejects lastMod ranges longer than 120 days, with or without an API key." >&2
    nvd_epoch_to_date "$floor_epoch"
    return 0
  fi

  start_epoch="$(nvd_date_to_epoch "$start_date")"
  if [ "$start_epoch" -lt "$floor_epoch" ]; then
    echo "Warning: last poll date ${start_date} is more than ${NVD_MAX_LOOKBACK_DAYS} days before ${end_date}; clamping the start. NVD rejects lastMod ranges longer than 120 days, with or without an API key." >&2
    nvd_epoch_to_date "$floor_epoch"
    return 0
  fi

  if [ "$start_epoch" -ge "$end_epoch" ]; then
    echo "Warning: start date ${start_date} is not before end date ${end_date}; using 24 hours before the end." >&2
    nvd_epoch_to_date $((end_epoch - 86400))
    return 0
  fi

  nvd_epoch_to_date "$start_epoch"
}

# GET one URL. The API key, when set, is sent as a header and never written to
# the URL, the curl argv, or xtrace. Returns 0 only for HTTP 200 with JSON.
nvd_curl() {
  local output_file="$1"
  local url="$2"
  local tracing=0
  local http_code=""
  local config_file=""
  local code_file=""
  local escaped_key=""

  case $- in
    *x*)
      tracing=1
      set +x
      ;;
  esac

  # xtrace is off before the key is expanded. Curl reads it from a
  # mode-600 config file, so the value is not part of the command line.
  # The signal trap removes that file if curl is killed mid-request.
  nvd_prepare_api_key
  code_file="$(mktemp)"
  NVD_CURL_CODE_FILE="$code_file"
  nvd_install_request_traps
  if [ "$NVD_API_KEY_IS_SET" -eq 1 ]; then
    config_file="$(mktemp)"
    # Track the path before the key is written so a signal cannot leave it behind.
    NVD_CURL_CONFIG_FILE="$config_file"
    chmod 600 "$config_file"
    escaped_key="${NVD_API_KEY//\\/\\\\}"
    escaped_key="${escaped_key//\"/\\\"}"
    printf 'header = "apiKey: %s"\n' "$escaped_key" >"$config_file"
    curl --config "$config_file" -sS --connect-timeout 30 --max-time 180 -w "%{http_code}" -o "$output_file" "$url" >"$code_file" || true
  else
    curl -sS --connect-timeout 30 --max-time 180 -w "%{http_code}" -o "$output_file" "$url" >"$code_file" || true
  fi
  http_code="$(tr -cd '0-9' <"$code_file" || true)"
  nvd_restore_request_traps

  if [ "$tracing" -eq 1 ]; then
    set -x
  fi

  http_code="${http_code//[!0-9]/}"
  if [ "${#http_code}" -ne 3 ]; then
    http_code="000"
  fi
  NVD_LAST_HTTP_CODE="$http_code"
}

nvd_http_get() {
  local url="$1"
  local output_file="$2"
  local attempt=1
  local http_code=""
  local backoff=0

  NVD_LAST_HTTP_CODE=""
  while [ "$attempt" -le "$NVD_FETCH_ATTEMPTS" ]; do
    nvd_curl "$output_file" "$url"
    http_code="$NVD_LAST_HTTP_CODE"

    if [ "$http_code" = "200" ] && jq -e . "$output_file" >/dev/null 2>&1; then
      return 0
    fi

    if [ "$http_code" = "200" ]; then
      echo "Invalid JSON from NVD (attempt ${attempt}/${NVD_FETCH_ATTEMPTS})."
    elif [ "$http_code" = "403" ] || [ "$http_code" = "429" ]; then
      echo "NVD rate limited with HTTP ${http_code} (attempt ${attempt}/${NVD_FETCH_ATTEMPTS})."
    elif nvd_is_transient_status "$http_code"; then
      echo "Transient NVD failure HTTP ${http_code} (attempt ${attempt}/${NVD_FETCH_ATTEMPTS})."
    else
      echo "NVD request failed with non-retryable HTTP ${http_code} (attempt ${attempt}/${NVD_FETCH_ATTEMPTS})."
      return 1
    fi

    if [ "$attempt" -ge "$NVD_FETCH_ATTEMPTS" ]; then
      echo "Giving up on NVD request after ${NVD_FETCH_ATTEMPTS} attempts (last HTTP ${http_code})."
      return 1
    fi

    backoff="$(nvd_retry_backoff_seconds "$attempt" "$http_code")"
    echo "Waiting ${backoff}s before the next NVD attempt."
    sleep "$backoff"
    attempt=$((attempt + 1))
  done

  return 1
}

# Succeeds when a page carries the fields NVD pagination is checked against.
nvd_page_is_complete_shape() {
  local page_file="$1"

  jq -e '
    (.vulnerabilities | type == "array") and
    (.totalResults | type == "number" and . >= 0 and . == floor) and
    (.startIndex | type == "number" and . >= 0 and . == floor) and
    (.resultsPerPage | type == "number" and . >= 0 and . == floor) and
    ([.vulnerabilities[]? | .cve.id | type == "string"] | all)
  ' "$page_file" >/dev/null 2>&1
}

# Download every page of one query into outfile. extra_suffix is appended
# before startIndex/resultsPerPage (empty for a full-history scan).
#
# A full rebuild replaces every CVE advisory with the fetched set, so the query
# only succeeds when the merged rows match NVD's own bookkeeping exactly. A
# shifted, short, duplicated or re-counted page fails the query instead of
# silently shrinking the feed.
nvd_fetch_query_pages() {
  local kind="$1"
  local value="$2"
  local outfile="$3"
  local extra_suffix="${4:-}"
  local start_index=0
  local page_file="${outfile}.page"
  local page_count=0
  local total_results=0
  local expected_total=-1
  local response_start=0
  local merged_count=0
  local unique_merged_count=0
  local url=""

  printf '%s\n' '{"vulnerabilities":[]}' >"$outfile"

  while true; do
    url="$(nvd_build_url "$kind" "$value" "${extra_suffix}&startIndex=${start_index}&resultsPerPage=${NVD_RESULTS_PER_PAGE}")"
    echo "URL: ${url}"
    if ! nvd_http_get "$url" "$page_file"; then
      rm -f "$page_file"
      return 1
    fi

    if ! nvd_page_is_complete_shape "$page_file"; then
      echo "Invalid or incomplete NVD JSON for '${kind}:${value}' at startIndex=${start_index}." >&2
      rm -f "$page_file"
      return 1
    fi

    response_start="$(jq -r '.startIndex' "$page_file")"
    page_count="$(jq '.vulnerabilities | length' "$page_file")"
    total_results="$(jq '.totalResults' "$page_file")"

    if [ "$response_start" -ne "$start_index" ]; then
      echo "NVD startIndex mismatch for '${kind}:${value}': requested ${start_index}, received ${response_start}." >&2
      rm -f "$page_file"
      return 1
    fi
    if [ "$expected_total" -eq -1 ]; then
      expected_total="$total_results"
    elif [ "$total_results" -ne "$expected_total" ]; then
      echo "NVD totalResults changed during pagination for '${kind}:${value}': ${expected_total} to ${total_results}." >&2
      rm -f "$page_file"
      return 1
    fi
    if [ "$page_count" -eq 0 ] && [ "$start_index" -lt "$expected_total" ]; then
      echo "NVD returned an empty page before all results for '${kind}:${value}' (startIndex=${start_index}, totalResults=${expected_total})." >&2
      rm -f "$page_file"
      return 1
    fi

    jq -s '.[0].vulnerabilities += .[1].vulnerabilities | .[0]' \
      "$outfile" "$page_file" >"${outfile}.merged"
    mv "${outfile}.merged" "$outfile"
    rm -f "$page_file"

    merged_count="$(jq '.vulnerabilities | length' "$outfile")"
    unique_merged_count="$(jq '[.vulnerabilities[].cve.id] | unique | length' "$outfile")"
    echo "Fetched ${page_count} results at startIndex=${start_index} (${merged_count}/${expected_total} complete)"

    if [ "$unique_merged_count" -ne "$merged_count" ]; then
      echo "NVD returned duplicate CVE IDs while paginating '${kind}:${value}'." >&2
      return 1
    fi
    if [ "$merged_count" -eq "$expected_total" ]; then
      return 0
    fi
    if [ "$merged_count" -gt "$expected_total" ]; then
      echo "NVD returned more rows than totalResults for '${kind}:${value}'." >&2
      return 1
    fi

    start_index=$((start_index + page_count))
    nvd_inter_request_sleep
  done
}

nvd_fetch_query_pass() {
  local specs="$1"
  local dest_dir="$2"
  local date_suffix="${3:-}"
  local query_kind=""
  local query_value=""
  local query_slug=""
  local outfile=""

  NVD_FAILED_QUERIES=()
  while IFS='|' read -r query_kind query_value || [ -n "$query_kind" ]; do
    [ -n "$query_kind" ] || continue
    query_slug="$(nvd_query_slug "$query_kind" "$query_value")"
    outfile="${dest_dir}/nvd_${query_slug}.json"
    echo "Fetching ${query_kind} query: ${query_value}"
    if [ -z "$date_suffix" ]; then
      echo "Full scan mode enabled: paginating complete NVD history for '${query_kind}:${query_value}'"
    fi

    if nvd_fetch_query_pages "$query_kind" "$query_value" "$outfile" "$date_suffix"; then
      echo "Success for ${query_kind}:${query_value}"
    else
      echo "::error::Failed to fetch valid NVD response for '${query_kind}:${query_value}' (last HTTP code: ${NVD_LAST_HTTP_CODE:-unknown})."
      NVD_FAILED_QUERIES+=("${query_kind}|${query_value}")
    fi
    nvd_inter_request_sleep
  done <<<"$specs"

  [ "${#NVD_FAILED_QUERIES[@]}" -eq 0 ]
}

# Fetch every spec. Queries that fail the first pass get one later pass, after
# the per-request backoff has already run. A query that still fails returns 1
# so the feed updated timestamp cannot move past CVEs that were not fetched.
nvd_fetch_all_queries() {
  local specs="$1"
  local dest_dir="$2"
  local date_suffix="${3:-}"
  local retry_specs=""

  mkdir -p "$dest_dir"
  if nvd_fetch_query_pass "$specs" "$dest_dir" "$date_suffix"; then
    return 0
  fi

  retry_specs="$(printf '%s\n' "${NVD_FAILED_QUERIES[@]}")"
  echo "Retrying ${#NVD_FAILED_QUERIES[@]} NVD query(ies) that failed the first pass."
  echo "Waiting ${NVD_RETRY_PASS_DELAY_SECONDS}s before the retry pass."
  sleep "$NVD_RETRY_PASS_DELAY_SECONDS"
  if nvd_fetch_query_pass "$retry_specs" "$dest_dir" "$date_suffix"; then
    echo "Retry pass recovered every failed NVD query."
    return 0
  fi

  echo "::error::NVD fetch failed for query spec(s): ${NVD_FAILED_QUERIES[*]}"
  return 1
}
