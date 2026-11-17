#!/bin/bash
# Behavioral checks for the NVD poll helper used by poll-nvd-cves.yml.
# Curl and sleep are stubbed. No network.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/feed-utils.sh
source "$SCRIPT_DIR/feed-utils.sh"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

FAILURES=0
RESPONSE_CODES=()
RESPONSE_BODIES=()
REQUEST_URLS=()
SLEEP_SECONDS=()
SAW_API_KEY_HEADER=0
CURL_ARG_LEAKED=0

fail() {
  echo "FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
}

pass() {
  echo "PASS: $*"
}

assert_eq() {
  local actual="$1"
  local expected="$2"
  local message="$3"
  if [ "$actual" != "$expected" ]; then
    fail "${message}: expected [${expected}] actual [${actual}]"
  else
    pass "$message"
  fi
}

reset_transport() {
  RESPONSE_CODES=()
  RESPONSE_BODIES=()
  REQUEST_URLS=()
  SLEEP_SECONDS=()
  SAW_API_KEY_HEADER=0
  CURL_ARG_LEAKED=0
}

queue_response() {
  RESPONSE_CODES+=("$1")
  RESPONSE_BODIES+=("$2")
}

install_stubs() {
  curl() {
    local output_file=""
    local url=""
    local config_file=""

    while [ "$#" -gt 0 ]; do
      case "$1" in
        -o)
          output_file="$2"
          shift 2
          ;;
        --config)
          config_file="$2"
          shift 2
          ;;
        -w | --max-time | --connect-timeout)
          shift 2
          ;;
        -sS | -s | -S)
          shift
          ;;
        https://* | http://*)
          url="$1"
          shift
          ;;
        *)
          echo "unexpected curl argument" >&2
          return 1
          ;;
      esac
    done

    if [ -n "${NVD_API_KEY:-}" ] && [ -n "$url" ] && [[ "$url" == *"$NVD_API_KEY"* ]]; then
      CURL_ARG_LEAKED=1
      echo "API key appeared in the request URL" >&2
      return 1
    fi
    if [ -n "${NVD_API_KEY:-}" ] && [ -n "$config_file" ] && [[ "$config_file" == *"$NVD_API_KEY"* ]]; then
      CURL_ARG_LEAKED=1
      echo "API key appeared in the curl config path" >&2
      return 1
    fi

    if [ -n "$config_file" ]; then
      if [ ! -f "$config_file" ]; then
        echo "curl config file is missing" >&2
        return 1
      fi
      if grep -F -q -x -- "header = \"apiKey: ${NVD_API_KEY}\"" "$config_file"; then
        SAW_API_KEY_HEADER=$((SAW_API_KEY_HEADER + 1))
      fi
    fi

    REQUEST_URLS+=("$url")
    if [ "${#RESPONSE_CODES[@]}" -eq 0 ]; then
      echo "curl stub ran out of queued responses" >&2
      return 1
    fi

    local code="${RESPONSE_CODES[0]}"
    local body="${RESPONSE_BODIES[0]}"
    if [ "${#RESPONSE_CODES[@]}" -gt 1 ]; then
      RESPONSE_CODES=("${RESPONSE_CODES[@]:1}")
      RESPONSE_BODIES=("${RESPONSE_BODIES[@]:1}")
    else
      RESPONSE_CODES=()
      RESPONSE_BODIES=()
    fi

    printf '%s' "$body" >"$output_file"
    printf '%s' "$code"
  }

  sleep() {
    SLEEP_SECONDS+=("$1")
  }
}

install_stubs

joined_sleeps() {
  local joined=""
  local item
  for item in "${SLEEP_SECONDS[@]}"; do
    joined="${joined} ${item}"
  done
  printf '%s' "${joined# }"
}

test_clamp() {
  local end="2026-11-16T00:00:00Z"
  local floor stderr stdout
  floor="$(date -u -d "${end} - ${NVD_MAX_LOOKBACK_DAYS} days" +%Y-%m-%dT%H:%M:%S.000Z)"

  assert_eq "$NVD_MAX_LOOKBACK_DAYS" "90" "lookback ceiling is 90 days"

  stderr="$WORKDIR/clamp-err"
  stdout="$(nvd_clamp_start_date "" "$end" 2>"$stderr")"
  assert_eq "$stdout" "$floor" "missing last poll date clamps to 90 days"
  if grep -F -q "120 days" "$stderr"; then
    pass "missing-date warning mentions the 120-day NVD cap"
  else
    fail "missing-date warning should mention the 120-day NVD cap"
  fi

  stdout="$(nvd_clamp_start_date "2026-01-01T00:00:00Z" "$end" 2>"$stderr")"
  assert_eq "$stdout" "$floor" "stale last poll date clamps to 90 days"
  if grep -F -q "120 days" "$stderr"; then
    pass "stale-date warning mentions the 120-day NVD cap"
  else
    fail "stale-date warning should mention the 120-day NVD cap"
  fi

  stdout="$(nvd_clamp_start_date "$floor" "$end" 2>"$stderr")"
  assert_eq "$stdout" "$floor" "a start exactly 90 days back is kept"

  local older
  older="$(date -u -d "${floor} - 1 second" +%Y-%m-%dT%H:%M:%S.000Z)"
  stdout="$(nvd_clamp_start_date "$older" "$end" 2>"$stderr")"
  assert_eq "$stdout" "$floor" "a start one second past 90 days is clamped"

  stdout="$(nvd_clamp_start_date "2026-10-28T06:07:13Z" "2026-11-16T06:07:43.000Z" 2>"$stderr")"
  assert_eq "$stdout" "2026-10-28T06:07:13.000Z" "the current feed timestamp stays inside the window"

  stdout="$(nvd_clamp_start_date "2026-11-17T00:00:00Z" "$end" 2>"$stderr")"
  assert_eq "$stdout" "2026-11-15T00:00:00.000Z" "a start after the end moves back 24 hours"
}

test_backoff_and_transient() {
  assert_eq "$(nvd_retry_backoff_seconds 1 503)" "10" "first transient backoff is 10s"
  assert_eq "$(nvd_retry_backoff_seconds 2 503)" "30" "second transient backoff is 30s"
  assert_eq "$(nvd_retry_backoff_seconds 3 524)" "60" "third transient backoff is 60s"
  assert_eq "$(nvd_retry_backoff_seconds 4 500)" "120" "fourth transient backoff is 120s"
  assert_eq "$(nvd_retry_backoff_seconds 1 403)" "30" "rate-limit backoff is at least 30s"
  assert_eq "$(nvd_retry_backoff_seconds 1 429)" "30" "HTTP 429 backoff is at least 30s"

  if nvd_is_transient_status 503 && nvd_is_transient_status 524 && nvd_is_transient_status 500 && nvd_is_transient_status 000; then
    pass "503, 524, 500, and 000 are transient"
  else
    fail "expected 503, 524, 500, and 000 to be transient"
  fi
  if nvd_is_transient_status 404 || nvd_is_transient_status 403; then
    fail "404 and 403 should not use the transient class"
  else
    pass "404 and 403 are not treated as generic transient errors"
  fi
}

test_authenticated_retry_and_header() {
  local outfile="$WORKDIR/one.json"
  reset_transport
  NVD_API_KEY=$'nvd-test-key-5941-do-not-log\n'
  nvd_prepare_api_key
  assert_eq "$NVD_API_KEY" "nvd-test-key-5941-do-not-log" "surrounding newlines are stripped from the API key"
  assert_eq "$NVD_API_KEY_IS_SET" "1" "a trimmed API key is treated as present"

  queue_response "503" "unavailable"
  queue_response "524" "timeout"
  queue_response "200" '{"vulnerabilities":[],"totalResults":0}'

  if nvd_http_get "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenClaw" "$outfile"; then
    pass "503 then 524 then 200 eventually succeeds"
  else
    fail "expected the third attempt to succeed"
  fi
  assert_eq "$(joined_sleeps)" "10 30" "transient retries sleep 10s then 30s"
  assert_eq "$SAW_API_KEY_HEADER" "3" "each attempt sends the apiKey header"
  assert_eq "$CURL_ARG_LEAKED" "0" "the API key stays out of the URL and curl argv"
  assert_eq "${#REQUEST_URLS[@]}" "3" "three attempts were made"
  if [[ "${REQUEST_URLS[0]}" == *apiKey* ]]; then
    fail "request URL contains an apiKey parameter"
  else
    pass "request URL does not carry the API key"
  fi

  local warning
  warning="$(nvd_warn_if_unauthenticated)"
  if printf '%s\n' "$warning" | grep -F -q -- "$NVD_API_KEY"; then
    fail "authenticated status line printed the API key"
  else
    pass "authenticated status line does not print the API key"
  fi
  if printf '%s\n' "$warning" | grep -F -q "apiKey header"; then
    pass "authenticated status line describes the header"
  else
    fail "authenticated status line should describe the header"
  fi
}

test_rate_limit_and_permanent_errors() {
  local outfile="$WORKDIR/rate.json"
  reset_transport
  NVD_API_KEY="nvd-test-key-5941-do-not-log"
  queue_response "429" "slow down"
  queue_response "200" '{"ok":true}'
  if nvd_http_get "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1" "$outfile"; then
    pass "HTTP 429 is retried"
  else
    fail "HTTP 429 should be retried"
  fi
  assert_eq "$(joined_sleeps)" "30" "HTTP 429 waits 30s before the next attempt"

  reset_transport
  queue_response "404" "missing"
  if nvd_http_get "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1" "$outfile"; then
    fail "HTTP 404 should fail without a long retry loop"
  else
    pass "HTTP 404 fails immediately"
  fi
  assert_eq "$(joined_sleeps)" "" "HTTP 404 does not sleep through the transient schedule"
  assert_eq "$NVD_LAST_HTTP_CODE" "404" "last HTTP code is retained for the job error"
}

test_connection_error_and_invalid_json() {
  local outfile="$WORKDIR/conn.json"
  reset_transport
  NVD_API_KEY="nvd-test-key-5941-do-not-log"
  queue_response "000" ""
  queue_response "200" "not-json"
  queue_response "200" '{"ok":true}'
  if nvd_http_get "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=baileys" "$outfile"; then
    pass "connection errors and invalid JSON are retried"
  else
    fail "connection errors and invalid JSON should be retried"
  fi
  assert_eq "$(joined_sleeps)" "10 30" "000 and invalid JSON use the transient backoff"
}

test_pagination() {
  local outfile="$WORKDIR/pages.json"
  local suffix="&lastModStartDate=2026-10-28T06%3A07%3A13.000Z&lastModEndDate=2026-11-16T06%3A07%3A43.000Z"
  reset_transport
  NVD_API_KEY="nvd-test-key-5941-do-not-log"
  queue_response "200" '{"vulnerabilities":[{"cve":{"id":"CVE-1"}}],"totalResults":4000}'
  queue_response "503" "unavailable"
  queue_response "200" '{"vulnerabilities":[{"cve":{"id":"CVE-2"}}],"totalResults":4000}'

  if nvd_fetch_query_pages "keyword" "OpenClaw" "$outfile" "$suffix"; then
    pass "paginated fetch recovers a transient failure on a later page"
  else
    fail "paginated fetch should recover a transient page failure"
  fi

  assert_eq "$(jq -r '[.vulnerabilities[].cve.id] | join(",")' "$outfile")" "CVE-1,CVE-2" "pages are merged in order"
  assert_eq "${#REQUEST_URLS[@]}" "3" "the failed page is requested again"
  if [[ "${REQUEST_URLS[0]}" == *"startIndex=0"* && "${REQUEST_URLS[0]}" == *"resultsPerPage=2000"* && "${REQUEST_URLS[0]}" == *"lastModStartDate="* ]]; then
    pass "the first page requests the date window and a full page size"
  else
    fail "first page URL missing pagination or date window: ${REQUEST_URLS[0]}"
  fi
  if [[ "${REQUEST_URLS[2]}" == *"startIndex=2000"* ]]; then
    pass "the follow-up page advances startIndex"
  else
    fail "follow-up page did not advance startIndex: ${REQUEST_URLS[2]}"
  fi

  reset_transport
  queue_response "200" '{"vulnerabilities":[],"totalResults":10}'
  if nvd_fetch_query_pages "keyword" "OpenClaw" "$outfile" "$suffix"; then
    fail "an empty page before totalResults must fail the query"
  else
    pass "an empty page before totalResults fails the query"
  fi
}

test_retry_pass() {
  local dest="$WORKDIR/fetch-ok"
  reset_transport
  NVD_API_KEY="nvd-test-key-5941-do-not-log"
  local n=0
  while [ "$n" -lt 5 ]; do
    queue_response "503" "unavailable"
    n=$((n + 1))
  done
  queue_response "200" '{"vulnerabilities":[],"totalResults":0}'
  queue_response "200" '{"vulnerabilities":[{"cve":{"id":"CVE-9"}}],"totalResults":1}'

  if nvd_fetch_all_queries $'keyword|OpenClaw\nkeyword|clawdbot\n' "$dest" "&lastModStartDate=2026-10-28T00%3A00%3A00.000Z&lastModEndDate=2026-11-16T00%3A00%3A00.000Z"; then
    pass "a later retry pass recovers a query that failed the first pass"
  else
    fail "retry pass should recover the failed query"
  fi
  assert_eq "$(jq -r '.vulnerabilities[0].cve.id' "$dest/nvd_keyword__openclaw.json")" "CVE-9" "recovered query replaces the partial response"
  assert_eq "$(joined_sleeps)" "10 30 60 120 1 1 30 1" "first pass backs off, then the retry pass waits 30s"

  local failed="$WORKDIR/fetch-fail"
  reset_transport
  n=0
  while [ "$n" -lt 10 ]; do
    queue_response "503" "unavailable"
    n=$((n + 1))
  done
  if nvd_fetch_all_queries "keyword|NanoClaw" "$failed" "&lastModStartDate=2026-10-28T00%3A00%3A00.000Z&lastModEndDate=2026-11-16T00%3A00%3A00.000Z"; then
    fail "a query that fails both passes must fail the fetch"
  else
    pass "a query that fails both passes fails the fetch"
  fi
  assert_eq "${#REQUEST_URLS[@]}" "10" "both passes use the full attempt budget"
}

test_unauthenticated_pace() {
  reset_transport
  unset NVD_API_KEY
  nvd_prepare_api_key
  assert_eq "$NVD_API_KEY_IS_SET" "0" "an empty API key falls back to unauthenticated requests"
  local warning
  warning="$(nvd_warn_if_unauthenticated)"
  if printf '%s\n' "$warning" | grep -F -q "::warning::" && printf '%s\n' "$warning" | grep -F -q "unauthenticated"; then
    pass "missing API key emits an unauthenticated warning"
  else
    fail "missing API key should warn and fall back"
  fi

  queue_response "200" '{"ok":true}'
  if nvd_http_get "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Picoclaw" "$WORKDIR/public.json"; then
    pass "unauthenticated requests still run"
  else
    fail "unauthenticated request should succeed"
  fi
  assert_eq "$SAW_API_KEY_HEADER" "0" "unauthenticated requests omit the apiKey header"

  nvd_inter_request_sleep
  assert_eq "$(joined_sleeps)" "6" "unauthenticated spacing stays at 6s"

  NVD_API_KEY="nvd-test-key-5941-do-not-log"
  reset_transport
  nvd_inter_request_sleep
  assert_eq "$(joined_sleeps)" "1" "authenticated spacing is 1s"
}

test_xtrace_does_not_print_the_key() {
  local secret="nvd-test-key-5941-do-not-log"
  local trace="$WORKDIR/xtrace.txt"
  local body="$WORKDIR/xtrace-body.json"
  local snippet="$WORKDIR/xtrace-snippet.sh"

  cat >"$snippet" <<'EOF'
set -euo pipefail
source "$1"
curl() {
  local output_file=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -o)
        output_file="$2"
        shift 2
        ;;
      --config | -w | --max-time | --connect-timeout)
        shift 2
        ;;
      -sS | -s | -S)
        shift
        ;;
      https://* | http://*)
        shift
        ;;
      *)
        shift
        ;;
    esac
  done
  printf '%s' '{"ok":true}' >"$output_file"
  printf '%s' "200"
}
sleep() { :; }
nvd_warn_if_unauthenticated
nvd_http_get "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenClaw" "$2"
EOF

  if ! env NVD_API_KEY="$secret" bash -x "$snippet" "$SCRIPT_DIR/feed-utils.sh" "$body" >"$trace" 2>&1; then
    fail "xtrace probe failed"
    sed "s/${secret}/REDACTED/g" "$trace" >&2
  fi
  if grep -F -q -- "$secret" "$trace"; then
    fail "xtrace printed the NVD API key"
    sed "s/${secret}/REDACTED/g" "$trace" >&2
  else
    pass "xtrace does not print the NVD API key"
  fi
}

test_request_traps_do_not_leak_the_api_key() {
  local before after
  before="$(trap -p EXIT)"
  reset_transport
  NVD_API_KEY="nvd-test-key-5941-do-not-log"
  queue_response "200" '{"ok":true}'
  if nvd_http_get "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenClaw" "$WORKDIR/trap.json"; then
    pass "request used for trap restoration succeeded"
  else
    fail "request used for trap restoration failed"
  fi
  after="$(trap -p EXIT)"
  assert_eq "$after" "$before" "nvd_curl restores the caller EXIT trap"
  if [ -n "${NVD_CURL_CONFIG_FILE:-}" ] || [ -n "${NVD_CURL_CODE_FILE:-}" ]; then
    fail "request temp paths were not cleared"
  else
    pass "request temp paths are cleared after a normal request"
  fi

  trap 'echo caller-int' INT
  trap 'echo caller-term' TERM
  local int_before term_before
  int_before="$(trap -p INT)"
  term_before="$(trap -p TERM)"
  reset_transport
  queue_response "200" '{"ok":true}'
  if nvd_http_get "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenClaw" "$WORKDIR/trap.json"; then
    pass "request used for signal-trap restoration succeeded"
  else
    fail "request used for signal-trap restoration failed"
  fi
  assert_eq "$(trap -p INT)" "$int_before" "nvd_curl restores the caller INT trap"
  assert_eq "$(trap -p TERM)" "$term_before" "nvd_curl restores the caller TERM trap"
  assert_eq "$(trap -p EXIT)" "$before" "signal-trap restoration leaves the EXIT trap in place"
  trap - INT TERM

  local config_file
  config_file="$(mktemp)"
  printf 'header = "apiKey: marker"\n' >"$config_file"
  chmod 600 "$config_file"
  NVD_CURL_CONFIG_FILE="$config_file"
  nvd_install_request_traps
  # shellcheck disable=SC2034
  value="$(echo still-here)"
  ( exit 0 )
  if [ -f "$config_file" ]; then
    pass "subshells do not delete the in-flight API key file"
  else
    fail "a subshell deleted the in-flight API key file"
  fi
  nvd_restore_request_traps
  if [ -e "$config_file" ]; then
    rm -f "$config_file"
    fail "normal cleanup left the API key config file"
  else
    pass "normal cleanup removes the API key config file"
  fi
  assert_eq "$(trap -p EXIT)" "$before" "direct cleanup restores the caller EXIT trap"

  local status_snippet="$WORKDIR/exit-status.sh"
  cat >"$status_snippet" <<'EOF'
set -euo pipefail
source "$1"
trap 'echo caller-exit' EXIT
nvd_install_request_traps
exit 4
EOF
  local exit_status=0
  set +e
  bash "$status_snippet" "$SCRIPT_DIR/feed-utils.sh" >"$WORKDIR/exit-status.out"
  exit_status=$?
  set -e
  assert_eq "$exit_status" "4" "EXIT cleanup preserves the shell exit status"
  if grep -F -q "caller-exit" "$WORKDIR/exit-status.out"; then
    pass "EXIT cleanup runs the caller EXIT trap"
  else
    fail "EXIT cleanup did not run the caller EXIT trap"
  fi

  local secret="nvd-test-key-5941-do-not-log"
  local snippet="$WORKDIR/interrupt.sh"
  local path_file="$WORKDIR/config-path"
  cat >"$snippet" <<'EOF'
set -euo pipefail
source "$1"
path_out="$2"
curl() {
  local config=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --config)
        config="$2"
        shift 2
        ;;
      -o | -w | --max-time | --connect-timeout)
        shift 2
        ;;
      -sS | -s | -S)
        shift
        ;;
      https://* | http://*)
        shift
        ;;
      *)
        shift
        ;;
    esac
  done
  printf '%s\n' "$config" >"$path_out"
  # A builtin loop, not an external sleep: bash defers traps until an
  # external command finishes, which would hide the cleanup.
  while true; do
    :
  done
}
export NVD_API_KEY="$3"
nvd_http_get "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenClaw" "$4"
EOF
  bash "$snippet" "$SCRIPT_DIR/feed-utils.sh" "$path_file" "$secret" "$WORKDIR/interrupt-out.json" &
  local pid=$!
  local config_path=""
  local i=0
  while [ "$i" -lt 50 ]; do
    if [ -s "$path_file" ]; then
      config_path="$(cat "$path_file")"
      break
    fi
    command sleep 0.1
    i=$((i + 1))
  done
  if [ -z "$config_path" ] || [ ! -f "$config_path" ]; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" || true
    fail "interrupt test did not observe the API key config file"
    return
  fi
  kill -TERM "$pid" 2>/dev/null || true
  local waited=0
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 30 ]; do
    command sleep 0.1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" || true
    fail "NVD request survived SIGTERM"
  fi
  if [ -e "$config_path" ]; then
    rm -f "$config_path"
    fail "API key config file survived SIGTERM"
  else
    pass "SIGTERM removes the API key config file"
  fi
}

test_nvidia_query_coverage() {
  local specs keywords pattern github_pattern cpe_pattern
  local repo_root
  repo_root="$(cd "$SCRIPT_DIR/.." && pwd)"
  specs="$(nvd_query_specs)"
  keywords="$(nvd_summary_keywords)"
  pattern="$(nvd_keyword_pattern)"
  github_pattern="$(nvd_github_ref_pattern)"
  cpe_pattern="$(nvd_cpe_pattern)"

  for expected in \
    'keyword|NemoClaw' \
    'keyword|NVIDIA OpenShell' \
    'virtualMatchString|cpe:2.3:a:nvidia:nemoclaw' \
    'virtualMatchString|cpe:2.3:a:nvidia:openshell'
  do
    if printf '%s\n' "$specs" | grep -F -x -q -- "$expected"; then
      pass "NVD query spec includes ${expected}"
    else
      fail "NVD query spec missing ${expected}"
    fi
  done

  if printf '%s\n' "$specs" | grep -E -x -q 'keyword\|OpenShell'; then
    fail "bare keyword|OpenShell query would pull unrelated OpenShell mentions"
  else
    pass "NVD queries do not use a bare OpenShell keyword"
  fi

  if printf '%s' "$pattern" | tr '|' '\n' | grep -E -i -x -q 'openshell'; then
    fail "post-filter keyword pattern contains a bare OpenShell alternative"
  else
    pass "post-filter keyword pattern has no bare OpenShell alternative"
  fi

  assert_eq "$keywords" "openclaw, nanoclaw, hermes, picoclaw, nemoclaw, openshell" "summary keywords include NVIDIA projects"

  local kept
  kept="$(jq -nc \
    --arg kw "$pattern" \
    --arg gh "$github_pattern" \
    --arg cpe "$cpe_pattern" \
    '
      def cve($id; $description; $url; $criteria): {
        cve: {
          id: $id,
          descriptions: [{lang: "en", value: $description}],
          references: (if $url == "" then [] else [{url: $url}] end),
          configurations: [{nodes: [{cpeMatch: [{criteria: $criteria}]}]}]
        }
      };
      [
        cve("CVE-NEMO"; "NVIDIA NeMoClaw contains a vulnerability in sandbox initialization."; ""; "cpe:2.3:a:nvidia:nemoclaw:*:*:*:*:*:*:*:*"),
        cve("CVE-SHELL"; "NVIDIA OpenShell for Linux contains a vulnerability in its sandbox provisioning API."; "https://github.com/NVIDIA/product-security/tree/main/2026/5872"; "cpe:2.3:a:nvidia:openshell:*:*:*:*:*:*:*:*"),
        cve("CVE-SHELL-REF"; "Sandbox policy bypass."; "https://github.com/NVIDIA/OpenShell/security/advisories/GHSA-test"; ""),
        cve("CVE-OPENCLAW-SHELL"; "OpenClaw before 2026.4.22 contains a race in the OpenShell filesystem bridge."; "https://github.com/openclaw/openclaw/security/advisories/GHSA-test"; ""),
        cve("CVE-SAP-SHELL"; "Kubernetes and OpenShell deployments are not affected because the relevant backend is unused."; "https://github.com/SAP/astonish/security/advisories/GHSA-test"; ""),
        cve("CVE-BARE-SHELL"; "OpenShell sandbox escape."; ""; "")
      ]
      | map(select(
          (.cve.descriptions[]? | select(.lang == "en") | .value | test($kw; "i"))
          or (.cve.references[]? | .url | test($gh; "i"))
          or ([.cve.configurations[]? | .. | objects | .criteria? | strings | test($cpe; "i")] | any)
        ) | .cve.id)
    ')"

  assert_eq "$kept" '["CVE-NEMO","CVE-SHELL","CVE-SHELL-REF","CVE-OPENCLAW-SHELL"]' "post-filter keeps NVIDIA records and drops unrelated OpenShell mentions"

  # Source files store the jq string escapes. The classifier below uses the
  # regex jq actually evaluates.
  local nemoclaw_source='github\\.com/nvidia/nemoclaw|\\bnemoclaw\\b|cpe:2\\.3:a:nvidia:nemoclaw(?::|$)'
  local openshell_source='github\\.com/nvidia/openshell|nvidia openshell|cpe:2\\.3:a:nvidia:openshell(?::|$)'
  local nemoclaw_pattern='github\.com/nvidia/nemoclaw|\bnemoclaw\b|cpe:2\.3:a:nvidia:nemoclaw(?::|$)'
  local openshell_pattern='github\.com/nvidia/openshell|nvidia openshell|cpe:2\.3:a:nvidia:openshell(?::|$)'
  local source_file
  for source_file in \
    "$repo_root/.github/workflows/poll-nvd-cves.yml" \
    "$repo_root/scripts/populate-local-feed.sh"
  do
    if grep -F -q -- "$nemoclaw_source" "$source_file" && grep -F -q -- "$openshell_source" "$source_file"; then
      pass "platform tagging in ${source_file##*/} names NemoClaw and NVIDIA OpenShell"
    else
      fail "platform tagging in ${source_file##*/} is missing an NVIDIA pattern"
    fi
    if grep -F -q '\bopenshell\b' "$source_file"; then
      fail "${source_file##*/} uses a bare OpenShell word match"
    else
      pass "${source_file##*/} does not use a bare OpenShell word match"
    fi
  done

  local workflow_hits
  workflow_hits="$(grep -F -c -- "$openshell_source" "$repo_root/.github/workflows/poll-nvd-cves.yml")"
  assert_eq "$workflow_hits" "2" "NVD workflow tags OpenShell in both transform copies"

  local classified
  classified="$(jq -nc \
    --arg nemoclaw "$nemoclaw_pattern" \
    --arg openshell "$openshell_pattern" \
    '
      def platforms($blob):
        [
          (if ($blob | test("github\\.com/openclaw/openclaw|\\bopenclaw\\b|\\bclawdbot\\b|\\bmoltbot\\b")) then "openclaw" else empty end),
          (if ($blob | test($nemoclaw)) then "nemoclaw" else empty end),
          (if ($blob | test($openshell)) then "openshell" else empty end)
        ];
      {
        nemoclaw: platforms("nvidia nemoclaw sandbox cpe:2.3:a:nvidia:nemoclaw:*:*:*:*:*:*:*:*"),
        openshell: platforms("nvidia openshell for linux cpe:2.3:a:nvidia:openshell:*:*:*:*:*:*:*:* cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"),
        openclaw_shell: platforms("openclaw before 2026.4.22 openshell filesystem bridge github.com/openclaw/openclaw"),
        sap: platforms("kubernetes and openshell deployments are not affected")
      }
    ')"
  assert_eq "$(jq -c .nemoclaw <<<"$classified")" '["nemoclaw"]' "NeMoClaw text and CPE map only to nemoclaw"
  assert_eq "$(jq -c .openshell <<<"$classified")" '["openshell"]' "NVIDIA OpenShell text and CPE map only to openshell"
  assert_eq "$(jq -c .openclaw_shell <<<"$classified")" '["openclaw"]' "OpenClaw OpenShell text stays on openclaw"
  assert_eq "$(jq -c .sap <<<"$classified")" '[]' "an unrelated OpenShell mention maps to no NVIDIA platform"
}

test_nvidia_query_coverage
test_clamp
test_backoff_and_transient
test_request_traps_do_not_leak_the_api_key
test_authenticated_retry_and_header
test_rate_limit_and_permanent_errors
test_connection_error_and_invalid_json
test_pagination
test_retry_pass
test_unauthenticated_pace
test_xtrace_does_not_print_the_key

if [ "$FAILURES" -ne 0 ]; then
  echo "${FAILURES} assertion(s) failed" >&2
  exit 1
fi

echo "NVD poll helper tests passed"
