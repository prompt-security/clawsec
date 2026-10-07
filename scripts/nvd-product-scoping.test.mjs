#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(scriptsDir, "..");
const fixturePath = resolve(scriptsDir, "fixtures", "nvd-product-scoping.json");
const transformProgram = 'include "nvd-advisory-transform"; [.[] | nvd_advisory]';

const transformed = JSON.parse(
  execFileSync("jq", ["-L", scriptsDir, transformProgram, fixturePath], { encoding: "utf8" }),
);
const byId = new Map(transformed.map((advisory) => [advisory.id, advisory]));

assert.equal(
  byId.has("CVE-TEST-UNRELATED-HERMES-WORKFLOW"),
  false,
  "softwarepub/hermes is a publishing workflow, not the protected Hermes agent",
);
assert.equal(
  byId.has("CVE-TEST-HERMES-UNCONFIRMED-CPE"),
  false,
  "Hermes NVD publication must wait for an authoritative NVD CPE identity",
);
assert.equal(
  byId.has("CVE-TEST-NANOCLAW-UNCONFIRMED-CPE"),
  false,
  "The NanoClaw repository owner is not an interchangeable NVD CPE vendor",
);
assert.equal(
  byId.has("CVE-TEST-PICOCLAW-UNCONFIRMED-CPE"),
  false,
  "PicoClaw NVD publication must use the canonical sipeed:picoclaw CPE",
);

assert.deepEqual(
  [...byId.keys()].sort(),
  [
    "CVE-TEST-NANOCLAW",
    "CVE-TEST-NEMO-CLAW",
    "CVE-TEST-OPEN-SHELL",
    "CVE-TEST-OPENCLAW-OPENSHELL-FEATURE",
  ],
  "Only allowlisted products with an explicit machine-readable version scope may be published",
);

assert.deepEqual(byId.get("CVE-TEST-OPEN-SHELL").affected, ["openshell@<=0.0.33"]);
assert.deepEqual(byId.get("CVE-TEST-OPEN-SHELL").platforms, ["openshell"]);
assert.equal(byId.get("CVE-TEST-OPEN-SHELL").updated, "2026-08-02T00:00:00.000");
assert.equal(
  byId.get("CVE-TEST-OPEN-SHELL").cvss_vector,
  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
);

assert.deepEqual(byId.get("CVE-TEST-NEMO-CLAW").affected, ["nemoclaw@>=0.0.10 <0.0.18"]);
assert.deepEqual(byId.get("CVE-TEST-NEMO-CLAW").platforms, ["nemoclaw"]);

assert.deepEqual(byId.get("CVE-TEST-OPENCLAW-OPENSHELL-FEATURE").affected, [
  "openclaw@>=2026.1.0 <2026.1.5",
]);
assert.deepEqual(byId.get("CVE-TEST-OPENCLAW-OPENSHELL-FEATURE").platforms, ["openclaw"]);

assert.deepEqual(byId.get("CVE-TEST-NANOCLAW").affected, ["nanoclaw@1.2.0"]);
assert.deepEqual(byId.get("CVE-TEST-NANOCLAW").platforms, ["nanoclaw"]);

assert.equal(
  byId.has("CVE-TEST-TRUSTED-REF-UNRELATED-CPE"),
  false,
  "A trusted repository reference must not lend its identity to an unrelated CPE range",
);

for (const advisory of transformed) {
  assert.ok(advisory.affected.length > 0, `${advisory.id} must have an affected selector`);
  assert.ok(
    advisory.affected.every((selector) => !selector.endsWith("@*") && !selector.startsWith("cpe:")),
    `${advisory.id} must use a translated, explicitly scoped component selector`,
  );
  assert.deepEqual(
    advisory.authoritative_nvd_affected,
    advisory.affected,
    `${advisory.id} must preserve its independent NVD scope as provenance`,
  );
  assert.deepEqual(advisory.authoritative_canonical_platforms, advisory.platforms);
  assert.deepEqual(advisory.authoritative_canonical_cwe_ids, advisory.cwe_ids);
  assert.equal(advisory.synthesized_from_ghsa, false);
}

assert.equal(
  byId.has("CVE-TEST-OPENCLAW-REJECTED"),
  false,
  "A rejected CVE must not remain publishable even when its CPE has explicit protected scope",
);

for (const [id, reason] of [
  ["CVE-TEST-OPENCLAW-NEGATED-CONFIG", "negated applicability"],
  ["CVE-TEST-OPENCLAW-AND-CONFIG", "AND-constrained applicability"],
  ["CVE-TEST-OPENCLAW-UNKNOWN-OPERATOR", "unknown Boolean applicability"],
  ["CVE-TEST-OPENCLAW-MALFORMED-NEGATE", "malformed negate applicability"],
]) {
  assert.equal(
    byId.has(id),
    false,
    `${reason} must fail closed when it cannot be represented by a product/version selector`,
  );
}

const sourceRecords = JSON.parse(readFileSync(fixturePath, "utf8"));
const sourceOpenShell = sourceRecords.find(({ cve }) => cve.id === "CVE-TEST-OPEN-SHELL");
const currentNvdState = (record) => JSON.parse(
  execFileSync(
    "jq",
    ["-L", scriptsDir, 'include "nvd-advisory-transform"; nvd_advisory_current_state'],
    { encoding: "utf8", input: JSON.stringify(record) },
  ),
);
const originalNvdState = currentNvdState(sourceOpenShell);
const vectorCorrected = JSON.parse(JSON.stringify(sourceOpenShell));
vectorCorrected.cve.metrics.cvssMetricV31[0].cvssData.vectorString =
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const vectorCorrectedState = currentNvdState(vectorCorrected);
assert.equal(vectorCorrectedState.cvss_score, originalNvdState.cvss_score);
assert.notEqual(
  vectorCorrectedState.cvss_vector,
  originalNvdState.cvss_vector,
  "A vector-only NVD correction must remain visible to incremental comparison",
);

const timestampCorrected = JSON.parse(JSON.stringify(sourceOpenShell));
timestampCorrected.cve.lastModified = "2026-08-03T00:00:00.000";
const timestampCorrectedState = currentNvdState(timestampCorrected);
assert.equal(timestampCorrectedState.cvss_vector, originalNvdState.cvss_vector);
assert.notEqual(
  timestampCorrectedState.updated,
  originalNvdState.updated,
  "A lastModified-only NVD correction must remain visible to incremental comparison",
);

const publishedCorrected = JSON.parse(JSON.stringify(sourceOpenShell));
publishedCorrected.cve.published = "2026-07-31T23:59:59.000";
const publishedCorrectedState = currentNvdState(publishedCorrected);
assert.equal(publishedCorrectedState.updated, originalNvdState.updated);
assert.notEqual(
  publishedCorrectedState.published,
  originalNvdState.published,
  "A published-only NVD correction must remain visible to incremental comparison",
);

const feedUtils = readFileSync(resolve(scriptsDir, "feed-utils.sh"), "utf8");
assert.match(feedUtils, /virtualMatchString\|cpe:2\.3:a:nvidia:nemoclaw/);
assert.match(feedUtils, /virtualMatchString\|cpe:2\.3:a:nvidia:openshell/);
const querySpecs = execFileSync(
  "bash",
  ["-c", 'source "$1"; nvd_query_specs', "nvd-query-test", resolve(scriptsDir, "feed-utils.sh")],
  { encoding: "utf8" },
).trim().split("\n");
assert.ok(querySpecs.includes("virtualMatchString|cpe:2.3:a:nvidia:nemoclaw"));
assert.ok(querySpecs.includes("virtualMatchString|cpe:2.3:a:nvidia:openshell"));
assert.ok(querySpecs.includes("keyword|hermes-agent"));
assert.ok(
  !querySpecs.includes("virtualMatchString|cpe:2.3:a:nousresearch:hermes_agent"),
  "Unconfirmed NousResearch CPE must not be queried as an authoritative Hermes identity",
);
assert.ok(
  !querySpecs.includes("virtualMatchString|cpe:2.3:a:software-metadata.pub:hermes"),
  "Unrelated softwarepub/hermes CPE must not be queried as a protected component",
);
assert.ok(!querySpecs.includes("virtualMatchString|cpe:2.3:a:qwibitai:nanoclaw"));
assert.ok(!querySpecs.includes("virtualMatchString|cpe:2.3:a:picoclaw:picoclaw"));
assert.ok(querySpecs.includes("virtualMatchString|cpe:2.3:a:nanoco:nanoclaw"));
assert.ok(querySpecs.includes("virtualMatchString|cpe:2.3:a:sipeed:picoclaw"));
assert.ok(
  !querySpecs.includes("keyword|hermes workflow"),
  "Unrelated Hermes workflow must not remain a discovery keyword",
);
assert.ok(querySpecs.every((spec) => /^(keyword|virtualMatchString)\|\S/.test(spec)), "Every query spec must be executable");

const exactDuplicateInventory = JSON.stringify({
  vulnerabilities: [
    { cve: { id: "CVE-2026-1000", lastModified: "2026-05-01T00:00:00.000" } },
    { cve: { id: "CVE-2026-1000", lastModified: "2026-05-01T00:00:00.000" } },
  ],
});
execFileSync(
  "bash",
  [
    "-c",
    'source "$1"; nvd_assert_no_conflicting_duplicates -',
    "nvd-identical-duplicate-test",
    resolve(scriptsDir, "feed-utils.sh"),
  ],
  { encoding: "utf8", input: exactDuplicateInventory },
);

const conflictingDuplicateInventory = JSON.stringify({
  vulnerabilities: [
    { cve: { id: "CVE-2026-1000", vulnStatus: "Analyzed", lastModified: "2026-05-01T00:00:00.000" } },
    { cve: { id: "CVE-2026-1000", vulnStatus: "Rejected", lastModified: "2026-05-02T00:00:00.000" } },
  ],
});
const conflictingDuplicateResult = spawnSync(
  "bash",
  [
    "-c",
    'source "$1"; nvd_assert_no_conflicting_duplicates -',
    "nvd-conflicting-duplicate-test",
    resolve(scriptsDir, "feed-utils.sh"),
  ],
  { encoding: "utf8", input: conflictingDuplicateInventory },
);
assert.notEqual(conflictingDuplicateResult.status, 0, "Conflicting snapshots for one CVE ID must fail closed");
assert.match(conflictingDuplicateResult.stderr, /CVE-2026-1000/);

const incrementalQuerySpecs = execFileSync(
  "bash",
  [
    "-c",
    'source "$1"; nvd_query_specs_for_scan false',
    "nvd-incremental-query-test",
    resolve(scriptsDir, "feed-utils.sh"),
  ],
  { encoding: "utf8" },
).trim().split("\n");
assert.deepEqual(
  incrementalQuerySpecs,
  ["modified|all"],
  "Incremental polling must inventory every CVE modified in the overlap window without keyword or CPE discovery filters",
);

const scheduledQuerySpecs = execFileSync(
  "bash",
  [
    "-c",
    'source "$1"; nvd_query_specs_for_scan ""',
    "nvd-scheduled-query-test",
    resolve(scriptsDir, "feed-utils.sh"),
  ],
  { encoding: "utf8" },
).trim().split("\n");
assert.deepEqual(
  scheduledQuerySpecs,
  incrementalQuerySpecs,
  "Scheduled runs without workflow_dispatch inputs must use the incremental inventory",
);

const fullScanQuerySpecs = execFileSync(
  "bash",
  ["-c", 'source "$1"; nvd_query_specs_for_scan true', "nvd-full-query-test", resolve(scriptsDir, "feed-utils.sh")],
  { encoding: "utf8" },
).trim().split("\n");
assert.deepEqual(fullScanQuerySpecs, querySpecs, "Full scans must retain the allowlisted discovery queries");

const incrementalInventoryUrl = execFileSync(
  "bash",
  [
    "-c",
    'source "$1"; nvd_build_url modified all "&lastModStartDate=start&lastModEndDate=end&startIndex=0&resultsPerPage=2000"',
    "nvd-incremental-url-test",
    resolve(scriptsDir, "feed-utils.sh"),
  ],
  { encoding: "utf8" },
).trim();
assert.equal(
  incrementalInventoryUrl,
  "https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=start&lastModEndDate=end&startIndex=0&resultsPerPage=2000",
  "The incremental inventory URL must be bounded only by the modification window and pagination",
);
assert.doesNotMatch(incrementalInventoryUrl, /keywordSearch|virtualMatchString/);

const retractionGuardResults = execFileSync(
  "bash",
  [
    "-c",
    'source "$1"; for pair in "0 661" "19 661" "20 661" "4 20" "5 20" "1 3"; do set -- $pair; if nvd_is_material_drop "$1" "$2"; then echo "$1/$2:review"; else echo "$1/$2:safe"; fi; done',
    "nvd-retraction-guard-test",
    resolve(scriptsDir, "feed-utils.sh"),
  ],
  { encoding: "utf8" },
).trim().split("\n");
assert.deepEqual(
  retractionGuardResults,
  ["0/661:safe", "19/661:safe", "20/661:review", "4/20:safe", "5/20:review", "1/3:review"],
  "Incremental mass retractions must cross an absolute or proportional manual-review threshold",
);

const localGenerator = readFileSync(resolve(scriptsDir, "populate-local-feed.sh"), "utf8");
const workflow = readFileSync(resolve(projectRoot, ".github", "workflows", "poll-nvd-cves.yml"), "utf8");
const transform = readFileSync(resolve(scriptsDir, "nvd-advisory-transform.jq"), "utf8");

assert.ok(
  (localGenerator.match(/include "nvd-advisory-transform";/g) ?? []).length >= 2,
  "Local filtering and transformation must use the shared NVD transform",
);
assert.ok(
  (workflow.match(/include "nvd-advisory-transform";/g) ?? []).length >= 3,
  "Workflow filtering, update comparison, and transformation must use the shared NVD transform",
);

for (const [name, source] of [
  ["local generator", localGenerator],
  ["workflow", workflow],
]) {
  assert.doesNotMatch(source, /if length == 0 then \["openclaw@\*"/i, `${name} must not default unknown CVEs to all products`);
  assert.doesNotMatch(source, /\\bnanoclaw\\b[\s\S]{0,80}then \["nanoclaw@\*"\]/i, `${name} must not classify from free text`);
}

for (const [name, source] of [
  ["local generator", localGenerator],
  ["workflow", workflow],
]) {
  assert.ok(
    source.indexOf("nvd_assert_no_conflicting_duplicates") < source.indexOf("unique_by(.cve.id)"),
    `${name} must reject conflicting duplicate snapshots before deduplicating CVE IDs`,
  );
}

assert.doesNotMatch(
  transform,
  /trusted_(?:component_for_reference|reference_components)/,
  "Repository references must not supply product identity for an unrelated CPE range",
);

assert.match(
  localGenerator,
  /if \[ "\$FORCE" = "true" \]; then[\s\S]*startIndex=\$\{START_INDEX\}&resultsPerPage=\$\{RESULTS_PER_PAGE\}/,
  "Local force mode must paginate complete NVD query history",
);
assert.match(
  localGenerator,
  /lastModStartDate=\$\{START_ENC\}&lastModEndDate=\$\{END_ENC\}/,
  "Local incremental mode must retain the date-window query",
);
assert.match(
  localGenerator,
  /NVD_QUERY_SPECS="\$\(nvd_query_specs_for_scan "\$FORCE"\)"/,
  "Local incremental mode must select the broad modified-CVE inventory instead of filtered discovery queries",
);
assert.match(
  localGenerator,
  /nvd_build_url[^\n]+\$\{QUERY_WINDOW_SUFFIX\}&startIndex=\$\{START_INDEX\}&resultsPerPage=\$\{RESULTS_PER_PAGE\}/,
  "Both full and incremental local scans must paginate their NVD queries",
);
assert.match(
  localGenerator,
  /\(\.vulnerabilities \| type\) == "array"[\s\S]*\(\.totalResults \| type == "number"/,
  "Local fetches must validate the NVD response schema",
);
assert.match(
  localGenerator,
  /if ! fetch_nvd_response[\s\S]*exit 1/,
  "A failed or invalid NVD query must abort local generation",
);
assert.match(
  localGenerator,
  /EXPECTED_TOTAL_RESULTS="\$TOTAL_RESULTS"[\s\S]*"\$TOTAL_RESULTS" -ne "\$EXPECTED_TOTAL_RESULTS"[\s\S]*exit 1/,
  "Pagination must reject a changing NVD totalResults value",
);
assert.match(
  localGenerator,
  /"\$PAGE_COUNT" -eq 0[^\n]+"\$START_INDEX" -lt "\$EXPECTED_TOTAL_RESULTS"[\s\S]*exit 1/,
  "Pagination must reject an empty page before the advertised result total",
);
assert.match(
  localGenerator,
  /START_INDEX=\$\(\(START_INDEX \+ PAGE_COUNT\)\)/,
  "Pagination must advance by the number of results actually returned",
);
assert.doesNotMatch(
  localGenerator,
  /START_INDEX=\$\(\(START_INDEX \+ RESULTS_PER_PAGE\)\)/,
  "Pagination must not assume NVD returned the requested page size",
);
assert.match(
  localGenerator,
  /MERGED_COUNT=\$\(jq[^\n]+[\s\S]*"\$MERGED_COUNT" -ne "\$EXPECTED_TOTAL_RESULTS"[\s\S]*exit 1/,
  "Each merged query result must equal NVD's advertised total",
);
assert.match(
  localGenerator,
  /UNIQUE_MERGED_COUNT=\$\(jq[^\n]+unique[^\n]+\)[\s\S]*"\$UNIQUE_MERGED_COUNT" -ne "\$MERGED_COUNT"[\s\S]*exit 1/,
  "Local pagination must reject duplicate CVE IDs before accepting an advertised total",
);
assert.match(
  workflow,
  /UNIQUE_MERGED_COUNT=\$\(jq[^\n]+unique[^\n]+\)[\s\S]*NVD returned duplicate CVE IDs/,
  "Workflow pagination must reject duplicate CVE IDs before a full rebuild",
);
assert.doesNotMatch(
  localGenerator,
  /Using last updated from feed|jq -r '\.updated \/\/ empty'/,
  "The consolidated feed timestamp must not be reused as an NVD cursor",
);
assert.match(
  localGenerator,
  /DAYS_BACK=119[\s\S]*DAYS_BACK[^\n]+-gt 119/,
  "Local NVD windows must stay below the API's 120-day maximum",
);
assert.match(
  workflow,
  /119 days ago/,
  "Workflow NVD windows must stay below the API's 120-day maximum",
);
assert.match(
  localGenerator,
  /"\$FORCE" = "true"[^\n]+"\$FILTERED" -eq 0[\s\S]*refusing full rebuild[\s\S]*exit 1/i,
  "A zero-result local full rebuild must fail instead of erasing existing CVEs",
);
assert.match(
  localGenerator,
  /full_rebuild_removed_ids\.json[\s\S]*nvd_is_material_drop "\$FULL_REBUILD_REMOVED_COUNT" "\$EXISTING_CVE_COUNT"[\s\S]*--allow-large-drop[\s\S]*exit 1/i,
  "A material local full-rebuild identity drop must require an explicit override",
);
assert.match(
  localGenerator,
  /retracted_advisory_ids\.json[\s\S]*no longer carrying publishable NVD scope/i,
  "Local incremental generation must retract fetched CVEs that lose publishable scope",
);
assert.match(
  workflow,
  /allow_large_rebuild_drop:[\s\S]*full_rebuild_removed_ids\.json[\s\S]*nvd_is_material_drop "\$FULL_REBUILD_REMOVED_COUNT" "\$EXISTING_CVE_COUNT"[\s\S]*allow_large_rebuild_drop/i,
  "A material workflow full-rebuild identity drop must require an explicit override",
);
assert.match(
  workflow,
  /NVD_QUERY_SPECS="\$\(nvd_query_specs_for_scan "\$FORCE_FULL_SCAN"\)"/,
  "Workflow incremental mode must select the broad modified-CVE inventory instead of filtered discovery queries",
);
assert.match(
  workflow,
  /if \[ -f "\$FEED_PATH" \]; then[\s\S]*Existing advisory feed is malformed or empty[\s\S]*if \[ "\$FORCE_FULL_SCAN" != "true" \]; then[\s\S]*Incremental generation cannot safely reconstruct history/,
  "Workflow incremental generation must require a valid canonical baseline unless an explicit full scan bootstraps it",
);
assert.match(
  localGenerator,
  /if \[ -f "\$FEED_PATH" \]; then[\s\S]*existing advisory feed is malformed or empty[\s\S]*elif \[ "\$FORCE" != "true" \]; then[\s\S]*Incremental generation cannot safely reconstruct history/,
  "Local incremental generation must require a valid canonical baseline unless --force explicitly bootstraps it",
);
assert.match(
  workflow,
  /retracted_advisory_ids\.json[\s\S]*no longer carrying publishable NVD scope/i,
  "Incremental workflow generation must retract fetched CVEs that lose publishable scope",
);
assert.match(
  workflow,
  /\$existing_entry\.authoritative_nvd_affected != \$nvd_entry\.authoritative_nvd_affected[\s\S]*updated_fields:[\s\S]*authoritative_nvd_affected: \$nvd_entry\.authoritative_nvd_affected[\s\S]*synthesized_from_ghsa: \$nvd_entry\.synthesized_from_ghsa/,
  "Incremental NVD updates must replace GHSA-synthesized scope with explicit NVD provenance",
);
assert.match(
  workflow,
  /\$existing_entry\.cvss_vector != \$nvd_entry\.cvss_vector[\s\S]*\$existing_entry\.published != \$nvd_entry\.published[\s\S]*\$existing_entry\.updated != \$nvd_entry\.updated[\s\S]*updated_fields:[\s\S]*cvss_vector: \$nvd_entry\.cvss_vector[\s\S]*published: \$nvd_entry\.published[\s\S]*updated: \$nvd_entry\.updated/,
  "Workflow incremental NVD updates must apply vector-only, published-only, and lastModified-only corrections",
);
assert.match(
  localGenerator,
  /\$existing_entry\.cvss_vector != \$nvd_entry\.cvss_vector[\s\S]*\$existing_entry\.published != \$nvd_entry\.published[\s\S]*\$existing_entry\.updated != \$nvd_entry\.updated[\s\S]*updated_fields:[\s\S]*cvss_vector: \$nvd_entry\.cvss_vector[\s\S]*published: \$nvd_entry\.published[\s\S]*updated: \$nvd_entry\.updated/,
  "Local incremental NVD updates must apply vector-only, published-only, and lastModified-only corrections",
);
assert.match(
  workflow,
  /\$existing_entry\.authoritative_canonical_platforms != \$nvd_entry\.authoritative_canonical_platforms[\s\S]*updated_fields:[\s\S]*authoritative_canonical_platforms: \$nvd_entry\.authoritative_canonical_platforms[\s\S]*authoritative_canonical_cwe_ids: \$nvd_entry\.authoritative_canonical_cwe_ids/,
  "Incremental NVD updates must refresh independent platform and CWE provenance",
);
assert.match(
  localGenerator,
  /nvd_is_material_drop "\$RETRACTED_COUNT" "\$EXISTING_CVE_COUNT"[\s\S]*--allow-large-drop[\s\S]*exit 1/i,
  "Local incremental mass retractions must require explicit operator review",
);
assert.match(
  workflow,
  /nvd_is_material_drop "\$RETRACTED_COUNT" "\$EXISTING_CVE_COUNT"[\s\S]*allow_large_rebuild_drop=true[\s\S]*exit 1/i,
  "Workflow incremental mass retractions must require explicit operator review",
);

execFileSync("bash", ["-n", resolve(scriptsDir, "feed-utils.sh")]);
execFileSync("bash", ["-n", resolve(scriptsDir, "populate-local-feed.sh")]);
execFileSync("node", [resolve(scriptsDir, "populate-local-feed.test.mjs")], { encoding: "utf8" });

console.log("NVD product scoping regression tests passed");
