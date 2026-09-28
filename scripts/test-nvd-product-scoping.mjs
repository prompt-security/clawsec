#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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

assert.deepEqual(
  [...byId.keys()].sort(),
  [
    "CVE-TEST-HERMES-CPE-ALIAS",
    "CVE-TEST-NANOCLAW",
    "CVE-TEST-NEMO-CLAW",
    "CVE-TEST-OPEN-SHELL",
    "CVE-TEST-OPENCLAW-OPENSHELL-FEATURE",
  ],
  "Only allowlisted products with an explicit machine-readable version scope may be published",
);

assert.deepEqual(byId.get("CVE-TEST-OPEN-SHELL").affected, ["openshell@<=0.0.33"]);
assert.deepEqual(byId.get("CVE-TEST-OPEN-SHELL").platforms, ["openshell"]);

assert.deepEqual(byId.get("CVE-TEST-NEMO-CLAW").affected, ["nemoclaw@>=0.0.10 <0.0.18"]);
assert.deepEqual(byId.get("CVE-TEST-NEMO-CLAW").platforms, ["nemoclaw"]);

assert.deepEqual(byId.get("CVE-TEST-OPENCLAW-OPENSHELL-FEATURE").affected, [
  "openclaw@>=2026.1.0 <2026.1.5",
]);
assert.deepEqual(byId.get("CVE-TEST-OPENCLAW-OPENSHELL-FEATURE").platforms, ["openclaw"]);

assert.deepEqual(byId.get("CVE-TEST-NANOCLAW").affected, ["nanoclaw@1.2.0"]);
assert.deepEqual(byId.get("CVE-TEST-NANOCLAW").platforms, ["nanoclaw"]);

assert.deepEqual(byId.get("CVE-TEST-HERMES-CPE-ALIAS").affected, ["hermes@<3.0.0"]);
assert.deepEqual(byId.get("CVE-TEST-HERMES-CPE-ALIAS").platforms, ["hermes"]);
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
}

const feedUtils = readFileSync(resolve(scriptsDir, "feed-utils.sh"), "utf8");
assert.match(feedUtils, /virtualMatchString\|cpe:2\.3:a:nvidia:nemoclaw/);
assert.match(feedUtils, /virtualMatchString\|cpe:2\.3:a:nvidia:openshell/);
assert.match(feedUtils, /virtualMatchString\|cpe:2\.3:a:nousresearch:hermes_agent/);
const querySpecs = execFileSync(
  "bash",
  ["-c", 'source "$1"; nvd_query_specs', "nvd-query-test", resolve(scriptsDir, "feed-utils.sh")],
  { encoding: "utf8" },
).trim().split("\n");
assert.ok(querySpecs.includes("virtualMatchString|cpe:2.3:a:nvidia:nemoclaw"));
assert.ok(querySpecs.includes("virtualMatchString|cpe:2.3:a:nvidia:openshell"));
assert.ok(querySpecs.includes("virtualMatchString|cpe:2.3:a:nousresearch:hermes_agent"));
assert.ok(querySpecs.every((spec) => /^(keyword|virtualMatchString)\|\S/.test(spec)), "Every query spec must be executable");

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
assert.doesNotMatch(
  localGenerator,
  /Using last updated from feed|jq -r '\.updated \/\/ empty'/,
  "The consolidated feed timestamp must not be reused as an NVD cursor",
);
assert.match(
  localGenerator,
  /"\$FORCE" = "true"[^\n]+"\$FILTERED" -eq 0[\s\S]*refusing full rebuild[\s\S]*exit 1/i,
  "A zero-result local full rebuild must fail instead of erasing existing CVEs",
);

execFileSync("bash", ["-n", resolve(scriptsDir, "feed-utils.sh")]);
execFileSync("bash", ["-n", resolve(scriptsDir, "populate-local-feed.sh")]);

console.log("NVD product scoping regression tests passed");
