import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflowPath = new URL('../.github/workflows/poll-nvd-cves.yml', import.meta.url);
const workflow = await readFile(workflowPath, 'utf8');
const codeqlWorkflowPath = new URL('../.github/workflows/codeql.yml', import.meta.url);
const codeqlWorkflow = await readFile(codeqlWorkflowPath, 'utf8');
const ciWorkflowPath = new URL('../.github/workflows/ci.yml', import.meta.url);
const ciWorkflow = await readFile(ciWorkflowPath, 'utf8');

function requiredIndex(snippet, message) {
  const index = workflow.indexOf(snippet);
  assert.notEqual(index, -1, message);
  return index;
}

assert.match(
  workflow,
  /GHSA_FEED_PATH:\s+advisories\/ghsa-without-cve\.json/,
  'NVD workflow must write the provisional GHSA source feed',
);
assert.match(
  workflow,
  /GHSA_FEED_SIG_PATH:\s+advisories\/ghsa-without-cve\.json\.sig/,
  'NVD workflow must sign the provisional GHSA source feed',
);
assert.match(
  workflow,
  /node scripts\/ghsa-without-cve-feed\.mjs[\s\S]*--output "\$GHSA_FEED_PATH"[\s\S]*--consolidated-feed "\$FEED_PATH"[\s\S]*--existing-feed "\$GHSA_FEED_PATH"[\s\S]*--nvd-feed "\$FEED_PATH"[\s\S]*--rejected-cve-ids "tmp\/rejected_cve_ids\.json"/,
  'NVD workflow must merge GHSA advisories into the signed agent feed',
);
assert.match(
  workflow,
  /ALLOW_LARGE_REBUILD_DROP: \$\{\{ inputs\.allow_large_rebuild_drop \|\| false \}\}[\s\S]*GHSA_DROP_ARGS=\(\)[\s\S]*GHSA_DROP_ARGS\+=\(--allow-large-drop\)[\s\S]*"\$\{GHSA_DROP_ARGS\[@\]\}"/,
  'NVD workflow must pass the reviewed NVD drop override through GHSA consolidation while scheduled runs default false',
);
assert.match(
  workflow,
  /select\(is_rejected\)[\s\S]*fetched_rejected_cve_ids\.json[\s\S]*existing_cve_ids[\s\S]*index\(\$id\)[\s\S]*rejected_cve_ids\.json/,
  'NVD workflow must carry only rejected existing canonical CVEs into GHSA consolidation',
);
assert.match(
  workflow,
  /id: feed_changes[\s\S]*ghsa_changed=\$GHSA_CHANGED[\s\S]*agent_changed=\$AGENT_CHANGED[\s\S]*changed=true/,
  'NVD workflow must detect GHSA and consolidated agent feed changes separately',
);
assert.match(
  workflow,
  /name: Validate GHSA source feed before signing\n\s+if: steps\.feed_changes\.outputs\.ghsa_changed == 'true'\n\s+run: node scripts\/ci\/validate_advisory_feed\.mjs "\$GHSA_FEED_PATH"[\s\S]*name: Sign GHSA feed and verify/,
  'NVD workflow must validate the exact provisional GHSA feed bytes before signing them',
);
assert.match(
  workflow,
  /if: steps\.feed_changes\.outputs\.ghsa_changed == 'true'[\s\S]*input_file: \$\{\{ env\.GHSA_FEED_PATH \}\}[\s\S]*signature_file: \$\{\{ env\.GHSA_FEED_SIG_PATH \}\}/,
  'NVD workflow must sign the provisional GHSA feed when it changes',
);
assert.match(
  workflow,
  /if: steps\.feed_changes\.outputs\.agent_changed == 'true'[\s\S]*input_file: \$\{\{ env\.FEED_PATH \}\}[\s\S]*signature_file: \$\{\{ env\.FEED_SIG_PATH \}\}/,
  'NVD workflow must sign the consolidated agent feed when it changes',
);
assert.match(
  workflow,
  /git add "\$FEED_PATH" "\$FEED_SIG_PATH" "\$GHSA_FEED_PATH" "\$GHSA_FEED_SIG_PATH" "\$SKILL_FEED_PATH" "\$SKILL_FEED_SIG_PATH"/,
  'NVD workflow PR must include both NVD and GHSA feed artifacts',
);
assert.match(
  workflow,
  /echo "nvd_filtered_count=\$FILTERED" >> \$GITHUB_OUTPUT/,
  'NVD workflow must expose the filtered NVD CVE count with an explicit output name',
);
assert.match(
  workflow,
  /echo "nvd_updated_count=\$UPDATE_COUNT" >> \$GITHUB_OUTPUT/,
  'NVD workflow must expose updated NVD advisories with an explicit output name',
);
assert.match(
  workflow,
  /node scripts\/ci\/repair_stale_exploitability\.mjs[\s\S]*--feed "\$FEED_PATH"[\s\S]*--updates tmp\/updated_advisories\.json[\s\S]*--output tmp\/updated_advisories\.json[\s\S]*--nvd-json tmp\/filtered_cves\.json/,
  'NVD delta updates must repair stale exploitability enrichment before publishing the feed',
);
const pollJob = workflow.split('\n  poll-and-update:\n')[1]?.split(/\n {2}[\w-]+:\n/)[0];
assert.ok(pollJob, 'NVD workflow must define the poll-and-update job');
const pollSteps = pollJob.split('\n      - ');
const pythonSetupSteps = pollSteps.filter((step) => /uses: actions\/setup-python@/.test(step));
assert.equal(pythonSetupSteps.length, 1, 'NVD job must select Python exactly once');
const pythonSetupStep = pythonSetupSteps[0];
assert.match(pythonSetupStep, /python-version: '3\.12'/, 'NVD analyzers must use Python 3.12');
assert.doesNotMatch(pythonSetupStep, /^ {8}if:/m, 'Python setup must also run when there are no new CVEs');
for (const analyzer of ['repair_stale_exploitability.mjs', 'enrich_exploitability.sh']) {
  const analyzerStepIndex = pollSteps.findIndex((step) => step.includes(analyzer));
  assert.ok(analyzerStepIndex !== -1, `NVD job must invoke ${analyzer}`);
  assert.ok(
    pollSteps.indexOf(pythonSetupStep) < analyzerStepIndex,
    `Python 3.12 setup must precede the step that invokes ${analyzer}`,
  );
}
assert.match(
  workflow,
  /id: nvd_counts[\s\S]*Final NVD advisories to update:[\s\S]*nvd_updated_count=\$UPDATE_COUNT/,
  'NVD workflow must finalize updated counts after enrichment and full-scan rebuild comparison',
);
assert.match(
  workflow,
  /REBUILT_COUNT=/,
  'NVD full-scan mode must report rebuilt CVEs separately from net-new CVEs',
);
assert.match(
  workflow,
  /echo "nvd_rebuilt_count=\$REBUILT_COUNT" >> \$GITHUB_OUTPUT/,
  'NVD workflow must expose rebuilt CVE count separately from new-to-feed count',
);
assert.match(
  workflow,
  /echo "nvd_new_to_feed_count=\$NET_NEW_COUNT" >> \$GITHUB_OUTPUT/,
  'NVD workflow must expose net-new CVE advisories separately from rebuilt count',
);
assert.match(
  workflow,
  /echo "ghsa_active_count=\$GHSA_ACTIVE_COUNT" >> "\$GITHUB_OUTPUT"/,
  'NVD workflow must expose active GHSA count from the consolidated feed path',
);
assert.match(
  workflow,
  /echo "ghsa_added_to_consolidated_count=\$GHSA_ADDED_COUNT" >> "\$GITHUB_OUTPUT"/,
  'NVD workflow must expose GHSA-only additions to the consolidated feed',
);
assert.match(
  workflow,
  /TITLE="chore: update NVD\/GHSA advisories - \$\{STEPS_TRANSFORM_OUTPUTS_NVD_NEW_TO_FEED_COUNT\} NVD new, \$\{STEPS_NVD_COUNTS_OUTPUTS_NVD_UPDATED_COUNT\} NVD updated, \$\{STEPS_UPDATES_OUTPUTS_NVD_RETRACTED_COUNT\} NVD retracted, \$\{STEPS_FEED_CHANGES_OUTPUTS_GHSA_ADDED_TO_CONSOLIDATED_COUNT\} GHSA active added"/,
  'Generated PR titles must include net-new, updated, and retracted NVD counts plus GHSA-only additions',
);
assert.match(
  workflow,
  /\*\*GHSA active advisories added to consolidated feed:\*\* \$\{STEPS_FEED_CHANGES_OUTPUTS_GHSA_ADDED_TO_CONSOLIDATED_COUNT\}/,
  'Generated PR bodies must include GHSA-only additions',
);
assert.doesNotMatch(
  workflow,
  /gh run list[\s\S]*--jq --arg/,
  'CodeQL run lookup must not pass jq CLI flags through gh --jq',
);
assert.match(
  workflow,
  /gh run list[\s\S]*--json databaseId,createdAt,headSha \\\s*\n\s+\| jq -r --arg since "\$DISPATCHED_AT" --arg sha "\$EXPECTED_HEAD_SHA"/,
  'CodeQL run lookup must filter the gh JSON output with jq variables',
);
assert.match(
  ciWorkflow,
  /name: NVD \+ GHSA Pipeline Dry Run[\s\S]*node scripts\/test-nvd-ghsa-pipeline-dry-run\.mjs/,
  'CI must run the deterministic NVD + GHSA pipeline dry run before merge',
);
assert.match(
  ciWorkflow,
  /name: NVD Product Scoping Tests[\s\S]*node scripts\/nvd-product-scoping\.test\.mjs/,
  'CI must run strict NVD product/version scoping tests before merge',
);
assert.match(
  ciWorkflow,
  /name: Advisory Consumer Release Gate Tests[\s\S]*node --test scripts\/verify-advisory-consumer-releases\.test\.mjs/,
  'CI must exercise the shared advisory consumer release gate before merge',
);
assert.match(
  workflow,
  /name: Update feed\.json\n\s+if: inputs\.force_full_scan == true/,
  'A validated full scan must replace stale CVE state even when there are no delta changes',
);
assert.match(
  workflow,
  /Refusing full rebuild: strict NVD scoping produced zero advisories/,
  'A zero-result full scan must fail instead of deleting the existing CVE set',
);
assert.match(
  workflow,
  /allow_large_rebuild_drop:[\s\S]*Full rebuild identity safety check:[^\n]+25%[\s\S]*Refusing full rebuild:[^\n]+allow_large_rebuild_drop=true/,
  'A material full-rebuild identity deletion must require explicit operator confirmation',
);
assert.match(
  workflow,
  /retracted_advisory_ids\.json[\s\S]*Retracted NVD advisories/,
  'Incremental generation must report and remove CVEs that lose publishable scope',
);
assert.match(
  workflow,
  /name: Set safe NVD overlap window[\s\S]*119 days ago/,
  'Incremental polling must use a safe NVD overlap window instead of the consolidated feed timestamp',
);
assert.doesNotMatch(
  workflow,
  /LAST_UPDATED=\$\(jq -r '\.updated \/\/ empty' "\$FEED_PATH"\)/,
  'Community or GHSA feed timestamps must not advance the NVD cursor',
);
assert.match(
  workflow,
  /Incremental mode: paginating the broad rolling NVD modification inventory/,
  'Incremental NVD fetches must paginate an unfiltered modified-CVE inventory',
);
assert.match(
  workflow,
  /Refusing incremental update:[^\n]+review threshold:[^\n]+25%[^\n]+allow_large_rebuild_drop=true/,
  'Incremental mass retractions must require explicit operator confirmation',
);
assert.match(
  workflow,
  /NVD returned an empty page before all results/,
  'NVD pagination must fail closed on incomplete result sets',
);
assert.match(
  workflow,
  /NVD totalResults changed during pagination/,
  'NVD pagination must verify advertised result counts remain stable',
);
assert.match(
  workflow,
  /NVD returned duplicate CVE IDs while paginating/,
  'NVD pagination must reject duplicate rows that could hide a missing CVE',
);
assert.match(
  codeqlWorkflow,
  /if: github\.event_name != 'pull_request' \|\| !startsWith\(github\.head_ref, 'automated\/nvd-cve-update'\)/,
  'PR-triggered CodeQL must skip generated NVD advisory PRs because poll-nvd-cves dispatches CodeQL explicitly',
);

const updateFeedIndex = requiredIndex('name: Update feed.json', 'NVD workflow must update the CVE feed first');
const pollGhsaIndex = requiredIndex(
  'name: Poll GHSA without CVE and consolidate feed',
  'NVD workflow must poll GHSA before signing',
);
const validateFeedIndex = requiredIndex(
  'node scripts/ci/validate_advisory_feed.mjs "$FEED_PATH"',
  'NVD workflow must validate the consolidated feed before signing',
);
const consumerReleaseGateIndex = requiredIndex(
  'name: Verify advisory consumer releases',
  'NVD workflow must gate exact Hermes date-build selectors on every compatible published consumer',
);
const consumerReleaseGateEnd = workflow.indexOf('\n      - name:', consumerReleaseGateIndex + 1);
assert.notEqual(consumerReleaseGateEnd, -1, 'Advisory consumer release gate must have a bounded workflow body');
const consumerReleaseGate = workflow.slice(consumerReleaseGateIndex, consumerReleaseGateEnd);
assert.match(
  consumerReleaseGate,
  /GH_TOKEN: \$\{\{ github\.token \}\}[\s\S]*node scripts\/ci\/verify_advisory_consumer_releases\.mjs "\$FEED_PATH"/,
  'NVD workflow must run the shared authenticated advisory consumer release gate',
);
const detectChangesIndex = requiredIndex(
  'name: Detect advisory feed changes',
  'NVD workflow must detect combined feed changes before signing',
);
const signGhsaIndex = requiredIndex(
  'name: Sign GHSA feed and verify',
  'NVD workflow must sign the GHSA source feed',
);
const signAgentIndex = requiredIndex(
  'name: Sign advisory feed and verify',
  'NVD workflow must sign the consolidated agent feed',
);
const upsertPrIndex = requiredIndex(
  'name: Upsert NVD advisory PR',
  'NVD workflow must upsert a PR for any feed change',
);

assert.ok(
  updateFeedIndex < pollGhsaIndex,
  'GHSA consolidation must run after the NVD update step so matured advisories can reconcile against new CVEs',
);
assert.ok(
  pollGhsaIndex < detectChangesIndex,
  'Combined feed change detection must run after GHSA consolidation',
);
assert.ok(
  pollGhsaIndex < validateFeedIndex && validateFeedIndex < consumerReleaseGateIndex,
  'Advisory consumer compatibility must be checked only after final consolidated feed validation',
);
assert.ok(consumerReleaseGateIndex < detectChangesIndex, 'Feed change detection must run after the consumer release gate');
assert.ok(detectChangesIndex < signGhsaIndex, 'GHSA signing must run after change detection');
assert.ok(detectChangesIndex < signAgentIndex, 'Agent feed signing must run after change detection');
assert.ok(consumerReleaseGateIndex < signAgentIndex, 'Agent feed signing must not bypass the consumer release gate');
assert.ok(signAgentIndex < upsertPrIndex, 'The PR must be created after feed signing');
