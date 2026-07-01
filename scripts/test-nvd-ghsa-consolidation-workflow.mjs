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
  /node scripts\/ghsa-without-cve-feed\.mjs[\s\S]*--output "\$GHSA_FEED_PATH"[\s\S]*--consolidated-feed "\$FEED_PATH"[\s\S]*--existing-feed "\$GHSA_FEED_PATH"[\s\S]*--nvd-feed "\$FEED_PATH"/,
  'NVD workflow must merge GHSA advisories into the signed agent feed',
);
assert.match(
  workflow,
  /id: feed_changes[\s\S]*ghsa_changed=\$GHSA_CHANGED[\s\S]*agent_changed=\$AGENT_CHANGED[\s\S]*changed=true/,
  'NVD workflow must detect GHSA and consolidated agent feed changes separately',
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
  /TITLE="chore: update NVD\/GHSA advisories - \$\{\{ steps\.transform\.outputs\.nvd_new_to_feed_count \}\} NVD new, \$\{\{ steps\.nvd_counts\.outputs\.nvd_updated_count \}\} NVD updated, \$\{\{ steps\.feed_changes\.outputs\.ghsa_added_to_consolidated_count \}\} GHSA active added"/,
  'Generated PR titles must include net-new NVD, updated NVD, and GHSA-only addition counts',
);
assert.match(
  workflow,
  /\*\*GHSA active advisories added to consolidated feed:\*\* \$\{\{ steps\.feed_changes\.outputs\.ghsa_added_to_consolidated_count \}\}/,
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
  codeqlWorkflow,
  /if: github\.event_name != 'pull_request' \|\| !startsWith\(github\.head_ref, 'automated\/nvd-cve-update'\)/,
  'PR-triggered CodeQL must skip generated NVD advisory PRs because poll-nvd-cves dispatches CodeQL explicitly',
);

const updateFeedIndex = requiredIndex('name: Update feed.json', 'NVD workflow must update the CVE feed first');
const pollGhsaIndex = requiredIndex(
  'name: Poll GHSA without CVE and consolidate feed',
  'NVD workflow must poll GHSA before signing',
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
assert.ok(detectChangesIndex < signGhsaIndex, 'GHSA signing must run after change detection');
assert.ok(detectChangesIndex < signAgentIndex, 'Agent feed signing must run after change detection');
assert.ok(signAgentIndex < upsertPrIndex, 'The PR must be created after feed signing');
