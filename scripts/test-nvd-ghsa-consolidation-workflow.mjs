import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflowPath = new URL('../.github/workflows/poll-nvd-cves.yml', import.meta.url);
const workflow = await readFile(workflowPath, 'utf8');
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
