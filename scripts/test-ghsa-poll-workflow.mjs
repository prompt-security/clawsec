import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflowPath = new URL('../.github/workflows/poll-ghsa-without-cve.yml', import.meta.url);
const workflow = await readFile(workflowPath, 'utf8');

assert.match(workflow, /workflow_dispatch:/, 'GHSA poll workflow must remain runnable as a manual fallback');
assert.match(
  workflow,
  /allow_large_rebuild_drop:[\s\S]*type: boolean/,
  'GHSA poll workflow must expose an explicit reviewed-drop override',
);
assert.doesNotMatch(
  workflow,
  /\n\s+schedule:/,
  'Scheduled GHSA consolidation belongs to the NVD workflow to avoid duplicate automated feed PRs',
);
assert.match(
  workflow,
  /FEED_PATH:\s+advisories\/feed\.json/,
  'GHSA poll workflow must know the consolidated agent feed path',
);
assert.match(
  workflow,
  /SKILL_FEED_PATH:\s+skills\/clawsec-feed\/advisories\/feed\.json/,
  'GHSA poll workflow must sync the consolidated agent feed into clawsec-feed',
);
assert.match(
  workflow,
  /--consolidated-feed "\$FEED_PATH"/,
  'GHSA poll workflow must merge GHSA advisories into the agent-facing feed',
);
assert.match(
  workflow,
  /ALLOW_LARGE_REBUILD_DROP: \$\{\{ inputs\.allow_large_rebuild_drop \|\| false \}\}[\s\S]*GHSA_DROP_ARGS=\(\)[\s\S]*GHSA_DROP_ARGS\+=\(--allow-large-drop\)[\s\S]*"\$\{GHSA_DROP_ARGS\[@\]\}"/,
  'GHSA poll workflow must pass its reviewed-drop override to the GHSA CLI and default scheduled-style missing input to false',
);
const baselineIndex = workflow.indexOf('- name: Require canonical advisory baseline');
const pollIndex = workflow.indexOf('- name: Poll GitHub Security Advisories');
assert.ok(
  baselineIndex !== -1 && baselineIndex < pollIndex,
  'GHSA polling must require a non-empty canonical baseline before any network fetch or feed write',
);
assert.match(
  workflow.slice(baselineIndex, pollIndex),
  /\[ ! -f "\$FEED_PATH" \][\s\S]*jq -e 'type == "object" and \(\.advisories \| type == "array" and length > 0\)' "\$FEED_PATH"/,
  'GHSA polling must fail closed when the canonical baseline is missing, malformed, or empty',
);
assert.match(
  workflow,
  /node scripts\/ci\/validate_advisory_feed\.mjs "\$FEED_PATH"/,
  'GHSA poll workflow must validate the complete consolidated feed before signing',
);
assert.match(
  workflow,
  /name: Validate GHSA source feed before signing\n\s+if: steps\.changes\.outputs\.ghsa_changed == 'true'\n\s+run: node scripts\/ci\/validate_advisory_feed\.mjs "\$GHSA_FEED_PATH"[\s\S]*name: Sign GHSA feed and verify/,
  'GHSA poll workflow must validate the exact provisional feed bytes before signing them',
);
assert.match(
  workflow,
  /input_file: \$\{\{ env\.FEED_PATH \}\}/,
  'GHSA poll workflow must sign the consolidated agent feed when it changes',
);
assert.match(
  workflow,
  /cp "\$FEED_SIG_PATH" "\$SKILL_FEED_SIG_PATH"/,
  'GHSA poll workflow must sync consolidated feed signature into clawsec-feed',
);
