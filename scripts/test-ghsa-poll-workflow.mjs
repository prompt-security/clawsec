import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflowPath = new URL('../.github/workflows/poll-ghsa-without-cve.yml', import.meta.url);
const workflow = await readFile(workflowPath, 'utf8');

assert.match(workflow, /workflow_dispatch:/, 'GHSA poll workflow must remain runnable as a manual fallback');
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
  /input_file: \$\{\{ env\.FEED_PATH \}\}/,
  'GHSA poll workflow must sign the consolidated agent feed when it changes',
);
assert.match(
  workflow,
  /cp "\$FEED_SIG_PATH" "\$SKILL_FEED_SIG_PATH"/,
  'GHSA poll workflow must sync consolidated feed signature into clawsec-feed',
);
