import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflowPath = new URL('../.github/workflows/skill-release.yml', import.meta.url);
const workflow = await readFile(workflowPath, 'utf8');

assert.match(
  workflow,
  /pull_request:[\s\S]*paths:[\s\S]*- 'skills\/\*\*'/,
  'Skill release workflow must run when any skill package file changes',
);

assert.match(
  workflow,
  /git diff --name-only "\$\{BASE_SHA\}\.\.\.\$\{HEAD_SHA\}" --[\s\S]*'skills\/\*\/\*\*'[\s\S]*':\(exclude\)skills\/\*\/test\/\*\*'[\s\S]*':\(exclude\)skills\/\*\/tests\/\*\*'/,
  'Skill release validation must ignore test-only skill changes while inspecting release-relevant skill files',
);

assert.doesNotMatch(
  workflow,
  /No version bump detected for \$\{skill_dir\}; skipping\./,
  'Changed skill directories without a version bump must fail validation instead of being skipped',
);

assert.match(
  workflow,
  /::error file=\$\{skill_dir\}::Changed skill package has no version bump\./,
  'Skill release validation must emit an explicit missing-version-bump error',
);
