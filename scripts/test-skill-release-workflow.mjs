import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflowPath = new URL('../.github/workflows/skill-release.yml', import.meta.url);
const ciWorkflowPath = new URL('../.github/workflows/ci.yml', import.meta.url);
const workflow = await readFile(workflowPath, 'utf8');
const ciWorkflow = await readFile(ciWorkflowPath, 'utf8');

assert.match(
  workflow,
  /pull_request:[\s\S]*paths:[\s\S]*- 'skills\/\*\*'/,
  'Skill release workflow must run when any skill package file changes',
);

assert.match(
  workflow,
  /pull_request:[\s\S]*paths:[\s\S]*- '\.github\/workflows\/skill-release\.yml'[\s\S]*- 'scripts\/ci\/\*\*'/,
  'Skill release workflow must also run when the release pipeline itself changes',
);

assert.ok(
  ciWorkflow.includes(`      - name: Skill Release Tooling Tests
        run: |
          set -euo pipefail
          for test_file in scripts/test-skill-*.mjs; do
            node "$test_file"
          done`),
  'CI must run every scripts/test-skill-*.mjs file so new skill release tests are not orphaned',
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

assert.match(
  workflow,
  /Install SkillSpector/,
  'Skill release workflow must install SkillSpector before publishing release evidence',
);

assert.match(
  workflow,
  /Generate SkillSpector report/,
  'Skill release workflow must generate a SkillSpector report for each released skill',
);

assert.match(
  workflow,
  /Generate release trust packet/,
  'Skill release workflow must generate skill cards, permission summaries, and npx install instructions',
);

for (const artifact of ['skill-card.md', 'permissions.json', 'install.md', 'skillspector-report.md']) {
  assert.match(
    workflow,
    new RegExp(`release-assets/${artifact.replace('.', '\\.')}`),
    `Skill release workflow must publish ${artifact} in release assets`,
  );
}

const escapeRegExp = (literal) => literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

for (const artifact of ['skill-card.md', 'permissions.json', 'install.md', 'skillspector-report.md']) {
  assert.match(
    workflow,
    new RegExp(
      String.raw`if ! add_release_asset_checksum "\$\{out_assets\}" "${escapeRegExp(artifact)}"; then` +
        String.raw`[\s\S]*?failures=\$\(\(failures \+ 1\)\)[\s\S]*?continue[\s\S]*?fi`,
    ),
    `PR dry-run validation must aggregate and continue when ${artifact} cannot be checksummed`,
  );
}

assert.match(
  workflow,
  /add_release_asset_checksum "skill-card\.md"/,
  'Skill card must be included in the signed checksums manifest',
);

assert.match(
  workflow,
  /add_release_asset_checksum "permissions\.json"/,
  'Permissions summary must be included in the signed checksums manifest',
);

assert.match(
  workflow,
  /add_release_asset_checksum "install\.md"/,
  'npx install/update instructions must be included in the signed checksums manifest',
);

assert.match(
  workflow,
  /add_release_asset_checksum "skillspector-report\.md"/,
  'SkillSpector report must be included in the signed checksums manifest',
);

assert.match(
  workflow,
  /Simulate tag release build/,
  'Skill release workflow must simulate a tag release build during PR validation',
);

assert.match(
  workflow,
  /simulate_skill_tag_release\.mjs/,
  'Skill release workflow must call the tag release simulation script',
);

assert.ok(
  workflow.includes('simulated_version | test("^[0-9]+\\\\.[0-9]+\\\\.[0-9]+(-[a-zA-Z0-9]+)?$")'),
  'Skill release workflow must accept every prerelease version format that release-skill.sh accepts',
);
