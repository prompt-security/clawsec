import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflowPath = new URL('../.github/workflows/skill-release.yml', import.meta.url);
const ciWorkflowPath = new URL('../.github/workflows/ci.yml', import.meta.url);
const validateSkillInstallDocsPath = new URL('./ci/validate_skill_install_docs.mjs', import.meta.url);
const installClawhubCliPath = new URL('./ci/install_clawhub_cli.sh', import.meta.url);
const patchClawhubPayloadPath = new URL('./ci/patch_clawhub_publish_payload.mjs', import.meta.url);
const workflow = await readFile(workflowPath, 'utf8');
const ciWorkflow = await readFile(ciWorkflowPath, 'utf8');
const validateSkillInstallDocs = await readFile(validateSkillInstallDocsPath, 'utf8');
const installClawhubCli = await readFile(installClawhubCliPath, 'utf8');
const patchClawhubPayload = await readFile(patchClawhubPayloadPath, 'utf8');

assert.match(
  workflow,
  /pull_request:[\s\S]*paths:[\s\S]*- 'skills\/\*\*'/,
  'Skill release workflow must run when any skill package file changes',
);

for (const generatedFeedPath of [
  'skills/clawsec-feed/advisories/feed.json',
  'skills/clawsec-feed/advisories/feed.json.sig',
]) {
  assert.ok(
    workflow.includes(`      - '!${generatedFeedPath}'`),
    `Skill release workflow must not run for generated advisory mirror-only changes to ${generatedFeedPath}`,
  );
}

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
  /git diff --name-only "\$\{BASE_SHA\}\.\.\.\$\{HEAD_SHA\}" --[\s\S]*'skills\/\*\/\*\*'[\s\S]*':\(exclude\)skills\/clawsec-feed\/advisories\/feed\.json'[\s\S]*':\(exclude\)skills\/clawsec-feed\/advisories\/feed\.json\.sig'[\s\S]*':\(exclude\)skills\/\*\/test\/\*\*'[\s\S]*':\(exclude\)skills\/\*\/tests\/\*\*'/,
  'Skill release validation must ignore generated clawsec-feed advisory mirror and test-only changes while inspecting release-relevant skill files',
);

for (const generatedFeedPath of [
  ':(exclude)skills/clawsec-feed/advisories/feed.json',
  ':(exclude)skills/clawsec-feed/advisories/feed.json.sig',
]) {
  assert.ok(
    validateSkillInstallDocs.includes(`"${generatedFeedPath}"`),
    `Install-doc validation changed-skill detection must ignore generated advisory mirror-only changes to ${generatedFeedPath}`,
  );
}

assert.ok(
  workflow.includes('name = tolower($NF)')
    && workflow.includes('name ~ /^(test|spec)[_-]/')
    && workflow.includes('name ~ /\\.(test|spec)\\./'),
  'Skill release validation must filter test-named skill files such as scripts/test_*.py before selecting dry-run skill directories',
);

assert.doesNotMatch(
  workflow,
  /No version bump detected for \$\{skill_dir\}; skipping\./,
  'Changed skill directories without a version bump must not be skipped without release-tag validation',
);

assert.match(
  workflow,
  /skill_release_name="\$\(basename "\$\{skill_dir\}"\)"/,
  'Skill release validation must derive the release tag prefix from the skill package directory',
);

assert.match(
  workflow,
  /release_tag="\$\{skill_release_name\}-v\$\{head_json_version\}"/,
  'Skill release validation must use the skill package directory name for release tag checks',
);

assert.doesNotMatch(
  workflow,
  /release_tag="\$\{head_skill_name\}-v\$\{head_json_version\}"/,
  'Skill release validation must not use skill.json name for release tag checks because release tags resolve to skill directories',
);

assert.match(
  workflow,
  /git show-ref --verify --quiet "refs\/tags\/\$\{release_tag\}"/,
  'Skill release validation must check whether the current skill version has already been tagged',
);

assert.match(
  workflow,
  /No version bump detected for \$\{skill_dir\}, but release tag \$\{release_tag\} does not exist; treating \$\{head_json_version\} as unreleased\./,
  'Skill release validation must allow edits to an unchanged version when that release tag does not exist yet',
);

assert.match(
  workflow,
  /::error file=\$\{skill_dir\}::Changed skill package has no version bump and release tag \$\{release_tag\} already exists\./,
  'Skill release validation must still fail unchanged versions after their release tag exists',
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

assert.doesNotMatch(
  workflow,
  /"### SkillSpector Security Report"/,
  'GitHub release notes must not add a duplicate SkillSpector heading before the generated report',
);

assert.match(
  workflow,
  /readFileSync\("release-assets\/skillspector-report\.md", "utf8"\)[\s\S]*report,[\s\S]*\[skillspector-report\.md\]\(https:\/\/github\.com\/\$\{process\.env\.REPO\}\/releases\/download\/\$\{process\.env\.TAG\}\/skillspector-report\.md\)/,
  'GitHub release notes must embed the generated SkillSpector report and include a direct report link',
);

assert.match(
  workflow,
  /readFileSync\("release-assets\/skillspector-report\.md", "utf8"\)/,
  'GitHub release notes must load the generated SkillSpector report content into the release body file',
);

assert.match(
  workflow,
  /body_path: \$\{\{ runner\.temp \}\}\/skill-release-body\.md/,
  'GitHub release creation must use body_path for the generated release body file',
);

assert.doesNotMatch(
  workflow,
  /SKILLSPECTOR_REPORT_EOF|\$\{\{ steps\.skillspector_report\.outputs\.body \}\}|cat release-assets\/skillspector-report\.md[\s\S]*>> "\$GITHUB_OUTPUT"/,
  'SkillSpector report content must not be sent through GitHub Actions step outputs',
);

assert.match(
  workflow,
  /generate_skillspector_report "\$\{inner_dir\}" "\$\{out_assets\}\/skillspector-report\.md"/,
  'PR dry-run SkillSpector scan must target the staged release payload, not the source skill directory',
);

assert.match(
  workflow,
  /Run release dry-run for changed skills[\s\S]*git diff --name-only "\$\{BASE_SHA\}\.\.\.\$\{HEAD_SHA\}" --[\s\S]*'skills\/\*\/\*\*'[\s\S]*':\(exclude\)skills\/clawsec-feed\/advisories\/feed\.json'[\s\S]*':\(exclude\)skills\/clawsec-feed\/advisories\/feed\.json\.sig'[\s\S]*':\(exclude\)skills\/\*\/test\/\*\*'[\s\S]*':\(exclude\)skills\/\*\/tests\/\*\*'/,
  'PR dry-run SkillSpector scan must run when any release-relevant skill package file changes except generated advisory mirror files',
);

assert.ok(
  workflow.includes('local name="${lower##*/}"')
    && workflow.includes('"$name" == test_*')
    && workflow.includes('"$name" == *.test.*')
    && workflow.includes('(__tests__|test|tests)/|(^|/)(test|spec)[_-]|(^|/).*\\.(test|spec)\\.'),
  'Skill release archives must exclude test directories and test-named files from staged release payloads',
);

assert.doesNotMatch(
  workflow,
  /generate_skillspector_report "\$\{skill_dir\}" "\$\{out_assets\}\/skillspector-report\.md"/,
  'PR dry-run SkillSpector scan must not include source-only test directories',
);

assert.match(
  workflow,
  /generate_skillspector_report "\$INNER_DIR" "release-assets\/skillspector-report\.md"/,
  'Tag release SkillSpector scan must target the staged release payload, not the source skill directory',
);

assert.doesNotMatch(
  workflow,
  /generate_skillspector_report "\$SKILL_PATH" "release-assets\/skillspector-report\.md"/,
  'Tag release SkillSpector scan must not include source-only test directories',
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
  /Upload SkillSpector PR reports[\s\S]*actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7\.0\.1[\s\S]*name: skillspector-pr-reports/,
  'PR dry-run must upload generated SkillSpector reports as workflow artifacts',
);

assert.match(
  workflow,
  /comment-skillspector-report:[\s\S]*needs: release[\s\S]*issues: write[\s\S]*actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8\.0\.1/,
  'Skill release workflow must download generated SkillSpector reports in a separate PR comment job with comment permissions',
);

assert.match(
  workflow,
  /comment-skillspector-report:[\s\S]*if: always\(\) && github\.event_name == 'pull_request' && needs\.release\.result != 'cancelled'[\s\S]*Download SkillSpector reports[\s\S]*continue-on-error: true/,
  'SkillSpector PR comments must still run when the release dry-run produced reports but the release job failed later',
);

assert.match(
  workflow,
  /function sanitizeReportForComment\(report\)[\s\S]*code block omitted from PR comment[\s\S]*inline snippet omitted[\s\S]*redacted-email[\s\S]*redacted-token/,
  'SkillSpector PR comments must sanitize raw report content before posting to the PR',
);

assert.match(
  workflow,
  /const sanitizedReport = sanitizeReportForComment\(report\);[\s\S]*`\$\{marker\}\\n\$\{sanitizedReport\}/,
  'SkillSpector PR comments must use the sanitized report body, not the raw artifact text',
);

assert.doesNotMatch(
  workflow,
  /`\$\{marker\}\\n\$\{report\.trimEnd\(\)\}/,
  'SkillSpector PR comments must not post report.trimEnd() verbatim',
);

assert.match(
  workflow,
  /clawsec-skillspector-report:\$\{tag\}[\s\S]*github\.rest\.issues\.updateComment[\s\S]*github\.rest\.issues\.createComment/,
  'SkillSpector PR comments must use stable per-skill markers and update existing comments before creating new ones',
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

assert.match(
  workflow,
  /clawhub_slug: \$\{\{ steps\.publishable\.outputs\.clawhub_slug \}\}/,
  'Skill release workflow must expose the resolved ClawHub slug from release-tag outputs',
);

assert.match(
  workflow,
  /CLAWHUB_SLUG=\$\(node scripts\/ci\/resolve_clawhub_slug\.mjs "\$SKILL_PATH"\)/,
  'Skill release workflow must resolve the ClawHub slug from the skill package path',
);

assert.match(
  workflow,
  /cp scripts\/ci\/resolve_clawhub_slug\.mjs "\$RUNNER_TEMP\/resolve_clawhub_slug\.mjs"/,
  'Manual ClawHub republish must preserve the current slug helper before checking out an older release tag',
);

assert.match(
  workflow,
  /CLAWHUB_SLUG=\$\(node "\$RUNNER_TEMP\/resolve_clawhub_slug\.mjs" "\$SKILL_PATH"\)/,
  'Manual ClawHub republish must resolve slugs with the preserved helper against the checked-out tag metadata',
);

assert.match(
  workflow,
  /npx clawhub@latest install \$\{CLAWHUB_SLUG\}/,
  'GitHub release quick install instructions must use the resolved ClawHub slug',
);

assert.match(
  workflow,
  /clawhub inspect "\$CLAWHUB_SLUG" --version "\$VERSION" --json/,
  'Duplicate ClawHub version guard must inspect the resolved ClawHub slug',
);

assert.match(
  workflow,
  /--slug "\$CLAWHUB_SLUG"/,
  'ClawHub publish must use the resolved ClawHub slug',
);

assert.equal(
  workflow.match(/bash scripts\/ci\/install_clawhub_cli\.sh/g)?.length,
  2,
  'ClawHub publish and republish jobs must share the same pinned CLI installer',
);

assert.equal(
  workflow.match(/node scripts\/ci\/patch_clawhub_publish_payload\.mjs/g)?.length,
  2,
  'ClawHub publish and republish jobs must share the same payload patch helper',
);

assert.doesNotMatch(
  workflow,
  /npm ci --prefix \.github\/clawhub-cli/,
  'ClawHub CLI installation must not be duplicated inline in the workflow',
);

assert.doesNotMatch(
  workflow,
  /node <<'NODE'[\s\S]*acceptLicenseTerms: true/,
  'ClawHub payload patching must not be duplicated inline in the workflow',
);

for (const secret of ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']) {
  assert.match(
    workflow,
    new RegExp(`${secret}: \\$\\{\\{ secrets\\.${secret} \\}\\}`),
    `ClawHub jobs must expose ${secret} for CodeArtifact npm authentication`,
  );
}

assert.match(
  installClawhubCli,
  /aws codeartifact login[\s\S]*--domain "\$CODEARTIFACT_DOMAIN"[\s\S]*--domain-owner "\$CODEARTIFACT_DOMAIN_OWNER"[\s\S]*--repository "\$CODEARTIFACT_REPOSITORY"[\s\S]*--region "\$AWS_REGION"/,
  'ClawHub CLI installer must authenticate npm against CodeArtifact before npm ci',
);

assert.match(
  installClawhubCli,
  /npm ci --prefix "\$CLI_PREFIX"/,
  'ClawHub CLI installer must install from the committed lockfile prefix',
);

assert.match(
  installClawhubCli,
  /"\$\{workspace\}\/\$\{CLI_PREFIX\}\/node_modules\/\.bin" >> "\$GITHUB_PATH"/,
  'ClawHub CLI installer must expose the pinned clawhub binary on GITHUB_PATH',
);

assert.match(
  patchClawhubPayload,
  /const payloadPattern = \/changelog,\\r\?\\n\(\\s\*\)tags,\/;/,
  'ClawHub payload patch helper must target the expected publish payload shape',
);

assert.match(
  patchClawhubPayload,
  /acceptLicenseTerms: true/,
  'ClawHub payload patch helper must preserve the acceptLicenseTerms workaround',
);

assert.doesNotMatch(
  workflow,
  /clawhub inspect "\$SKILL_NAME" --version "\$VERSION" --json/,
  'Duplicate ClawHub version guard must not inspect the raw skill package name',
);

assert.doesNotMatch(
  workflow,
  /--slug "\$SKILL_NAME"/,
  'ClawHub publish must not use the raw skill package name as the ClawHub slug',
);
