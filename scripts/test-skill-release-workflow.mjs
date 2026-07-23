import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const workflowPath = new URL('../.github/workflows/controlled-skill-release.yml', import.meta.url);
const ciWorkflowPath = new URL('../.github/workflows/ci.yml', import.meta.url);
const clawhubLockPath = new URL('../.github/clawhub-cli/package-lock.json', import.meta.url);
const validateSkillInstallDocsPath = new URL('./ci/validate_skill_install_docs.mjs', import.meta.url);
const installClawhubCliPath = new URL('./ci/install_clawhub_cli.sh', import.meta.url);
const patchClawhubPayloadPath = new URL('./ci/patch_clawhub_publish_payload.mjs', import.meta.url);
const patchClawhubTrustExtensionsPath = new URL('./ci/patch_clawhub_trust_extensions.mjs', import.meta.url);
const guardClawhubSlugOwnerPath = new URL('./ci/guard_clawhub_slug_owner.sh', import.meta.url);
const releaseSkillScriptPath = new URL('./release-skill.sh', import.meta.url);
const workflow = await readFile(workflowPath, 'utf8');
const ciWorkflow = await readFile(ciWorkflowPath, 'utf8');
const clawhubLock = JSON.parse(await readFile(clawhubLockPath, 'utf8'));
const validateSkillInstallDocs = await readFile(validateSkillInstallDocsPath, 'utf8');
const installClawhubCli = await readFile(installClawhubCliPath, 'utf8');
const patchClawhubPayload = await readFile(patchClawhubPayloadPath, 'utf8');
const patchClawhubTrustExtensions = await readFile(patchClawhubTrustExtensionsPath, 'utf8');
const guardClawhubSlugOwner = await readFile(guardClawhubSlugOwnerPath, 'utf8');
const releaseSkillScript = await readFile(releaseSkillScriptPath, 'utf8');

function requiredIndex(text, needle, message) {
  const index = text.indexOf(needle);
  assert.notEqual(index, -1, message);
  return index;
}

const preservedHelperBlock = workflow.match(
  /- name: Prepare current ClawHub workflow helpers\s+run: \|\n(?<body>[\s\S]*?)\n\s+- name: Checkout tag/,
)?.groups?.body;
assert.ok(preservedHelperBlock, 'Manual ClawHub republish must define a preserved-helper block');
const preservedHelperCopies = [...preservedHelperBlock.matchAll(
  /cp (scripts\/ci\/[^\s]+\.mjs) "\$RUNNER_TEMP\/([^"/]+\.mjs)"/g,
)].map((match) => ({ source: match[1], destination: match[2] }));
const preservedHelperDestinations = new Set(preservedHelperCopies.map(({ destination }) => destination));
assert.ok(
  preservedHelperDestinations.has('skill_installability.mjs'),
  'Manual ClawHub republish must preserve the current installability policy before checking out an older tag',
);

for (const { source, destination } of preservedHelperCopies) {
  const sourceText = await readFile(new URL(`../${source}`, import.meta.url), 'utf8');
  for (const match of sourceText.matchAll(/\bfrom\s+["'](\.[^"']+)["']/g)) {
    const dependency = path.posix.normalize(path.posix.join(path.posix.dirname(destination), match[1]));
    assert.ok(
      preservedHelperDestinations.has(dependency),
      `Manual ClawHub republish must preserve ${dependency}, imported by ${source}`,
    );
  }
}

const preservedHelperDir = await mkdtemp(path.join(tmpdir(), 'clawhub-republish-helpers-'));
try {
  await Promise.all(preservedHelperCopies.map(({ source, destination }) => cp(
    new URL(`../${source}`, import.meta.url),
    path.join(preservedHelperDir, destination),
  )));
  for (const { destination } of preservedHelperCopies) {
    await import(`${pathToFileURL(path.join(preservedHelperDir, destination)).href}?test=${Date.now()}`);
  }
} finally {
  await rm(preservedHelperDir, { recursive: true, force: true });
}

assert.match(
  workflow,
  /pull_request:[\s\S]*paths:[\s\S]*- 'skills\/\*\*'/,
  'Skill release workflow must run when any skill package file changes',
);

for (const generatedFeedPath of [
  'skills/clawsec-feed/advisories/feed.json',
  'skills/clawsec-feed/advisories/feed.json.sig',
  'skills/clawsec-suite/advisories/feed.json',
  'skills/clawsec-suite/advisories/feed.json.sig',
]) {
  assert.ok(
    workflow.includes(`      - '!${generatedFeedPath}'`),
    `Skill release workflow must not run for generated advisory mirror-only changes to ${generatedFeedPath}`,
  );
}

assert.match(
  workflow,
  /pull_request:[\s\S]*paths:[\s\S]*- '\.github\/workflows\/controlled-skill-release\.yml'[\s\S]*- '\.github\/workflows\/create-skill-release-tag\.yml'[\s\S]*- 'scripts\/ci\/\*\*'/,
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
  /git diff --name-only "\$\{BASE_SHA\}\.\.\.\$\{HEAD_SHA\}" --[\s\S]*'skills\/\*\/\*\*'[\s\S]*':\(exclude\)skills\/clawsec-feed\/advisories\/feed\.json'[\s\S]*':\(exclude\)skills\/clawsec-feed\/advisories\/feed\.json\.sig'[\s\S]*':\(exclude\)skills\/clawsec-suite\/advisories\/feed\.json'[\s\S]*':\(exclude\)skills\/clawsec-suite\/advisories\/feed\.json\.sig'[\s\S]*':\(exclude\)skills\/\*\/test\/\*\*'[\s\S]*':\(exclude\)skills\/\*\/tests\/\*\*'/,
  'Skill release validation must ignore generated advisory mirrors and test-only changes while inspecting release-relevant skill files',
);

for (const generatedFeedPath of [
  ':(exclude)skills/clawsec-feed/advisories/feed.json',
  ':(exclude)skills/clawsec-feed/advisories/feed.json.sig',
  ':(exclude)skills/clawsec-suite/advisories/feed.json',
  ':(exclude)skills/clawsec-suite/advisories/feed.json.sig',
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
  /sign_advisory_artifacts "\$\{inner_dir\}"/,
  'PR release dry-runs must sign advisory artifacts inside the staged package',
);

assert.doesNotMatch(
  workflow,
  /Removed test signatures from release staging|rm -f "\$\{inner_dir\}\/advisories\/(?:feed\.json\.sig|checksums\.json|checksums\.json\.sig|feed-signing-public\.pem)"/,
  'PR release dry-runs must retain the complete signed advisory trust set in the simulated archive',
);

assert.doesNotMatch(
  workflow,
  /rm -f "\$\{skill_dir\}\/advisories\/(?:feed\.json\.sig|checksums\.json|checksums\.json\.sig|feed-signing-public\.pem)"/,
  'PR release dry-runs must not delete tracked or generated advisory trust files from source directories',
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
  /node scripts\/ci\/semver_increment\.mjs "\$\{base_json_version\}" "\$\{head_json_version\}"/,
  'Changed skill versions must increase by SemVer precedence instead of merely differing from the base version',
);

assert.match(
  workflow,
  /Install SkillSpector/,
  'Skill release workflow must install SkillSpector before publishing release evidence',
);

assert.equal(
  (workflow.match(/"advisories\/feed-signing-public\.pem": \{/g) || []).length,
  2,
  'PR dry-run and tag release embedded manifests must both checksum the feed signing public key',
);

assert.match(
  workflow,
  /cp "\$pub_file" "\$advisory_dir\/feed-signing-public\.pem"[\s\S]*local public_key_sha=[\s\S]*"advisories\/feed-signing-public\.pem": \{sha256: \$public_key_sha, size: \$public_key_size\}/,
  'PR dry-run must stage the embedded public key before checksumming it',
);

assert.match(
  workflow,
  /PUBLIC_KEY_SHA=\$\(sha256sum "\$ADVISORY_DIR\/feed-signing-public\.pem"[\s\S]*"advisories\/feed-signing-public\.pem": \{[\s\S]*sha256: \$public_key_sha/,
  'Tag releases must include the embedded public key digest in the signed advisory manifest',
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
  /\bgh\s+release\s+delete\b/,
  'Skill release workflow must retain every published GitHub release, including superseded same-major versions',
);

assert.doesNotMatch(
  workflow,
  /- name: Delete superseded releases\b/,
  'Skill release workflow must not run superseded-release cleanup',
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
  /Run release dry-run for changed skills[\s\S]*git diff --name-only "\$\{BASE_SHA\}\.\.\.\$\{HEAD_SHA\}" --[\s\S]*'skills\/\*\/\*\*'[\s\S]*':\(exclude\)skills\/clawsec-feed\/advisories\/feed\.json'[\s\S]*':\(exclude\)skills\/clawsec-feed\/advisories\/feed\.json\.sig'[\s\S]*':\(exclude\)skills\/clawsec-suite\/advisories\/feed\.json'[\s\S]*':\(exclude\)skills\/clawsec-suite\/advisories\/feed\.json\.sig'[\s\S]*':\(exclude\)skills\/\*\/test\/\*\*'[\s\S]*':\(exclude\)skills\/\*\/tests\/\*\*'/,
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

for (const artifact of [
  'skill-card.md',
  'permissions.json',
  'install.md',
  'verify_skill_release_bundle.py',
  'skillspector-report.md',
]) {
  assert.match(
    workflow,
    new RegExp(`release-assets/${artifact.replace('.', '\\.')}`),
    `Skill release workflow must publish ${artifact} in release assets`,
  );
}

const escapeRegExp = (literal) => literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

for (const artifact of [
  'skill-card.md',
  'permissions.json',
  'install.md',
  'verify_skill_release_bundle.py',
  'skillspector-report.md',
]) {
  assert.match(
    workflow,
    new RegExp(
      String.raw`if ! add_release_asset_checksum "\$\{out_assets\}" "${escapeRegExp(artifact)}"; then` +
        String.raw`[\s\S]*?failures=\$\(\(failures \+ 1\)\)[\s\S]*?continue[\s\S]*?fi`,
    ),
    `PR dry-run validation must aggregate and continue when ${artifact} cannot be checksummed`,
  );
}

for (const artifact of ['skill.json', 'SKILL.md']) {
  assert.match(
    workflow,
    new RegExp(
      String.raw`cp [\s\S]*? "\$\{out_assets\}/${escapeRegExp(artifact)}"[\s\S]*?` +
        String.raw`if ! add_release_asset_checksum "\$\{out_assets\}" "${escapeRegExp(artifact)}"; then`,
    ),
    `PR dry-run validation must checksum standalone downloadable ${artifact} after copying it to release assets`,
  );
}

assert.match(
  workflow,
  /if \[ -f "\$\{out_assets\}\/README\.md" \] && ! add_release_asset_checksum "\$\{out_assets\}" "README\.md"; then/,
  'PR dry-run validation must checksum standalone downloadable README.md when it is shipped',
);

assert.match(
  workflow,
  /cp "\$SKILL_PATH\/skill\.json" release-assets\/skill\.json[\s\S]*add_release_asset_checksum "skill\.json"[\s\S]*add_release_asset_checksum "SKILL\.md"[\s\S]*add_release_asset_checksum "README\.md"/,
  'Tag release validation must checksum standalone downloadable skill files before signing checksums.json',
);

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
  'verify-first install instructions must be included in the signed checksums manifest',
);

assert.match(
  workflow,
  /add_release_asset_checksum "verify_skill_release_bundle\.py"/,
  'the bounded release verifier must be included in the signed checksums manifest',
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
  'Skill release workflow must download generated SkillSpector reports in a separate PR comment job with issue-comment permissions',
);

const commentJob = workflow.match(/[ ]{2}comment-skillspector-report:[\s\S]*?\n[ ]{2}[a-z][^:\n]*:/)?.[0] || "";
assert.match(
  commentJob,
  /issues: write/,
  'SkillSpector PR comment publishing must request issues write permissions so report comments can be created',
);

assert.doesNotMatch(
  commentJob,
  /pull-requests: write/,
  'SkillSpector PR comment publishing must not broaden the token with pull-requests write permissions',
);

assert.match(
  workflow,
  /comment-skillspector-report:[\s\S]*if: always\(\) && github\.event_name == 'pull_request' && needs\.release\.result != 'cancelled'[\s\S]*Download SkillSpector reports/,
  'SkillSpector PR comments must still run when the release dry-run produced reports but the release job failed later',
);

assert.match(
  workflow,
  /Comment SkillSpector reports[\s\S]*actions\/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9\.0\.0/,
  'SkillSpector PR comment publishing must use the pinned GitHub script action',
);

assert.doesNotMatch(
  commentJob,
  /continue-on-error: true/,
  'SkillSpector PR comment publishing must not hide the whole job behind continue-on-error',
);

assert.match(
  commentJob,
  /status === 403 && message\.includes\("Resource not accessible by integration"\)[\s\S]*core\.warning\([\s\S]*skillspector-pr-reports artifact[\s\S]*throw error/,
  'SkillSpector PR comments must fall back to the uploaded artifact only for GitHub integration permission denials',
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

const simulationJob = workflow.slice(
  requiredIndex(workflow, '  simulate-tag-release-build:', 'PR tag simulation job must exist'),
  requiredIndex(workflow, '  release-tag:', 'Tag release job must exist'),
);
const simulationRunIndex = requiredIndex(
  simulationJob,
  'node scripts/ci/simulate_skill_tag_release.mjs',
  'PR validation must build signed simulation evidence',
);
const simulationInstallabilityIndex = requiredIndex(
  simulationJob,
  "installable=\"$(jq -r '.installable'",
  'PR simulation must read the resolved installability decision from its signed-build summary',
);
const simulationSkipIndex = requiredIndex(
  simulationJob,
  'Non-installable package: signed denial evidence generated; skipping ClawHub package preparation.',
  'PR simulation must skip ClawHub staging for non-installable packages',
);
const simulationClawhubIndex = requiredIndex(
  simulationJob,
  'clawhub_release_package.mjs prepare',
  'PR simulation must retain ClawHub staging for installable packages',
);
assert.ok(
  simulationRunIndex < simulationInstallabilityIndex
    && simulationInstallabilityIndex < simulationSkipIndex
    && simulationSkipIndex < simulationClawhubIndex,
  'PR simulation must first build denial evidence, then branch before ClawHub package preparation',
);
assert.match(
  simulationJob,
  /if \[ "\$installable" = "false" \]; then[\s\S]*continue[\s\S]*test "\$installable" = "true"/,
  'PR simulation must fail closed on invalid summary values and continue past ClawHub staging only for false',
);
assert.match(
  simulationJob,
  /jq -e '\(\.installable \| type\) == "boolean"' "\$summary_path"/,
  'PR simulation must reject a missing or non-boolean installability decision',
);
assert.match(
  simulationJob,
  /jq -e --argjson expected_installable "\$installable"[\s\S]*'\.installable == \$expected_installable'[\s\S]*"\$release_dir\/permissions\.json"/,
  'PR simulation must cross-check its summary decision against the signed denial permissions',
);
assert.match(
  simulationJob,
  /if \[ "\$installable" = "false" \]; then[\s\S]*test ! -e "\$clawhub_output"[\s\S]*continue/,
  'PR simulation must prove it did not prepare a ClawHub package for non-installable evidence',
);

assert.ok(
  workflow.includes('simulated_version | test("^[0-9]+\\\\.[0-9]+\\\\.[0-9]+(-[a-zA-Z0-9]+)?$")'),
  'PR release simulation must continue recognizing legacy candidate versions while public preparation is stable-only',
);

assert.ok(
  releaseSkillScript.includes(`VERSION_ASSIGNMENT_PATTERN='^VERSION="[0-9]+\\.[0-9]+\\.[0-9]+(-[a-zA-Z0-9.]+)?"$'`),
  'release-skill.sh must detect hardcoded release verification VERSION assignments in SKILL.md',
);

assert.ok(
  releaseSkillScript.includes('sed -E "s|$VERSION_ASSIGNMENT_PATTERN|VERSION=\\"$VERSION\\"|g"'),
  'release-skill.sh must update hardcoded release verification VERSION assignments when bumping a skill',
);

const releaseScriptPolicyIndex = requiredIndex(
  releaseSkillScript,
  'node scripts/ci/stable_tag_policy.mjs --tag "$TAG"',
  'release-skill.sh must enforce the shared stable policy before preparation',
);
for (const [needle, description] of [
  ['jq --arg version "$VERSION"', 'version mutation'],
  ['git add -- "$file"', 'staging'],
  ['git commit -m', 'commit creation'],
]) {
  assert.ok(
    releaseScriptPolicyIndex
      < requiredIndex(releaseSkillScript, needle, `release-skill.sh must contain ${description}`),
    `release-skill.sh must enforce final-version policy before ${description}`,
  );
}
assert.match(
  releaseSkillScript,
  /git status --porcelain=v1 --untracked-files=all[\s\S]*jq --arg version "\$VERSION"/,
  'release-skill.sh must reject globally dirty source before version mutation',
);
assert.match(
  releaseSkillScript,
  /restoring the original clean tree[\s\S]*cp -p "\$\{BACKUP_FILES\[\$index\]\}" "\$\{TARGET_FILES\[\$index\]\}"[\s\S]*git add -- "\$\{TARGET_FILES\[@\]\}"[\s\S]*trap cleanup EXIT/,
  'release-skill.sh must restore both worktree files and index state when preparation fails',
);
assert.match(
  releaseSkillScript,
  /PREPARATION_COMPLETED=false[\s\S]*\[ "\$PREPARATION_COMPLETED" != "true" \][\s\S]*trap 'handle_signal 129' HUP[\s\S]*trap 'handle_signal 130' INT[\s\S]*trap 'handle_signal 143' TERM[\s\S]*PREPARATION_COMPLETED=true/,
  'release-skill.sh must roll back incomplete preparation after fatal signals',
);
assert.match(
  releaseSkillScript,
  /if \[ "\$INSTALLABLE" = "false" \]; then[\s\S]*signed denial evidence[\s\S]*Do not request a public tag, GitHub Release, store publication, or catalog activation/,
  'Non-installable prep mode must not print follow-up instructions that authorize publication',
);
for (const forbidden of ['--force-tag', 'git tag', 'gh release create', 'git reset --hard']) {
  assert.equal(
    releaseSkillScript.includes(forbidden),
    false,
    `release-skill.sh must not retain direct release primitive: ${forbidden}`,
  );
}

assert.match(
  workflow,
  /clawhub_slug: \$\{\{ steps\.publishable\.outputs\.clawhub_slug \}\}/,
  'Skill release workflow must expose the resolved ClawHub slug from release-tag outputs',
);

assert.match(
  workflow,
  /installable: \$\{\{ steps\.installability\.outputs\.installable \}\}/,
  'Tag releases must expose the shared installability decision as a job output',
);

assert.equal(
  workflow.match(/skill_installability\.mjs"? "\$SKILL_PATH" --require-publication/g)?.length,
  2,
  'Only public tag release and manual republish entrypoints may require publication eligibility',
);

const releaseTagJob = workflow.slice(
  requiredIndex(workflow, '  release-tag:', 'Tag release job must exist'),
  requiredIndex(workflow, '  publish-clawhub:', 'Automatic ClawHub job must exist'),
);
const tagGateIndex = requiredIndex(
  releaseTagJob,
  '- name: Reject non-installable public release',
  'Tag release must reject non-installable packages',
);
for (const [needle, description] of [
  ['- name: Install SkillSpector', 'SkillSpector installation'],
  ['- name: Sign embedded advisory feed and verify', 'embedded advisory signing'],
  ['- name: Build quick install instructions', 'install-command generation'],
  ['- name: Create GitHub Release', 'GitHub release creation'],
]) {
  assert.ok(
    tagGateIndex < requiredIndex(releaseTagJob, needle, `Tag release must contain ${description}`),
    `Tag release installability denial must happen before ${description}`,
  );
}
assert.match(
  releaseTagJob,
  /node scripts\/ci\/skill_installability\.mjs "\$SKILL_PATH" --require-publication/,
  'Tag release must enforce the shared installability contract',
);

const republishJob = workflow.slice(
  requiredIndex(workflow, '  republish-clawhub:', 'Manual ClawHub republish job must exist'),
);
const republishCheckoutIndex = requiredIndex(
  republishJob,
  '- name: Checkout tag',
  'Manual republish must inspect the selected immutable tag',
);
const republishGateIndex = requiredIndex(
  republishJob,
  '- name: Reject non-installable public republish',
  'Manual republish must reject non-installable packages',
);
assert.ok(
  republishCheckoutIndex < republishGateIndex,
  'Manual republish must evaluate installability from the selected tag metadata',
);
for (const [needle, description] of [
  ['- name: Prepare verified ClawHub release package', 'release asset download and package preparation'],
  ['- name: Login to ClawHub', 'ClawHub authentication'],
  ['- name: Publish to ClawHub', 'ClawHub publication'],
]) {
  assert.ok(
    republishGateIndex < requiredIndex(republishJob, needle, `Manual republish must contain ${description}`),
    `Manual republish installability denial must happen before ${description}`,
  );
}
assert.match(
  republishJob,
  /node "\$RUNNER_TEMP\/skill_installability\.mjs" "\$SKILL_PATH" --require-publication/,
  'Manual republish must enforce the preserved current installability contract against selected tag metadata',
);

assert.match(
  workflow,
  /CLAWHUB_SLUG=\$\(node scripts\/ci\/resolve_clawhub_slug\.mjs "\$SKILL_PATH"\)/,
  'Skill release workflow must resolve the ClawHub slug from the skill package path',
);

assert.match(
  workflow,
  /cp scripts\/ci\/resolve_clawhub_slug\.mjs "\$RUNNER_TEMP\/resolve_clawhub_slug\.mjs"[\s\S]*cp scripts\/ci\/skill_platforms\.mjs "\$RUNNER_TEMP\/skill_platforms\.mjs"[\s\S]*cp scripts\/ci\/clawhub_release_package\.mjs "\$RUNNER_TEMP\/clawhub_release_package\.mjs"/,
  'Manual ClawHub republish must preserve current slug and signed-package helpers before checking out an older release tag',
);

assert.match(
  workflow,
  /cp scripts\/ci\/clawhub_release_package\.mjs "\$RUNNER_TEMP\/clawhub_release_package\.mjs"[\s\S]*cp scripts\/ci\/release_path_policy\.mjs "\$RUNNER_TEMP\/release_path_policy\.mjs"/,
  'Manual ClawHub republish must preserve signed-package helper dependencies before checking out an older release tag',
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
  /id: clawhub-version[\s\S]*already_exists=true[\s\S]*skipping upload and verifying exact registry contents/,
  'Automatic ClawHub retries must verify an existing version instead of failing before package parity checks',
);

assert.match(
  workflow,
  /Publish to ClawHub[\s\S]*steps\.clawhub-version\.outputs\.already_exists != 'true'/,
  'Automatic ClawHub retries must skip only the duplicate upload while retaining post-publish verification',
);

assert.match(
  workflow,
  /--slug "\$CLAWHUB_SLUG"/,
  'ClawHub publish must use the resolved ClawHub slug',
);

assert.match(
  workflow,
  /clawhub publish "\$SKILL_PATH"[\s\S]*--slug "\$CLAWHUB_SLUG"/,
  'ClawHub publish must use the resolved ClawHub slug',
);

assert.equal(
  workflow.match(/gh release download "\$TAG"/g)?.length,
  2,
  'Automatic and manual ClawHub publication must download the GitHub release payload',
);

assert.equal(
  workflow.match(/--pattern "checksums\.sig"/g)?.length,
  2,
  'Automatic and manual ClawHub publication must download the signed release manifest companions',
);

assert.equal(
  workflow.match(/clawhub_release_package\.mjs"? prepare/g)?.length,
  3,
  'PR simulation, automatic publication, and manual publication must prepare a verified package from the signed release archive',
);

assert.equal(
  workflow.match(/clawhub_release_package\.mjs"? verify-registry/g)?.length,
  2,
  'Automatic and manual ClawHub publication must share registry retry and hash verification',
);

assert.doesNotMatch(
  workflow,
  /for attempt in 1 2 3 4 5 6/,
  'ClawHub registry retry logic must remain centralized in the release package helper',
);

assert.equal(
  workflow.match(/SKILL_PATH="\$\{\{ steps\.clawhub-package\.outputs\.skill_path \}\}"/g)?.length,
  4,
  'ClawHub publish, republish, and their verification steps must use the verified release package path',
);

assert.doesNotMatch(
  workflow,
  /publish-clawhub:[\s\S]*?continue-on-error:\s*true/,
  'ClawHub package verification must be a blocking release gate',
);

assert.match(
  workflow,
  /Require ClawHub token[\s\S]*::error::CLAWHUB_TOKEN secret is not set/,
  'Publishable tagged skills must fail when the ClawHub token is unavailable',
);

assert.equal(
  workflow.match(/grep -Eqi "version \.\*already exists"/g)?.length,
  2,
  'Duplicate publish retries must recognize version-specific already-exists responses before post-publish verification',
);

assert.equal(
  workflow.match(/bash scripts\/ci\/install_clawhub_cli\.sh/g)?.length,
  3,
  'ClawHub simulation, publish, and republish jobs must share the same pinned CLI installer',
);

assert.equal(
  workflow.match(/node scripts\/ci\/patch_clawhub_publish_payload\.mjs/g)?.length,
  2,
  'ClawHub publish and republish jobs must share the same payload patch helper',
);

assert.equal(
  workflow.match(/run: node (?:scripts\/ci\/|"\$RUNNER_TEMP\/)?patch_clawhub_trust_extensions\.mjs"?/g)?.length,
  3,
  'ClawHub simulation, automatic publishing, and manual publishing must apply the trust-extension patch',
);

assert.match(
  workflow,
  /cp scripts\/ci\/patch_clawhub_trust_extensions\.mjs "\$RUNNER_TEMP\/patch_clawhub_trust_extensions\.mjs"/,
  'Manual ClawHub republish must preserve the current trust-extension patch across tag checkout',
);

assert.match(
  workflow,
  /Legacy unsigned releases cannot be safely republished; create a new patch release/,
  'Manual ClawHub republish must fail clearly when a legacy release lacks signed verification assets',
);

assert.match(
  workflow,
  /simulate-tag-release-build:[\s\S]*clawhub_release_package\.mjs prepare[\s\S]*clawhub_release_package\.mjs verify-client-selection/,
  'PR tag simulation must verify signed release staging through the patched pinned ClawHub client',
);

assert.equal(
  workflow.match(/bash scripts\/ci\/guard_clawhub_slug_owner\.sh/g)?.length,
  2,
  'ClawHub publish and republish jobs must guard mapped slug ownership before publishing',
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

assert.match(
  installClawhubCli,
  /npm ci --prefix "\$CLI_PREFIX"/,
  'ClawHub CLI installer must install from the committed lockfile prefix',
);

assert.doesNotMatch(
  installClawhubCli,
  /aws codeartifact login|AWS credentials are required/,
  'ClawHub CLI installer must not require AWS secrets that are not configured for release workflows',
);

const clawhubLockResolvedUrls = Object.values(clawhubLock.packages ?? {})
  .map((entry) => entry.resolved)
  .filter(Boolean);
assert.ok(clawhubLockResolvedUrls.length > 0, 'ClawHub CLI lockfile must contain resolved tarball URLs');
assert.ok(
  clawhubLockResolvedUrls.every((url) => url.startsWith('https://registry.npmjs.org/')),
  'ClawHub CLI lockfile must use public npm tarballs because release workflows do not have AWS CodeArtifact secrets',
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

assert.match(
  patchClawhubPayload,
  /Already patched/,
  'ClawHub payload patch helper must stay idempotent when the pinned CLI already includes acceptLicenseTerms',
);

for (const extension of ['pem', 'sig']) {
  assert.ok(
    patchClawhubTrustExtensions.includes(`"${extension}"`),
    `ClawHub trust-extension patch must preserve .${extension} release artifacts`,
  );
}

assert.match(
  patchClawhubTrustExtensions,
  /REQUIRED_TRUST_CONTENT_TYPE = "text\/plain"/,
  'ClawHub trust-extension patch must send ASCII trust artifacts with a server-accepted text MIME type',
);

assert.match(
  patchClawhubTrustExtensions,
  /Already patched/,
  'ClawHub trust-extension patch must be idempotent when the client already accepts trust artifacts',
);

assert.match(
  guardClawhubSlugOwner,
  /api_get "\/api\/v1\/whoami" "\$whoami_json"/,
  'ClawHub slug ownership guard must verify the authenticated publisher through the ClawHub API',
);

assert.match(
  guardClawhubSlugOwner,
  /api_get "\/api\/v1\/skills\/\$\{TARGET_SLUG\}" "\$target_json"/,
  'ClawHub slug ownership guard must inspect the resolved publish slug through the ClawHub API',
);

assert.match(
  guardClawhubSlugOwner,
  /\[ "\$target_status" = "404" \]/,
  'ClawHub slug ownership guard must treat HTTP 404 as the structured unpublished-slug signal',
);

assert.match(
  guardClawhubSlugOwner,
  /\[ "\$target_owner" != "\$publisher_handle" \]/,
  'ClawHub slug ownership guard must reject slugs owned by a different authenticated registry publisher',
);

assert.doesNotMatch(
  guardClawhubSlugOwner,
  /SOURCE_SLUG|source_owner|grep -Eqi[\s\S]*Skill not found/,
  'ClawHub slug ownership guard must not inspect raw source names or depend on stderr wording',
);

assert.match(
  workflow,
  /SITE=\$\{CLAWHUB_SITE:-https:\/\/clawhub\.ai\}[\s\S]*REGISTRY=\$\{CLAWHUB_REGISTRY:-\$SITE\}[\s\S]*export CLAWHUB_CONFIG_PATH="\$HOME\/\.clawhub-ci\/config\.json"[\s\S]*export CLAWHUB_SITE="\$SITE"[\s\S]*export CLAWHUB_REGISTRY="\$REGISTRY"[\s\S]*bash scripts\/ci\/guard_clawhub_slug_owner\.sh[\s\S]*\$\{\{ needs\.release-tag\.outputs\.clawhub_slug \}\}/,
  'ClawHub publish job must guard the resolved publish slug with the authenticated ClawHub config path',
);

assert.match(
  workflow,
  /SITE=\$\{CLAWHUB_SITE:-https:\/\/clawhub\.ai\}[\s\S]*REGISTRY=\$\{CLAWHUB_REGISTRY:-\$SITE\}[\s\S]*export CLAWHUB_CONFIG_PATH="\$HOME\/\.clawhub-ci\/config\.json"[\s\S]*export CLAWHUB_SITE="\$SITE"[\s\S]*export CLAWHUB_REGISTRY="\$REGISTRY"[\s\S]*bash scripts\/ci\/guard_clawhub_slug_owner\.sh[\s\S]*\$\{\{ steps\.publishable\.outputs\.clawhub_slug \}\}/,
  'ClawHub republish job must guard the resolved publish slug with the authenticated ClawHub config path',
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
