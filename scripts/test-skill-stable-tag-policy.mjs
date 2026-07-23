#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  LEGACY_PRERELEASE_INVENTORY_SHA256,
  evaluateStableTagPolicy,
  loadLegacyPrereleaseInventory,
  validateLegacyPrereleaseInventory,
} from "./ci/stable_tag_policy.mjs";

const helperPath = fileURLToPath(new URL("./ci/stable_tag_policy.mjs", import.meta.url));
const workflowPath = fileURLToPath(
  new URL("../.github/workflows/controlled-skill-release.yml", import.meta.url),
);
const releaseScriptPath = fileURLToPath(new URL("./release-skill.sh", import.meta.url));
const inventoryPath = fileURLToPath(
  new URL("../contracts/release-policy/legacy-prereleases-v1.json", import.meta.url),
);
const lifecyclePath = fileURLToPath(new URL("./ci/lifecycle_semver.mjs", import.meta.url));
const installabilityPath = fileURLToPath(
  new URL("./ci/skill_installability.mjs", import.meta.url),
);

function requiredIndex(text, needle, message) {
  const index = text.indexOf(needle);
  assert.notEqual(index, -1, message);
  return index;
}

function runHelper(...args) {
  return spawnSync(process.execPath, [helperPath, ...args], {
    encoding: "utf8",
  });
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

const {
  inventory,
  historicalTags,
  digest: inventoryDigest,
} = await loadLegacyPrereleaseInventory();
assert.equal(inventoryDigest, LEGACY_PRERELEASE_INVENTORY_SHA256);
assert.equal(historicalTags.size, 15);

for (const tag of historicalTags) {
  const decision = evaluateStableTagPolicy({ tag, historicalTags });
  assert.equal(decision.publication_eligible, false, `${tag} must remain denied`);
  assert.equal(decision.stable_authorized, false);
  assert.equal(decision.historical_fetch_only, true);
  assert.equal(decision.reason_code, "frozen_legacy_history_non_authorized");
}

for (const [tag, packageName, version] of [
  ["clawsec-suite-v0.1.0", "clawsec-suite", "0.1.0"],
  ["clawsec-suite-v0.0.0", "clawsec-suite", "0.0.0"],
  ["agent-v-tools-v1.2.3", "agent-v-tools", "1.2.3"],
  [
    "clawsec-core-openclaw-v18446744073709551616.99999999999999999999.0",
    "clawsec-core-openclaw",
    "18446744073709551616.99999999999999999999.0",
  ],
]) {
  const decision = evaluateStableTagPolicy({ tag, historicalTags });
  assert.equal(decision.publication_eligible, true, `${tag} should pass the temporary gate`);
  assert.equal(decision.stable_authorized, false, "final SemVer is not stable authorization");
  assert.equal(decision.reason_code, "final_version_eligible_not_authorized");
  assert.equal(decision.package_name, packageName);
  assert.equal(decision.version, version);
  assert.equal(decision.tag, tag);
}

const deniedValidTags = new Map([
  ["clawsec-suite-v0.2.0-beta.1", "candidate_prerelease_lab_only"],
  ["clawsec-suite-v0.2.0-rc.1", "candidate_prerelease_lab_only"],
  ["clawsec-suite-v0.2.0-beta1", "legacy_prerelease_non_authorized"],
  ["clawsec-suite-v0.2.0-rc1", "legacy_prerelease_non_authorized"],
  ["clawsec-suite-v0.2.0-alpha.1", "legacy_prerelease_non_authorized"],
  ["clawsec-suite-v0.2.0-preview", "legacy_prerelease_non_authorized"],
  ["clawsec-suite-v0.2.0-canary.7", "legacy_prerelease_non_authorized"],
  ["clawsec-suite-v0.2.0-nightly.20260723", "legacy_prerelease_non_authorized"],
  ["clawsec-suite-v0.2.0-dev", "legacy_prerelease_non_authorized"],
  ["clawsec-suite-v0.2.0-beta-1", "legacy_prerelease_non_authorized"],
  ["clawsec-suite-v0.2.0-beta.1.extra", "legacy_prerelease_non_authorized"],
  ["clawsec-suite-v0.2.0-1", "legacy_prerelease_non_authorized"],
  ["clawsec-suite-v0.2.0+build.1", "build_metadata_disallowed"],
  ["clawsec-suite-v0.2.0-beta.1+build.1", "build_metadata_disallowed"],
]);

for (const [tag, reasonCode] of deniedValidTags) {
  const decision = evaluateStableTagPolicy({ tag, historicalTags });
  assert.equal(decision.publication_eligible, false, `${tag} must be denied`);
  assert.equal(decision.stable_authorized, false);
  assert.equal(decision.reason_code, reasonCode);
}

for (const tag of [
  "",
  "v1.2.3",
  "clawsec-suite-1.2.3",
  "clawsec-suite-v1.2",
  "clawsec-suite-v01.2.3",
  "ClawSec-suite-v1.2.3",
  "clawsec_suite-v1.2.3",
  "clawsec-suite-V1.2.3",
  "clawsec-suite-v1.2.3-beta.01",
  " clawsec-suite-v1.2.3",
  "clawsec-suite-v1.2.3 ",
  "clawsec-suite-v1.2.3\noutput=true",
  "clawsec-suite-v1.2.3\t",
  "clawsec-suite-v1.2.3\u00a0",
  "clawsec-suite-v1.2.3\u200b",
  "clawsec-suite-ｖ1.2.3",
  "clawsec-suite-v１.２.３",
  "clawsec-suite-v1.2.3;echo-owned",
  "clawsec-suite-v1.2.3$(touch-owned)",
  'clawsec-suite-v1.2.3"',
]) {
  const decision = evaluateStableTagPolicy({ tag, historicalTags });
  assert.equal(decision.publication_eligible, false, `malformed tag must fail: ${JSON.stringify(tag)}`);
  assert.equal(decision.reason_code, "invalid_package_tag");
  assert.equal(decision.tag, null, "invalid input must not be reflected into workflow outputs");
}

const requiredFalseFields = [
  "authorization_granted",
  "public_write_authorized",
  "tag_creation_permitted",
  "github_release_creation_permitted",
  "store_publication_permitted",
  "catalog_activation_permitted",
  "active_resolution",
  "discovery_publication_permitted",
  "republish_permitted",
  "ref_or_asset_mutation_permitted",
];
for (const field of requiredFalseFields) {
  for (const unsafeValue of [true, "false", 0, null]) {
    const changed = cloneJson(inventory);
    changed.policy[field] = unsafeValue;
    assert.throws(
      () => validateLegacyPrereleaseInventory(changed),
      new RegExp(`${field} must be exactly false`),
    );
  }
}

for (const [field, unsafeValue] of [
  ["historical_fetch_only", false],
  ["classification", "authorized_history"],
  ["retention", "republishable"],
]) {
  const changed = cloneJson(inventory);
  changed.policy[field] = unsafeValue;
  assert.throws(() => validateLegacyPrereleaseInventory(changed));
}

const duplicateInventory = cloneJson(inventory);
duplicateInventory.tags.push(cloneJson(duplicateInventory.tags[0]));
duplicateInventory.counts.tags += 1;
assert.throws(
  () => validateLegacyPrereleaseInventory(duplicateInventory),
  /duplicate tag name/,
);

const finalVersionInventory = cloneJson(inventory);
finalVersionInventory.tags[0].name = "clawsec-suite-v9.9.9";
assert.throws(
  () => validateLegacyPrereleaseInventory(finalVersionInventory),
  /must not contain a publication-eligible tag/,
);

const allowedCli = runHelper("--tag", "agent-v-tools-v1.2.3");
assert.equal(allowedCli.status, 0, allowedCli.stderr);
assert.equal(JSON.parse(allowedCli.stdout).publication_eligible, true);

const deniedCli = runHelper(
  "--tag",
  "hermes-traffic-guardian-v0.0.1-beta5",
);
assert.equal(deniedCli.status, 2);
assert.equal(JSON.parse(deniedCli.stdout).historical_fetch_only, true);
assert.match(deniedCli.stderr, /frozen_legacy_history_non_authorized/);

const injectionCli = runHelper("--tag", "clawsec-suite-v1.2.3\noutput=true");
assert.equal(injectionCli.status, 2);
assert.equal(JSON.parse(injectionCli.stdout).tag, null);
assert.doesNotMatch(injectionCli.stderr, /output=true/);

const badArgsCli = runHelper("--unknown", "value");
assert.equal(badArgsCli.status, 1);
assert.match(badArgsCli.stderr, /usage:/);

const tamperedDir = await mkdtemp(path.join(tmpdir(), "clawsec-stable-tag-tampered-"));
try {
  const tamperedPath = path.join(tamperedDir, "inventory.json");
  await writeFile(
    tamperedPath,
    `${(await readFile(inventoryPath, "utf8")).trimEnd()} \n`,
    "utf8",
  );
  await assert.rejects(
    () => loadLegacyPrereleaseInventory(tamperedPath),
    /snapshot digest does not match/,
  );
  const tamperedCli = runHelper(
    "--tag",
    "clawsec-suite-v1.2.3",
    "--inventory",
    tamperedPath,
  );
  assert.equal(tamperedCli.status, 1);
  assert.match(tamperedCli.stderr, /snapshot digest does not match/);
} finally {
  await rm(tamperedDir, { recursive: true, force: true });
}

const workflow = await readFile(workflowPath, "utf8");
const releaseScript = await readFile(releaseScriptPath, "utf8");
const policyJobStart = requiredIndex(
  workflow,
  "  stable-publication-policy:",
  "workflow must define a read-only stable publication policy job",
);
const releaseJobStart = requiredIndex(workflow, "  release-tag:", "release-tag job must exist");
const publishJobStart = requiredIndex(
  workflow,
  "  publish-clawhub:",
  "publish-clawhub job must exist",
);
const republishJobStart = requiredIndex(
  workflow,
  "  republish-clawhub:",
  "republish-clawhub job must exist",
);
assert.ok(policyJobStart < releaseJobStart);
assert.ok(releaseJobStart < publishJobStart);
assert.ok(publishJobStart < republishJobStart);

const policyJob = workflow.slice(policyJobStart, releaseJobStart);
const releaseJob = workflow.slice(releaseJobStart, publishJobStart);
const publishJob = workflow.slice(publishJobStart, republishJobStart);
const republishJob = workflow.slice(republishJobStart);

assert.match(policyJob, /permissions:\n\s+contents: read/);
assert.doesNotMatch(policyJob, /contents: write|pages: write|id-token: write|secrets\.|CLAWHUB_TOKEN/);
assert.match(policyJob, /ref: \$\{\{ github\.event\.repository\.default_branch \}\}/);
assert.match(policyJob, /fetch-depth: 0[\s\S]*persist-credentials: false/);
assert.match(policyJob, /REQUESTED_TAG: \$\{\{ inputs\.tag \}\}/);
assert.match(policyJob, /stable_tag_policy\.mjs --tag "\$REQUESTED_TAG"/);
assert.match(policyJob, /git show-ref --verify --quiet "refs\/tags\/\$\{validated_tag\}"/);
assert.match(policyJob, /"\$REQUESTED_REF" = "refs\/heads\/\$DEFAULT_BRANCH"/);
assert.match(policyJob, /controlled_tag_creation\.mjs verify-release/);

assert.match(releaseJob, /needs: stable-publication-policy/);
assert.match(releaseJob, /permissions:\n\s+contents: write/);
assert.match(releaseJob, /VALIDATED_TAG: \$\{\{ needs\.stable-publication-policy\.outputs\.tag \}\}/);
assert.doesNotMatch(releaseJob, /github\.ref_name|github\.event\.inputs\.tag/);
assert.match(
  releaseJob,
  /ref: \$\{\{ needs\.stable-publication-policy\.outputs\.peeled_commit_oid \}\}/,
);
assert.match(releaseJob, /inputs\.operation == 'controlled_release'/);
assert.match(releaseJob, /tag_name: \$\{\{ needs\.stable-publication-policy\.outputs\.tag \}\}/);
assert.match(releaseJob, /prerelease: false/);

assert.match(publishJob, /needs: \[stable-publication-policy, release-tag\]/);
assert.match(publishJob, /needs\.stable-publication-policy\.outputs\.publication_eligible == 'true'/);
assert.match(publishJob, /CLAWHUB_TOKEN: \$\{\{ secrets\.CLAWHUB_TOKEN \}\}/);
assert.match(
  publishJob,
  /ref: \$\{\{ needs\.stable-publication-policy\.outputs\.peeled_commit_oid \}\}/,
);
assert.match(publishJob, /inputs\.operation == 'controlled_release'/);

assert.match(republishJob, /needs: stable-publication-policy/);
assert.match(republishJob, /needs\.stable-publication-policy\.outputs\.publication_eligible == 'true'/);
assert.match(republishJob, /inputs\.operation == 'republish_clawhub'/);
assert.match(republishJob, /VALIDATED_TAG: \$\{\{ needs\.stable-publication-policy\.outputs\.tag \}\}/);
assert.doesNotMatch(republishJob, /github\.event\.inputs\.tag|github\.ref_name/);
assert.match(
  republishJob,
  /Checkout workflow helpers[\s\S]*ref: \$\{\{ github\.event\.repository\.default_branch \}\}[\s\S]*persist-credentials: false/,
);
assert.match(
  republishJob,
  /Checkout tag[\s\S]*ref: refs\/tags\/\$\{\{ needs\.stable-publication-policy\.outputs\.tag \}\}[\s\S]*persist-credentials: false/,
);
assert.match(republishJob, /CLAWHUB_TOKEN: \$\{\{ secrets\.CLAWHUB_TOKEN \}\}/);

assert.doesNotMatch(
  workflow,
  /TAG="\$\{\{ (?:github\.ref_name|github\.event\.inputs\.tag) \}\}"/,
  "raw event tag strings must never be interpolated into shell source",
);

const scriptPolicyIndex = requiredIndex(
  releaseScript,
  'node scripts/ci/stable_tag_policy.mjs --tag "$TAG"',
  "release-skill.sh must call the shared stable tag policy",
);
for (const [needle, operation] of [
  ['TEMP_DIR="$(mktemp -d)"', "temporary mutation staging"],
  ['jq --arg version "$VERSION"', "skill metadata write"],
  ['git add -- "$file"', "Git staging"],
  ['git commit -m "chore($SKILL_NAME): bump version to $VERSION"', "Git commit"],
]) {
  assert.ok(
    scriptPolicyIndex < requiredIndex(releaseScript, needle, `${operation} must remain present`),
    `stable tag policy must run before ${operation}`,
  );
}
for (const forbidden of ["--force-tag", "git tag", "gh release create", "git reset --hard"]) {
  assert.equal(
    releaseScript.includes(forbidden),
    false,
    `version-preparation helper must not contain ${forbidden}`,
  );
}
assert.doesNotMatch(
  releaseScript,
  /Validate semver format \(supports prerelease|Invalid version format\. Use semver|if ! \[\[ "\$VERSION" =~/,
  "release-skill.sh must not retain a second prerelease parser",
);

const fixtureRoot = await mkdtemp(path.join(tmpdir(), "clawsec-stable-tag-release-script-"));
const fixtureSkillDir = path.join(fixtureRoot, "skills", "stable-skill");
const fixtureCiDir = path.join(fixtureRoot, "scripts", "ci");
const fixturePolicyDir = path.join(fixtureRoot, "contracts", "release-policy");
const fakeBinDir = path.join(fixtureRoot, "fake-bin");
const ghAttemptPath = path.join(fixtureRoot, "gh-attempted");
const childPath = `${fakeBinDir}:${path.dirname(process.execPath)}:${process.env.PATH ?? ""}`;

function runFixture(command, args) {
  return spawnSync(command, args, {
    cwd: fixtureRoot,
    encoding: "utf8",
    env: { ...process.env, PATH: childPath },
  });
}

function runFixtureGit(...args) {
  const result = runFixture("git", args);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

try {
  await Promise.all([
    mkdir(fixtureSkillDir, { recursive: true }),
    mkdir(fixtureCiDir, { recursive: true }),
    mkdir(fixturePolicyDir, { recursive: true }),
    mkdir(fakeBinDir, { recursive: true }),
  ]);
  await Promise.all([
    cp(releaseScriptPath, path.join(fixtureRoot, "scripts", "release-skill.sh")),
    cp(helperPath, path.join(fixtureCiDir, "stable_tag_policy.mjs")),
    cp(lifecyclePath, path.join(fixtureCiDir, "lifecycle_semver.mjs")),
    cp(installabilityPath, path.join(fixtureCiDir, "skill_installability.mjs")),
    cp(inventoryPath, path.join(fixturePolicyDir, "legacy-prereleases-v1.json")),
    writeFile(
      path.join(fixtureSkillDir, "skill.json"),
      `${JSON.stringify({ name: "stable-skill", version: "0.1.0", installable: true }, null, 2)}\n`,
    ),
    writeFile(
      path.join(fixtureSkillDir, "SKILL.md"),
      "---\nname: stable-skill\nversion: 0.1.0\n---\n\n# Stable skill\n",
    ),
    writeFile(
      path.join(fakeBinDir, "gh"),
      `#!/bin/sh\nprintf attempted > "${ghAttemptPath}"\nexit 0\n`,
    ),
  ]);
  await chmod(path.join(fakeBinDir, "gh"), 0o700);

  runFixtureGit("init", "--initial-branch=main");
  runFixtureGit("config", "user.name", "ClawSec Test");
  runFixtureGit("config", "user.email", "clawsec-test@example.invalid");
  runFixtureGit("config", "commit.gpgsign", "false");
  runFixtureGit("config", "tag.gpgsign", "false");
  runFixtureGit("add", ".");
  runFixtureGit("commit", "-m", "stable policy fixture");

  const initialHead = runFixtureGit("rev-parse", "HEAD");
  for (const version of [
    "0.2.0-beta1",
    "0.2.0-beta.1",
    "0.2.0-rc1",
    "0.2.0-rc.1",
    "0.2.0-alpha.1",
    "0.2.0-preview",
    "0.2.0+build.1",
    "0.2.0\noutput=true",
  ]) {
    const result = runFixture("bash", ["scripts/release-skill.sh", "stable-skill", version]);
    assert.equal(result.status, 1, `${version} unexpectedly passed\n${result.stdout}\n${result.stderr}`);
    assert.equal(runFixtureGit("rev-parse", "HEAD"), initialHead);
    assert.equal(runFixtureGit("status", "--short"), "");
    assert.equal(runFixtureGit("tag", "--list"), "");
    assert.equal(existsSync(ghAttemptPath), false);
  }

  runFixtureGit("switch", "-c", "review/candidate");
  for (const args of [
    ["stable-skill", "0.2.0-beta.2"],
    ["stable-skill", "0.2.0-rc.2", "--force-tag"],
  ]) {
    const result = runFixture("bash", ["scripts/release-skill.sh", ...args]);
    assert.equal(result.status, 1, `feature-branch candidate unexpectedly passed: ${args.join(" ")}`);
    assert.equal(runFixtureGit("rev-parse", "HEAD"), initialHead);
    assert.equal(runFixtureGit("status", "--short"), "");
    assert.equal(runFixtureGit("tag", "--list"), "");
    assert.equal(existsSync(ghAttemptPath), false);
  }
} finally {
  await rm(fixtureRoot, { recursive: true, force: true });
}

process.stdout.write(
  "Stable tag policy tests passed: final versions eligible-not-authorized; prereleases fail closed.\n",
);
