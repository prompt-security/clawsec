#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  CONTROLLED_RELEASE_WORKFLOW,
  GitHubApiError,
  createControlledTagPlan,
  createOrResumeControlledTag,
  dispatchControlledRelease,
  preflightControlledTag,
  validateSourceCheckout,
  validateTagRuleset,
  verifyControlledReleaseTuple,
} from "./ci/controlled_tag_creation.mjs";
import { loadLegacyPrereleaseInventory } from "./ci/stable_tag_policy.mjs";

const repository = "prompt-security/clawsec";
const defaultBranch = "main";
const sourceCommit = "a".repeat(40);
const advancedCommit = "b".repeat(40);
const createdObjectOid = "c".repeat(40);
const racedObjectOid = "d".repeat(40);
const releaseAttemptId = "123456:789012";
const rulesetId = 24680;
const appId = 13579;
const rulesetUpdatedAt = "2026-07-23T12:34:56Z";
const { historicalTags } = await loadLegacyPrereleaseInventory();

function plan(overrides = {}) {
  return createControlledTagPlan({
    repository,
    packageName: "clawsec-suite",
    version: "0.2.0",
    sourceCommit,
    releaseAttemptId,
    rulesetId,
    rulesetUpdatedAt,
    appId,
    historicalTags,
    ...overrides,
  });
}

function ruleset(overrides = {}) {
  return {
    id: rulesetId,
    source_type: "Repository",
    source: repository,
    updated_at: rulesetUpdatedAt,
    target: "tag",
    enforcement: "active",
    conditions: {
      ref_name: {
        include: ["refs/tags/*-v*"],
        exclude: [],
      },
    },
    rules: [
      { type: "creation" },
      { type: "update" },
      { type: "deletion" },
      { type: "non_fast_forward" },
    ],
    bypass_actors: [
      { actor_type: "Integration", actor_id: appId, bypass_mode: "always" },
    ],
    ...overrides,
  };
}

function refResponse(releasePlan, tagObjectOid = createdObjectOid) {
  return {
    ref: `refs/tags/${releasePlan.tag}`,
    object: { type: "tag", sha: tagObjectOid },
  };
}

function tagResponse(releasePlan, tagObjectOid = createdObjectOid) {
  return {
    sha: tagObjectOid,
    tag: releasePlan.tag,
    message: releasePlan.tag_message,
    object: { type: "commit", sha: releasePlan.protected_main_commit },
  };
}

class FakeClient {
  constructor(role, handler) {
    this.role = role;
    this.handler = handler;
    this.calls = [];
  }

  async request(apiPath, options = {}) {
    const call = {
      role: this.role,
      path: apiPath,
      method: options.method ?? "GET",
      body: options.body,
      expected: options.expected ?? [200],
    };
    this.calls.push(call);
    return this.handler(call, this.calls.length - 1);
  }
}

function writeCalls(client) {
  return client.calls.filter(({ method }) => method !== "GET");
}

function missingTag() {
  throw new GitHubApiError("missing", { status: 404 });
}

const validPlan = plan();
assert.equal(validPlan.tag, "clawsec-suite-v0.2.0");
assert.equal(validPlan.repository, repository);
assert.match(validPlan.tag_message_sha256, /^[0-9a-f]{64}$/);
assert.deepEqual(JSON.parse(validPlan.tag_message), {
  schema: "clawsec.controlled-tag/v1",
  repository,
  package_name: "clawsec-suite",
  version: "0.2.0",
  tag: "clawsec-suite-v0.2.0",
  protected_main_commit: sourceCommit,
  release_attempt_id: releaseAttemptId,
  tag_ruleset_id: rulesetId,
  tag_ruleset_updated_at: rulesetUpdatedAt,
  release_app_id: appId,
});

for (const version of [
  "0.2.0-beta.1",
  "0.2.0-rc.1",
  "0.2.0-beta1",
  "0.2.0+build.1",
  "0.2.0\noutput=true",
  "01.2.3",
]) {
  assert.throws(
    () => plan({ version }),
    /stable tag policy denied/,
    `public controller must reject ${JSON.stringify(version)}`,
  );
}
for (const [field, value] of [
  ["packageName", "../clawsec-suite"],
  ["packageName", "ClawSec-suite"],
  ["sourceCommit", "A".repeat(40)],
  ["sourceCommit", "a".repeat(39)],
  ["releaseAttemptId", "123456:0"],
  ["releaseAttemptId", "not-an-attempt"],
  ["rulesetUpdatedAt", "not-a-timestamp"],
  ["repository", "prompt-security/clawsec/extra"],
]) {
  assert.throws(() => plan({ [field]: value }));
}

const rulesetExpectation = {
  ruleset_id: rulesetId,
  ruleset_updated_at: rulesetUpdatedAt,
  app_id: appId,
  active: true,
  bypass_actor_visibility: "api_verified",
};
assert.deepEqual(
  validateTagRuleset(ruleset(), { repository, rulesetId, rulesetUpdatedAt, appId }),
  rulesetExpectation,
);
const redactedRuleset = ruleset();
delete redactedRuleset.bypass_actors;
assert.deepEqual(
  validateTagRuleset(redactedRuleset, { repository, rulesetId, rulesetUpdatedAt, appId }),
  { ...rulesetExpectation, bypass_actor_visibility: "redacted_operator_proof_required" },
);
for (const unsafeRuleset of [
  ruleset({ enforcement: "evaluate" }),
  ruleset({ target: "branch" }),
  ruleset({ source: "prompt-security/other" }),
  ruleset({ updated_at: "2026-07-23T12:34:57Z" }),
  ruleset({ conditions: { ref_name: { include: ["refs/tags/special"], exclude: [] } } }),
  ruleset({ conditions: { ref_name: { include: ["~ALL"], exclude: ["refs/tags/a-v1.0.0"] } } }),
  ruleset({ rules: [{ type: "creation" }, { type: "update" }, { type: "deletion" }] }),
  ruleset({ bypass_actors: [] }),
  ruleset({ bypass_actors: [
    { actor_type: "Integration", actor_id: appId, bypass_mode: "always" },
    { actor_type: "RepositoryRole", actor_id: 5, bypass_mode: "always" },
  ] }),
  ruleset({ bypass_actors: [
    { actor_type: "Integration", actor_id: appId + 1, bypass_mode: "always" },
  ] }),
]) {
  assert.throws(() => validateTagRuleset(
    unsafeRuleset,
    { repository, rulesetId, rulesetUpdatedAt, appId },
  ));
}

const sourceFixtureRoots = [];
async function makeSourceFixture(dirtyMode = "clean") {
  const root = await mkdtemp(path.join(tmpdir(), "clawsec-controlled-source-"));
  sourceFixtureRoots.push(root);
  const skillDir = path.join(root, "skills", "clawsec-suite");
  await mkdir(skillDir, { recursive: true });
  await writeFile(
    path.join(skillDir, "skill.json"),
    `${JSON.stringify({ name: "clawsec-suite", version: "0.2.0", installable: true }, null, 2)}\n`,
  );
  await writeFile(
    path.join(skillDir, "SKILL.md"),
    "---\nname: clawsec-suite\nversion: 0.2.0\n---\n\n# Fixture\n",
  );
  execFileSync("git", ["init", "--initial-branch=main"], { cwd: root });
  execFileSync("git", ["config", "user.name", "ClawSec Test"], { cwd: root });
  execFileSync("git", ["config", "user.email", "clawsec-test@example.invalid"], { cwd: root });
  execFileSync("git", ["add", "."], { cwd: root });
  execFileSync("git", ["commit", "-m", "fixture"], { cwd: root });
  const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  const fixturePlan = plan({ sourceCommit: head });
  if (dirtyMode === "tracked") {
    await writeFile(path.join(skillDir, "SKILL.md"), "changed\n");
  } else if (dirtyMode === "staged") {
    await writeFile(path.join(root, "staged.txt"), "staged\n");
    execFileSync("git", ["add", "staged.txt"], { cwd: root });
  } else if (dirtyMode === "untracked") {
    await writeFile(path.join(root, "untracked.txt"), "untracked\n");
  }
  return { root, fixturePlan };
}

try {
  const cleanFixture = await makeSourceFixture();
  const validated = await validateSourceCheckout({
    repoRoot: cleanFixture.root,
    plan: cleanFixture.fixturePlan,
  });
  assert.equal(validated.source_checkout_verified, true);

  for (const dirtyMode of ["tracked", "staged", "untracked"]) {
    const fixture = await makeSourceFixture(dirtyMode);
    await assert.rejects(
      () => validateSourceCheckout({ repoRoot: fixture.root, plan: fixture.fixturePlan }),
      /source checkout is dirty/,
    );
  }

  const metadataMismatch = await makeSourceFixture();
  const metadataPath = path.join(metadataMismatch.root, "skills", "clawsec-suite", "skill.json");
  await writeFile(
    metadataPath,
    `${JSON.stringify({ name: "other", version: "0.2.0", installable: true })}\n`,
  );
  execFileSync("git", ["add", "."], { cwd: metadataMismatch.root });
  execFileSync("git", ["commit", "-m", "mismatch"], { cwd: metadataMismatch.root });
  const mismatchHead = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: metadataMismatch.root,
    encoding: "utf8",
  }).trim();
  await assert.rejects(
    () => validateSourceCheckout({
      repoRoot: metadataMismatch.root,
      plan: plan({ sourceCommit: mismatchHead }),
    }),
    /skill\.json name must exactly match/,
  );

  const nonInstallable = await makeSourceFixture();
  const nonInstallablePath = path.join(nonInstallable.root, "skills", "clawsec-suite", "skill.json");
  await writeFile(
    nonInstallablePath,
    `${JSON.stringify({ name: "clawsec-suite", version: "0.2.0", installable: false })}\n`,
  );
  execFileSync("git", ["add", "."], { cwd: nonInstallable.root });
  execFileSync("git", ["commit", "-m", "non-installable"], { cwd: nonInstallable.root });
  const nonInstallableHead = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: nonInstallable.root,
    encoding: "utf8",
  }).trim();
  await assert.rejects(
    () => validateSourceCheckout({
      repoRoot: nonInstallable.root,
      plan: plan({ sourceCommit: nonInstallableHead }),
    }),
    /Publication denied/,
  );
} finally {
  await Promise.all(sourceFixtureRoots.map((root) => rm(root, { recursive: true, force: true })));
}

function creationClient({ mainHeads = [sourceCommit, sourceCommit], unsafeRuleset, refRace = false } = {}) {
  let mainIndex = 0;
  let readback = false;
  return new FakeClient("release-app", ({ path: apiPath, method }) => {
    if (apiPath.endsWith(`/rulesets/${rulesetId}`) && method === "GET") {
      return { status: 200, data: unsafeRuleset ?? ruleset() };
    }
    if (apiPath.includes("/git/ref/tags/") && method === "GET") {
      if (!readback) {
        readback = true;
        return missingTag();
      }
      const objectOid = refRace ? racedObjectOid : createdObjectOid;
      return { status: 200, data: refResponse(validPlan, objectOid) };
    }
    if (apiPath.endsWith("/git/ref/heads/main") && method === "GET") {
      const sha = mainHeads[Math.min(mainIndex, mainHeads.length - 1)];
      mainIndex += 1;
      return { status: 200, data: { object: { sha } } };
    }
    if (apiPath.endsWith("/git/tags") && method === "POST") {
      return { status: 201, data: tagResponse(validPlan, createdObjectOid) };
    }
    if (apiPath.endsWith("/git/refs") && method === "POST") {
      if (refRace) {
        throw new GitHubApiError("race", { status: 422 });
      }
      return { status: 201, data: { ref: `refs/tags/${validPlan.tag}` } };
    }
    if (apiPath.endsWith(`/git/tags/${refRace ? racedObjectOid : createdObjectOid}`)) {
      return {
        status: 200,
        data: tagResponse(validPlan, refRace ? racedObjectOid : createdObjectOid),
      };
    }
    throw new Error(`Unexpected fake API call: ${method} ${apiPath}`);
  });
}

const createdClient = creationClient();
const created = await createOrResumeControlledTag({
  client: createdClient,
  repository,
  defaultBranch,
  rulesetId,
  appId,
  plan: validPlan,
});
assert.equal(created.operation, "created");
assert.equal(created.tag_object_oid, createdObjectOid);
assert.deepEqual(writeCalls(createdClient).map(({ method, path: apiPath }) => [method, apiPath]), [
  ["POST", `/repos/prompt-security/clawsec/git/tags`],
  ["POST", `/repos/prompt-security/clawsec/git/refs`],
]);
assert.equal(writeCalls(createdClient)[0].role, "release-app");
assert.deepEqual(writeCalls(createdClient)[0].body, {
  tag: validPlan.tag,
  message: validPlan.tag_message,
  object: sourceCommit,
  type: "commit",
});
assert.deepEqual(writeCalls(createdClient)[1].body, {
  ref: `refs/tags/${validPlan.tag}`,
  sha: createdObjectOid,
});

const exactRetryClient = new FakeClient("release-app", ({ path: apiPath }) => {
  if (apiPath.endsWith(`/rulesets/${rulesetId}`)) return { status: 200, data: ruleset() };
  if (apiPath.includes("/git/ref/tags/")) return { status: 200, data: refResponse(validPlan) };
  if (apiPath.endsWith(`/git/tags/${createdObjectOid}`)) {
    return { status: 200, data: tagResponse(validPlan) };
  }
  throw new Error(`Unexpected retry call: ${apiPath}`);
});
const resumed = await createOrResumeControlledTag({
  client: exactRetryClient,
  repository,
  defaultBranch,
  rulesetId,
  appId,
  plan: validPlan,
});
assert.equal(resumed.operation, "resumed");
assert.equal(writeCalls(exactRetryClient).length, 0);
assert.equal(
  exactRetryClient.calls.some(({ path: apiPath }) => apiPath.endsWith("/git/ref/heads/main")),
  false,
  "an exact same-attempt retry must remain resumable after protected main advances",
);

const wrongAttemptPlan = plan({ releaseAttemptId: "123456:789013" });
const wrongAttemptClient = new FakeClient("release-app", ({ path: apiPath }) => {
  if (apiPath.endsWith(`/rulesets/${rulesetId}`)) return { status: 200, data: ruleset() };
  if (apiPath.includes("/git/ref/tags/")) return { status: 200, data: refResponse(validPlan) };
  if (apiPath.endsWith(`/git/tags/${createdObjectOid}`)) {
    return { status: 200, data: tagResponse(validPlan) };
  }
  throw new Error(`Unexpected wrong-attempt call: ${apiPath}`);
});
await assert.rejects(
  () => createOrResumeControlledTag({
    client: wrongAttemptClient,
    repository,
    defaultBranch,
    rulesetId,
    appId,
    plan: wrongAttemptPlan,
  }),
  /tag message does not match/,
);
assert.equal(writeCalls(wrongAttemptClient).length, 0);

for (const [label, client, expectedError] of [
  ["inactive ruleset", creationClient({ unsafeRuleset: ruleset({ enforcement: "evaluate" }) }), /active enforcement/],
  ["initial main mismatch", creationClient({ mainHeads: [advancedCommit] }), /protected main changed/],
  ["pre-write main movement", creationClient({ mainHeads: [sourceCommit, advancedCommit] }), /protected main changed/],
]) {
  await assert.rejects(
    () => createOrResumeControlledTag({
      client,
      repository,
      defaultBranch,
      rulesetId,
      appId,
      plan: validPlan,
    }),
    expectedError,
    label,
  );
  assert.equal(writeCalls(client).length, 0, `${label} must produce no write`);
}

const raceClient = creationClient({ refRace: true });
const raced = await createOrResumeControlledTag({
  client: raceClient,
  repository,
  defaultBranch,
  rulesetId,
  appId,
  plan: validPlan,
});
assert.equal(raced.operation, "resumed");
assert.equal(raced.tag_object_oid, racedObjectOid);
assert.equal(writeCalls(raceClient).length, 2);

const lightweightClient = new FakeClient("release-app", ({ path: apiPath }) => {
  if (apiPath.endsWith(`/rulesets/${rulesetId}`)) return { status: 200, data: ruleset() };
  if (apiPath.includes("/git/ref/tags/")) {
    return { status: 200, data: {
      ref: `refs/tags/${validPlan.tag}`,
      object: { type: "commit", sha: sourceCommit },
    } };
  }
  throw new Error(`Unexpected lightweight call: ${apiPath}`);
});
await assert.rejects(
  () => createOrResumeControlledTag({
    client: lightweightClient,
    repository,
    defaultBranch,
    rulesetId,
    appId,
    plan: validPlan,
  }),
  /annotated tag object/,
);
assert.equal(writeCalls(lightweightClient).length, 0);

const preflightRetryClient = new FakeClient("github-token", ({ path: apiPath }) => {
  if (apiPath.includes("/git/ref/tags/")) return { status: 200, data: refResponse(validPlan) };
  if (apiPath.endsWith(`/git/tags/${createdObjectOid}`)) {
    return { status: 200, data: tagResponse(validPlan) };
  }
  if (apiPath.endsWith("/git/ref/heads/main")) {
    return { status: 200, data: { object: { sha: advancedCommit } } };
  }
  if (apiPath.includes(`/compare/${sourceCommit}...${advancedCommit}`)) {
    return {
      status: 200,
      data: { status: "ahead", merge_base_commit: { sha: sourceCommit } },
    };
  }
  throw new Error(`Unexpected preflight call: ${apiPath}`);
});
const retryPreflight = await preflightControlledTag({
  client: preflightRetryClient,
  repository,
  defaultBranch,
  plan: validPlan,
});
assert.equal(retryPreflight.preflight, "exact_retry");
assert.equal(writeCalls(preflightRetryClient).length, 0);

function dispatchClient({ advancedMain = false, wrongObject = false } = {}) {
  return new FakeClient("github-token", ({ path: apiPath, method, body }) => {
    if (apiPath.includes("/git/ref/tags/") && method === "GET") {
      return { status: 200, data: refResponse(validPlan, wrongObject ? racedObjectOid : createdObjectOid) };
    }
    if (apiPath.endsWith(`/git/tags/${wrongObject ? racedObjectOid : createdObjectOid}`)) {
      return {
        status: 200,
        data: tagResponse(validPlan, wrongObject ? racedObjectOid : createdObjectOid),
      };
    }
    if (apiPath.endsWith("/git/ref/heads/main")) {
      return { status: 200, data: { object: { sha: advancedMain ? advancedCommit : sourceCommit } } };
    }
    if (apiPath.includes(`/compare/${sourceCommit}...${advancedCommit}`)) {
      return {
        status: 200,
        data: { status: "ahead", merge_base_commit: { sha: sourceCommit } },
      };
    }
    if (
      apiPath.endsWith(`/actions/workflows/${CONTROLLED_RELEASE_WORKFLOW}/dispatches`)
      && method === "POST"
    ) {
      assert.deepEqual(body, {
        ref: "main",
        inputs: {
          operation: "controlled_release",
          tag: validPlan.tag,
          tag_object_oid: createdObjectOid,
          peeled_commit_oid: sourceCommit,
          protected_main_commit: sourceCommit,
          release_attempt_id: releaseAttemptId,
          tag_ruleset_id: String(rulesetId),
          tag_ruleset_updated_at: rulesetUpdatedAt,
          release_app_id: String(appId),
        },
      });
      return {
        status: 200,
        data: {
          workflow_run_id: 987654,
          run_url: "https://api.github.test/actions/runs/987654",
          html_url: "https://github.test/actions/runs/987654",
        },
      };
    }
    throw new Error(`Unexpected dispatch call: ${method} ${apiPath}`);
  });
}

for (const advancedMain of [false, true]) {
  const client = dispatchClient({ advancedMain });
  const dispatched = await dispatchControlledRelease({
    client,
    repository,
    defaultBranch,
    plan: validPlan,
    tagObjectOid: createdObjectOid,
    peeledCommitOid: sourceCommit,
  });
  assert.equal(dispatched.downstream_workflow_run_id, 987654);
  const writes = writeCalls(client);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].role, "github-token");
  assert.match(writes[0].path, /controlled-skill-release\.yml\/dispatches$/);
}

const wrongObjectClient = dispatchClient({ wrongObject: true });
await assert.rejects(
  () => verifyControlledReleaseTuple({
    client: wrongObjectClient,
    repository,
    plan: validPlan,
    tagObjectOid: createdObjectOid,
    peeledCommitOid: sourceCommit,
  }),
  /tag-object ID does not match/,
);
assert.equal(writeCalls(wrongObjectClient).length, 0);

const controllerWorkflow = await readFile(
  new URL("../.github/workflows/create-skill-release-tag.yml", import.meta.url),
  "utf8",
);
const releaseWorkflow = await readFile(
  new URL("../.github/workflows/controlled-skill-release.yml", import.meta.url),
  "utf8",
);
const releaseScript = await readFile(new URL("./release-skill.sh", import.meta.url), "utf8");
assert.equal(
  existsSync(new URL("../.github/workflows/skill-release.yml", import.meta.url)),
  false,
  "historically dispatchable release workflow path must be removed",
);

assert.match(controllerWorkflow, /^name: Create Skill Release Tag/m);
assert.match(controllerWorkflow, /environment: clawsec-stable-release/);
assert.match(controllerWorkflow, /CLAWSEC_CONTROLLED_RELEASE_ENABLED/);
assert.match(controllerWorkflow, /CLAWSEC_RELEASE_TAG_RULESET_UPDATED_AT/);
assert.match(controllerWorkflow, /refs\/heads\/\$DEFAULT_BRANCH/);
assert.match(controllerWorkflow, /path: policy[\s\S]*path: source/);
assert.match(controllerWorkflow, /actions\/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1/);
const writeJob = controllerWorkflow.slice(
  controllerWorkflow.indexOf("  write-annotated-tag:"),
  controllerWorkflow.indexOf("  dispatch-release:"),
);
const postApprovalGate = writeJob.indexOf(
  "- name: Recheck enabled controller after environment approval",
);
const mintAppToken = writeJob.indexOf("- name: Mint repository-scoped release App token");
assert.ok(postApprovalGate >= 0, "write job must recheck the release kill switch");
assert.ok(
  postApprovalGate < mintAppToken,
  "environment-gated kill-switch recheck must run before minting the write token",
);
assert.match(
  writeJob.slice(postApprovalGate, mintAppToken),
  /RELEASE_ENABLED: \$\{\{ vars\.CLAWSEC_CONTROLLED_RELEASE_ENABLED \}\}[\s\S]*\[\[ "\$RELEASE_ENABLED" != "true" \]\]/,
);
const appTokenStep = controllerWorkflow.slice(
  controllerWorkflow.indexOf("- name: Mint repository-scoped release App token"),
  controllerWorkflow.indexOf("- name: Preflight ruleset"),
);
assert.match(appTokenStep, /permission-contents: write/);
assert.doesNotMatch(
  appTokenStep,
  /permission-actions|permission-workflows|permission-administration|github\.token/,
);
const dispatchJob = controllerWorkflow.slice(controllerWorkflow.indexOf("  dispatch-release:"));
assert.match(dispatchJob, /actions: write[\s\S]*contents: read/);
assert.match(dispatchJob, /GITHUB_TOKEN: \$\{\{ github\.token \}\}/);
assert.doesNotMatch(dispatchJob, /release-app-token|CONTROLLED_TAG_TOKEN|APP_PRIVATE_KEY/);
assert.match(dispatchJob, /dispatch-release/);

assert.doesNotMatch(releaseWorkflow, /\n\s+push:\s*\n\s+tags:/);
assert.match(releaseWorkflow, /operation:[\s\S]*republish_clawhub[\s\S]*controlled_release/);
assert.match(releaseWorkflow, /REQUESTED_REF[\s\S]*refs\/heads\/\$DEFAULT_BRANCH/);
assert.match(releaseWorkflow, /controlled_tag_creation\.mjs verify-release/);
assert.match(releaseWorkflow, /inputs\.operation == 'controlled_release'/);
assert.match(releaseWorkflow, /inputs\.operation == 'republish_clawhub'/);
const releaseJob = releaseWorkflow.slice(
  releaseWorkflow.indexOf("  release-tag:"),
  releaseWorkflow.indexOf("  publish-clawhub:"),
);
assert.ok(
  releaseJob.indexOf("Reverify controlled tag provenance")
    < releaseJob.indexOf("Sign embedded advisory feed and verify"),
  "release provenance must be reverified before any signing or release write",
);
assert.match(
  releaseJob,
  /ref: \$\{\{ needs\.stable-publication-policy\.outputs\.peeled_commit_oid \}\}/,
);

for (const forbidden of [
  /--force-tag/,
  /\bgit tag\b/,
  /\bgh release create\b/,
  /git push origin \$TAG/,
  /git tag -d/,
  /git reset --hard/,
]) {
  assert.doesNotMatch(releaseScript, forbidden);
}
assert.match(releaseScript, /version preparation must run on a review branch/);
assert.match(releaseScript, /repository must be globally clean/);
assert.match(releaseScript, /Create Skill Release Tag/);

const helperSource = await readFile(
  new URL("./ci/controlled_tag_creation.mjs", import.meta.url),
  "utf8",
);
assert.doesNotMatch(helperSource, /method:\s*["'](?:PATCH|DELETE)["']/);
assert.doesNotMatch(helperSource, /force:\s*true|\/git\/refs\/tags\/.*PATCH/);

process.stdout.write("Controlled tag creation tests passed.\n");
