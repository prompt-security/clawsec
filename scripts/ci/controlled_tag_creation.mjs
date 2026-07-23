#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { requireSkillPublication } from "./skill_installability.mjs";
import {
  evaluateStableTagPolicy,
  loadLegacyPrereleaseInventory,
} from "./stable_tag_policy.mjs";

export const CONTROLLED_TAG_SCHEMA = "clawsec.controlled-tag/v1";
export const CONTROLLED_RELEASE_WORKFLOW = "controlled-skill-release.yml";
export const REQUIRED_TAG_RULESET_PATTERN = "refs/tags/*-v*";

const OBJECT_ID_PATTERN = /^[0-9a-f]{40}$/;
const PACKAGE_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const ATTEMPT_ID_PATTERN = /^[1-9][0-9]*:[1-9][0-9]*$/;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const REQUIRED_RULE_TYPES = ["creation", "update", "deletion", "non_fast_forward"];

function fail(message) {
  throw new Error(message);
}

function requireString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${name} must be a non-empty string`);
  }
  return value;
}

function requireObjectId(value, name) {
  requireString(value, name);
  if (!OBJECT_ID_PATTERN.test(value)) {
    fail(`${name} must be a lowercase 40-character Git object ID`);
  }
  return value;
}

function requireAttemptId(value) {
  requireString(value, "release attempt ID");
  if (!ATTEMPT_ID_PATTERN.test(value)) {
    fail("release attempt ID must be <repository_id>:<workflow_run_id>");
  }
  return value;
}

function requirePositiveInteger(value, name) {
  const parsed = Number(requireString(String(value), name));
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    fail(`${name} must be a positive integer`);
  }
  return parsed;
}

function requireRulesetUpdatedAt(value) {
  requireString(value, "ruleset updated_at");
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)
    || Number.isNaN(Date.parse(value))
  ) {
    fail("ruleset updated_at must be an exact UTC RFC 3339 timestamp");
  }
  return value;
}

function requireRepository(value) {
  requireString(value, "repository");
  if (!REPOSITORY_PATTERN.test(value)) {
    fail("repository must be an owner/name pair");
  }
  return value;
}

function requireDefaultBranch(value) {
  if (value !== "main") {
    fail("controlled release requires the protected default branch to be main");
  }
  return value;
}

function canonicalTagMessage({
  repository,
  packageName,
  version,
  tag,
  sourceCommit,
  releaseAttemptId,
  rulesetId,
  rulesetUpdatedAt,
  appId,
}) {
  return JSON.stringify({
    schema: CONTROLLED_TAG_SCHEMA,
    repository,
    package_name: packageName,
    version,
    tag,
    protected_main_commit: sourceCommit,
    release_attempt_id: releaseAttemptId,
    tag_ruleset_id: rulesetId,
    tag_ruleset_updated_at: rulesetUpdatedAt,
    release_app_id: appId,
  });
}

export function createControlledTagPlan({
  repository,
  packageName,
  version,
  sourceCommit,
  releaseAttemptId,
  rulesetId,
  rulesetUpdatedAt,
  appId,
  historicalTags,
}) {
  requireRepository(repository);
  requireString(packageName, "package name");
  if (!PACKAGE_PATTERN.test(packageName)) {
    fail("package name must use lowercase alphanumeric kebab-case");
  }
  requireString(version, "version");
  requireObjectId(sourceCommit, "protected main commit");
  requireAttemptId(releaseAttemptId);
  const normalizedRulesetId = requirePositiveInteger(rulesetId, "ruleset ID");
  const normalizedRulesetUpdatedAt = requireRulesetUpdatedAt(rulesetUpdatedAt);
  const normalizedAppId = requirePositiveInteger(appId, "GitHub App ID");
  if (!(historicalTags instanceof Set)) {
    fail("historicalTags must be a validated Set");
  }

  const tag = `${packageName}-v${version}`;
  const stableDecision = evaluateStableTagPolicy({ tag, historicalTags });
  if (!stableDecision.publication_eligible) {
    fail(`stable tag policy denied ${tag}: ${stableDecision.reason_code}`);
  }
  if (stableDecision.package_name !== packageName || stableDecision.version !== version) {
    fail("stable tag policy returned a mismatched package or version");
  }

  const tagMessage = canonicalTagMessage({
    repository,
    packageName,
    version,
    tag,
    sourceCommit,
    releaseAttemptId,
    rulesetId: normalizedRulesetId,
    rulesetUpdatedAt: normalizedRulesetUpdatedAt,
    appId: normalizedAppId,
  });
  return {
    schema: CONTROLLED_TAG_SCHEMA,
    repository,
    package_name: packageName,
    version,
    tag,
    protected_main_commit: sourceCommit,
    release_attempt_id: releaseAttemptId,
    tag_ruleset_id: normalizedRulesetId,
    tag_ruleset_updated_at: normalizedRulesetUpdatedAt,
    release_app_id: normalizedAppId,
    tag_message: tagMessage,
    tag_message_sha256: createHash("sha256").update(tagMessage).digest("hex"),
  };
}

function parseSkillMarkdownVersion(markdown, source) {
  const normalized = markdown.replaceAll("\r\n", "\n");
  if (!normalized.startsWith("---\n")) {
    fail(`${source} must start with YAML frontmatter`);
  }
  const end = normalized.indexOf("\n---\n", 4);
  if (end === -1) {
    fail(`${source} has unterminated YAML frontmatter`);
  }
  const matches = [...normalized.slice(4, end).matchAll(/^version:[ \t]*([^ \t\n]+)[ \t]*$/gm)];
  if (matches.length !== 1) {
    fail(`${source} must declare exactly one frontmatter version`);
  }
  return matches[0][1];
}

function runGit(repoRoot, args) {
  try {
    return execFileSync("git", ["-C", repoRoot, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    const detail = String(error?.stderr ?? "").trim();
    fail(`Git source inspection failed${detail ? `: ${detail}` : ""}`);
  }
}

export async function validateSourceCheckout({ repoRoot, plan }) {
  const root = path.resolve(requireString(repoRoot, "repository root"));
  const topLevel = path.resolve(runGit(root, ["rev-parse", "--show-toplevel"]));
  if (topLevel !== root) {
    fail(`repository root mismatch: expected ${root}, observed ${topLevel}`);
  }
  const observedHead = runGit(root, ["rev-parse", "HEAD"]);
  if (observedHead !== plan.protected_main_commit) {
    fail("checked-out commit does not match the requested protected-main commit");
  }
  const status = runGit(root, ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status !== "") {
    fail("source checkout is dirty; tracked, staged, and untracked changes are forbidden");
  }

  const skillDir = path.join(root, "skills", plan.package_name);
  const skillJsonPath = path.join(skillDir, "skill.json");
  const skillMarkdownPath = path.join(skillDir, "SKILL.md");
  let metadata;
  try {
    metadata = JSON.parse(await readFile(skillJsonPath, "utf8"));
  } catch (error) {
    fail(`unable to load valid skill metadata from ${skillJsonPath}: ${error.message}`);
  }
  if (metadata?.name !== plan.package_name) {
    fail("skill.json name must exactly match the package directory and release tag");
  }
  if (metadata?.version !== plan.version) {
    fail("skill.json version must exactly match the requested final version");
  }
  requireSkillPublication(metadata, skillJsonPath);

  let markdown;
  try {
    markdown = await readFile(skillMarkdownPath, "utf8");
  } catch (error) {
    fail(`unable to load ${skillMarkdownPath}: ${error.message}`);
  }
  if (parseSkillMarkdownVersion(markdown, skillMarkdownPath) !== plan.version) {
    fail("SKILL.md frontmatter version must exactly match the requested final version");
  }

  return {
    ...plan,
    source_checkout_verified: true,
  };
}

export function validateTagRuleset(
  ruleset,
  { repository, rulesetId, rulesetUpdatedAt, appId },
) {
  requireRepository(repository);
  const expectedRulesetId = requirePositiveInteger(rulesetId, "ruleset ID");
  const expectedRulesetUpdatedAt = requireRulesetUpdatedAt(rulesetUpdatedAt);
  const expectedAppId = requirePositiveInteger(appId, "GitHub App ID");
  if (!ruleset || typeof ruleset !== "object" || Array.isArray(ruleset)) {
    fail("tag ruleset response must be an object");
  }
  if (ruleset.id !== expectedRulesetId) {
    fail("tag ruleset ID does not match the configured ruleset");
  }
  if (ruleset.updated_at !== expectedRulesetUpdatedAt) {
    fail("tag ruleset changed after the operator-reviewed ruleset proof");
  }
  if (ruleset.source_type !== "Repository" || ruleset.source !== repository) {
    fail("tag ruleset must be owned by the release repository named in the proof");
  }
  if (ruleset.target !== "tag" || ruleset.enforcement !== "active") {
    fail("tag ruleset must target tags with active enforcement");
  }

  const refName = ruleset.conditions?.ref_name;
  const includes = refName?.include;
  const excludes = refName?.exclude;
  if (!Array.isArray(includes) || !Array.isArray(excludes)) {
    fail("tag ruleset must expose ref_name include and exclude conditions");
  }
  if (excludes.length !== 0) {
    fail("tag ruleset must not exclude refs from release-tag protection");
  }
  if (!includes.includes("~ALL") && !includes.includes(REQUIRED_TAG_RULESET_PATTERN)) {
    fail(`tag ruleset must include ~ALL or ${REQUIRED_TAG_RULESET_PATTERN}`);
  }

  const ruleTypes = new Set(
    Array.isArray(ruleset.rules) ? ruleset.rules.map((rule) => rule?.type) : [],
  );
  for (const ruleType of REQUIRED_RULE_TYPES) {
    if (!ruleTypes.has(ruleType)) {
      fail(`tag ruleset is missing required ${ruleType} protection`);
    }
  }

  let bypassActorVisibility = "redacted_operator_proof_required";
  if (Object.hasOwn(ruleset, "bypass_actors")) {
    if (!Array.isArray(ruleset.bypass_actors) || ruleset.bypass_actors.length !== 1) {
      fail("visible tag-ruleset policy must have exactly one bypass actor");
    }
    const bypass = ruleset.bypass_actors[0];
    if (
      bypass?.actor_type !== "Integration"
      || bypass?.actor_id !== expectedAppId
      || bypass?.bypass_mode !== "always"
    ) {
      fail("the sole visible tag-ruleset bypass must be the dedicated release GitHub App");
    }
    bypassActorVisibility = "api_verified";
  }

  return {
    ruleset_id: expectedRulesetId,
    ruleset_updated_at: expectedRulesetUpdatedAt,
    app_id: expectedAppId,
    active: true,
    bypass_actor_visibility: bypassActorVisibility,
  };
}

export class GitHubApiError extends Error {
  constructor(message, { status, response } = {}) {
    super(message);
    this.name = "GitHubApiError";
    this.status = status;
    this.response = response;
  }
}

export class GitHubApiClient {
  constructor({ token, apiUrl = "https://api.github.com", fetchImpl = globalThis.fetch }) {
    requireString(token, "GitHub API token");
    if (typeof fetchImpl !== "function") {
      fail("GitHub API client requires fetch support");
    }
    const parsedUrl = new URL(apiUrl);
    if (!new Set(["https:", "http:"]).has(parsedUrl.protocol)) {
      fail("GitHub API URL must use HTTP or HTTPS");
    }
    this.token = token;
    this.apiUrl = parsedUrl.href.replace(/\/$/, "");
    this.fetchImpl = fetchImpl;
  }

  async request(apiPath, { method = "GET", body, expected = [200] } = {}) {
    const response = await this.fetchImpl(`${this.apiUrl}${apiPath}`, {
      method,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2026-03-10",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const responseText = await response.text();
    let responseBody = null;
    if (responseText !== "") {
      try {
        responseBody = JSON.parse(responseText);
      } catch {
        throw new GitHubApiError("GitHub API returned malformed JSON", {
          status: response.status,
          response: responseText.slice(0, 500),
        });
      }
    }
    if (!expected.includes(response.status)) {
      throw new GitHubApiError(`GitHub API request failed with status ${response.status}`, {
        status: response.status,
        response: responseBody,
      });
    }
    return { status: response.status, data: responseBody };
  }
}

function repositoryApiPath(repository) {
  requireRepository(repository);
  const [owner, name] = repository.split("/");
  return `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;
}

async function readDefaultBranchHead(client, repository, defaultBranch) {
  requireDefaultBranch(defaultBranch);
  const { data } = await client.request(
    `${repositoryApiPath(repository)}/git/ref/heads/${encodeURIComponent(defaultBranch)}`,
  );
  return requireObjectId(data?.object?.sha, "observed default-branch head");
}

async function readTagRecord(client, repository, tag, { allowMissing = false } = {}) {
  let refResponse;
  try {
    refResponse = await client.request(
      `${repositoryApiPath(repository)}/git/ref/tags/${encodeURIComponent(tag)}`,
    );
  } catch (error) {
    if (allowMissing && error instanceof GitHubApiError && error.status === 404) {
      return null;
    }
    throw error;
  }
  if (refResponse.data?.ref !== `refs/tags/${tag}`) {
    fail("tag ref readback returned a mismatched or nested ref");
  }
  if (refResponse.data?.object?.type !== "tag") {
    fail("release tag must be an annotated tag object, not a lightweight tag");
  }
  const tagObjectOid = requireObjectId(refResponse.data.object.sha, "tag-object ID");
  const { data: tagObject } = await client.request(
    `${repositoryApiPath(repository)}/git/tags/${tagObjectOid}`,
  );
  if (tagObject?.sha !== tagObjectOid) {
    fail("annotated tag-object readback returned a mismatched object ID");
  }
  if (tagObject?.object?.type !== "commit") {
    fail("annotated release tag must peel directly to a commit");
  }
  return {
    tag: tagObject.tag,
    message: tagObject.message,
    tag_object_oid: tagObjectOid,
    peeled_commit_oid: requireObjectId(tagObject.object.sha, "peeled commit ID"),
  };
}

function verifyTagRecord(record, plan, expected = {}) {
  if (!record) {
    fail(`release tag ${plan.tag} does not exist`);
  }
  if (record.tag !== plan.tag) {
    fail("annotated tag object contains the wrong tag name");
  }
  if (record.message !== plan.tag_message) {
    fail("annotated tag message does not match the controlled release tuple");
  }
  if (record.peeled_commit_oid !== plan.protected_main_commit) {
    fail("annotated tag peels to the wrong protected-main commit");
  }
  if (expected.tagObjectOid && record.tag_object_oid !== expected.tagObjectOid) {
    fail("tag-object ID does not match the dispatched release tuple");
  }
  if (expected.peeledCommitOid && record.peeled_commit_oid !== expected.peeledCommitOid) {
    fail("peeled commit does not match the dispatched release tuple");
  }
  return record;
}

async function requireCurrentMain(client, repository, defaultBranch, sourceCommit) {
  const observed = await readDefaultBranchHead(client, repository, defaultBranch);
  if (observed !== sourceCommit) {
    fail("protected main changed or does not match the requested source commit");
  }
  return observed;
}

export async function createOrResumeControlledTag({
  client,
  repository,
  defaultBranch,
  rulesetId,
  appId,
  plan,
}) {
  requireRepository(repository);
  if (plan.repository !== repository) {
    fail("release plan repository does not match the GitHub API repository");
  }
  if (
    plan.tag_ruleset_id !== requirePositiveInteger(rulesetId, "ruleset ID")
    || plan.release_app_id !== requirePositiveInteger(appId, "GitHub App ID")
  ) {
    fail("release plan does not match the configured ruleset or GitHub App");
  }
  requireDefaultBranch(defaultBranch);
  const { data: ruleset } = await client.request(
    `${repositoryApiPath(repository)}/rulesets/${encodeURIComponent(String(rulesetId))}`,
  );
  const rulesetProof = validateTagRuleset(ruleset, {
    repository,
    rulesetId,
    rulesetUpdatedAt: plan.tag_ruleset_updated_at,
    appId,
  });

  const existing = await readTagRecord(client, repository, plan.tag, { allowMissing: true });
  if (existing) {
    verifyTagRecord(existing, plan);
    return { ...plan, ...existing, ...rulesetProof, operation: "resumed" };
  }

  await requireCurrentMain(
    client,
    repository,
    defaultBranch,
    plan.protected_main_commit,
  );

  // This second server-side read is intentionally the last operation before the
  // first write. A changed protected-main SHA must produce no tag/ref write.
  await requireCurrentMain(
    client,
    repository,
    defaultBranch,
    plan.protected_main_commit,
  );

  const { data: createdTag } = await client.request(
    `${repositoryApiPath(repository)}/git/tags`,
    {
      method: "POST",
      expected: [201],
      body: {
        tag: plan.tag,
        message: plan.tag_message,
        object: plan.protected_main_commit,
        type: "commit",
      },
    },
  );
  const createdTagObjectOid = requireObjectId(createdTag?.sha, "created tag-object ID");
  if (
    createdTag?.tag !== plan.tag
    || createdTag?.message !== plan.tag_message
    || createdTag?.object?.type !== "commit"
    || createdTag?.object?.sha !== plan.protected_main_commit
  ) {
    fail("created annotated tag object did not match the requested release tuple");
  }

  let refRace = false;
  try {
    await client.request(`${repositoryApiPath(repository)}/git/refs`, {
      method: "POST",
      expected: [201],
      body: {
        ref: `refs/tags/${plan.tag}`,
        sha: createdTagObjectOid,
      },
    });
  } catch (error) {
    if (!(error instanceof GitHubApiError) || error.status !== 422) {
      throw error;
    }
    refRace = true;
    // Another rerun of this same workflow may have won the create-ref race.
    // The exact tuple readback below is the only accepted recovery.
  }

  const readback = await readTagRecord(client, repository, plan.tag);
  verifyTagRecord(readback, plan);
  return {
    ...plan,
    ...readback,
    ...rulesetProof,
    operation: refRace ? "resumed" : "created",
  };
}

export async function verifyControlledReleaseTuple({
  client,
  repository,
  plan,
  tagObjectOid,
  peeledCommitOid,
}) {
  if (plan.repository !== repository) {
    fail("release plan repository does not match the GitHub API repository");
  }
  requireObjectId(tagObjectOid, "dispatched tag-object ID");
  requireObjectId(peeledCommitOid, "dispatched peeled-commit ID");
  if (peeledCommitOid !== plan.protected_main_commit) {
    fail("protected-main commit and peeled-commit inputs must be identical");
  }
  const record = await readTagRecord(client, repository, plan.tag);
  verifyTagRecord(record, plan, { tagObjectOid, peeledCommitOid });
  return { ...plan, ...record, provenance_verified: true };
}

async function requireProtectedMainAncestry({
  client,
  repository,
  defaultBranch,
  sourceCommit,
}) {
  const currentHead = await readDefaultBranchHead(client, repository, defaultBranch);
  if (currentHead === sourceCommit) {
    return currentHead;
  }
  const { data: comparison } = await client.request(
    `${repositoryApiPath(repository)}/compare/${sourceCommit}...${currentHead}`,
  );
  if (
    comparison?.status !== "ahead"
    || comparison?.merge_base_commit?.sha !== sourceCommit
  ) {
    fail("tagged commit is no longer an ancestor of protected main");
  }
  return currentHead;
}

export async function preflightControlledTag({
  client,
  repository,
  defaultBranch,
  plan,
}) {
  if (plan.repository !== repository) {
    fail("release plan repository does not match the GitHub API repository");
  }
  const existing = await readTagRecord(client, repository, plan.tag, { allowMissing: true });
  if (existing) {
    verifyTagRecord(existing, plan);
    await requireProtectedMainAncestry({
      client,
      repository,
      defaultBranch,
      sourceCommit: plan.protected_main_commit,
    });
    return { ...plan, ...existing, preflight: "exact_retry" };
  }
  await requireCurrentMain(
    client,
    repository,
    defaultBranch,
    plan.protected_main_commit,
  );
  return { ...plan, preflight: "new_tag" };
}

export async function dispatchControlledRelease({
  client,
  repository,
  defaultBranch,
  plan,
  tagObjectOid,
  peeledCommitOid,
}) {
  const verified = await verifyControlledReleaseTuple({
    client,
    repository,
    plan,
    tagObjectOid,
    peeledCommitOid,
  });
  await requireProtectedMainAncestry({
    client,
    repository,
    defaultBranch,
    sourceCommit: plan.protected_main_commit,
  });

  const { data } = await client.request(
    `${repositoryApiPath(repository)}/actions/workflows/${encodeURIComponent(CONTROLLED_RELEASE_WORKFLOW)}/dispatches`,
    {
      method: "POST",
      expected: [200],
      body: {
        ref: requireDefaultBranch(defaultBranch),
        inputs: {
          operation: "controlled_release",
          tag: plan.tag,
          tag_object_oid: verified.tag_object_oid,
          peeled_commit_oid: verified.peeled_commit_oid,
          protected_main_commit: plan.protected_main_commit,
          release_attempt_id: plan.release_attempt_id,
          tag_ruleset_id: String(plan.tag_ruleset_id),
          tag_ruleset_updated_at: plan.tag_ruleset_updated_at,
          release_app_id: String(plan.release_app_id),
        },
      },
    },
  );
  if (!Number.isSafeInteger(data?.workflow_run_id) || data.workflow_run_id <= 0) {
    fail("workflow dispatch did not return a valid downstream run ID");
  }
  if (typeof data?.run_url !== "string" || typeof data?.html_url !== "string") {
    fail("workflow dispatch did not return downstream run URLs");
  }
  return {
    ...verified,
    downstream_workflow_run_id: data.workflow_run_id,
    downstream_run_url: data.run_url,
    downstream_html_url: data.html_url,
  };
}

function usage() {
  return [
    "Usage:",
    "  All commands require --ruleset-id <id> --ruleset-updated-at <timestamp> --app-id <id>.",
    "  controlled_tag_creation.mjs plan --package <name> --version <x.y.z> --source-commit <sha> --release-attempt-id <repo_id:run_id> --repository <owner/name> --ruleset-id <id> --ruleset-updated-at <timestamp> --app-id <id> [--repo-root <path>]",
    "  controlled_tag_creation.mjs preflight --package <name> --version <x.y.z> --source-commit <sha> --release-attempt-id <repo_id:run_id> --repository <owner/name> --ruleset-id <id> --ruleset-updated-at <timestamp> --app-id <id> --default-branch main [--repo-root <path>]",
    "  controlled_tag_creation.mjs create --package <name> --version <x.y.z> --source-commit <sha> --release-attempt-id <repo_id:run_id> --repository <owner/name> --ruleset-id <id> --ruleset-updated-at <timestamp> --app-id <id> --default-branch main [--repo-root <path>]",
    "  controlled_tag_creation.mjs verify-release --tag <tag> --tag-object-oid <sha> --peeled-commit-oid <sha> --protected-main-commit <sha> --release-attempt-id <repo_id:run_id> --repository <owner/name> --ruleset-id <id> --ruleset-updated-at <timestamp> --app-id <id>",
    "  controlled_tag_creation.mjs dispatch-release --tag <tag> --tag-object-oid <sha> --peeled-commit-oid <sha> --protected-main-commit <sha> --release-attempt-id <repo_id:run_id> --repository <owner/name> --ruleset-id <id> --ruleset-updated-at <timestamp> --app-id <id> --default-branch main",
  ].join("\n");
}

function parseArguments(argv) {
  if (argv.length === 0) {
    fail(usage());
  }
  const command = argv[0];
  const options = {};
  for (let index = 1; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined || value.startsWith("--")) {
      fail(usage());
    }
    const key = name.slice(2);
    if (Object.hasOwn(options, key)) {
      fail(`duplicate option: ${name}`);
    }
    options[key] = value;
  }
  return { command, options };
}

function requireOnlyOptions(options, required, optional = []) {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) {
      fail(`unknown option: --${key}`);
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(options, key)) {
      fail(`missing required option: --${key}`);
    }
  }
}

async function planFromOptions(options, { validateCheckout = false } = {}) {
  const { historicalTags } = await loadLegacyPrereleaseInventory();
  const plan = createControlledTagPlan({
    repository: options.repository,
    packageName: options.package,
    version: options.version,
    sourceCommit: options["source-commit"],
    releaseAttemptId: options["release-attempt-id"],
    rulesetId: options["ruleset-id"],
    rulesetUpdatedAt: options["ruleset-updated-at"],
    appId: options["app-id"],
    historicalTags,
  });
  if (!validateCheckout) {
    return plan;
  }
  return validateSourceCheckout({
    repoRoot: options["repo-root"] ?? ".",
    plan,
  });
}

async function planFromReleaseTuple(options) {
  const separator = options.tag.lastIndexOf("-v");
  if (separator <= 0) {
    fail("controlled release tag is not package-qualified");
  }
  const { historicalTags } = await loadLegacyPrereleaseInventory();
  return createControlledTagPlan({
    repository: options.repository,
    packageName: options.tag.slice(0, separator),
    version: options.tag.slice(separator + 2),
    sourceCommit: options["protected-main-commit"],
    releaseAttemptId: options["release-attempt-id"],
    rulesetId: options["ruleset-id"],
    rulesetUpdatedAt: options["ruleset-updated-at"],
    appId: options["app-id"],
    historicalTags,
  });
}

function apiClientFromEnvironment(tokenName) {
  return new GitHubApiClient({
    token: process.env[tokenName],
    apiUrl: process.env.GITHUB_API_URL ?? "https://api.github.com",
  });
}

async function runCli(argv) {
  const { command, options } = parseArguments(argv);
  const planOptions = [
    "package",
    "version",
    "source-commit",
    "release-attempt-id",
    "repository",
    "ruleset-id",
    "ruleset-updated-at",
    "app-id",
  ];
  const releaseOptions = [
    "tag",
    "tag-object-oid",
    "peeled-commit-oid",
    "protected-main-commit",
    "release-attempt-id",
    "repository",
    "ruleset-id",
    "ruleset-updated-at",
    "app-id",
  ];

  if (command === "plan") {
    requireOnlyOptions(options, planOptions, ["repo-root"]);
    return planFromOptions(options, { validateCheckout: true });
  }
  if (command === "preflight") {
    requireOnlyOptions(options, [...planOptions, "default-branch"], ["repo-root"]);
    const plan = await planFromOptions(options, { validateCheckout: true });
    return preflightControlledTag({
      client: apiClientFromEnvironment("GITHUB_TOKEN"),
      repository: options.repository,
      defaultBranch: options["default-branch"],
      plan,
    });
  }
  if (command === "create") {
    requireOnlyOptions(
      options,
      [...planOptions, "default-branch"],
      ["repo-root"],
    );
    const plan = await planFromOptions(options, { validateCheckout: true });
    return createOrResumeControlledTag({
      client: apiClientFromEnvironment("CONTROLLED_TAG_TOKEN"),
      repository: options.repository,
      defaultBranch: options["default-branch"],
      rulesetId: options["ruleset-id"],
      appId: options["app-id"],
      plan,
    });
  }
  if (command === "verify-release") {
    requireOnlyOptions(options, releaseOptions);
    const plan = await planFromReleaseTuple(options);
    return verifyControlledReleaseTuple({
      client: apiClientFromEnvironment("GITHUB_TOKEN"),
      repository: options.repository,
      plan,
      tagObjectOid: options["tag-object-oid"],
      peeledCommitOid: options["peeled-commit-oid"],
    });
  }
  if (command === "dispatch-release") {
    requireOnlyOptions(options, [...releaseOptions, "default-branch"]);
    const plan = await planFromReleaseTuple(options);
    return dispatchControlledRelease({
      client: apiClientFromEnvironment("GITHUB_TOKEN"),
      repository: options.repository,
      defaultBranch: options["default-branch"],
      plan,
      tagObjectOid: options["tag-object-oid"],
      peeledCommitOid: options["peeled-commit-oid"],
    });
  }
  fail(usage());
}

async function main() {
  try {
    const result = await runCli(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`Controlled tag operation denied: ${error.message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
