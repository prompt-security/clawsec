import assert from "node:assert/strict";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  projectSkillCatalogInstallability,
  projectSkillCatalogInstallabilityFromFiles,
  runSkillCatalogInstallabilityCli,
} from "./ci/project_skill_catalog_installability.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const workflowPath = path.join(repositoryRoot, ".github/workflows/deploy-pages.yml");
const localPopulatorPath = path.join(repositoryRoot, "scripts/populate-local-skills.sh");
const projectionHelperPath = path.join(
  repositoryRoot,
  "scripts/ci/project_skill_catalog_installability.mjs",
);
const installabilityHelperPath = path.join(repositoryRoot, "scripts/ci/skill_installability.mjs");
const nanoClawSkillJsonPath = path.join(repositoryRoot, "skills/clawsec-nanoclaw/skill.json");
const fixtureRoot = await mkdtemp(path.join(tmpdir(), "clawsec-catalog-installability-"));

function runProjectionCli(...args) {
  return spawnSync(process.execPath, [projectionHelperPath, ...args], { encoding: "utf8" });
}

async function prepareLocalPopulatorFixture(name) {
  const root = path.join(fixtureRoot, name);
  const scriptsDir = path.join(root, "scripts");
  const ciDir = path.join(scriptsDir, "ci");
  await mkdir(ciDir, { recursive: true });
  await mkdir(path.join(root, "skills"), { recursive: true });
  await copyFile(localPopulatorPath, path.join(scriptsDir, "populate-local-skills.sh"));
  await copyFile(projectionHelperPath, path.join(ciDir, "project_skill_catalog_installability.mjs"));
  await copyFile(installabilityHelperPath, path.join(ciDir, "skill_installability.mjs"));
  return root;
}

async function writeFixtureSkill(root, directoryName, metadata) {
  const skillDir = path.join(root, "skills", directoryName);
  await mkdir(skillDir, { recursive: true });
  const source = typeof metadata === "string"
    ? metadata
    : `${JSON.stringify(metadata, null, 2)}\n`;
  await writeFile(path.join(skillDir, "skill.json"), source);
  return source;
}

function localSkillMetadata(name, installable) {
  const metadata = {
    name,
    version: "1.0.0",
    description: `${name} fixture`,
    sbom: { files: [] },
    openclaw: { emoji: "📦", category: "security" },
  };
  if (installable !== undefined) metadata.installable = installable;
  return metadata;
}

function runLocalPopulator(root) {
  return spawnSync("bash", [path.join(root, "scripts/populate-local-skills.sh")], {
    cwd: root,
    encoding: "utf8",
  });
}

try {
  assert.deepEqual(
    projectSkillCatalogInstallability({
      releaseSkill: { name: "legacy" },
      expectedSkillName: "legacy",
    }),
    {
      release_installable: true,
      release_installable_explicitly_declared: false,
      repository_metadata_present: false,
      repository_installable: false,
      repository_installable_explicitly_declared: false,
      effective_installable: false,
    },
  );
  assert.deepEqual(
    projectSkillCatalogInstallability({
      releaseSkill: { name: "enabled", installable: true },
      repositorySkill: { name: "enabled" },
      expectedSkillName: "enabled",
    }),
    {
      release_installable: true,
      release_installable_explicitly_declared: true,
      repository_metadata_present: true,
      repository_installable: true,
      repository_installable_explicitly_declared: false,
      effective_installable: true,
    },
  );
  assert.deepEqual(
    projectSkillCatalogInstallability({
      releaseSkill: { name: "withdrawn-release", installable: false },
      repositorySkill: { name: "withdrawn-release", installable: true },
      expectedSkillName: "withdrawn-release",
    }),
    {
      release_installable: false,
      release_installable_explicitly_declared: true,
      repository_metadata_present: true,
      repository_installable: true,
      repository_installable_explicitly_declared: true,
      effective_installable: false,
    },
    "repository metadata must never authorize a non-installable release",
  );
  assert.deepEqual(
    projectSkillCatalogInstallability({
      releaseSkill: { name: "withdrawn-current" },
      repositorySkill: { name: "withdrawn-current", installable: false },
      expectedSkillName: "withdrawn-current",
    }),
    {
      release_installable: true,
      release_installable_explicitly_declared: false,
      repository_metadata_present: true,
      repository_installable: false,
      repository_installable_explicitly_declared: true,
      effective_installable: false,
    },
    "current repository metadata must be able to withdraw a legacy release",
  );

  for (const invalidValue of [null, 0, "false", {}, []]) {
    assert.throws(
      () => projectSkillCatalogInstallability({
        releaseSkill: { name: "invalid", installable: invalidValue },
        repositorySkill: { name: "invalid" },
        releaseSource: "release-fixture.json",
      }),
      /Invalid skill metadata in release-fixture\.json: "installable" must be a boolean when present/,
    );
    assert.throws(
      () => projectSkillCatalogInstallability({
        releaseSkill: { name: "invalid" },
        repositorySkill: { name: "invalid", installable: invalidValue },
        repositorySource: "repository-fixture.json",
      }),
      /Invalid skill metadata in repository-fixture\.json: "installable" must be a boolean when present/,
    );
  }

  assert.throws(
    () => projectSkillCatalogInstallability({ releaseSkill: { version: "1.0.0" } }),
    /Invalid skill metadata in release skill\.json: "name" must be a non-empty string/,
  );
  assert.throws(
    () => projectSkillCatalogInstallability({
      releaseSkill: { name: "named" },
      repositorySkill: { name: "  " },
    }),
    /Invalid skill metadata in repository skill\.json: "name" must be a non-empty string/,
  );
  assert.throws(
    () => projectSkillCatalogInstallability({
      releaseSkill: { name: "release-name" },
      repositorySkill: { name: "repository-name" },
    }),
    /Catalog skill identity mismatch: release name "release-name" does not match repository name "repository-name"/,
  );
  assert.throws(
    () => projectSkillCatalogInstallability({
      releaseSkill: { name: "actual-name" },
      expectedSkillName: "expected-name",
    }),
    /Catalog skill identity mismatch: release name "actual-name" does not match expected name "expected-name"/,
  );
  assert.throws(
    () => projectSkillCatalogInstallability({
      releaseSkill: { name: "actual-name" },
      expectedSkillName: "",
    }),
    /Invalid expected skill identity: "name" must be a non-empty string/,
  );

  const legacyReleaseSkillJsonPath = path.join(fixtureRoot, "legacy-release-skill.json");
  const legacyReleaseSource = `${JSON.stringify({
    name: "clawsec-nanoclaw",
    version: "0.0.10",
  }, null, 2)}\n`;
  await writeFile(legacyReleaseSkillJsonPath, legacyReleaseSource);

  const nanoClawRepositorySource = await readFile(nanoClawSkillJsonPath, "utf8");
  const nanoClawRepositorySkill = JSON.parse(nanoClawRepositorySource);
  assert.equal(nanoClawRepositorySkill.installable, false, "NanoClaw repository metadata must remain a tombstone");

  const nanoClawProjection = await projectSkillCatalogInstallabilityFromFiles({
    releaseSkillJsonPath: legacyReleaseSkillJsonPath,
    repositorySkillJsonPath: nanoClawSkillJsonPath,
    expectedSkillName: "clawsec-nanoclaw",
  });
  assert.deepEqual(nanoClawProjection, {
    release_installable: true,
    release_installable_explicitly_declared: false,
    repository_metadata_present: true,
    repository_installable: false,
    repository_installable_explicitly_declared: true,
    effective_installable: false,
  });
  assert.equal(
    await readFile(legacyReleaseSkillJsonPath, "utf8"),
    legacyReleaseSource,
    "projection must not mutate mirrored release metadata",
  );
  assert.equal(
    await readFile(nanoClawSkillJsonPath, "utf8"),
    nanoClawRepositorySource,
    "projection must not mutate repository metadata",
  );

  const cliResult = await runSkillCatalogInstallabilityCli([
    "--release-skill-json",
    legacyReleaseSkillJsonPath,
    "--repository-skill-json",
    nanoClawSkillJsonPath,
    "--expected-skill-name",
    "clawsec-nanoclaw",
  ]);
  assert.equal(cliResult.output, "false\n");
  assert.equal(cliResult.projection.effective_installable, false);
  assert.equal(cliResult.projection.repository_metadata_present, true);
  assert.equal(cliResult.projection.release_installable_explicitly_declared, false);
  assert.equal(cliResult.projection.repository_installable_explicitly_declared, true);

  const missingRepositoryResult = runProjectionCli(
    "--release-skill-json",
    legacyReleaseSkillJsonPath,
    "--expected-skill-name",
    "clawsec-nanoclaw",
  );
  assert.equal(missingRepositoryResult.status, 0, missingRepositoryResult.stderr);
  assert.equal(missingRepositoryResult.stdout, "false\n");
  assert.match(missingRepositoryResult.stderr, /"repository_metadata_present":false/);
  assert.match(missingRepositoryResult.stderr, /"repository_installable":false/);

  const spawnedCliResult = runProjectionCli(
    "--release-skill-json",
    legacyReleaseSkillJsonPath,
    "--repository-skill-json",
    nanoClawSkillJsonPath,
    "--expected-skill-name",
    "clawsec-nanoclaw",
  );
  assert.equal(spawnedCliResult.status, 0, spawnedCliResult.stderr);
  assert.equal(spawnedCliResult.stdout, "false\n", "CLI stdout must remain a JSON boolean token");
  assert.match(spawnedCliResult.stderr, /"repository_metadata_present":true/);
  assert.match(spawnedCliResult.stderr, /"release_installable_explicitly_declared":false/);
  assert.match(spawnedCliResult.stderr, /"repository_installable_explicitly_declared":true/);
  assert.equal(await readFile(legacyReleaseSkillJsonPath, "utf8"), legacyReleaseSource);
  assert.equal(await readFile(nanoClawSkillJsonPath, "utf8"), nanoClawRepositorySource);

  const invalidRepositorySkillJsonPath = path.join(fixtureRoot, "invalid-repository-skill.json");
  await writeFile(
    invalidRepositorySkillJsonPath,
    `${JSON.stringify({ name: "clawsec-nanoclaw", installable: "false" }, null, 2)}\n`,
  );
  await assert.rejects(
    projectSkillCatalogInstallabilityFromFiles({
      releaseSkillJsonPath: legacyReleaseSkillJsonPath,
      repositorySkillJsonPath: invalidRepositorySkillJsonPath,
      expectedSkillName: "clawsec-nanoclaw",
    }),
    /"installable" must be a boolean when present/,
  );

  const malformedSkillJsonPath = path.join(fixtureRoot, "malformed-skill.json");
  const unreadableSkillJsonPath = path.join(fixtureRoot, "unreadable-skill.json");
  const missingSkillJsonPath = path.join(fixtureRoot, "missing-skill.json");
  const missingRepositorySkillJsonPath = path.join(fixtureRoot, "missing-repository-skill.json");
  const missingNameSkillJsonPath = path.join(fixtureRoot, "missing-name-skill.json");
  const mismatchedRepositorySkillJsonPath = path.join(fixtureRoot, "mismatched-repository-skill.json");
  await writeFile(malformedSkillJsonPath, "{ not-json\n");
  await writeFile(missingNameSkillJsonPath, `${JSON.stringify({ version: "1.0.0" })}\n`);
  await writeFile(
    mismatchedRepositorySkillJsonPath,
    `${JSON.stringify({ name: "different-skill" })}\n`,
  );
  await mkdir(unreadableSkillJsonPath);

  const cliFailureCases = [
    [
      "missing release metadata",
      "--release-skill-json",
      missingSkillJsonPath,
      "--expected-skill-name",
      "clawsec-nanoclaw",
    ],
    [
      "malformed release metadata",
      "--release-skill-json",
      malformedSkillJsonPath,
      "--expected-skill-name",
      "clawsec-nanoclaw",
    ],
    [
      "unreadable release metadata",
      "--release-skill-json",
      unreadableSkillJsonPath,
      "--expected-skill-name",
      "clawsec-nanoclaw",
    ],
    [
      "missing repository metadata path",
      "--release-skill-json",
      legacyReleaseSkillJsonPath,
      "--repository-skill-json",
      missingRepositorySkillJsonPath,
      "--expected-skill-name",
      "clawsec-nanoclaw",
    ],
    [
      "invalid repository installability",
      "--release-skill-json",
      legacyReleaseSkillJsonPath,
      "--repository-skill-json",
      invalidRepositorySkillJsonPath,
      "--expected-skill-name",
      "clawsec-nanoclaw",
    ],
    [
      "missing release identity",
      "--release-skill-json",
      missingNameSkillJsonPath,
      "--expected-skill-name",
      "clawsec-nanoclaw",
    ],
    [
      "mismatched repository identity",
      "--release-skill-json",
      legacyReleaseSkillJsonPath,
      "--repository-skill-json",
      mismatchedRepositorySkillJsonPath,
      "--expected-skill-name",
      "clawsec-nanoclaw",
    ],
  ];
  for (const [description, ...args] of cliFailureCases) {
    const result = runProjectionCli(...args);
    assert.notEqual(result.status, 0, `${description} must fail`);
    assert.equal(result.stdout, "", `${description} must not emit a permissive boolean`);
  }

  const specialName = "skill name+[]$()";
  const specialReleaseSkillJsonPath = path.join(fixtureRoot, "release skill +[]$.json");
  const specialRepositorySkillJsonPath = path.join(fixtureRoot, "repository skill +[]$.json");
  const specialReleaseSource = `${JSON.stringify({ name: specialName, installable: true })}\n`;
  const specialRepositorySource = `${JSON.stringify({ name: specialName })}\n`;
  await writeFile(specialReleaseSkillJsonPath, specialReleaseSource);
  await writeFile(specialRepositorySkillJsonPath, specialRepositorySource);
  const specialNameResult = runProjectionCli(
    "--release-skill-json",
    specialReleaseSkillJsonPath,
    "--repository-skill-json",
    specialRepositorySkillJsonPath,
    "--expected-skill-name",
    specialName,
  );
  assert.equal(specialNameResult.status, 0, specialNameResult.stderr);
  assert.equal(specialNameResult.stdout, "true\n");
  assert.equal(await readFile(specialReleaseSkillJsonPath, "utf8"), specialReleaseSource);
  assert.equal(await readFile(specialRepositorySkillJsonPath, "utf8"), specialRepositorySource);

  const falseReleaseSkillJsonPath = path.join(fixtureRoot, "false-release-skill.json");
  const trueRepositorySkillJsonPath = path.join(fixtureRoot, "true-repository-skill.json");
  await writeFile(
    falseReleaseSkillJsonPath,
    `${JSON.stringify({ name: "release-denied", installable: false })}\n`,
  );
  await writeFile(
    trueRepositorySkillJsonPath,
    `${JSON.stringify({ name: "release-denied", installable: true })}\n`,
  );
  const falseReleaseResult = runProjectionCli(
    "--release-skill-json",
    falseReleaseSkillJsonPath,
    "--repository-skill-json",
    trueRepositorySkillJsonPath,
    "--expected-skill-name",
    "release-denied",
  );
  assert.equal(falseReleaseResult.status, 0, falseReleaseResult.stderr);
  assert.equal(falseReleaseResult.stdout, "false\n");

  const localProjectionRoot = await prepareLocalPopulatorFixture("local-projection");
  const legacyLocalSource = await writeFixtureSkill(
    localProjectionRoot,
    "legacy-public",
    localSkillMetadata("legacy-public", undefined),
  );
  const withdrawnLocalSource = await writeFixtureSkill(
    localProjectionRoot,
    "withdrawn-public",
    localSkillMetadata("withdrawn-public", false),
  );
  const specialLocalSource = await writeFixtureSkill(
    localProjectionRoot,
    "special+public",
    localSkillMetadata("special+public", true),
  );
  const nanoClawLocalSource = await writeFixtureSkill(
    localProjectionRoot,
    "clawsec-nanoclaw",
    nanoClawRepositorySource,
  );
  const localProjectionResult = runLocalPopulator(localProjectionRoot);
  assert.equal(localProjectionResult.status, 0, localProjectionResult.stderr);
  const generatedIndex = JSON.parse(
    await readFile(path.join(localProjectionRoot, "public/skills/index.json"), "utf8"),
  );
  const generatedByName = new Map(generatedIndex.skills.map((skill) => [skill.name, skill]));
  assert.equal(generatedByName.get("legacy-public")?.installable, true);
  assert.equal(generatedByName.get("withdrawn-public")?.installable, false);
  assert.equal(generatedByName.get("special+public")?.installable, true);
  assert.equal(generatedByName.get("clawsec-nanoclaw")?.installable, false);
  assert.equal(
    await readFile(path.join(localProjectionRoot, "skills/legacy-public/skill.json"), "utf8"),
    legacyLocalSource,
  );
  assert.equal(
    await readFile(path.join(localProjectionRoot, "skills/withdrawn-public/skill.json"), "utf8"),
    withdrawnLocalSource,
  );
  for (const [skillName, source] of [
    ["legacy-public", legacyLocalSource],
    ["withdrawn-public", withdrawnLocalSource],
    ["special+public", specialLocalSource],
    ["clawsec-nanoclaw", nanoClawLocalSource],
  ]) {
    assert.equal(
      await readFile(path.join(localProjectionRoot, `public/skills/${skillName}/skill.json`), "utf8"),
      source,
      `Local catalog copy for ${skillName} must remain byte-identical to source metadata`,
    );
  }

  const preflightRoot = await prepareLocalPopulatorFixture("local-preflight");
  await writeFixtureSkill(preflightRoot, "a-valid", localSkillMetadata("a-valid", true));
  await writeFixtureSkill(
    preflightRoot,
    "z-invalid",
    localSkillMetadata("z-invalid", "false"),
  );
  const sentinelIndexPath = path.join(preflightRoot, "public/skills/index.json");
  const sentinelSource = "sentinel catalog must survive failed preflight\n";
  await mkdir(path.dirname(sentinelIndexPath), { recursive: true });
  await writeFile(sentinelIndexPath, sentinelSource);
  const preflightResult = runLocalPopulator(preflightRoot);
  assert.notEqual(preflightResult.status, 0, "invalid lifecycle metadata must fail preflight");
  assert.equal(
    await readFile(sentinelIndexPath, "utf8"),
    sentinelSource,
    "preflight failure must occur before catalog truncation",
  );
  await assert.rejects(
    readFile(path.join(preflightRoot, "public/skills/a-valid/skill.json")),
    { code: "ENOENT" },
    "preflight failure must occur before the first skill copy",
  );

  const [workflow, localPopulator, helperSource] = await Promise.all([
    readFile(workflowPath, "utf8"),
    readFile(localPopulatorPath, "utf8"),
    readFile(
      projectionHelperPath,
      "utf8",
    ),
  ]);
  const helperInvocation = "project_skill_catalog_installability.mjs";

  assert.ok(workflow.includes(helperInvocation), "Pages deployment must use the shared projection helper");
  assert.ok(
    workflow.includes('--release-skill-json "$MIRROR_DIR/skill.json"'),
    "Pages deployment must resolve the immutable release metadata",
  );
  assert.ok(
    workflow.includes('--repository-skill-json "$REPOSITORY_SKILL_JSON"'),
    "Pages deployment must apply the checked-out repository lifecycle override",
  );
  assert.ok(
    workflow.includes('--expected-skill-name "$SKILL_NAME"'),
    "Pages deployment must bind release and repository metadata to the tag-derived skill identity",
  );
  assert.ok(
    workflow.includes('cp "$MIRROR_DIR/skill.json" "public/skills/${SKILL_NAME}/skill.json"'),
    "Pages deployment must preserve release metadata as an unmodified catalog artifact",
  );
  assert.ok(
    workflow.includes('--argjson installable "$EFFECTIVE_INSTALLABLE"'),
    "Pages deployment must pass a JSON boolean into the index projection",
  );
  assert.ok(
    workflow.includes("installable: $installable"),
    "Pages deployment must publish the effective boolean in each index record",
  );

  assert.ok(localPopulator.includes(helperInvocation), "Local population must use the shared projection helper");
  assert.ok(
    localPopulator.includes('--release-skill-json "$SKILL_JSON"'),
    "Local population must validate source metadata",
  );
  assert.ok(
    localPopulator.includes('--repository-skill-json "$SKILL_JSON"'),
    "Local population must apply the same repository lifecycle rule",
  );
  assert.ok(
    localPopulator.includes('--expected-skill-name "$SKILL_NAME"'),
    "Local population must bind both metadata roles to the directory-derived skill identity",
  );
  assert.ok(
    localPopulator.includes('--argjson installable "$EFFECTIVE_INSTALLABLE"'),
    "Local population must pass a JSON boolean into the index projection",
  );
  assert.ok(
    localPopulator.includes("installable: $installable"),
    "Local population must publish the effective boolean in each index record",
  );

  const preflightCompletionIndex = localPopulator.indexOf("Lifecycle metadata preflight passed.");
  const firstPublicDirectoryMutationIndex = localPopulator.indexOf('mkdir -p "$PUBLIC_SKILLS_DIR"');
  const indexTruncationIndex = localPopulator.indexOf('> "$PUBLIC_SKILLS_DIR/index.json"');
  const firstSkillCopyIndex = localPopulator.indexOf('cp "$SKILL_JSON"');
  assert.notEqual(preflightCompletionIndex, -1, "Local population must declare a lifecycle preflight boundary");
  for (const [description, mutationIndex] of [
    ["public directory creation", firstPublicDirectoryMutationIndex],
    ["index truncation", indexTruncationIndex],
    ["skill copy", firstSkillCopyIndex],
  ]) {
    assert.notEqual(mutationIndex, -1, `Missing expected local output mutation: ${description}`);
    assert.ok(
      preflightCompletionIndex < mutationIndex,
      `Lifecycle preflight must finish before ${description}`,
    );
  }

  assert.match(helperSource, /repository_metadata_present: repositoryMetadataPresent/);
  assert.match(helperSource, /release_installable_explicitly_declared: release\.explicitlyDeclared/);
  assert.match(helperSource, /repository_installable_explicitly_declared: repository\.explicitlyDeclared/);

  assert.doesNotMatch(
    `${workflow}\n${localPopulator}\n${helperSource}`,
    /\.installable\s*\/\/\s*true/,
    "jq alternative defaults must not turn an explicit false value back into true",
  );

  process.stdout.write("Skill catalog installability projection tests passed.\n");
} finally {
  await rm(fixtureRoot, { recursive: true, force: true });
}
