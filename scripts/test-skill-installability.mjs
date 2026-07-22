import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  loadSkillInstallability,
  requireSkillPublication,
  resolveSkillInstallability,
  runSkillInstallabilityCli,
} from "./ci/skill_installability.mjs";

const scriptPath = path.resolve("scripts/ci/skill_installability.mjs");
const fixtureRoot = await mkdtemp(path.join(tmpdir(), "clawsec-installability-"));

async function writeSkill(name, metadataSource) {
  const skillDir = path.join(fixtureRoot, name);
  await mkdir(skillDir, { recursive: true });
  const source = typeof metadataSource === "string"
    ? metadataSource
    : `${JSON.stringify(metadataSource, null, 2)}\n`;
  await writeFile(path.join(skillDir, "skill.json"), source);
  return skillDir;
}

function runCli(skillDir, ...options) {
  return spawnSync(process.execPath, [scriptPath, skillDir, ...options], {
    encoding: "utf8",
  });
}

try {
  assert.deepEqual(resolveSkillInstallability({ name: "absent" }), {
    installable: true,
    explicitlyDeclared: false,
  });
  assert.deepEqual(resolveSkillInstallability({ name: "enabled", installable: true }), {
    installable: true,
    explicitlyDeclared: true,
  });
  assert.deepEqual(resolveSkillInstallability({ name: "disabled", installable: false }), {
    installable: false,
    explicitlyDeclared: true,
  });
  assert.throws(
    () => resolveSkillInstallability({ installable: "false" }, "fixture/skill.json"),
    /Invalid skill metadata in fixture\/skill\.json: "installable" must be a boolean when present/,
  );
  assert.throws(
    () => resolveSkillInstallability([], "fixture/skill.json"),
    /Invalid skill metadata in fixture\/skill\.json: expected a JSON object/,
  );
  assert.throws(
    () => requireSkillPublication({ installable: false }, "fixture/skill.json"),
    /Publication denied for fixture\/skill\.json: skill\.json declares "installable": false/,
  );

  const absentDir = await writeSkill("absent", { name: "absent", version: "0.0.1" });
  const trueDir = await writeSkill("true", {
    name: "true",
    version: "0.0.1",
    installable: true,
  });
  const falseDir = await writeSkill("false", {
    name: "false",
    version: "0.0.1",
    installable: false,
  });
  const invalidTypeDir = await writeSkill("invalid-type", {
    name: "invalid-type",
    version: "0.0.1",
    installable: "false",
  });
  const badJsonDir = await writeSkill("bad-json", "{ not-json\n");
  const missingDir = path.join(fixtureRoot, "missing");

  const absentResolution = await loadSkillInstallability(absentDir);
  assert.equal(absentResolution.installable, true);
  assert.equal(absentResolution.explicitlyDeclared, false);
  assert.equal(absentResolution.skillJsonPath, path.join(absentDir, "skill.json"));

  const importedCliResult = await runSkillInstallabilityCli([falseDir]);
  assert.equal(importedCliResult.output, "false\n");
  assert.equal(importedCliResult.resolution.installable, false);

  for (const skillDir of [absentDir, trueDir]) {
    const resolveResult = runCli(skillDir);
    assert.equal(resolveResult.status, 0, resolveResult.stderr);
    assert.equal(resolveResult.stdout, "true\n");
    assert.equal(resolveResult.stderr, "");

    const publicationResult = runCli(skillDir, "--require-publication");
    assert.equal(publicationResult.status, 0, publicationResult.stderr);
    assert.equal(publicationResult.stdout, "true\n");
    assert.equal(publicationResult.stderr, "");
  }

  const falseResolveResult = runCli(falseDir);
  assert.equal(falseResolveResult.status, 0, falseResolveResult.stderr);
  assert.equal(falseResolveResult.stdout, "false\n");
  assert.equal(falseResolveResult.stderr, "");

  const falsePublicationResult = runCli(falseDir, "--require-publication");
  assert.equal(falsePublicationResult.status, 1);
  assert.equal(falsePublicationResult.stdout, "");
  assert.equal(
    falsePublicationResult.stderr,
    `Publication denied for ${path.join(falseDir, "skill.json")}: skill.json declares "installable": false\n`,
  );

  const invalidTypeResult = runCli(invalidTypeDir);
  assert.equal(invalidTypeResult.status, 1);
  assert.equal(invalidTypeResult.stdout, "");
  assert.equal(
    invalidTypeResult.stderr,
    `Invalid skill metadata in ${path.join(invalidTypeDir, "skill.json")}: "installable" must be a boolean when present\n`,
  );

  const badJsonResult = runCli(badJsonDir);
  assert.equal(badJsonResult.status, 1);
  assert.equal(badJsonResult.stdout, "");
  assert.equal(
    badJsonResult.stderr,
    `Invalid JSON in skill metadata: ${path.join(badJsonDir, "skill.json")}\n`,
  );

  const missingResult = runCli(missingDir);
  assert.equal(missingResult.status, 1);
  assert.equal(missingResult.stdout, "");
  assert.equal(
    missingResult.stderr,
    `Skill metadata not found: ${path.join(missingDir, "skill.json")}\n`,
  );

  const unknownOptionResult = spawnSync(
    process.execPath,
    [scriptPath, absentDir, "--unknown"],
    { encoding: "utf8" },
  );
  assert.equal(unknownOptionResult.status, 1);
  assert.match(unknownOptionResult.stderr, /^Unknown option: --unknown\nUsage:/);

  const helpResult = spawnSync(process.execPath, [scriptPath, "--help"], { encoding: "utf8" });
  assert.equal(helpResult.status, 0, helpResult.stderr);
  assert.match(helpResult.stdout, /^Usage:/);

  process.stdout.write("Skill installability contract tests passed.\n");
} finally {
  await rm(fixtureRoot, { recursive: true, force: true });
}
