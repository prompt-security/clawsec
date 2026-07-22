#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { resolveSkillInstallability } from "./skill_installability.mjs";

function usage() {
  return [
    "Usage:",
    "  node scripts/ci/project_skill_catalog_installability.mjs --release-skill-json <path> [--repository-skill-json <path>] [--expected-skill-name <name>]",
    "",
    "Projects the catalog lifecycle bit without changing either metadata file.",
    "A missing installable field resolves to true; an invalid value is rejected.",
    "An omitted repository metadata source resolves to non-installable.",
  ].join("\n");
}

async function readSkillJson(skillJsonPath, label) {
  let source;
  try {
    source = await readFile(skillJsonPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`${label} metadata not found: ${skillJsonPath}`);
    }
    throw new Error(`Unable to read ${label.toLowerCase()} metadata: ${skillJsonPath}`);
  }

  try {
    return JSON.parse(source);
  } catch {
    throw new Error(`Invalid JSON in ${label.toLowerCase()} metadata: ${skillJsonPath}`);
  }
}

function requireSkillName(skill, source) {
  if (typeof skill.name !== "string" || !skill.name.trim()) {
    throw new Error(`Invalid skill metadata in ${source}: "name" must be a non-empty string`);
  }
  return skill.name;
}

function requireExpectedSkillName(expectedSkillName) {
  if (typeof expectedSkillName !== "string" || !expectedSkillName.trim()) {
    throw new Error('Invalid expected skill identity: "name" must be a non-empty string');
  }
  return expectedSkillName;
}

export function projectSkillCatalogInstallability({
  releaseSkill,
  repositorySkill,
  expectedSkillName,
  releaseSource = "release skill.json",
  repositorySource = "repository skill.json",
}) {
  const release = resolveSkillInstallability(releaseSkill, releaseSource);
  const repositoryMetadataPresent = repositorySkill !== undefined;
  const repository = repositoryMetadataPresent
    ? resolveSkillInstallability(repositorySkill, repositorySource)
    : { installable: false, explicitlyDeclared: false };

  const releaseName = requireSkillName(releaseSkill, releaseSource);
  const repositoryName = repositoryMetadataPresent
    ? requireSkillName(repositorySkill, repositorySource)
    : undefined;

  if (repositoryMetadataPresent && releaseName !== repositoryName) {
    throw new Error(
      `Catalog skill identity mismatch: release name "${releaseName}" does not match repository name "${repositoryName}"`,
    );
  }

  if (expectedSkillName !== undefined) {
    const expectedName = requireExpectedSkillName(expectedSkillName);
    if (releaseName !== expectedName) {
      throw new Error(
        `Catalog skill identity mismatch: release name "${releaseName}" does not match expected name "${expectedName}"`,
      );
    }
    if (repositoryMetadataPresent && repositoryName !== expectedName) {
      throw new Error(
        `Catalog skill identity mismatch: repository name "${repositoryName}" does not match expected name "${expectedName}"`,
      );
    }
  }

  return {
    release_installable: release.installable,
    release_installable_explicitly_declared: release.explicitlyDeclared,
    repository_metadata_present: repositoryMetadataPresent,
    repository_installable: repository.installable,
    repository_installable_explicitly_declared: repository.explicitlyDeclared,
    effective_installable: release.installable && repository.installable,
  };
}

export async function projectSkillCatalogInstallabilityFromFiles({
  releaseSkillJsonPath,
  repositorySkillJsonPath,
  expectedSkillName,
}) {
  const releaseSkill = await readSkillJson(releaseSkillJsonPath, "Release skill.json");
  const repositorySkill = repositorySkillJsonPath
    ? await readSkillJson(repositorySkillJsonPath, "Repository skill.json")
    : undefined;

  return projectSkillCatalogInstallability({
    releaseSkill,
    repositorySkill,
    expectedSkillName,
    releaseSource: releaseSkillJsonPath,
    repositorySource: repositorySkillJsonPath,
  });
}

function readOptionValue(argv, index, option) {
  const value = argv[index + 1];
  if (value === undefined || value === "") {
    throw new Error(`Missing value for ${option}\n${usage()}`);
  }
  return value;
}

function parseArgs(argv) {
  const options = {
    help: false,
    releaseSkillJsonPath: "",
    repositorySkillJsonPath: "",
    expectedSkillName: undefined,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") {
      options.help = true;
    } else if (argument === "--release-skill-json") {
      options.releaseSkillJsonPath = readOptionValue(argv, index, argument);
      index += 1;
    } else if (argument === "--repository-skill-json") {
      options.repositorySkillJsonPath = readOptionValue(argv, index, argument);
      index += 1;
    } else if (argument === "--expected-skill-name") {
      options.expectedSkillName = readOptionValue(argv, index, argument);
      index += 1;
    } else {
      throw new Error(`Unknown option: ${argument}\n${usage()}`);
    }
  }

  if (!options.help && !options.releaseSkillJsonPath) {
    throw new Error(usage());
  }

  return options;
}

export async function runSkillCatalogInstallabilityCli(argv) {
  const options = parseArgs(argv);
  if (options.help) {
    return { output: `${usage()}\n` };
  }

  const projection = await projectSkillCatalogInstallabilityFromFiles(options);
  return {
    output: `${projection.effective_installable}\n`,
    projection,
  };
}

async function main() {
  const result = await runSkillCatalogInstallabilityCli(process.argv.slice(2));
  if (result.projection) {
    process.stderr.write(`Catalog installability projection: ${JSON.stringify(result.projection)}\n`);
  }
  process.stdout.write(result.output);
}

const invokedUrl = process.argv[1]
  ? pathToFileURL(path.resolve(process.argv[1])).href
  : "";
if (import.meta.url === invokedUrl) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  });
}
