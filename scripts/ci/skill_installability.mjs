#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

function usage() {
  return [
    "Usage: node scripts/ci/skill_installability.mjs <skill-dir> [--require-publication]",
    "",
    "Without --require-publication, prints the resolved installable value.",
    "With --require-publication, fails when the skill is non-installable.",
  ].join("\n");
}

function validateSkillObject(skill, source) {
  if (!skill || typeof skill !== "object" || Array.isArray(skill)) {
    throw new Error(`Invalid skill metadata in ${source}: expected a JSON object`);
  }
}

export function resolveSkillInstallability(skill, source = "skill.json") {
  validateSkillObject(skill, source);

  const explicitlyDeclared = Object.hasOwn(skill, "installable");
  if (explicitlyDeclared && typeof skill.installable !== "boolean") {
    throw new Error(
      `Invalid skill metadata in ${source}: "installable" must be a boolean when present`,
    );
  }

  return {
    installable: explicitlyDeclared ? skill.installable : true,
    explicitlyDeclared,
  };
}

export function requireSkillPublication(skill, source = "skill.json") {
  const resolution = resolveSkillInstallability(skill, source);
  if (!resolution.installable) {
    throw new Error(
      `Publication denied for ${source}: skill.json declares "installable": false`,
    );
  }
  return resolution;
}

export async function loadSkillInstallability(skillDir) {
  if (typeof skillDir !== "string" || !skillDir.trim()) {
    throw new Error("Skill directory must be a non-empty path");
  }

  const resolvedSkillDir = path.resolve(skillDir);
  const skillJsonPath = path.join(resolvedSkillDir, "skill.json");
  let source;
  try {
    source = await readFile(skillJsonPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`Skill metadata not found: ${skillJsonPath}`);
    }
    throw new Error(`Unable to read skill metadata: ${skillJsonPath}`);
  }

  let skill;
  try {
    skill = JSON.parse(source);
  } catch {
    throw new Error(`Invalid JSON in skill metadata: ${skillJsonPath}`);
  }

  return {
    skillDir: resolvedSkillDir,
    skillJsonPath,
    skill,
    ...resolveSkillInstallability(skill, skillJsonPath),
  };
}

function parseArgs(argv) {
  const positional = [];
  let requirePublication = false;

  for (const argument of argv) {
    if (argument === "--require-publication") {
      requirePublication = true;
    } else if (argument === "--help" || argument === "-h") {
      return { help: true, requirePublication, skillDir: "" };
    } else if (argument.startsWith("--")) {
      throw new Error(`Unknown option: ${argument}\n${usage()}`);
    } else {
      positional.push(argument);
    }
  }

  if (positional.length !== 1) {
    throw new Error(usage());
  }

  return {
    help: false,
    requirePublication,
    skillDir: positional[0],
  };
}

export async function runSkillInstallabilityCli(argv) {
  const options = parseArgs(argv);
  if (options.help) {
    return { output: `${usage()}\n` };
  }

  const resolution = await loadSkillInstallability(options.skillDir);
  if (options.requirePublication) {
    requireSkillPublication(resolution.skill, resolution.skillJsonPath);
  }

  return {
    output: `${resolution.installable}\n`,
    resolution,
  };
}

async function main() {
  const result = await runSkillInstallabilityCli(process.argv.slice(2));
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
