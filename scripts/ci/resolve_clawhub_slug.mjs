#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const PLATFORM_KEYS = ["openclaw", "hermes", "nanoclaw", "picoclaw"];
const EXPLICIT_SLUGS = new Map([
  ["openclaw-traffic-guardian", "clawsec-openclaw-traffic-guardian"],
  ["openclaw-audit-watchdog", "clawsec-openclaw-audit-watchdog"],
  ["soul-guardian", "clawsec-openclaw-soul-guardian"],
  ["hermes-attestation-guardian", "clawsec-hermes-attestation-guardian"],
  ["hermes-traffic-guardian", "clawsec-hermes-traffic-guardian"],
  ["nanoclaw-traffic-guardian", "clawsec-nanoclaw-traffic-guardian"],
  ["picoclaw-security-guardian", "clawsec-picoclaw-security-guardian"],
  ["picoclaw-self-pen-testing", "clawsec-picoclaw-self-pen-testing"],
  ["picoclaw-traffic-guardian", "clawsec-picoclaw-traffic-guardian"],
  ["clawtributor", "clawsec-clawtributor"],
]);

function usage() {
  return [
    "Usage: node scripts/ci/resolve_clawhub_slug.mjs <skill-dir-or-name>",
    "",
    "Prints the ClawHub slug for a skill without changing the GitHub release tag or skill package name.",
  ].join("\n");
}

function asStringArray(value) {
  if (Array.isArray(value)) {
    return value.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim());
  }
  if (typeof value === "string" && value.trim()) {
    return [value.trim()];
  }
  return [];
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function collectPlatforms(skill) {
  return unique([
    ...asStringArray(skill.platform),
    ...asStringArray(skill.platforms),
    ...PLATFORM_KEYS.filter((key) => skill[key] && typeof skill[key] === "object"),
  ]);
}

function loadSkill(input) {
  const skillJsonPath = existsSync(path.join(input, "skill.json")) ? path.join(input, "skill.json") : null;
  if (!skillJsonPath) {
    return { name: input, platforms: [] };
  }

  const skill = JSON.parse(readFileSync(skillJsonPath, "utf8"));
  if (!skill.name || typeof skill.name !== "string") {
    throw new Error(`${skillJsonPath} missing string field: name`);
  }

  return { name: skill.name, platforms: collectPlatforms(skill) };
}

export function resolveClawHubSlug({ name, platforms = [] }) {
  if (!/^[a-z0-9-]+$/.test(name)) {
    throw new Error(`Invalid skill name for ClawHub slug mapping: ${name}`);
  }

  if (name.startsWith("clawsec-")) {
    return name;
  }

  if (EXPLICIT_SLUGS.has(name)) {
    return EXPLICIT_SLUGS.get(name);
  }

  if (PLATFORM_KEYS.some((platform) => name.startsWith(`${platform}-`))) {
    return `clawsec-${name}`;
  }

  const declaredPlatforms = unique(platforms);
  if (declaredPlatforms.length === 1 && PLATFORM_KEYS.includes(declaredPlatforms[0])) {
    return `clawsec-${declaredPlatforms[0]}-${name}`;
  }

  return `clawsec-${name}`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = process.argv[2];
  if (!input || input === "--help" || input === "-h") {
    console.log(usage());
    process.exit(input ? 0 : 1);
  }

  try {
    console.log(resolveClawHubSlug(loadSkill(input)));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
