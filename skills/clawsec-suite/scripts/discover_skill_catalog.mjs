#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadTextFile } from "./local_file_io.mjs";

const DEFAULT_INDEX_URL = "https://clawsec.prompt.security/skills/index.json";
const DEFAULT_TIMEOUT_MS = 5000;
const EXIT_RECOMMENDATION_DENIED = 2;
const SAFE_SKILL_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SAFE_CATALOG_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const SAFE_CATALOG_UPDATED = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SUITE_DIR = path.resolve(SCRIPT_DIR, "..");
const SUITE_SKILL_JSON = path.join(SUITE_DIR, "skill.json");

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonicalSkillId(value) {
  return value.normalize("NFKC").toLowerCase();
}

function requireExactString(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw new Error(`${label} must be an exact non-empty string`);
  }
  return value;
}

function optionalString(value, label) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string when present`);
  }
  return value.trim() || null;
}

function optionalStringArray(value, label) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array when present`);
  }
  return value.map((entry, index) => requireExactString(entry, `${label} entry at index ${index}`));
}

function optionalCatalogVersion(value) {
  if (value === undefined || value === null) return null;
  const version = requireExactString(value, "Catalog index version");
  if (!SAFE_CATALOG_VERSION.test(version)) {
    throw new Error("Catalog index version must use numeric major.minor.patch form");
  }
  return version;
}

function optionalCatalogUpdated(value) {
  if (value === undefined || value === null) return null;
  const updated = requireExactString(value, "Catalog index updated");
  const timestamp = Date.parse(updated);
  const normalized = Number.isFinite(timestamp)
    ? new Date(timestamp).toISOString().replace(".000Z", "Z")
    : null;
  if (!SAFE_CATALOG_UPDATED.test(updated) || normalized !== updated) {
    throw new Error("Catalog index updated must be a valid UTC timestamp");
  }
  return updated;
}

function normalizeBoolean(value) {
  return value === true;
}

const ENVIRONMENT = (() => {
  const runtimeProcess = Reflect.get(globalThis, "process");
  if (!runtimeProcess || typeof runtimeProcess !== "object") return {};
  if (!("env" in runtimeProcess)) return {};
  const env = runtimeProcess.env;
  return env && typeof env === "object" ? env : {};
})();

function envVar(name) {
  const value = ENVIRONMENT[name];
  return typeof value === "string" ? value.trim() : "";
}

function parseTimeoutMs() {
  const raw = envVar("CLAWSEC_SKILLS_INDEX_TIMEOUT_MS");
  if (!raw) return DEFAULT_TIMEOUT_MS;

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_TIMEOUT_MS;
  }
  return parsed;
}

function indexUrlForOutput(value) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return null;
  }
}

function validateRequestedSkill(value) {
  const skillId = requireExactString(value, "--skill value");
  if (skillId !== canonicalSkillId(skillId) || !SAFE_SKILL_ID.test(skillId)) {
    throw new Error("Invalid --skill value. Use canonical lowercase letters, digits, and single hyphens only.");
  }
  return skillId;
}

function parseArgs(argv) {
  const args = {
    json: false,
    skill: null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];

    if (token === "--json") {
      if (args.json) throw new Error("Duplicate argument: --json");
      args.json = true;
      continue;
    }
    if (token === "--skill") {
      if (args.skill !== null) throw new Error("Duplicate argument: --skill");
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("-")) {
        throw new Error("Missing value for --skill");
      }
      args.skill = validateRequestedSkill(value);
      index += 1;
      continue;
    }
    if (token === "--help" || token === "-h") {
      printUsage();
      process.exit(0);
    }

    throw new Error(`Unknown argument: ${token}`);
  }

  return args;
}

function printUsage() {
  process.stdout.write(
    [
      "Usage:",
      "  node scripts/discover_skill_catalog.mjs [--skill <skill-id>] [--json]",
      "",
      "Behavior:",
      "  - Fetches the projected catalog from CLAWSEC_SKILLS_INDEX_URL",
      "  - Lists only exact remote records that the lifecycle projection does not deny",
      "  - Treats suite-local catalog metadata as non-authorizing context only",
      "  - Emits no install command when the remote catalog is unavailable, malformed, missing the requested record, or explicitly non-installable",
      "  - Acts only as a denial overlay; positive stable-install authorization is evaluated separately",
      "",
      "Environment:",
      "  CLAWSEC_SKILLS_INDEX_URL         Override remote catalog index URL",
      "  CLAWSEC_SKILLS_INDEX_TIMEOUT_MS  HTTP timeout in milliseconds (default: 5000)",
      "",
      "Exit codes:",
      "  0  catalog report or lifecycle-screened candidate",
      `  ${EXIT_RECOMMENDATION_DENIED}  requested skill was not eligible for recommendation`,
      "  1  invalid arguments or runtime error",
      "",
    ].join("\n"),
  );
}

function normalizeRemoteSkills(payload) {
  if (!isObject(payload)) {
    throw new Error("Catalog index payload must be a JSON object");
  }

  const rawSkills = payload.skills;
  if (!Array.isArray(rawSkills)) {
    throw new Error("Catalog index missing skills array");
  }

  const exactIds = new Set();
  const canonicalIds = new Map();
  const records = [];

  for (let index = 0; index < rawSkills.length; index += 1) {
    const entry = rawSkills[index];
    const label = `Catalog skill at index ${index}`;
    if (!isObject(entry)) {
      throw new Error(`${label} must be a JSON object`);
    }

    const id = requireExactString(entry.id, `${label} id`);
    const name = requireExactString(entry.name, `${label} name`);
    const version = requireExactString(entry.version, `${label} version`);
    const tag = requireExactString(entry.tag, `${label} tag`);
    const canonicalId = canonicalSkillId(id);

    if (exactIds.has(id)) {
      throw new Error(`Catalog index contains duplicate skill id: ${id}`);
    }
    const canonicalOwner = canonicalIds.get(canonicalId);
    if (canonicalOwner !== undefined) {
      throw new Error(`Catalog index contains canonical skill-id collision: ${canonicalOwner} and ${id}`);
    }
    exactIds.add(id);
    canonicalIds.set(canonicalId, id);

    if (id !== canonicalId || !SAFE_SKILL_ID.test(id)) {
      throw new Error(`${label} id must use canonical lowercase letters, digits, and single hyphens only`);
    }
    if (id !== name) {
      throw new Error(`${label} id and name must match exactly`);
    }
    if (tag !== `${name}-v${version}`) {
      throw new Error(`${label} tag must equal ${name}-v${version}`);
    }

    const installableExplicitlyDeclared = Object.hasOwn(entry, "installable");
    if (installableExplicitlyDeclared && typeof entry.installable !== "boolean") {
      throw new Error(`${label} installable must be a boolean when present`);
    }
    const installable = installableExplicitlyDeclared ? entry.installable : true;

    records.push({
      id,
      name,
      version,
      description: optionalString(entry.description, `${label} description`),
      emoji: optionalString(entry.emoji, `${label} emoji`),
      category: optionalString(entry.category, `${label} category`),
      platforms: optionalStringArray(entry.platforms, `${label} platforms`),
      tag,
      trust: optionalString(entry.trust, `${label} trust`),
      installable,
      installable_explicitly_declared: installableExplicitlyDeclared,
      lifecycle_status: installable ? "not_denied" : "historical",
      source: "remote",
    });
  }

  return {
    version: optionalCatalogVersion(payload.version),
    updated: optionalCatalogUpdated(payload.updated),
    records: records.sort((left, right) => left.id.localeCompare(right.id)),
  };
}

async function loadFallbackCatalog() {
  const raw = await loadTextFile(SUITE_SKILL_JSON);
  const parsed = JSON.parse(raw);
  if (!isObject(parsed)) {
    throw new Error("Suite skill.json must contain a JSON object");
  }

  const catalogSkills = isObject(parsed.catalog?.skills) ? parsed.catalog.skills : {};
  const context = [];

  for (const [rawId, meta] of Object.entries(catalogSkills)) {
    if (rawId !== canonicalSkillId(rawId) || !SAFE_SKILL_ID.test(rawId)) {
      throw new Error(`Suite-local catalog contains invalid skill id: ${rawId}`);
    }

    const safeMeta = isObject(meta) ? meta : {};
    context.push({
      id: rawId,
      name: rawId,
      version: null,
      description: optionalString(safeMeta.description, `Suite-local catalog ${rawId} description`),
      emoji: null,
      category: null,
      platforms: [],
      tag: null,
      trust: null,
      installable: false,
      installable_explicitly_declared: false,
      lifecycle_status: "local_context_only",
      source: "fallback",
      integrated_in_suite: normalizeBoolean(safeMeta.integrated_in_suite),
      requires_explicit_consent: normalizeBoolean(safeMeta.requires_explicit_consent),
      default_install: normalizeBoolean(safeMeta.default_install),
    });
  }

  return context.sort((left, right) => left.id.localeCompare(right.id));
}

function enrichWithFallbackMetadata(remoteRecords, fallbackContext) {
  const fallbackById = new Map(fallbackContext.map((skill) => [skill.id, skill]));

  return remoteRecords.map((skill) => {
    const fallback = fallbackById.get(skill.id);
    return {
      ...skill,
      description: skill.description || fallback?.description || null,
      integrated_in_suite: normalizeBoolean(fallback?.integrated_in_suite),
      requires_explicit_consent: normalizeBoolean(fallback?.requires_explicit_consent),
      default_install: normalizeBoolean(fallback?.default_install),
    };
  });
}

function toNonAuthorizingSummary(skill) {
  return {
    id: skill.id,
    name: skill.id,
    version: null,
    description: null,
    emoji: null,
    category: null,
    platforms: [],
    tag: null,
    trust: null,
    installable: false,
    installable_explicitly_declared: normalizeBoolean(skill.installable_explicitly_declared),
    lifecycle_status: skill.lifecycle_status,
    source: skill.source,
    integrated_in_suite: normalizeBoolean(skill.integrated_in_suite),
    requires_explicit_consent: normalizeBoolean(skill.requires_explicit_consent),
    default_install: normalizeBoolean(skill.default_install),
  };
}

async function loadRemoteCatalog(indexUrl, timeoutMs) {
  if (typeof globalThis.fetch !== "function") {
    throw new Error("fetch is unavailable in this runtime");
  }
  if (typeof globalThis.AbortController !== "function") {
    throw new Error("AbortController is unavailable in this runtime");
  }

  const controller = new globalThis.AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await globalThis.fetch(indexUrl, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} while fetching catalog`);
    }

    const payload = await response.json();
    return normalizeRemoteSkills(payload);
  } finally {
    clearTimeout(timeout);
  }
}

function formatFlags(skill) {
  const flags = [];

  if (skill.id === "clawsec-suite") {
    flags.push("this suite");
  }
  if (skill.integrated_in_suite) {
    flags.push("already integrated in suite");
  }
  if (skill.requires_explicit_consent) {
    flags.push("explicit opt-in");
  }
  if (skill.default_install) {
    flags.push(
      skill.installable
        ? "suite default preference (lifecycle screened only)"
        : "packaged default preference (non-authorizing)",
    );
  }

  return flags;
}

function buildRecommendation(requestedSkill, remoteRecords, catalogAvailable) {
  if (!requestedSkill) return null;

  if (!catalogAvailable) {
    return {
      requested_skill: requestedSkill,
      status: "denied",
      reason: "catalog_unavailable",
    };
  }

  const record = remoteRecords.find((skill) => skill.id === requestedSkill);
  if (!record) {
    return {
      requested_skill: requestedSkill,
      status: "denied",
      reason: "missing_remote_record",
    };
  }
  if (!record.installable) {
    return {
      requested_skill: requestedSkill,
      status: "denied",
      reason: "non_installable",
    };
  }

  return {
    requested_skill: requestedSkill,
    status: "eligible_candidate",
    reason: "remote_lifecycle_not_denied",
    stable_authorization: "not_evaluated",
    version: record.version,
    tag: record.tag,
    install_command: `npx clawhub@latest install ${record.id}`,
  };
}

function printSkillDetails(skill) {
  const label = skill.version ? `${skill.id} (v${skill.version})` : skill.id;
  process.stdout.write(`- ${label}\n`);
  if (skill.description) {
    process.stdout.write(`  ${skill.description}\n`);
  }

  const flags = formatFlags(skill);
  if (flags.length > 0) {
    process.stdout.write(`  notes: ${flags.join("; ")}\n`);
  }
}

function printHumanSummary(result) {
  process.stdout.write("=== ClawSec Skill Catalog Discovery ===\n");
  process.stdout.write(`Source: ${result.source}\n`);
  process.stdout.write(`Status: ${result.status}\n`);
  if (result.index_url) {
    process.stdout.write(`Index URL: ${result.index_url}\n`);
  }
  if (result.updated) {
    process.stdout.write(`Catalog updated: ${result.updated}\n`);
  }
  if (result.warning) {
    process.stdout.write(`Catalog warning: ${result.warning}\n`);
  }

  if (result.recommendation) {
    process.stdout.write("\nRequested skill lifecycle screen:\n");
    process.stdout.write(`- skill: ${result.recommendation.requested_skill}\n`);
    process.stdout.write(`- status: ${result.recommendation.status}\n`);
    process.stdout.write(`- reason: ${result.recommendation.reason}\n`);
    if (result.recommendation.status === "eligible_candidate") {
      process.stdout.write(`- install: ${result.recommendation.install_command}\n`);
    } else {
      process.stdout.write("- no install command was emitted\n");
    }
    return;
  }

  process.stdout.write("\nLifecycle-screened candidates (not stable authorization):\n");
  if (result.skills.length === 0) {
    process.stdout.write("- none\n");
  } else {
    for (const skill of result.skills) {
      printSkillDetails(skill);
      process.stdout.write(`  install: npx clawhub@latest install ${skill.id}\n`);
    }
  }

  if (result.historical.length > 0) {
    process.stdout.write("\nHistorical, non-installable remote records:\n");
    for (const skill of result.historical) {
      printSkillDetails(skill);
      process.stdout.write("  lifecycle: historical; no install recommendation\n");
    }
  }

  if (result.context.length > 0) {
    process.stdout.write("\nSuite-local context (non-authorizing):\n");
    for (const skill of result.context) {
      printSkillDetails(skill);
      process.stdout.write("  lifecycle: local context only; no install recommendation\n");
    }
  }
}

async function discoverCatalog(requestedSkill) {
  const indexUrl = envVar("CLAWSEC_SKILLS_INDEX_URL") || DEFAULT_INDEX_URL;
  const outputIndexUrl = indexUrlForOutput(indexUrl);
  const timeoutMs = parseTimeoutMs();
  const fallbackContext = await loadFallbackCatalog();

  try {
    const remote = await loadRemoteCatalog(indexUrl, timeoutMs);
    const records = enrichWithFallbackMetadata(remote.records, fallbackContext);
    const skills = records.filter((skill) => skill.installable);
    const historical = records
      .filter((skill) => !skill.installable)
      .map(toNonAuthorizingSummary);
    const context = fallbackContext.map(toNonAuthorizingSummary);
    const recommendation = buildRecommendation(requestedSkill, records, true);
    const requestDenied = recommendation?.status === "denied";
    const requestedOnly = (entries) =>
      requestedSkill ? entries.filter((entry) => entry.id === requestedSkill) : entries;

    return {
      source: "remote",
      status: "available",
      catalog_role: "denial_overlay",
      stable_authorization: "not_evaluated",
      index_url: outputIndexUrl,
      version: requestDenied ? null : remote.version,
      updated: requestDenied ? null : remote.updated,
      skills: requestDenied ? [] : requestedOnly(skills),
      historical: requestedOnly(historical),
      context: requestedOnly(context),
      recommendation,
      warning: null,
    };
  } catch {
    return {
      source: "unavailable",
      status: "catalog_unavailable",
      catalog_role: "denial_overlay",
      stable_authorization: "not_evaluated",
      failure_reason: "remote_catalog_unavailable_or_invalid",
      index_url: outputIndexUrl,
      version: null,
      updated: null,
      skills: [],
      historical: [],
      context: fallbackContext
        .map(toNonAuthorizingSummary)
        .filter((entry) => !requestedSkill || entry.id === requestedSkill),
      recommendation: buildRecommendation(requestedSkill, [], false),
      warning: "Remote catalog unavailable or invalid; lifecycle-screened install recommendations are disabled.",
    };
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = await discoverCatalog(args.skill);

  if (args.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    printHumanSummary(result);
  }

  if (result.recommendation?.status === "denied") {
    process.exitCode = EXIT_RECOMMENDATION_DENIED;
  }
}

main().catch((error) => {
  process.stderr.write(`${String(error)}\n`);
  process.exit(1);
});
