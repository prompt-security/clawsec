#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import {
  isCpeAffectedSpecifier,
  parseAffectedSpecifier,
  parseVersionSpec,
} from "../../skills/hermes-attestation-guardian/lib/semver.mjs";

const PROTECTED_COMPONENTS = new Set([
  "openclaw",
  "nanoclaw",
  "hermes",
  "picoclaw",
  "openshell",
  "nemoclaw",
]);

const PROTECTED_CPE_COMPONENTS = new Map([
  ["openclaw:openclaw", "openclaw"],
  ["openclaw:clawdbot", "openclaw"],
  ["openclaw:moltbot", "openclaw"],
  ["nanoco:nanoclaw", "nanoclaw"],
  ["qwibitai:nanoclaw", "nanoclaw"],
  ["software-metadata.pub:hermes", "hermes"],
  ["nousresearch:hermes_agent", "hermes"],
  ["sipeed:picoclaw", "picoclaw"],
  ["picoclaw:picoclaw", "picoclaw"],
  ["nvidia:nemoclaw", "nemoclaw"],
  ["nvidia:openshell", "openshell"],
]);

const SEVERITIES = new Set(["low", "medium", "high", "critical"]);

function requiredString(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value.trim();
}

function nonEmptyStrings(value) {
  return Array.isArray(value)
    && value.length > 0
    && value.every((entry) => typeof entry === "string" && entry.trim().length > 0);
}

function validateCpeSelector(selector, advisoryId) {
  const fields = selector.split(":");
  const part = fields[2]?.toLowerCase();
  const vendor = fields[3]?.replaceAll("\\", "").toLowerCase();
  const product = fields[4]?.replaceAll("\\", "").toLowerCase();
  const version = fields[5]?.replaceAll("\\", "");
  const component = PROTECTED_CPE_COMPONENTS.get(`${vendor}:${product}`);

  if (part !== "a" || !component) {
    throw new Error(`${advisoryId}: affected CPE does not identify an allowlisted protected application`);
  }
  if (!version || version === "*" || version === "-") {
    throw new Error(`${advisoryId}: affected CPE must include an explicit version`);
  }
}

function permitsExplicitAllVersions(advisory) {
  return /^GHSA-/i.test(String(advisory.id || ""))
    || /^GHSA-/i.test(String(advisory.ghsa_id || ""))
    || advisory.source_feed === "ghsa-without-cve";
}

function validateAffectedSelector(selector, advisoryId, advisory) {
  if (isCpeAffectedSpecifier(selector)) {
    validateCpeSelector(selector, advisoryId);
    return;
  }

  const parsed = parseAffectedSpecifier(selector);
  if (!parsed) {
    throw new Error(`${advisoryId}: invalid affected selector ${JSON.stringify(selector)}`);
  }
  const version = parseVersionSpec(parsed.versionSpec);
  if (!version.supported) {
    throw new Error(`${advisoryId}: unsupported affected version scope ${JSON.stringify(parsed.versionSpec)}`);
  }
  if (version.normalized === "*" && !permitsExplicitAllVersions(advisory)) {
    throw new Error(`${advisoryId}: wildcard affected scope is only valid when supplied by an authoritative GHSA`);
  }
  if (parsed.name.toLowerCase().includes("clawhub")) {
    throw new Error(`${advisoryId}: ClawHub is a distribution channel, not a protected component`);
  }
}

function validateOptionalStrings(value, label, { allowEmpty = false } = {}) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new Error(`${label} must be ${allowEmpty ? "a" : "a non-empty"} string array when present`);
  }
  if (!value.every((entry) => typeof entry === "string" && entry.trim().length > 0)) {
    throw new Error(`${label} must contain only non-empty strings`);
  }
  return value.map((entry) => entry.trim());
}

export function validateAdvisoryFeed(feed) {
  if (!feed || typeof feed !== "object" || Array.isArray(feed)) {
    throw new Error("Advisory feed must be a JSON object");
  }
  requiredString(feed.version, "Advisory feed version");
  const updated = requiredString(feed.updated, "Advisory feed updated timestamp");
  if (!Number.isFinite(Date.parse(updated))) {
    throw new Error("Advisory feed updated timestamp must be a valid date");
  }
  if (!Array.isArray(feed.advisories) || feed.advisories.length === 0) {
    throw new Error("Advisory feed must contain at least one advisory");
  }

  const advisoryIds = new Set();
  const aliasOwners = new Map();

  for (const advisory of feed.advisories) {
    const advisoryId = typeof advisory?.id === "string" ? advisory.id.trim() : "";
    if (!advisoryId) throw new Error("Every advisory must have a non-empty id");
    if (advisoryIds.has(advisoryId)) throw new Error(`Duplicate advisory id: ${advisoryId}`);
    advisoryIds.add(advisoryId);

    const severity = requiredString(advisory.severity, `${advisoryId}: severity`).toLowerCase();
    if (!SEVERITIES.has(severity)) {
      throw new Error(`${advisoryId}: unsupported severity ${JSON.stringify(advisory.severity)}`);
    }
    requiredString(advisory.title, `${advisoryId}: title`);
    requiredString(advisory.description, `${advisoryId}: description`);
    requiredString(advisory.action, `${advisoryId}: action`);
    const published = requiredString(advisory.published, `${advisoryId}: published`);
    if (!Number.isFinite(Date.parse(published))) {
      throw new Error(`${advisoryId}: published must be a valid date`);
    }

    if (!nonEmptyStrings(advisory.affected)) {
      throw new Error(`${advisoryId}: affected must contain an explicit product and version scope`);
    }
    for (const selector of advisory.affected) validateAffectedSelector(selector, advisoryId, advisory);

    if (!nonEmptyStrings(advisory.platforms)) {
      throw new Error(`${advisoryId}: platforms must identify at least one protected component`);
    }
    for (const platform of advisory.platforms) {
      const normalized = platform.trim().toLowerCase();
      if (!PROTECTED_COMPONENTS.has(normalized)) {
        throw new Error(`${advisoryId}: unsupported protected component ${JSON.stringify(platform)}`);
      }
    }

    const aliases = validateOptionalStrings(advisory.aliases, `${advisoryId}: aliases`);
    const ghsaIds = validateOptionalStrings(advisory.ghsa_ids, `${advisoryId}: ghsa_ids`);
    const stableIdentifiers = [
      advisoryId,
      typeof advisory.cve_id === "string" ? advisory.cve_id.trim() : "",
      typeof advisory.ghsa_id === "string" ? advisory.ghsa_id.trim() : "",
      ...ghsaIds,
      ...aliases,
    ].filter(Boolean);
    for (const identifier of stableIdentifiers) {
      const normalized = identifier.toUpperCase();
      const owner = aliasOwners.get(normalized);
      if (owner && owner !== advisoryId) {
        throw new Error(`Stable identifier ${identifier} belongs to both ${owner} and ${advisoryId}`);
      }
      aliasOwners.set(normalized, advisoryId);
    }

    if (advisory.ghsa_id && !aliases.includes(advisory.ghsa_id)) {
      throw new Error(`${advisoryId}: ghsa_id must also appear in aliases`);
    }
    if (advisory.cve_id && !aliases.includes(advisory.cve_id)) {
      throw new Error(`${advisoryId}: cve_id must also appear in aliases`);
    }
    for (const ghsaId of ghsaIds) {
      if (!aliases.includes(ghsaId)) {
        throw new Error(`${advisoryId}: every ghsa_ids entry must also appear in aliases`);
      }
    }
  }

  return feed;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    const feedPath = process.argv[2];
    if (!feedPath) throw new Error("Usage: validate_advisory_feed.mjs <feed.json>");
    const feed = JSON.parse(await readFile(feedPath, "utf8"));
    validateAdvisoryFeed(feed);
    process.stdout.write(`Advisory feed validation passed: ${feed.advisories.length} advisories\n`);
  } catch (error) {
    console.error(`Advisory feed validation failed: ${error.message}`);
    process.exitCode = 1;
  }
}
