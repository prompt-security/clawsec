#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  evaluatePublicationVersion,
  parsePackageTag,
} from "./lifecycle_semver.mjs";

export const STABLE_TAG_POLICY = "clawsec.stable-tag-policy/v1";
export const LEGACY_PRERELEASE_INVENTORY_SHA256 =
  "f688f138685126e6bb234151f7fa5d737096b525191922ad06d2cfaa49ba1720";

const DEFAULT_INVENTORY_PATH = fileURLToPath(
  new URL("../../contracts/release-policy/legacy-prereleases-v1.json", import.meta.url),
);
const REQUIRED_DENIAL_FIELDS = [
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

function policyError(message) {
  return new Error(`Legacy prerelease inventory rejected: ${message}`);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validateLegacyPrereleaseInventory(inventory) {
  if (!isObject(inventory)) {
    throw policyError("root must be an object");
  }
  if (inventory.schema !== "clawsec.legacy-prerelease-inventory/v1") {
    throw policyError("unexpected schema");
  }
  if (!isObject(inventory.policy)) {
    throw policyError("policy must be an object");
  }
  if (inventory.policy.classification !== "frozen_legacy_public_prerelease_history") {
    throw policyError("unexpected policy classification");
  }
  if (inventory.policy.retention !== "fetchable_history") {
    throw policyError("unexpected retention policy");
  }
  if (inventory.policy.historical_fetch_only !== true) {
    throw policyError("history must be fetch-only");
  }
  for (const field of REQUIRED_DENIAL_FIELDS) {
    if (inventory.policy[field] !== false) {
      throw policyError(`${field} must be exactly false`);
    }
  }
  if (!Array.isArray(inventory.tags) || inventory.tags.length === 0) {
    throw policyError("tags must be a non-empty array");
  }
  if (!isObject(inventory.counts) || inventory.counts.tags !== inventory.tags.length) {
    throw policyError("tag count mismatch");
  }

  const historicalTags = new Set();
  for (const record of inventory.tags) {
    if (!isObject(record) || typeof record.name !== "string" || record.name.length === 0) {
      throw policyError("every tag record must have a non-empty name");
    }
    if (historicalTags.has(record.name)) {
      throw policyError("duplicate tag name");
    }
    let parsed;
    try {
      parsed = parsePackageTag(record.name);
    } catch {
      throw policyError("historical tag must remain a valid package-qualified tag");
    }
    const publication = evaluatePublicationVersion(parsed.version);
    if (publication.publicPublicationEligible) {
      throw policyError("historical inventory must not contain a publication-eligible tag");
    }
    historicalTags.add(record.name);
  }

  return historicalTags;
}

export async function loadLegacyPrereleaseInventory(inventoryPath = DEFAULT_INVENTORY_PATH) {
  let raw;
  try {
    raw = await readFile(inventoryPath, "utf8");
  } catch {
    throw policyError("snapshot is unavailable");
  }

  const digest = createHash("sha256").update(raw).digest("hex");
  if (digest !== LEGACY_PRERELEASE_INVENTORY_SHA256) {
    throw policyError("snapshot digest does not match the reviewed policy data");
  }

  let inventory;
  try {
    inventory = JSON.parse(raw);
  } catch {
    throw policyError("snapshot is not valid JSON");
  }
  return {
    inventory,
    historicalTags: validateLegacyPrereleaseInventory(inventory),
    digest,
  };
}

function deniedDecision(reasonCode, overrides = {}) {
  return {
    policy: STABLE_TAG_POLICY,
    publication_eligible: false,
    stable_authorized: false,
    historical_fetch_only: false,
    reason_code: reasonCode,
    package_name: null,
    version: null,
    tag: null,
    ...overrides,
  };
}

export function evaluateStableTagPolicy({ tag, historicalTags } = {}) {
  if (!(historicalTags instanceof Set)) {
    throw new Error("historicalTags must be a validated Set");
  }

  let parsedTag;
  try {
    parsedTag = parsePackageTag(tag);
  } catch {
    return deniedDecision("invalid_package_tag");
  }

  const identity = {
    tag: parsedTag.raw,
    package_name: parsedTag.packageName,
    version: parsedTag.version,
  };
  if (historicalTags.has(parsedTag.raw)) {
    return deniedDecision("frozen_legacy_history_non_authorized", {
      ...identity,
      historical_fetch_only: true,
    });
  }

  const publication = evaluatePublicationVersion(parsedTag.version);
  return {
    policy: STABLE_TAG_POLICY,
    publication_eligible: publication.publicPublicationEligible,
    stable_authorized: false,
    historical_fetch_only: false,
    reason_code: publication.reasonCode,
    lifecycle_class: publication.lifecycleClass,
    ...identity,
  };
}

function parseArguments(argv) {
  let tag;
  let inventoryPath = DEFAULT_INVENTORY_PATH;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--tag" && tag === undefined && index + 1 < argv.length) {
      tag = argv[index + 1];
      index += 1;
      continue;
    }
    if (
      argument === "--inventory"
      && inventoryPath === DEFAULT_INVENTORY_PATH
      && index + 1 < argv.length
    ) {
      inventoryPath = argv[index + 1];
      index += 1;
      continue;
    }
    throw new Error("usage: stable_tag_policy.mjs --tag <package-vversion> [--inventory <path>]");
  }

  if (tag === undefined) {
    throw new Error("usage: stable_tag_policy.mjs --tag <package-vversion> [--inventory <path>]");
  }
  return { tag, inventoryPath };
}

async function main() {
  try {
    const { tag, inventoryPath } = parseArguments(process.argv.slice(2));
    const { historicalTags } = await loadLegacyPrereleaseInventory(inventoryPath);
    const decision = evaluateStableTagPolicy({ tag, historicalTags });
    process.stdout.write(`${JSON.stringify(decision)}\n`);
    if (!decision.publication_eligible) {
      process.stderr.write(
        `Stable tag policy denied public publication: ${decision.reason_code}\n`,
      );
      process.exitCode = 2;
    }
  } catch (error) {
    process.stderr.write(`Stable tag policy unavailable: ${error.message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
