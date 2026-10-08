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
  // NVD assigns Clawdbot/Moltbot-era releases to the canonical
  // openclaw:openclaw CPE. Their legacy names remain discovery keywords, not
  // independent CPE identities.
  ["openclaw:openclaw", "openclaw"],
  ["nanoco:nanoclaw", "nanoclaw"],
  // Hermes has no confirmed NVD product CPE. Its authoritative scope comes
  // from exact NVD CNA affected data, repository advisories, or GitHub's
  // reviewed global pip/hermes-agent advisory index.
  ["sipeed:picoclaw", "picoclaw"],
  ["nvidia:nemoclaw", "nemoclaw"],
  ["nvidia:openshell", "openshell"],
]);

const SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const GHSA_IDENTIFIER = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i;
const CVE_IDENTIFIER = /^CVE-\d{4}-\d{4,}$/i;
const GHSA_SOURCE_STATUSES = new Set(["active", "matured", "stale"]);
const GLOBAL_REVIEWED_PACKAGE_SOURCE = "global_reviewed_package";
const HERMES_GHSA_REPOSITORY = "nousresearch/hermes-agent";
const HERMES_GHSA_ECOSYSTEM = "pip";
const HERMES_GHSA_PACKAGE = "hermes-agent";
const PROTECTED_GHSA_REPOSITORIES = new Map([
  ["openclaw/openclaw", "openclaw"],
  ["qwibitai/nanoclaw", "nanoclaw"],
  ["nousresearch/hermes-agent", "hermes"],
  ["sipeed/picoclaw", "picoclaw"],
  ["nvidia/openshell", "openshell"],
  ["nvidia/nemoclaw", "nemoclaw"],
]);

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

function isGhsaIdentifier(value) {
  return typeof value === "string" && GHSA_IDENTIFIER.test(value.trim());
}

function tiedGhsaIdentifiers(advisory) {
  return [
    advisory.id,
    advisory.ghsa_id,
    ...(Array.isArray(advisory.ghsa_ids) ? advisory.ghsa_ids : []),
    ...(Array.isArray(advisory.aliases) ? advisory.aliases : []),
  ].filter(isGhsaIdentifier);
}

function permitsExplicitAllVersions(advisory, productName) {
  if (isGhsaIdentifier(advisory.id)) {
    return true;
  }
  return tiedGhsaIdentifiers(advisory).length > 0
    && Array.isArray(advisory.authoritative_ghsa_affected)
    && advisory.authoritative_ghsa_affected.some((selector) => {
      const parsed = parseAffectedSpecifier(selector);
      if (!parsed || parsed.name.toLowerCase() !== productName.toLowerCase()) return false;
      const scope = parseVersionSpec(parsed.versionSpec);
      return scope.supported && scope.normalized === "*";
    });
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
  if (version.normalized === "*" && !permitsExplicitAllVersions(advisory, parsed.name)) {
    throw new Error(`${advisoryId}: wildcard affected scope is only valid when supplied by an authoritative GHSA`);
  }
  if (parsed.name.toLowerCase().includes("clawhub")) {
    throw new Error(`${advisoryId}: ClawHub is a distribution channel, not a protected component`);
  }
}

function validateAuthoritativeGhsaSelector(selector, advisoryId) {
  if (isCpeAffectedSpecifier(selector)) {
    throw new Error(`${advisoryId}: authoritative_ghsa_affected must contain package selectors, not CPEs`);
  }

  const parsed = parseAffectedSpecifier(selector);
  if (!parsed) {
    throw new Error(`${advisoryId}: invalid authoritative GHSA selector ${JSON.stringify(selector)}`);
  }
  const version = parseVersionSpec(parsed.versionSpec);
  if (!version.supported) {
    throw new Error(
      `${advisoryId}: unsupported authoritative GHSA version scope ${JSON.stringify(parsed.versionSpec)}`,
    );
  }
  if (parsed.name.toLowerCase().includes("clawhub")) {
    throw new Error(`${advisoryId}: ClawHub is a distribution channel, not a protected component`);
  }
}

function validateAuthoritativeNvdSelector(selector, advisoryId) {
  if (isCpeAffectedSpecifier(selector)) {
    validateCpeSelector(selector, advisoryId);
    return;
  }

  const parsed = parseAffectedSpecifier(selector);
  if (!parsed) {
    throw new Error(`${advisoryId}: invalid authoritative NVD selector ${JSON.stringify(selector)}`);
  }
  const version = parseVersionSpec(parsed.versionSpec);
  if (!version.supported || version.normalized === "*") {
    throw new Error(
      `${advisoryId}: authoritative NVD scope must contain an explicit version range`,
    );
  }
  if (parsed.name.toLowerCase().includes("clawhub")) {
    throw new Error(`${advisoryId}: ClawHub is a distribution channel, not a protected component`);
  }
}

function validateGhsaIdentifier(identifier, label) {
  if (!isGhsaIdentifier(identifier)) {
    throw new Error(`${label} must be a valid GHSA identifier`);
  }
}

function isCveIdentifier(value) {
  return typeof value === "string" && CVE_IDENTIFIER.test(value.trim());
}

function owns(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
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

function validateGhsaSourceEntry(advisory, collectionLabel, { enrichment = false } = {}) {
  if (!advisory || typeof advisory !== "object" || Array.isArray(advisory)) {
    throw new Error(`${collectionLabel} entries must be JSON objects`);
  }

  const advisoryId = requiredString(advisory.id, `${collectionLabel} entry id`);
  validateGhsaIdentifier(advisoryId, `${collectionLabel} entry id`);
  const ghsaId = requiredString(advisory.ghsa_id, `${advisoryId}: ghsa_id`);
  validateGhsaIdentifier(ghsaId, `${advisoryId}: ghsa_id`);
  if (ghsaId.toUpperCase() !== advisoryId.toUpperCase()) {
    throw new Error(`${advisoryId}: GHSA source id and ghsa_id must identify the same advisory`);
  }

  const cveId = advisory.cve_id;
  if (cveId !== null && !isCveIdentifier(cveId)) {
    throw new Error(`${advisoryId}: cve_id must be null or a valid CVE identifier`);
  }
  if (enrichment && !isCveIdentifier(cveId)) {
    throw new Error(`${advisoryId}: enrichment advisory must have a valid CVE alias`);
  }

  const aliases = validateOptionalStrings(advisory.aliases, `${advisoryId}: aliases`);
  const normalizedAliases = aliases.map((alias) => alias.toUpperCase());
  if (new Set(normalizedAliases).size !== normalizedAliases.length) {
    throw new Error(`${advisoryId}: aliases must not contain duplicate stable identifiers`);
  }
  if (!normalizedAliases.includes(advisoryId.toUpperCase())) {
    throw new Error(`${advisoryId}: GHSA source id must also appear in aliases`);
  }
  if (cveId && !normalizedAliases.includes(cveId.toUpperCase())) {
    throw new Error(`${advisoryId}: cve_id must also appear in aliases`);
  }
  for (const alias of aliases) {
    if (
      alias.toUpperCase() !== advisoryId.toUpperCase()
      && (!cveId || alias.toUpperCase() !== cveId.toUpperCase())
    ) {
      throw new Error(`${advisoryId}: GHSA source aliases may contain only its GHSA id and CVE alias`);
    }
  }

  const status = requiredString(advisory.status, `${advisoryId}: status`).toLowerCase();
  if (!GHSA_SOURCE_STATUSES.has(status)) {
    throw new Error(`${advisoryId}: unsupported GHSA source status ${JSON.stringify(advisory.status)}`);
  }
  if (typeof advisory.stale !== "boolean") {
    throw new Error(`${advisoryId}: stale must be a boolean`);
  }
  if (!Number.isInteger(advisory.stale_after_days) || advisory.stale_after_days < 1) {
    throw new Error(`${advisoryId}: stale_after_days must be a positive integer`);
  }
  const expectedStatus = cveId ? "matured" : advisory.stale ? "stale" : "active";
  if (status !== expectedStatus) {
    throw new Error(
      `${advisoryId}: status must be ${expectedStatus} for its CVE and stale state`,
    );
  }
  if (cveId && advisory.stale) {
    throw new Error(`${advisoryId}: a matured GHSA with a CVE alias cannot be stale`);
  }

  const severity = requiredString(advisory.severity, `${advisoryId}: severity`).toLowerCase();
  if (!SEVERITIES.has(severity)) {
    throw new Error(`${advisoryId}: unsupported severity ${JSON.stringify(advisory.severity)}`);
  }
  requiredString(advisory.title, `${advisoryId}: title`);
  requiredString(advisory.description, `${advisoryId}: description`);
  requiredString(advisory.action, `${advisoryId}: action`);
  requiredString(advisory.type, `${advisoryId}: type`);
  const published = requiredString(advisory.published, `${advisoryId}: published`);
  if (!Number.isFinite(Date.parse(published))) {
    throw new Error(`${advisoryId}: published must be a valid date`);
  }
  const updated = requiredString(advisory.updated, `${advisoryId}: updated`);
  if (!Number.isFinite(Date.parse(updated))) {
    throw new Error(`${advisoryId}: updated must be a valid date`);
  }
  if (
    advisory.withdrawn_at != null
    && (typeof advisory.withdrawn_at !== "string" || !Number.isFinite(Date.parse(advisory.withdrawn_at)))
  ) {
    throw new Error(`${advisoryId}: withdrawn_at must be null or a valid date`);
  }

  if (advisory.source !== "GitHub Security Advisory") {
    throw new Error(`${advisoryId}: GHSA source provenance must identify GitHub Security Advisory`);
  }
  const repository = requiredString(advisory.repository, `${advisoryId}: repository`);
  if (!/^[^/\s]+\/[^/\s]+$/.test(repository)) {
    throw new Error(`${advisoryId}: repository must use owner/name syntax`);
  }
  const repositoryPlatform = PROTECTED_GHSA_REPOSITORIES.get(repository.toLowerCase());
  if (!repositoryPlatform) {
    throw new Error(`${advisoryId}: repository is not an allowlisted protected GHSA source`);
  }
  const globalSourceFields = [
    "ghsa_source_kind",
    "ghsa_source_ecosystem",
    "ghsa_source_package",
    "github_reviewed_at",
  ];
  const hasGlobalSourceMetadata = globalSourceFields.some((field) => owns(advisory, field));
  const isHermesRepository = repository.toLowerCase() === HERMES_GHSA_REPOSITORY;
  const hasGlobalAdvisoryUrl = String(advisory.github_advisory_url ?? "")
    .startsWith("https://github.com/advisories/");
  const isHermesGlobalSource = isHermesRepository
    && (hasGlobalSourceMetadata || hasGlobalAdvisoryUrl);
  if (isHermesGlobalSource) {
    if (advisory.ghsa_source_kind !== GLOBAL_REVIEWED_PACKAGE_SOURCE) {
      throw new Error(`${advisoryId}: Hermes GHSA entries must come from the reviewed global package source`);
    }
    if (advisory.ghsa_source_ecosystem !== HERMES_GHSA_ECOSYSTEM) {
      throw new Error(`${advisoryId}: Hermes GHSA source ecosystem must be pip`);
    }
    if (advisory.ghsa_source_package !== HERMES_GHSA_PACKAGE) {
      throw new Error(`${advisoryId}: Hermes GHSA source package must be hermes-agent`);
    }
    if (!Number.isFinite(Date.parse(advisory.github_reviewed_at))) {
      throw new Error(`${advisoryId}: github_reviewed_at must be a valid date`);
    }
    if (advisory.withdrawn_at !== null) {
      throw new Error(`${advisoryId}: reviewed global package advisory must not be withdrawn`);
    }
  } else if (hasGlobalSourceMetadata) {
    throw new Error(`${advisoryId}: reviewed global package provenance is only allowlisted for Hermes`);
  }
  const githubAdvisoryUrl = requiredString(
    advisory.github_advisory_url,
    `${advisoryId}: github_advisory_url`,
  );
  if (
    !githubAdvisoryUrl.startsWith("https://github.com/")
    || !githubAdvisoryUrl.toUpperCase().includes(advisoryId.toUpperCase())
  ) {
    throw new Error(`${advisoryId}: github_advisory_url must be a GitHub URL for this GHSA`);
  }
  if (isHermesGlobalSource && !githubAdvisoryUrl.startsWith("https://github.com/advisories/")) {
    throw new Error(`${advisoryId}: reviewed global package advisory must use its global GitHub advisory URL`);
  }

  const references = validateOptionalStrings(advisory.references, `${advisoryId}: references`);
  if (!references.includes(githubAdvisoryUrl)) {
    throw new Error(`${advisoryId}: github_advisory_url must remain in references`);
  }
  if (cveId) {
    const expectedNvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
    if (advisory.nvd_url !== expectedNvdUrl || !references.includes(expectedNvdUrl)) {
      throw new Error(`${advisoryId}: CVE alias must retain its matching NVD URL provenance`);
    }
  } else if (advisory.nvd_url !== null) {
    throw new Error(`${advisoryId}: nvd_url must be null when no CVE alias is present`);
  }

  for (const field of ["patched", "cwe_ids", "credits"]) {
    if (!Array.isArray(advisory[field])) {
      throw new Error(`${advisoryId}: ${field} must be an array`);
    }
  }
  const patched = validateOptionalStrings(advisory.patched, `${advisoryId}: patched`, {
    allowEmpty: true,
  });
  for (const selector of patched) {
    const parsed = parseAffectedSpecifier(selector);
    if (!parsed || !parseVersionSpec(parsed.versionSpec).supported) {
      throw new Error(`${advisoryId}: invalid patched selector ${JSON.stringify(selector)}`);
    }
    if (parsed.name.toLowerCase().includes("clawhub")) {
      throw new Error(`${advisoryId}: ClawHub is a distribution channel, not a protected component`);
    }
    if (isHermesGlobalSource && parsed.name.toLowerCase() !== HERMES_GHSA_PACKAGE) {
      throw new Error(`${advisoryId}: reviewed Hermes patched scope must identify hermes-agent`);
    }
  }
  const cweIds = validateOptionalStrings(advisory.cwe_ids, `${advisoryId}: cwe_ids`, {
    allowEmpty: true,
  });
  for (const cweId of cweIds) {
    if (!/^CWE-\d+$/i.test(cweId)) {
      throw new Error(`${advisoryId}: cwe_ids entry must be a valid CWE identifier`);
    }
  }
  if (
    advisory.nvd_category_id !== null
    && (
      typeof advisory.nvd_category_id !== "string"
      || !/^CWE-\d+$/i.test(advisory.nvd_category_id)
      || !cweIds.includes(advisory.nvd_category_id)
    )
  ) {
    throw new Error(`${advisoryId}: nvd_category_id must be null or a CWE present in cwe_ids`);
  }
  validateOptionalStrings(advisory.credits, `${advisoryId}: credits`, { allowEmpty: true });
  if (
    advisory.cvss_score !== null
    && (typeof advisory.cvss_score !== "number" || advisory.cvss_score < 0 || advisory.cvss_score > 10)
  ) {
    throw new Error(`${advisoryId}: cvss_score must be null or a number from 0 through 10`);
  }
  if (
    advisory.cvss_vector !== null
    && (typeof advisory.cvss_vector !== "string" || !advisory.cvss_vector.startsWith("CVSS:"))
  ) {
    throw new Error(`${advisoryId}: cvss_vector must be null or a CVSS vector string`);
  }

  if (!Array.isArray(advisory.affected)) {
    throw new Error(`${advisoryId}: affected must be an array`);
  }
  if (enrichment && advisory.affected.length > 0) {
    throw new Error(`${advisoryId}: enrichment advisory must not contain directly publishable scope`);
  }
  if (isHermesGlobalSource && advisory.affected.length === 0) {
    throw new Error(`${advisoryId}: reviewed Hermes advisory must contain explicit package scope`);
  }
  for (const selector of advisory.affected) {
    if (typeof selector !== "string" || selector.trim().length === 0) {
      throw new Error(`${advisoryId}: affected must contain only non-empty strings`);
    }
    validateAffectedSelector(selector, advisoryId, advisory);
    const parsed = parseAffectedSpecifier(selector);
    if (isHermesGlobalSource && parsed?.name.toLowerCase() !== HERMES_GHSA_PACKAGE) {
      throw new Error(`${advisoryId}: reviewed Hermes affected scope must identify hermes-agent`);
    }
  }

  if (!Array.isArray(advisory.platforms)) {
    throw new Error(`${advisoryId}: platforms must be an array`);
  }
  if (!enrichment && advisory.platforms.length === 0) {
    throw new Error(`${advisoryId}: platforms must identify at least one protected component`);
  }
  for (const platform of advisory.platforms) {
    if (typeof platform !== "string" || !PROTECTED_COMPONENTS.has(platform.trim().toLowerCase())) {
      throw new Error(`${advisoryId}: unsupported protected component ${JSON.stringify(platform)}`);
    }
    if (platform.trim().toLowerCase() !== repositoryPlatform) {
      throw new Error(`${advisoryId}: platform does not match GHSA source repository provenance`);
    }
  }

  if (advisory.authoritative_nvd_affected !== undefined || advisory.synthesized_from_ghsa !== undefined) {
    throw new Error(`${advisoryId}: GHSA source entries must not claim canonical NVD provenance`);
  }

  return advisoryId;
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
  const hasEnrichmentAdvisories = owns(feed, "enrichment_advisories");
  const hasExcludedAdvisoryIds = owns(feed, "excluded_advisory_ids");
  const isGhsaSourceState = hasEnrichmentAdvisories || hasExcludedAdvisoryIds;
  if (isGhsaSourceState && (!hasEnrichmentAdvisories || !hasExcludedAdvisoryIds)) {
    throw new Error(
      "GHSA source feed must record both enrichment_advisories and excluded_advisory_ids",
    );
  }
  if (!Array.isArray(feed.advisories) || (!isGhsaSourceState && feed.advisories.length === 0)) {
    throw new Error("Advisory feed must contain at least one advisory");
  }
  if (isGhsaSourceState && !Array.isArray(feed.enrichment_advisories)) {
    throw new Error("GHSA source enrichment_advisories must be an array");
  }
  if (isGhsaSourceState && !Array.isArray(feed.excluded_advisory_ids)) {
    throw new Error("GHSA source excluded_advisory_ids must be an array");
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
    const advisoryUpdated = requiredString(advisory.updated, `${advisoryId}: updated`);
    if (!Number.isFinite(Date.parse(advisoryUpdated))) {
      throw new Error(`${advisoryId}: updated must be a valid date`);
    }

    const aliases = validateOptionalStrings(advisory.aliases, `${advisoryId}: aliases`);
    const ghsaIds = validateOptionalStrings(advisory.ghsa_ids, `${advisoryId}: ghsa_ids`);
    const authoritativeGhsaAffected = validateOptionalStrings(
      advisory.authoritative_ghsa_affected,
      `${advisoryId}: authoritative_ghsa_affected`,
      { allowEmpty: true },
    );
    const authoritativeNvdAffected = validateOptionalStrings(
      advisory.authoritative_nvd_affected,
      `${advisoryId}: authoritative_nvd_affected`,
      { allowEmpty: true },
    );
    const patched = validateOptionalStrings(advisory.patched, `${advisoryId}: patched`, {
      allowEmpty: true,
    });
    const authoritativeCanonicalPatched = validateOptionalStrings(
      advisory.authoritative_canonical_patched,
      `${advisoryId}: authoritative_canonical_patched`,
      { allowEmpty: true },
    );
    const authoritativeGhsaPatched = validateOptionalStrings(
      advisory.authoritative_ghsa_patched,
      `${advisoryId}: authoritative_ghsa_patched`,
      { allowEmpty: true },
    );
    const cweIds = validateOptionalStrings(advisory.cwe_ids, `${advisoryId}: cwe_ids`, {
      allowEmpty: true,
    });
    const authoritativeCanonicalPlatforms = validateOptionalStrings(
      advisory.authoritative_canonical_platforms,
      `${advisoryId}: authoritative_canonical_platforms`,
      { allowEmpty: true },
    );
    const authoritativeGhsaPlatforms = validateOptionalStrings(
      advisory.authoritative_ghsa_platforms,
      `${advisoryId}: authoritative_ghsa_platforms`,
      { allowEmpty: true },
    );
    const authoritativeCanonicalCweIds = validateOptionalStrings(
      advisory.authoritative_canonical_cwe_ids,
      `${advisoryId}: authoritative_canonical_cwe_ids`,
      { allowEmpty: true },
    );
    const authoritativeGhsaCweIds = validateOptionalStrings(
      advisory.authoritative_ghsa_cwe_ids,
      `${advisoryId}: authoritative_ghsa_cwe_ids`,
      { allowEmpty: true },
    );
    if (
      advisory.synthesized_from_ghsa !== undefined
      && typeof advisory.synthesized_from_ghsa !== "boolean"
    ) {
      throw new Error(`${advisoryId}: synthesized_from_ghsa must be a boolean when present`);
    }
    if (/^GHSA-/i.test(advisoryId)) {
      validateGhsaIdentifier(advisoryId, `${advisoryId}: id`);
    }
    if (advisory.ghsa_id !== undefined && advisory.ghsa_id !== null) {
      validateGhsaIdentifier(advisory.ghsa_id, `${advisoryId}: ghsa_id`);
    }
    for (const ghsaId of ghsaIds) {
      validateGhsaIdentifier(ghsaId, `${advisoryId}: ghsa_ids entry`);
    }
    for (const alias of aliases) {
      if (/^GHSA-/i.test(alias)) validateGhsaIdentifier(alias, `${advisoryId}: GHSA alias`);
    }
    for (const selector of authoritativeGhsaAffected) {
      validateAuthoritativeGhsaSelector(selector, advisoryId);
    }
    for (const selector of authoritativeNvdAffected) {
      validateAuthoritativeNvdSelector(selector, advisoryId);
    }
    if (authoritativeGhsaAffected.length > 0 && tiedGhsaIdentifiers(advisory).length === 0) {
      throw new Error(
        `${advisoryId}: authoritative_ghsa_affected requires a tied, valid GHSA stable identifier`,
      );
    }
    if (authoritativeGhsaPatched.length > 0 && tiedGhsaIdentifiers(advisory).length === 0) {
      throw new Error(
        `${advisoryId}: authoritative_ghsa_patched requires a tied, valid GHSA stable identifier`,
      );
    }
    if (
      (authoritativeGhsaPlatforms.length > 0 || authoritativeGhsaCweIds.length > 0)
      && tiedGhsaIdentifiers(advisory).length === 0
    ) {
      throw new Error(
        `${advisoryId}: authoritative GHSA platform/CWE metadata requires a tied GHSA identifier`,
      );
    }
    if (
      (advisory.authoritative_canonical_patched === undefined)
      !== (advisory.authoritative_ghsa_patched === undefined)
    ) {
      throw new Error(`${advisoryId}: canonical and GHSA patch provenance must be recorded together`);
    }
    if (advisory.synthesized_from_ghsa === true) {
      throw new Error(
        `${advisoryId}: GHSA-synthesized canonical CVEs must not be published; retain the GHSA identity until NVD confirms the CVE`,
      );
    }
    if (isCveIdentifier(advisoryId) && advisory.synthesized_from_ghsa !== false) {
      throw new Error(`${advisoryId}: canonical CVEs require explicit NVD provenance`);
    }
    if (advisory.synthesized_from_ghsa === false && authoritativeNvdAffected.length === 0) {
      throw new Error(`${advisoryId}: NVD-backed CVEs require authoritative NVD scope`);
    }
    if (
      advisory.authoritative_nvd_affected !== undefined
      && advisory.synthesized_from_ghsa === undefined
    ) {
      throw new Error(`${advisoryId}: authoritative NVD scope requires explicit provenance`);
    }

    if (!nonEmptyStrings(advisory.affected)) {
      throw new Error(`${advisoryId}: affected must contain an explicit product and version scope`);
    }
    for (const selector of advisory.affected) validateAffectedSelector(selector, advisoryId, advisory);
    for (const selector of authoritativeNvdAffected) {
      if (!advisory.affected.includes(selector)) {
        throw new Error(`${advisoryId}: authoritative NVD scope must remain in affected selectors`);
      }
    }
    for (const selector of authoritativeGhsaAffected) {
      if (!advisory.affected.includes(selector)) {
        throw new Error(`${advisoryId}: authoritative GHSA scope must remain in affected selectors`);
      }
    }
    for (const selector of [...authoritativeCanonicalPatched, ...authoritativeGhsaPatched]) {
      if (!patched.includes(selector)) {
        throw new Error(`${advisoryId}: authoritative patch provenance must remain in patched selectors`);
      }
    }

    if (!nonEmptyStrings(advisory.platforms)) {
      throw new Error(`${advisoryId}: platforms must identify at least one protected component`);
    }
    for (const platform of advisory.platforms) {
      const normalized = platform.trim().toLowerCase();
      if (!PROTECTED_COMPONENTS.has(normalized)) {
        throw new Error(`${advisoryId}: unsupported protected component ${JSON.stringify(platform)}`);
      }
    }
    for (const platform of [...authoritativeCanonicalPlatforms, ...authoritativeGhsaPlatforms]) {
      if (!advisory.platforms.includes(platform)) {
        throw new Error(`${advisoryId}: authoritative platform provenance must remain in platforms`);
      }
    }
    for (const cweId of [...authoritativeCanonicalCweIds, ...authoritativeGhsaCweIds]) {
      if (!cweIds.includes(cweId)) {
        throw new Error(`${advisoryId}: authoritative CWE provenance must remain in cwe_ids`);
      }
    }

    const stableIdentifiers = [
      advisoryId,
      typeof advisory.cve_id === "string" ? advisory.cve_id.trim() : "",
      typeof advisory.ghsa_id === "string" ? advisory.ghsa_id.trim() : "",
      ...ghsaIds,
      ...aliases,
    ].filter(Boolean);
    const ownedIdentifiers = isGhsaSourceState
      ? stableIdentifiers.filter(isGhsaIdentifier)
      : stableIdentifiers;
    for (const identifier of ownedIdentifiers) {
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

    if (isGhsaSourceState) {
      validateGhsaSourceEntry(advisory, "advisories");
    }
  }

  if (isGhsaSourceState) {
    const publishedGhsaIds = new Set(
      feed.advisories.map((advisory) => advisory.id.trim().toUpperCase()),
    );
    if (publishedGhsaIds.size !== feed.advisories.length) {
      throw new Error("GHSA source advisories contain a duplicate GHSA identity");
    }

    const enrichmentGhsaIds = new Set();
    for (const advisory of feed.enrichment_advisories) {
      const advisoryId = validateGhsaSourceEntry(advisory, "enrichment_advisories", {
        enrichment: true,
      });
      const normalizedId = advisoryId.toUpperCase();
      if (enrichmentGhsaIds.has(normalizedId)) {
        throw new Error(`Duplicate GHSA enrichment identity: ${advisoryId}`);
      }
      if (publishedGhsaIds.has(normalizedId)) {
        throw new Error(
          `${advisoryId}: GHSA identity cannot be both directly publishable and enrichment-only`,
        );
      }
      enrichmentGhsaIds.add(normalizedId);
    }

    const excludedGhsaIds = new Set();
    for (const excludedId of feed.excluded_advisory_ids) {
      validateGhsaIdentifier(excludedId, "excluded_advisory_ids entry");
      const normalizedId = excludedId.trim().toUpperCase();
      if (excludedGhsaIds.has(normalizedId)) {
        throw new Error(`Duplicate excluded GHSA identity: ${excludedId}`);
      }
      if (publishedGhsaIds.has(normalizedId)) {
        throw new Error(`${excludedId}: directly publishable GHSA cannot also be excluded`);
      }
      excludedGhsaIds.add(normalizedId);
    }
    for (const enrichmentId of enrichmentGhsaIds) {
      if (!excludedGhsaIds.has(enrichmentId)) {
        throw new Error(
          `${enrichmentId}: enrichment advisory must also appear in excluded_advisory_ids`,
        );
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
