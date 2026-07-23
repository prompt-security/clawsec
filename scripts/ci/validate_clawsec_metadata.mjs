#!/usr/bin/env node

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import Ajv from "ajv";

import {
  classifyLifecycleVersion,
  compareSemverV2,
  parseSemverV2,
} from "./lifecycle_semver.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const metadataSchemaPath = path.join(
  repositoryRoot,
  "contracts/schemas/component/metadata-v1.schema.json",
);
const componentRefSchemaPath = path.join(
  repositoryRoot,
  "contracts/schemas/component/component-ref-v1.schema.json",
);
const capabilityRegistryPath = path.join(
  repositoryRoot,
  "contracts/capability-registry.json",
);

const [metadataSchema, componentRefSchema, capabilityRegistry] = await Promise.all([
  readJson(metadataSchemaPath),
  readJson(componentRefSchemaPath),
  readJson(capabilityRegistryPath),
]);

const ajv = new Ajv({
  allErrors: true,
  jsonPointers: true,
  schemaId: "auto",
});
const validateMetadataSchema = ajv.compile(metadataSchema);
const validateComponentRefSchema = ajv.compile(componentRefSchema);

const HARNESSES = Object.freeze(["openclaw", "hermes", "nanoclaw", "picoclaw"]);
const CORE_PROTOCOL = "clawsec-core/v1";
const CANONICAL_NAME_PATTERN = /^clawsec-(core|suite|drift-guardian)-(openclaw|hermes|nanoclaw|picoclaw)$/;

const capabilityByName = new Map();
for (const capability of capabilityRegistry.capabilities ?? []) {
  if (capabilityByName.has(capability.name)) {
    throw new Error(`Duplicate capability registry entry: ${capability.name}`);
  }
  capabilityByName.set(capability.name, capability);
}

export function isCanonicalClawsecName(name) {
  return typeof name === "string" && CANONICAL_NAME_PATTERN.test(name);
}

export function validateClawsecMetadata({
  skill,
  skillDir = null,
  requireClawsec = false,
} = {}) {
  const errors = [];
  const warnings = [];

  if (!isPlainObject(skill)) {
    addError(errors, "SKILL_METADATA_INVALID", "", "skill.json must contain a JSON object");
    return finish("invalid", errors, warnings);
  }

  const hasClawsec = Object.hasOwn(skill, "clawsec");
  if (!hasClawsec) {
    if (requireClawsec || isCanonicalClawsecName(skill.name)) {
      addError(
        errors,
        "MISSING_CLAWSEC_METADATA",
        "/clawsec",
        "canonical ClawSec packages require normalized clawsec metadata",
      );
      return finish("invalid", errors, warnings);
    }

    warnings.push({
      code: "LEGACY_INPUT",
      path: "/clawsec",
      message: "no normalized clawsec metadata; usable only as migration material",
    });
    return finish("legacy", errors, warnings);
  }

  if (!validateMetadataSchema(skill)) {
    for (const schemaError of validateMetadataSchema.errors ?? []) {
      addError(
        errors,
        "METADATA_SCHEMA_INVALID",
        schemaError.dataPath || "/",
        `${schemaError.keyword}: ${schemaError.message}`,
      );
    }
    return finish("invalid", errors, warnings);
  }

  validatePackageVersion(skill.version, errors);

  const metadata = skill.clawsec;
  const harness = metadata.supported_harness.name;
  validateBoundedVersionRange(metadata.supported_harness, "/clawsec/supported_harness", errors);

  if (skill.platform !== harness) {
    addError(
      errors,
      "PLATFORM_HARNESS_MISMATCH",
      "/platform",
      `platform ${skill.platform} does not match supported harness ${harness}`,
    );
  }
  if (
    skill.platforms !== undefined
    && (
      skill.platforms.length !== 1
      || skill.platforms[0] !== harness
    )
  ) {
    addError(
      errors,
      "PLATFORM_DECLARATION_AMBIGUOUS",
      "/platforms",
      `platforms must be omitted or contain only ${harness}`,
    );
  }

  const declaredHarnessBlocks = HARNESSES.filter((name) => Object.hasOwn(skill, name));
  if (!Object.hasOwn(skill, harness) || !isPlainObject(skill[harness])) {
    addError(
      errors,
      "HARNESS_METADATA_BLOCK_MISSING",
      `/${harness}`,
      `one ${harness} metadata object is required`,
    );
  }
  if (declaredHarnessBlocks.length !== 1 || declaredHarnessBlocks[0] !== harness) {
    addError(
      errors,
      "HARNESS_METADATA_BLOCK_AMBIGUOUS",
      "/",
      `expected only the ${harness} harness metadata block`,
    );
  }

  const expectedName = expectedPackageName(metadata.role, metadata.family, harness);
  if (skill.name !== expectedName) {
    addError(
      errors,
      "CANONICAL_NAME_MISMATCH",
      "/name",
      `expected canonical name ${expectedName}, got ${skill.name}`,
    );
  }

  validateSortedStrings(metadata.provides, "/clawsec/provides", errors);
  validateSortedStrings(
    metadata.management_protocol_provides,
    "/clawsec/management_protocol_provides",
    errors,
  );
  validateSortedStrings(
    metadata.management_protocol_requires,
    "/clawsec/management_protocol_requires",
    errors,
  );
  validateSortedStrings(metadata.legacy_names, "/clawsec/legacy_names", errors);
  validateDependencies(metadata.install_requires, "/clawsec/install_requires", skill, errors);
  validateDependencies(metadata.runtime_requires, "/clawsec/runtime_requires", skill, errors);
  validateCapabilities(metadata, errors);
  validateRoleGraph(metadata, harness, errors);
  if (metadata.maturity === "stable") {
    warnings.push({
      code: "STABLE_MATURITY_REQUIRES_CONFORMANCE",
      path: "/clawsec/maturity",
      message: "metadata validity does not prove conformance, qualification, or catalog authorization",
    });
  } else if (metadata.maturity === "deprecated") {
    warnings.push({
      code: "DEPRECATED_MATURITY_REQUIRES_SUCCESSOR",
      path: "/clawsec/maturity",
      message: "a later compatibility/catalog contract must bind the canonical successor",
    });
  }

  if (metadata.legacy_names.includes(skill.name)) {
    addError(
      errors,
      "LEGACY_NAME_SELF_REFERENCE",
      "/clawsec/legacy_names",
      "legacy_names cannot include the canonical package name",
    );
  }

  if (harness === "nanoclaw") {
    validateNanoclawV2(skill, skillDir, errors);
  } else if (metadata.native !== undefined) {
    addError(
      errors,
      "NATIVE_METADATA_FORBIDDEN",
      "/clawsec/native",
      "native metadata is reserved for NanoClaw v2 packages in contract v1",
    );
  }

  return finish(errors.length === 0 ? "canonical" : "invalid", errors, warnings);
}

export function validateComponentRef(componentRef) {
  const errors = [];
  const warnings = [];

  if (!validateComponentRefSchema(componentRef)) {
    for (const schemaError of validateComponentRefSchema.errors ?? []) {
      addError(
        errors,
        "COMPONENT_REF_SCHEMA_INVALID",
        schemaError.dataPath || "/",
        `${schemaError.keyword}: ${schemaError.message}`,
      );
    }
    return finish("invalid", errors, warnings);
  }

  validatePackageVersion(componentRef.version, errors, "/version");
  const expectedName = expectedPackageName(
    componentRef.role,
    componentRef.family,
    componentRef.harness,
  );
  if (componentRef.name !== expectedName) {
    addError(
      errors,
      "COMPONENT_REF_IDENTITY_MISMATCH",
      "/name",
      `expected canonical name ${expectedName}, got ${componentRef.name}`,
    );
  }

  return finish(errors.length === 0 ? "component_ref" : "invalid", errors, warnings);
}

function validatePackageVersion(version, errors, errorPath = "/version") {
  try {
    parseSemverV2(version);
  } catch (error) {
    addError(errors, "PACKAGE_VERSION_INVALID", errorPath, error.message);
  }
}

function validateBoundedVersionRange(
  range,
  errorPath,
  errors,
  { allowCandidateMinimum = false } = {},
) {
  let minimum;
  let maximum;
  try {
    minimum = parseSemverV2(range.minimum_version);
    maximum = parseSemverV2(range.maximum_version_exclusive);
  } catch (error) {
    addError(errors, "VERSION_RANGE_INVALID", errorPath, error.message);
    return false;
  }

  const minimumLifecycle = classifyLifecycleVersion(range.minimum_version);
  const minimumIsAllowed = minimum.build.length === 0
    && (
      minimumLifecycle === "final"
      || (
        allowCandidateMinimum
        && (minimumLifecycle === "beta" || minimumLifecycle === "rc")
      )
    );
  const maximumIsFinal = maximum.prerelease.length === 0 && maximum.build.length === 0;

  if (
    !minimumIsAllowed
    || !maximumIsFinal
  ) {
    const message = allowCandidateMinimum
      ? "dependency minimum_version must be final SemVer or canonical beta.N/rc.N without build metadata; maximum_version_exclusive must be final SemVer without build metadata"
      : "version-range bounds must be final SemVer versions without build metadata";
    addError(
      errors,
      "VERSION_RANGE_INVALID",
      errorPath,
      message,
    );
    return false;
  }

  if (compareSemverV2(range.minimum_version, range.maximum_version_exclusive) >= 0) {
    addError(
      errors,
      "VERSION_RANGE_INVALID",
      errorPath,
      "minimum_version must be lower than maximum_version_exclusive",
    );
    return false;
  }
  return true;
}

function validateCapabilities(metadata, errors) {
  for (const capabilityName of metadata.provides) {
    const capability = capabilityByName.get(capabilityName);
    if (!capability) {
      addError(
        errors,
        "UNKNOWN_CAPABILITY",
        "/clawsec/provides",
        `unknown capability ${capabilityName}`,
      );
      continue;
    }
    if (
      capability.role !== metadata.role
      || (capability.family !== undefined && capability.family !== metadata.family)
    ) {
      addError(
        errors,
        "CAPABILITY_ROLE_MISMATCH",
        "/clawsec/provides",
        `${capabilityName} does not belong to ${metadata.role}${metadata.family ? `/${metadata.family}` : ""}`,
      );
    }
  }

  if (metadata.maturity !== "stable") return;

  for (const capability of capabilityByName.values()) {
    const applies = capability.role === metadata.role
      && (capability.family === undefined || capability.family === metadata.family);
    if (
      applies
      && capability.required_for_stable
      && !metadata.provides.includes(capability.name)
    ) {
      addError(
        errors,
        "STABLE_CAPABILITY_MISSING",
        "/clawsec/provides",
        `stable ${metadata.role} metadata must declare ${capability.name}`,
      );
    }
  }
}

function validateRoleGraph(metadata, harness, errors) {
  const expectedProvides = metadata.role === "core" ? [CORE_PROTOCOL] : [];
  const expectedRequires = metadata.role === "core" ? [] : [CORE_PROTOCOL];

  if (!arraysEqual(metadata.management_protocol_provides, expectedProvides)) {
    addError(
      errors,
      "MANAGEMENT_PROTOCOL_INVALID",
      "/clawsec/management_protocol_provides",
      `${metadata.role} must declare ${JSON.stringify(expectedProvides)}`,
    );
  }
  if (!arraysEqual(metadata.management_protocol_requires, expectedRequires)) {
    addError(
      errors,
      "MANAGEMENT_PROTOCOL_INVALID",
      "/clawsec/management_protocol_requires",
      `${metadata.role} must declare ${JSON.stringify(expectedRequires)}`,
    );
  }

  const allDependencies = [...metadata.install_requires, ...metadata.runtime_requires];
  const canonicalDependencies = allDependencies
    .map((dependency) => ({
      dependency,
      identity: parseCanonicalIdentity(dependency.name),
    }))
    .filter(({ identity }) => identity !== null);

  for (const { dependency, identity } of canonicalDependencies) {
    if (identity.harness !== harness) {
      addError(
        errors,
        "CROSS_HARNESS_DEPENDENCY",
        "/clawsec",
        `${dependency.name} targets ${identity.harness}, not ${harness}`,
      );
    }
  }

  if (
    metadata.role === "core"
    && (metadata.install_requires.length > 0 || metadata.runtime_requires.length > 0)
  ) {
    addError(
      errors,
      "CORE_PACKAGE_DEPENDENCY_FORBIDDEN",
      "/clawsec",
      "contract v1 cores must keep install_requires and runtime_requires empty",
    );
  }

  if (metadata.role === "suite") {
    const expectedCore = `clawsec-core-${harness}`;
    if (
      metadata.install_requires.length !== 0
      || metadata.runtime_requires.length !== 1
      || metadata.runtime_requires[0].name !== expectedCore
    ) {
      addError(
        errors,
        "SUITE_CORE_RUNTIME_REQUIRED",
        "/clawsec/runtime_requires",
        `suite must have no install dependencies and exactly one runtime dependency on ${expectedCore}`,
      );
    }
  }

  if (metadata.role === "guardian") {
    if (metadata.install_requires.length > 0 || metadata.runtime_requires.length > 0) {
      addError(
        errors,
        "GUARDIAN_PACKAGE_DEPENDENCY_FORBIDDEN",
        "/clawsec",
        "contract v1 guardians use core management compatibility without package dependencies",
      );
    }
  }
}

function validateDependencies(dependencies, errorPath, skill, errors) {
  const sorted = [...dependencies].sort(compareDependencies);
  if (!arraysEqual(dependencies, sorted)) {
    addError(
      errors,
      "DEPENDENCIES_NOT_SORTED",
      errorPath,
      "dependencies must be sorted by name and version bounds",
    );
  }

  const seenNames = new Set();
  for (const [index, dependency] of dependencies.entries()) {
    const dependencyPath = `${errorPath}/${index}`;
    validateBoundedVersionRange(
      dependency,
      dependencyPath,
      errors,
      { allowCandidateMinimum: true },
    );
    if (seenNames.has(dependency.name)) {
      addError(
        errors,
        "DUPLICATE_DEPENDENCY",
        dependencyPath,
        `dependency ${dependency.name} appears more than once`,
      );
    }
    seenNames.add(dependency.name);
    if (dependency.name === skill.name) {
      addError(
        errors,
        "SELF_DEPENDENCY",
        dependencyPath,
        "a package cannot depend on itself",
      );
    }
  }
}

function validateNanoclawV2(skill, skillDir, errors) {
  const metadata = skill.clawsec;
  const native = metadata.native;
  if (!native) {
    addError(
      errors,
      "NANOCLAW_NATIVE_REQUIRED",
      "/clawsec/native",
      "NanoClaw v2 packages require one host-owned native profile",
    );
    return;
  }

  const supported = metadata.supported_harness;
  try {
    if (
      compareSemverV2(supported.minimum_version, "2.0.0") < 0
      || compareSemverV2(supported.maximum_version_exclusive, "3.0.0") > 0
    ) {
      addError(
        errors,
        "NANOCLAW_V2_RANGE_REQUIRED",
        "/clawsec/supported_harness",
        "NanoClaw contract v1 accepts only a bounded v2 support range",
      );
    }
  } catch {
    // The common bounded-range validator already reports malformed SemVer.
  }

  if (
    (metadata.role === "core" || metadata.role === "guardian")
    && native.category !== "utility"
  ) {
    addError(
      errors,
      "NANOCLAW_NATIVE_CATEGORY_INVALID",
      "/clawsec/native/category",
      `${metadata.role} must be a NanoClaw host utility`,
    );
  }

  if (
    metadata.role === "suite"
    && native.category === "operational"
    && (native.apply_leaves_state || native.remove_document_required)
  ) {
    addError(
      errors,
      "NANOCLAW_OPERATIONAL_STATE_FORBIDDEN",
      "/clawsec/native",
      "an operational NanoClaw suite must be instruction-only; use utility for code or state",
    );
  }

  const expectedLocation = `.claude/skills/${skill.name}`;
  if (native.install_location !== expectedLocation) {
    addError(
      errors,
      "NANOCLAW_LOCATION_INVALID",
      "/clawsec/native/install_location",
      `expected ${expectedLocation}`,
    );
  }

  if (
    (metadata.role === "core" || metadata.role === "guardian")
    && !native.apply_leaves_state
  ) {
    addError(
      errors,
      "NANOCLAW_STATEFUL_PROFILE_REQUIRED",
      "/clawsec/native/apply_leaves_state",
      `${metadata.role} owns host state and must declare it`,
    );
  }

  if (native.apply_leaves_state && !native.remove_document_required) {
    addError(
      errors,
      "NANOCLAW_REMOVE_DOCUMENT_REQUIRED",
      "/clawsec/native/remove_document_required",
      "stateful NanoClaw apply requires REMOVE.md",
    );
  }

  if (native.remove_document_required) {
    const sbomFiles = Array.isArray(skill.sbom?.files) ? skill.sbom.files : [];
    const sbomRemoveEntry = sbomFiles.find(
      (entry) => isPlainObject(entry) && entry.path === "REMOVE.md",
    );
    if (!sbomRemoveEntry || sbomRemoveEntry.required !== true) {
      addError(
        errors,
        "NANOCLAW_REMOVE_DOCUMENT_NOT_IN_SBOM",
        "/sbom/files",
        "REMOVE.md must be a required SBOM file",
      );
    }
    if (skillDir !== null && !existsSync(path.join(skillDir, "REMOVE.md"))) {
      addError(
        errors,
        "NANOCLAW_REMOVE_DOCUMENT_MISSING",
        "/clawsec/native/remove_document_required",
        "declared REMOVE.md does not exist",
      );
    }
  }

}

function validateSortedStrings(values, errorPath, errors) {
  const sorted = [...values].sort();
  if (!arraysEqual(values, sorted)) {
    addError(errors, "ARRAY_NOT_SORTED", errorPath, "set-like arrays must be lexically sorted");
  }
}

function expectedPackageName(role, family, harness) {
  if (role === "core") return `clawsec-core-${harness}`;
  if (role === "suite") return `clawsec-suite-${harness}`;
  return `clawsec-${family}-guardian-${harness}`;
}

function parseCanonicalIdentity(name) {
  const match = typeof name === "string" ? name.match(CANONICAL_NAME_PATTERN) : null;
  if (!match) return null;
  return {
    role: match[1] === "drift-guardian" ? "guardian" : match[1],
    family: match[1] === "drift-guardian" ? "drift" : undefined,
    harness: match[2],
  };
}

function compareDependencies(left, right) {
  return left.name.localeCompare(right.name)
    || left.minimum_version.localeCompare(right.minimum_version)
    || left.maximum_version_exclusive.localeCompare(right.maximum_version_exclusive);
}

function arraysEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function addError(errors, code, errorPath, message) {
  const candidate = { code, path: errorPath, message };
  if (!errors.some((entry) => arraysEqual(entry, candidate))) {
    errors.push(candidate);
  }
}

function finish(classification, errors, warnings) {
  return {
    valid: errors.length === 0,
    classification,
    errors: [...errors].sort(compareDiagnostics),
    warnings: [...warnings].sort(compareDiagnostics),
  };
}

function compareDiagnostics(left, right) {
  return left.code.localeCompare(right.code)
    || left.path.localeCompare(right.path)
    || left.message.localeCompare(right.message);
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

function parseArguments(argv) {
  const options = {
    skillDir: null,
    requireClawsec: false,
    json: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--skill-dir") {
      options.skillDir = argv[index + 1] ?? null;
      index += 1;
    } else if (argument === "--require-clawsec") {
      options.requireClawsec = true;
    } else if (argument === "--json") {
      options.json = true;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }

  if (!options.skillDir) {
    throw new Error(
      "Usage: node scripts/ci/validate_clawsec_metadata.mjs --skill-dir <path> [--require-clawsec] [--json]",
    );
  }
  return options;
}

async function main() {
  let options;
  let result;
  try {
    options = parseArguments(process.argv.slice(2));
    const skillDir = path.resolve(options.skillDir);
    const skill = await readJson(path.join(skillDir, "skill.json"));
    result = validateClawsecMetadata({
      skill,
      skillDir,
      requireClawsec: options.requireClawsec,
    });
  } catch (error) {
    result = finish(
      "invalid",
      [{
        code: "METADATA_VALIDATOR_ERROR",
        path: "/",
        message: error.message,
      }],
      [],
    );
  }

  if (options?.json) {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } else if (result.valid && result.classification === "legacy") {
    process.stdout.write(`LEGACY_INPUT: ${result.warnings[0].message}\n`);
  } else if (result.valid) {
    process.stdout.write("CONTRACT_VALID: normalized ClawSec metadata v1\n");
    for (const warning of result.warnings) {
      process.stdout.write(`WARNING ${warning.code} ${warning.path}: ${warning.message}\n`);
    }
  } else {
    for (const error of result.errors) {
      process.stderr.write(`${error.code} ${error.path}: ${error.message}\n`);
    }
  }
  process.exitCode = result.valid ? 0 : 1;
}

const isDirectInvocation = process.argv[1]
  && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (isDirectInvocation) {
  await main();
}
