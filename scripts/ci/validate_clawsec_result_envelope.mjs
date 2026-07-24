#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual, TextDecoder } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

import Ajv from "ajv";

import {
  compareSemverV2,
  parseSemverV2,
} from "./lifecycle_semver.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const RESULT_MAXIMUM_BYTES = 1024 * 1024;
const RESULT_MAXIMUM_NESTING_DEPTH = 64;
const MAXIMUM_DIAGNOSTICS = 64;
const diagnosticKeysByArray = new WeakMap();
const resultSchemaPath = path.join(
  repositoryRoot,
  "contracts/schemas/result/result-v1.schema.json",
);
const componentRefSchemaPath = path.join(
  repositoryRoot,
  "contracts/schemas/component/component-ref-v1.schema.json",
);
const capabilityRegistryPath = path.join(
  repositoryRoot,
  "contracts/capability-registry.json",
);
const outcomeRegistryPath = path.join(repositoryRoot, "contracts/result-outcomes.json");
const reasonRegistryPath = path.join(repositoryRoot, "contracts/result-reason-codes.json");
const exitCodeRegistryPath = path.join(repositoryRoot, "contracts/exit-codes.json");
const operationPolicyPath = path.join(
  repositoryRoot,
  "contracts/result-operation-policy.json",
);

const loadedContracts = await Promise.all([
  readContractJson(
    resultSchemaPath,
    "RESULT_SCHEMA_SOURCE",
    "/contracts/schemas/result/result-v1.schema.json",
  ),
  readContractJson(
    componentRefSchemaPath,
    "COMPONENT_REF_SCHEMA_SOURCE",
    "/contracts/schemas/component/component-ref-v1.schema.json",
  ),
  readContractJson(
    capabilityRegistryPath,
    "CAPABILITY_REGISTRY_SOURCE",
    "/contracts/capability-registry.json",
  ),
  readContractJson(
    outcomeRegistryPath,
    "RESULT_OUTCOME_REGISTRY_SOURCE",
    "/contracts/result-outcomes.json",
  ),
  readContractJson(
    reasonRegistryPath,
    "RESULT_REASON_REGISTRY_SOURCE",
    "/contracts/result-reason-codes.json",
  ),
  readContractJson(
    exitCodeRegistryPath,
    "RESULT_EXIT_REGISTRY_SOURCE",
    "/contracts/exit-codes.json",
  ),
  readContractJson(
    operationPolicyPath,
    "RESULT_OPERATION_POLICY_SOURCE",
    "/contracts/result-operation-policy.json",
  ),
]);

const initializationErrors = loadedContracts.flatMap((entry) => entry.errors);
const [
  resultSchema,
  componentRefSchema,
  capabilityRegistry,
  outcomeRegistry,
  reasonRegistry,
  exitCodeRegistry,
  operationPolicy,
] = loadedContracts.map((entry) => entry.value ?? {});

let validateClawsecMetadata = null;
let validateComponentRef = null;
if (initializationErrors.length === 0) {
  try {
    const metadataValidator = await import("./validate_clawsec_metadata.mjs");
    validateClawsecMetadata = metadataValidator.validateClawsecMetadata;
    validateComponentRef = metadataValidator.validateComponentRef;
  } catch {
    addError(
      initializationErrors,
      "RESULT_METADATA_VALIDATOR_LOAD_FAILED",
      "/scripts/ci/validate_clawsec_metadata.mjs",
      "metadata validator could not be loaded",
    );
  }
}

let validateResultSchema = null;
if (initializationErrors.length === 0) {
  try {
    const ajv = new Ajv({
      allErrors: true,
      jsonPointers: true,
      schemaId: "auto",
    });
    ajv.addSchema(componentRefSchema);
    validateResultSchema = ajv.compile(resultSchema);
  } catch {
    addError(
      initializationErrors,
      "RESULT_SCHEMA_COMPILE_FAILED",
      "/contracts/schemas/result/result-v1.schema.json",
      "result schema could not be compiled with its registered component schema",
    );
  }
}

const EXPECTED_OUTCOMES = Object.freeze([
  "blocked",
  "confirmation_required",
  "degraded",
  "error",
  "finding",
  "not_applicable",
  "pass",
  "unsupported",
]);
const EXPECTED_EXIT_CODES = Object.freeze({
  blocked: 3,
  confirmation_required: 42,
  degraded: 4,
  error: 1,
  finding: 2,
  not_applicable: 6,
  pass: 0,
  unsupported: 5,
});
const NULL_VERSION_OUTCOMES = new Set(["blocked", "error"]);
const SAFE_REFUSAL_OUTCOMES = new Set(["blocked", "error", "unsupported"]);
const NANOCLAW_CHECKOUT_OPERATIONS = new Set([
  "core.install-release",
  "core.plan-release",
  "core.remove-release",
  "core.update-release",
  "suite.disable",
  "suite.enable",
  "suite.install",
  "suite.recurring-advisory-verification",
]);
const NANOCLAW_PACKAGE_TREE_OPERATIONS = new Set([
  "core.install-release",
  "core.plan-release",
  "core.remove-release",
  "core.update-release",
  "suite.install",
]);
const capabilityByName = new Map(
  (Array.isArray(capabilityRegistry.capabilities)
    ? capabilityRegistry.capabilities
    : []).map((entry) => [entry.name, entry]),
);
const reasonByCode = new Map(
  (Array.isArray(reasonRegistry.reasons)
    ? reasonRegistry.reasons
    : []).map((entry) => [entry.code, entry]),
);
const exitCodeByOutcome = new Map(
  (Array.isArray(exitCodeRegistry.entries)
    ? exitCodeRegistry.entries
    : []).map((entry) => [entry.outcome, entry.code]),
);

export function validateResultEnvelopeRegistries() {
  const errors = [...initializationErrors];
  if (errors.length > 0) return finish(errors);

  validateClosedObject(
    capabilityRegistry,
    ["capabilities", "contract", "contract_version"],
    "/contracts/capability-registry.json",
    errors,
  );
  validateClosedObject(
    outcomeRegistry,
    ["contract", "contract_version", "outcomes"],
    "/contracts/result-outcomes.json",
    errors,
  );
  validateClosedObject(
    reasonRegistry,
    ["contract", "contract_version", "reasons"],
    "/contracts/result-reason-codes.json",
    errors,
  );
  validateClosedObject(
    exitCodeRegistry,
    ["contract", "contract_version", "entries", "passthrough_child_exit_codes"],
    "/contracts/exit-codes.json",
    errors,
  );
  validateClosedObject(
    operationPolicy,
    ["contract", "contract_version", "effect_classes", "operations"],
    "/contracts/result-operation-policy.json",
    errors,
  );
  validateRegistryHeader(
    capabilityRegistry,
    "clawsec.capability-registry/v1",
    "/contracts/capability-registry.json",
    errors,
  );
  validateRegistryHeader(
    outcomeRegistry,
    "clawsec.result-outcomes/v1",
    "/contracts/result-outcomes.json",
    errors,
  );
  validateRegistryHeader(
    reasonRegistry,
    "clawsec.result-reason-codes/v1",
    "/contracts/result-reason-codes.json",
    errors,
  );
  validateRegistryHeader(
    exitCodeRegistry,
    "clawsec.cli-exit-codes/v1",
    "/contracts/exit-codes.json",
    errors,
  );
  validateRegistryHeader(
    operationPolicy,
    "clawsec.result-operation-policy/v1",
    "/contracts/result-operation-policy.json",
    errors,
  );

  validateCapabilityRegistry(errors);
  const outcomes = validateOutcomeRegistry(errors);
  validateReasonRegistry(outcomes, errors);
  validateExitCodeRegistry(outcomes, errors);
  validateOperationPolicyRegistry(outcomes, errors);

  const schemaOutcomes = resultSchema?.definitions?.outcome?.enum;
  if (
    !Array.isArray(schemaOutcomes)
    || !sameStringSet(schemaOutcomes, EXPECTED_OUTCOMES)
  ) {
    addError(
      errors,
      "RESULT_SCHEMA_OUTCOMES_MISMATCH",
      "/contracts/schemas/result/result-v1.schema.json/definitions/outcome/enum",
      "result schema outcomes must exactly match the result outcome registry",
    );
  }

  return finish(errors);
}

export function validateUnboundResultEnvelope(document) {
  const registryResult = validateResultEnvelopeRegistries();
  const errors = [...registryResult.errors];
  if (!registryResult.valid || validateResultSchema === null) {
    return finishStructure(errors);
  }

  if (!validateResultSchema(document)) {
    for (const schemaError of validateResultSchema.errors ?? []) {
      const additionalProperty = schemaError.keyword === "additionalProperties"
        ? schemaError.params?.additionalProperty
        : null;
      const errorPath = additionalProperty
        ? joinJsonPointer(schemaError.dataPath || "", additionalProperty)
        : schemaError.dataPath || "/";
      addError(
        errors,
        "RESULT_SCHEMA_INVALID",
        errorPath,
        `${schemaError.keyword}: ${schemaError.message}`,
      );
      if (errors.length >= MAXIMUM_DIAGNOSTICS) break;
    }
    return finishStructure(errors);
  }

  appendNestedDiagnostics(
    errors,
    validateComponentRef(document.executor).errors,
    "/executor",
  );
  if (document.subject.kind === "component") {
    appendNestedDiagnostics(
      errors,
      validateComponentRef(document.subject.component).errors,
      "/subject/component",
    );
  }

  const capability = capabilityByName.get(document.invocation.operation);
  if (!capability) {
    addError(
      errors,
      "RESULT_OPERATION_UNKNOWN",
      "/invocation/operation",
      `operation ${document.invocation.operation} is not registered`,
    );
  } else {
    if (capability.role !== document.executor.role) {
      addError(
        errors,
        "RESULT_OPERATION_ROLE_MISMATCH",
        "/invocation/operation",
        `operation ${capability.name} belongs to role ${capability.role}`,
      );
    }
    if ((capability.family ?? null) !== (document.executor.family ?? null)) {
      addError(
        errors,
        "RESULT_OPERATION_FAMILY_MISMATCH",
        "/invocation/operation",
        `operation ${capability.name} does not match the executor family`,
      );
    }
  }

  if (document.invocation.harness.name !== document.executor.harness) {
    addError(
      errors,
      "RESULT_EXECUTOR_HARNESS_MISMATCH",
      "/invocation/harness/name",
      "invocation harness must match the executor harness",
    );
  }
  validateHarnessVersion(document.invocation.harness.version, document.outcome, errors);
  validateScopeHarness(
    document.invocation.scope.kind,
    document.invocation.harness.name,
    errors,
  );

  if (
    document.subject.kind === "component"
    && document.subject.component.harness !== document.invocation.harness.name
  ) {
    addError(
      errors,
      "RESULT_SUBJECT_HARNESS_MISMATCH",
      "/subject/component/harness",
      "component subject harness must match the invocation harness",
    );
  }

  const reason = reasonByCode.get(document.reason_code);
  if (!reason) {
    addError(
      errors,
      "RESULT_REASON_UNKNOWN",
      "/reason_code",
      `reason code ${document.reason_code} is not registered`,
    );
  } else if (reason.outcome !== document.outcome) {
    addError(
      errors,
      "RESULT_REASON_OUTCOME_MISMATCH",
      "/reason_code",
      `reason ${reason.code} is registered for outcome ${reason.outcome}`,
    );
  }

  validateOperationSemantics(document, errors);
  validateEffectSemantics(document, errors);
  return finishStructure(errors);
}

export function validateUnboundResultEnvelopeBytes(resultBytes) {
  const parsed = parseJsonObjectBytes(resultBytes, "RESULT", "/");
  if (!parsed.valid) return finishStructure(parsed.errors);
  return validateUnboundResultEnvelope(parsed.value);
}

export function validateBoundResultEnvelope({
  resultBytes,
  metadataBytesByDigest,
  expectedContext,
} = {}) {
  const parsedResult = parseJsonObjectBytes(resultBytes, "RESULT", "/");
  if (!parsedResult.valid) return finishBound(parsedResult.errors, []);

  const document = parsedResult.value;
  const structureResult = validateUnboundResultEnvelope(document);
  const errors = [...structureResult.errors];
  const warnings = [];
  if (!structureResult.valid || validateResultSchema === null) {
    return finishBound(errors, warnings);
  }

  if (
    !isPlainObject(expectedContext)
    || !isDeepStrictEqual(
      Object.keys(expectedContext).sort(),
      ["executor", "invocation", "subject"],
    )
  ) {
    addError(
      errors,
      "RESULT_EXPECTED_CONTEXT_REQUIRED",
      "/",
      "bound validation requires expected executor, subject, and invocation",
    );
  } else {
    if (!isDeepStrictEqual(document.executor, expectedContext.executor)) {
      addError(
        errors,
        "RESULT_EXECUTOR_CONTEXT_MISMATCH",
        "/executor",
        "result executor does not match the caller's expected executor",
      );
    }
    if (!isDeepStrictEqual(document.subject, expectedContext.subject)) {
      addError(
        errors,
        "RESULT_SUBJECT_CONTEXT_MISMATCH",
        "/subject",
        "result subject does not match the caller's expected subject",
      );
    }
    if (!isDeepStrictEqual(document.invocation, expectedContext.invocation)) {
      addError(
        errors,
        "RESULT_INVOCATION_MISMATCH",
        "/invocation",
        "result invocation does not match the caller's expected invocation",
      );
    }
  }

  const executorBinding = resolveAndValidateMetadata({
    componentRef: document.executor,
    metadataBytesByDigest,
    label: "EXECUTOR",
    errorPath: "/executor",
    errors,
    warnings,
  });

  let subjectBinding = null;
  if (document.subject.kind === "component") {
    subjectBinding = resolveAndValidateMetadata({
      componentRef: document.subject.component,
      metadataBytesByDigest,
      label: "SUBJECT",
      errorPath: "/subject/component",
      errors,
      warnings,
    });
  }

  if (executorBinding) {
    const operation = document.invocation.operation;
    if (!executorBinding.skill.clawsec.provides.includes(operation)) {
      addError(
        errors,
        "RESULT_OPERATION_NOT_DECLARED",
        "/invocation/operation",
        `executor metadata does not declare operation ${operation}`,
      );
    }

    const harnessVersion = document.invocation.harness.version;
    if (
      harnessVersion !== null
      && isStrictSemver(harnessVersion)
      && !versionIsInRange(harnessVersion, executorBinding.skill.clawsec.supported_harness)
      && !SAFE_REFUSAL_OUTCOMES.has(document.outcome)
    ) {
      addError(
        errors,
        "RESULT_EXECUTOR_VERSION_UNSUPPORTED",
        "/invocation/harness/version",
        "harness version is outside the executor's declared support range",
      );
    }
  }

  if (subjectBinding) {
    const harnessVersion = document.invocation.harness.version;
    if (
      harnessVersion !== null
      && isStrictSemver(harnessVersion)
      && !versionIsInRange(harnessVersion, subjectBinding.skill.clawsec.supported_harness)
      && !SAFE_REFUSAL_OUTCOMES.has(document.outcome)
    ) {
      addError(
        errors,
        "RESULT_SUBJECT_VERSION_UNSUPPORTED",
        "/invocation/harness/version",
        "harness version is outside the component subject's declared support range",
      );
    }
  }

  validateBoundHarnessSemantics(document, subjectBinding?.skill ?? null, errors);
  return finishBound(errors, warnings);
}

export function digestBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("digestBytes requires Buffer or Uint8Array input");
  }
  const buffer = Buffer.from(bytes);
  return `sha256:${createHash("sha256").update(buffer).digest("hex")}`;
}

export function exitCodeForOutcome(outcome) {
  if (!validateResultEnvelopeRegistries().valid) return null;
  return exitCodeByOutcome.get(outcome) ?? null;
}

function validateCapabilityRegistry(errors) {
  const registryPath = "/contracts/capability-registry.json/capabilities";
  if (!Array.isArray(capabilityRegistry.capabilities)) {
    addError(
      errors,
      "RESULT_CAPABILITY_REGISTRY_INVALID",
      registryPath,
      "capabilities must be an array",
    );
    return;
  }

  const names = [];
  for (let index = 0; index < capabilityRegistry.capabilities.length; index += 1) {
    const entry = capabilityRegistry.capabilities[index];
    const entryPath = `${registryPath}/${index}`;
    const expectedKeys = entry?.role === "guardian"
      ? ["family", "name", "required_for_stable", "role"]
      : ["name", "required_for_stable", "role"];
    validateClosedObject(entry, expectedKeys, entryPath, errors);
    if (
      !isPlainObject(entry)
      || typeof entry.name !== "string"
      || !/^(?:core|suite|guardian|posture)\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/
        .test(entry.name)
      || !["core", "guardian", "suite"].includes(entry.role)
      || typeof entry.required_for_stable !== "boolean"
    ) {
      addError(
        errors,
        "RESULT_CAPABILITY_ENTRY_INVALID",
        entryPath,
        "each capability requires canonical name, role, and stability requirement",
      );
      continue;
    }
    names.push(entry.name);
    if (entry.role === "guardian" && entry.family !== "drift") {
      addError(
        errors,
        "RESULT_CAPABILITY_FAMILY_INVALID",
        `${entryPath}/family`,
        "guardian capabilities require drift family in contract v1",
      );
    } else if (entry.role !== "guardian" && entry.family !== undefined) {
      addError(
        errors,
        "RESULT_CAPABILITY_FAMILY_FORBIDDEN",
        `${entryPath}/family`,
        "only guardian capabilities declare a family",
      );
    }
  }
  validateSortedUniqueStrings(
    names,
    registryPath,
    "RESULT_CAPABILITY",
    errors,
  );
}

function validateOutcomeRegistry(errors) {
  const registryPath = "/contracts/result-outcomes.json/outcomes";
  if (!Array.isArray(outcomeRegistry.outcomes)) {
    addError(
      errors,
      "RESULT_OUTCOME_REGISTRY_INVALID",
      registryPath,
      "outcomes must be an array",
    );
    return new Set();
  }

  const names = [];
  for (let index = 0; index < outcomeRegistry.outcomes.length; index += 1) {
    const entry = outcomeRegistry.outcomes[index];
    const entryPath = `${registryPath}/${index}`;
    validateClosedObject(entry, ["description", "name"], entryPath, errors);
    if (
      !isPlainObject(entry)
      || typeof entry.name !== "string"
      || typeof entry.description !== "string"
      || entry.description.length === 0
    ) {
      addError(
        errors,
        "RESULT_OUTCOME_ENTRY_INVALID",
        entryPath,
        "each outcome requires non-empty name and description strings",
      );
      continue;
    }
    names.push(entry.name);
  }

  validateSortedUniqueStrings(names, registryPath, "RESULT_OUTCOME", errors);
  if (!sameStringSet(names, EXPECTED_OUTCOMES)) {
    addError(
      errors,
      "RESULT_OUTCOME_SET_MISMATCH",
      registryPath,
      "outcomes must contain exactly the v1 outcome vocabulary",
    );
  }
  return new Set(names);
}

function validateReasonRegistry(outcomes, errors) {
  const registryPath = "/contracts/result-reason-codes.json/reasons";
  if (!Array.isArray(reasonRegistry.reasons)) {
    addError(
      errors,
      "RESULT_REASON_REGISTRY_INVALID",
      registryPath,
      "reasons must be an array",
    );
    return;
  }

  const codes = [];
  const coveredOutcomes = new Set();
  for (let index = 0; index < reasonRegistry.reasons.length; index += 1) {
    const entry = reasonRegistry.reasons[index];
    const entryPath = `${registryPath}/${index}`;
    validateClosedObject(entry, ["code", "description", "outcome"], entryPath, errors);
    if (
      !isPlainObject(entry)
      || typeof entry.code !== "string"
      || !/^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/.test(entry.code)
      || typeof entry.description !== "string"
      || entry.description.length === 0
      || typeof entry.outcome !== "string"
    ) {
      addError(
        errors,
        "RESULT_REASON_ENTRY_INVALID",
        entryPath,
        "each reason requires a canonical code, outcome, and description",
      );
      continue;
    }
    codes.push(entry.code);
    if (!outcomes.has(entry.outcome)) {
      addError(
        errors,
        "RESULT_REASON_OUTCOME_UNKNOWN",
        `${entryPath}/outcome`,
        `reason ${entry.code} references unknown outcome ${entry.outcome}`,
      );
    } else {
      coveredOutcomes.add(entry.outcome);
    }
  }

  validateSortedUniqueStrings(codes, registryPath, "RESULT_REASON", errors);
  for (const outcome of EXPECTED_OUTCOMES) {
    if (!coveredOutcomes.has(outcome)) {
      addError(
        errors,
        "RESULT_REASON_OUTCOME_UNCOVERED",
        registryPath,
        `outcome ${outcome} has no registered reason code`,
      );
    }
  }
}

function validateExitCodeRegistry(outcomes, errors) {
  const registryPath = "/contracts/exit-codes.json";
  if (exitCodeRegistry.passthrough_child_exit_codes !== false) {
    addError(
      errors,
      "RESULT_EXIT_PASSTHROUGH_FORBIDDEN",
      `${registryPath}/passthrough_child_exit_codes`,
      "child exit codes must not pass through",
    );
  }
  if (!Array.isArray(exitCodeRegistry.entries)) {
    addError(
      errors,
      "RESULT_EXIT_REGISTRY_INVALID",
      `${registryPath}/entries`,
      "entries must be an array",
    );
    return;
  }

  const seenCodes = new Set();
  const seenOutcomes = new Set();
  let previousCode = -1;
  for (let index = 0; index < exitCodeRegistry.entries.length; index += 1) {
    const entry = exitCodeRegistry.entries[index];
    const entryPath = `${registryPath}/entries/${index}`;
    validateClosedObject(entry, ["code", "outcome"], entryPath, errors);
    if (
      !isPlainObject(entry)
      || !Number.isInteger(entry.code)
      || entry.code < 0
      || entry.code > 255
      || typeof entry.outcome !== "string"
    ) {
      addError(
        errors,
        "RESULT_EXIT_ENTRY_INVALID",
        entryPath,
        "each exit entry requires a unique byte-sized code and outcome",
      );
      continue;
    }
    if (entry.code <= previousCode) {
      addError(
        errors,
        "RESULT_EXIT_CODES_NOT_SORTED",
        entryPath,
        "exit entries must be sorted by numeric code",
      );
    }
    previousCode = entry.code;
    if (seenCodes.has(entry.code)) {
      addError(
        errors,
        "RESULT_EXIT_CODE_DUPLICATE",
        `${entryPath}/code`,
        `exit code ${entry.code} appears more than once`,
      );
    }
    if (seenOutcomes.has(entry.outcome)) {
      addError(
        errors,
        "RESULT_EXIT_OUTCOME_DUPLICATE",
        `${entryPath}/outcome`,
        `outcome ${entry.outcome} appears more than once`,
      );
    }
    seenCodes.add(entry.code);
    seenOutcomes.add(entry.outcome);
    if (!outcomes.has(entry.outcome)) {
      addError(
        errors,
        "RESULT_EXIT_OUTCOME_UNKNOWN",
        `${entryPath}/outcome`,
        `exit entry references unknown outcome ${entry.outcome}`,
      );
    }
    if (EXPECTED_EXIT_CODES[entry.outcome] !== entry.code) {
      addError(
        errors,
        "RESULT_EXIT_MAPPING_MISMATCH",
        entryPath,
        `outcome ${entry.outcome} must map to exit code ${EXPECTED_EXIT_CODES[entry.outcome]}`,
      );
    }
  }

  if (!sameStringSet([...seenOutcomes], EXPECTED_OUTCOMES)) {
    addError(
      errors,
      "RESULT_EXIT_OUTCOME_SET_MISMATCH",
      `${registryPath}/entries`,
      "every result outcome must have exactly one exit-code mapping",
    );
  }
}

function validateOperationPolicyRegistry(outcomes, errors) {
  const registryPath = "/contracts/result-operation-policy.json";
  if (!isPlainObject(operationPolicy.operations)) {
    addError(
      errors,
      "RESULT_OPERATION_POLICY_INVALID",
      `${registryPath}/operations`,
      "operations must be an object",
    );
    return;
  }
  if (!isPlainObject(operationPolicy.effect_classes)) {
    addError(
      errors,
      "RESULT_EFFECT_CLASS_POLICY_INVALID",
      `${registryPath}/effect_classes`,
      "effect_classes must be an object",
    );
    return;
  }

  const operationNames = Object.keys(operationPolicy.operations);
  const capabilityNames = [...capabilityByName.keys()];
  validateSortedUniqueStrings(
    operationNames,
    `${registryPath}/operations`,
    "RESULT_OPERATION_POLICY",
    errors,
  );
  if (!sameStringSet(operationNames, capabilityNames)) {
    addError(
      errors,
      "RESULT_OPERATION_POLICY_SET_MISMATCH",
      `${registryPath}/operations`,
      "operation policy keys must exactly match the capability registry",
    );
  }

  const effectClassNames = Object.keys(operationPolicy.effect_classes);
  const expectedEffectClasses = ["mutation", "planning", "read_only"];
  if (!isDeepStrictEqual(effectClassNames, expectedEffectClasses)) {
    addError(
      errors,
      "RESULT_EFFECT_CLASS_SET_MISMATCH",
      `${registryPath}/effect_classes`,
      "effect classes must be mutation, planning, and read_only in lexical order",
    );
  }

  for (const operationName of operationNames) {
    const entry = operationPolicy.operations[operationName];
    const entryPath = `${registryPath}/operations/${escapeJsonPointerToken(operationName)}`;
    validateClosedObject(entry, ["effect_class", "subject_kinds"], entryPath, errors);
    if (
      !isPlainObject(entry)
      || !expectedEffectClasses.includes(entry.effect_class)
      || !Array.isArray(entry.subject_kinds)
      || entry.subject_kinds.length === 0
    ) {
      addError(
        errors,
        "RESULT_OPERATION_POLICY_ENTRY_INVALID",
        entryPath,
        "each operation requires an effect class and at least one subject kind",
      );
      continue;
    }
    validateSortedUniqueStrings(
      entry.subject_kinds,
      `${entryPath}/subject_kinds`,
      "RESULT_SUBJECT_KIND",
      errors,
    );
    for (const subjectKind of entry.subject_kinds) {
      if (!["component", "executor", "scope"].includes(subjectKind)) {
        addError(
          errors,
          "RESULT_SUBJECT_KIND_UNKNOWN",
          `${entryPath}/subject_kinds`,
          `unknown subject kind ${subjectKind}`,
        );
      }
    }
  }

  for (const effectClass of expectedEffectClasses) {
    const classPath = `${registryPath}/effect_classes/${effectClass}`;
    const rules = operationPolicy.effect_classes[effectClass];
    if (!isPlainObject(rules)) {
      addError(
        errors,
        "RESULT_EFFECT_CLASS_RULES_INVALID",
        classPath,
        "effect class rules must be an object",
      );
      continue;
    }
    const ruleOutcomes = Object.keys(rules);
    if (
      !sameStringSet(ruleOutcomes, [...outcomes])
      || !isDeepStrictEqual(ruleOutcomes, [...ruleOutcomes].sort())
    ) {
      addError(
        errors,
        "RESULT_EFFECT_CLASS_OUTCOMES_MISMATCH",
        classPath,
        "each effect class must define every outcome in lexical order",
      );
    }
    for (const outcome of ruleOutcomes) {
      const rule = rules[outcome];
      const rulePath = `${classPath}/${outcome}`;
      if (rule === null) continue;
      validateClosedObject(rule, ["allowed_states", "minimum_count"], rulePath, errors);
      if (
        !isPlainObject(rule)
        || !Array.isArray(rule.allowed_states)
        || !Number.isInteger(rule.minimum_count)
        || rule.minimum_count < 0
        || rule.minimum_count > 1
      ) {
        addError(
          errors,
          "RESULT_EFFECT_RULE_INVALID",
          rulePath,
          "effect rule requires allowed_states and minimum_count of zero or one",
        );
        continue;
      }
      validateSortedUniqueStrings(
        rule.allowed_states,
        `${rulePath}/allowed_states`,
        "RESULT_EFFECT_STATE",
        errors,
      );
      for (const state of rule.allowed_states) {
        if (!["applied", "failed", "proposed", "rolled_back"].includes(state)) {
          addError(
            errors,
            "RESULT_EFFECT_STATE_UNKNOWN",
            `${rulePath}/allowed_states`,
            `unknown effect state ${state}`,
          );
        }
      }
      if (rule.minimum_count > 0 && rule.allowed_states.length === 0) {
        addError(
          errors,
          "RESULT_EFFECT_RULE_UNSATISFIABLE",
          rulePath,
          "a positive minimum_count requires at least one allowed state",
        );
      }
    }
  }

  validateRequiredEffectInvariants(errors);
}

function validateRequiredEffectInvariants(errors) {
  const policies = operationPolicy.effect_classes;
  const expected = {
    mutation: {
      blocked: [["proposed"], 0],
      confirmation_required: [["proposed"], 1],
      degraded: null,
      error: [["applied", "failed", "proposed", "rolled_back"], 0],
      finding: null,
      not_applicable: [[], 0],
      pass: [["applied"], 1],
      unsupported: [[], 0],
    },
    planning: {
      blocked: [["proposed"], 0],
      confirmation_required: null,
      degraded: [["proposed"], 0],
      error: [[], 0],
      finding: null,
      not_applicable: [[], 0],
      pass: [["proposed"], 1],
      unsupported: [[], 0],
    },
    read_only: {
      blocked: [[], 0],
      confirmation_required: null,
      degraded: [[], 0],
      error: [[], 0],
      finding: [[], 0],
      not_applicable: [[], 0],
      pass: [[], 0],
      unsupported: [[], 0],
    },
  };

  for (const [effectClass, outcomes] of Object.entries(expected)) {
    for (const [outcome, expectedRule] of Object.entries(outcomes)) {
      const actualRule = policies?.[effectClass]?.[outcome];
      const normalizedActual = actualRule === null
        ? null
        : [actualRule?.allowed_states, actualRule?.minimum_count];
      if (!isDeepStrictEqual(normalizedActual, expectedRule)) {
        addError(
          errors,
          "RESULT_EFFECT_INVARIANT_MISMATCH",
          `/contracts/result-operation-policy.json/effect_classes/${effectClass}/${outcome}`,
          "effect rule does not match the required v1 safety invariant",
        );
      }
    }
  }
}

function validateRegistryHeader(document, expectedContract, errorPath, errors) {
  if (!isPlainObject(document)) {
    addError(
      errors,
      "RESULT_REGISTRY_INVALID",
      errorPath,
      "registry must contain a JSON object",
    );
    return;
  }
  if (document.contract !== expectedContract) {
    addError(
      errors,
      "RESULT_REGISTRY_CONTRACT_MISMATCH",
      `${errorPath}/contract`,
      `expected contract ${expectedContract}`,
    );
  }
  if (document.contract_version !== "1") {
    addError(
      errors,
      "RESULT_REGISTRY_VERSION_MISMATCH",
      `${errorPath}/contract_version`,
      "expected contract version 1",
    );
  }
}

function validateHarnessVersion(version, outcome, errors) {
  if (version === null) {
    if (!NULL_VERSION_OUTCOMES.has(outcome)) {
      addError(
        errors,
        "RESULT_HARNESS_VERSION_REQUIRED",
        "/invocation/harness/version",
        "a harness version may be null only for blocked or error outcomes",
      );
    }
    return;
  }
  try {
    parseSemverV2(version);
  } catch {
    addError(
      errors,
      "RESULT_HARNESS_VERSION_INVALID",
      "/invocation/harness/version",
      "harness version must be strict SemVer",
    );
  }
}

function validateScopeHarness(scopeKind, harness, errors) {
  if (scopeKind === "host") return;
  if (!scopeKind.startsWith(`${harness}.`)) {
    addError(
      errors,
      "RESULT_SCOPE_HARNESS_MISMATCH",
      "/invocation/scope/kind",
      `scope ${scopeKind} does not belong to harness ${harness}`,
    );
  }
}

function validateOperationSemantics(document, errors) {
  const policy = operationPolicy.operations?.[document.invocation.operation];
  if (!isPlainObject(policy)) return;

  if (!policy.subject_kinds.includes(document.subject.kind)) {
    addError(
      errors,
      "RESULT_SUBJECT_KIND_FORBIDDEN",
      "/subject/kind",
      `operation ${document.invocation.operation} does not accept subject kind `
      + document.subject.kind,
    );
  }
  if (
    document.invocation.operation === "core.verify-release"
    && document.subject.kind === "scope"
    && !SAFE_REFUSAL_OUTCOMES.has(document.outcome)
  ) {
    addError(
      errors,
      "RESULT_RELEASE_COMPONENT_SUBJECT_REQUIRED",
      "/subject",
      "successful release verification requires an exact component subject",
    );
  }

  const rule = operationPolicy.effect_classes?.[policy.effect_class]?.[document.outcome];
  if (rule === null || rule === undefined) {
    addError(
      errors,
      "RESULT_OUTCOME_FORBIDDEN",
      "/outcome",
      `outcome ${document.outcome} is invalid for ${policy.effect_class} operation `
      + document.invocation.operation,
    );
    return;
  }

  if (document.effects.length < rule.minimum_count) {
    addError(
      errors,
      "RESULT_EFFECT_COUNT_INSUFFICIENT",
      "/effects",
      `outcome ${document.outcome} requires at least ${rule.minimum_count} effect`,
    );
  }
  for (let index = 0; index < document.effects.length; index += 1) {
    const effect = document.effects[index];
    if (!rule.allowed_states.includes(effect.state)) {
      addError(
        errors,
        "RESULT_EFFECT_STATE_FORBIDDEN",
        `/effects/${index}/state`,
        `state ${effect.state} is invalid for ${policy.effect_class} outcome `
        + document.outcome,
      );
    }
  }
}

function validateBoundHarnessSemantics(document, subjectSkill, errors) {
  if (document.executor.harness !== "nanoclaw") return;
  const operation = document.invocation.operation;
  if (
    NANOCLAW_CHECKOUT_OPERATIONS.has(operation)
    && document.invocation.scope.kind !== "nanoclaw.checkout"
  ) {
    addError(
      errors,
      "RESULT_NANOCLAW_CHECKOUT_SCOPE_REQUIRED",
      "/invocation/scope/kind",
      `NanoClaw operation ${operation} requires an explicit checkout scope`,
    );
  }

  if (
    !subjectSkill
    || !NANOCLAW_PACKAGE_TREE_OPERATIONS.has(operation)
    || !["confirmation_required", "pass"].includes(document.outcome)
  ) {
    return;
  }
  const installLocation = subjectSkill.clawsec.native?.install_location;
  const identifiesPackageTree = document.effects.some((effect) => (
    effect.target.kind === "relative_path"
    && effect.target.value === installLocation
  ));
  if (!identifiesPackageTree) {
    addError(
      errors,
      "RESULT_NANOCLAW_PACKAGE_TREE_EFFECT_REQUIRED",
      "/effects",
      "NanoClaw package operation must identify the subject's declared install location",
    );
  }
}

function validateEffectSemantics(document, errors) {
  const effectIds = [];
  for (let index = 0; index < document.effects.length; index += 1) {
    const effect = document.effects[index];
    effectIds.push(effect.effect_id);
    if (
      effect.target.kind === "relative_path"
      && !isNormalizedRelativePath(effect.target.value)
    ) {
      addError(
        errors,
        "RESULT_EFFECT_PATH_INVALID",
        `/effects/${index}/target/value`,
        "effect target must be a normalized portable relative path",
      );
    }
  }
  validateSortedUniqueStrings(
    effectIds,
    "/effects",
    "RESULT_EFFECT_ID",
    errors,
  );
}

function resolveAndValidateMetadata({
  componentRef,
  metadataBytesByDigest,
  label,
  errorPath,
  errors,
  warnings,
}) {
  const suppliedBytes = resolveDigestBytes(
    metadataBytesByDigest,
    componentRef.metadata_digest,
  );
  if (!(suppliedBytes instanceof Uint8Array)) {
    addError(
      errors,
      `RESULT_${label}_METADATA_MISSING`,
      `${errorPath}/metadata_digest`,
      `no metadata bytes were supplied for ${componentRef.metadata_digest}`,
    );
    return null;
  }
  const bytes = Buffer.from(suppliedBytes);

  const actualDigest = digestBytes(bytes);
  if (actualDigest !== componentRef.metadata_digest) {
    addError(
      errors,
      `RESULT_${label}_METADATA_DIGEST_MISMATCH`,
      `${errorPath}/metadata_digest`,
      "component reference does not match the exact supplied metadata bytes",
    );
    return null;
  }

  const parsed = parseJsonObjectBytes(
    bytes,
    `${label}_METADATA`,
    `${errorPath}/metadata`,
  );
  if (!parsed.valid) {
    for (const error of parsed.errors) addError(errors, error.code, error.path, error.message);
    return null;
  }

  const metadataResult = validateClawsecMetadata({
    skill: parsed.value,
    skillDir: null,
    requireClawsec: true,
  });
  appendNestedDiagnostics(
    errors,
    metadataResult.errors,
    `${errorPath}/metadata`,
    `RESULT_${label}_`,
  );
  appendNestedDiagnostics(
    warnings,
    metadataResult.warnings,
    `${errorPath}/metadata`,
    `RESULT_${label}_`,
  );
  if (!metadataResult.valid) return null;

  const expected = componentIdentityFromSkill(parsed.value, actualDigest);
  for (const field of ["name", "version", "harness", "role", "family"]) {
    if ((componentRef[field] ?? null) !== (expected[field] ?? null)) {
      addError(
        errors,
        `RESULT_${label}_IDENTITY_MISMATCH`,
        `${errorPath}/${field}`,
        `component reference ${field} does not match exact metadata`,
      );
    }
  }

  return {
    skill: parsed.value,
    digest: actualDigest,
  };
}

function componentIdentityFromSkill(skill, metadataDigest) {
  return {
    name: skill.name,
    version: skill.version,
    harness: skill.clawsec.supported_harness.name,
    role: skill.clawsec.role,
    family: skill.clawsec.family,
    metadata_digest: metadataDigest,
  };
}

function resolveDigestBytes(resolver, digest) {
  if (resolver instanceof Map) return resolver.get(digest);
  if (isPlainObject(resolver) && Object.hasOwn(resolver, digest)) {
    return resolver[digest];
  }
  return null;
}

function versionIsInRange(version, range) {
  try {
    return compareSemverV2(version, range.minimum_version) >= 0
      && compareSemverV2(version, range.maximum_version_exclusive) < 0;
  } catch {
    return false;
  }
}

function isStrictSemver(version) {
  try {
    parseSemverV2(version);
    return true;
  } catch {
    return false;
  }
}

export function parseJsonObjectBytes(bytes, label, errorPath) {
  const errors = [];
  if (!(bytes instanceof Uint8Array)) {
    addError(
      errors,
      `${label}_BYTES_REQUIRED`,
      errorPath,
      "input must be Buffer or Uint8Array",
    );
    return { valid: false, value: null, errors: finish(errors).errors };
  }
  const stableBytes = Buffer.from(bytes);
  if (stableBytes.length === 0) {
    addError(errors, `${label}_EMPTY`, errorPath, "input bytes cannot be empty");
    return { valid: false, value: null, errors: finish(errors).errors };
  }
  if (stableBytes.length > RESULT_MAXIMUM_BYTES) {
    addError(
      errors,
      `${label}_TOO_LARGE`,
      errorPath,
      `input exceeds the ${RESULT_MAXIMUM_BYTES}-byte contract limit`,
    );
    return { valid: false, value: null, errors: finish(errors).errors };
  }
  if (
    stableBytes[0] === 0xef
    && stableBytes[1] === 0xbb
    && stableBytes[2] === 0xbf
  ) {
    addError(errors, `${label}_BOM_FORBIDDEN`, errorPath, "UTF-8 BOM is forbidden");
    return { valid: false, value: null, errors: finish(errors).errors };
  }

  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(stableBytes);
  } catch {
    addError(errors, `${label}_UTF8_INVALID`, errorPath, "input is not valid UTF-8");
    return { valid: false, value: null, errors: finish(errors).errors };
  }
  if (exceedsJsonNestingDepth(text, RESULT_MAXIMUM_NESTING_DEPTH)) {
    addError(
      errors,
      `${label}_NESTING_TOO_DEEP`,
      errorPath,
      `JSON nesting exceeds the ${RESULT_MAXIMUM_NESTING_DEPTH}-level contract limit`,
    );
    return { valid: false, value: null, errors: finish(errors).errors };
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch {
    addError(
      errors,
      `${label}_JSON_INVALID`,
      errorPath,
      "input is not one complete JSON document",
    );
    return { valid: false, value: null, errors: finish(errors).errors };
  }

  let duplicate;
  try {
    duplicate = findDuplicateJsonKey(text);
  } catch {
    addError(
      errors,
      `${label}_STRUCTURE_INVALID`,
      errorPath,
      "JSON structure could not be validated deterministically",
    );
    return { valid: false, value: null, errors: finish(errors).errors };
  }
  if (duplicate) {
    addError(
      errors,
      `${label}_DUPLICATE_KEY`,
      errorPath,
      "duplicate object keys are forbidden",
    );
  }
  if (!isPlainObject(value)) {
    addError(
      errors,
      `${label}_ROOT_INVALID`,
      errorPath,
      "top-level JSON value must be an object",
    );
  }
  return {
    valid: errors.length === 0,
    value,
    errors: finish(errors).errors,
  };
}

function exceedsJsonNestingDepth(text, maximumDepth) {
  let depth = 0;
  let escaped = false;
  let inString = false;
  for (const character of text) {
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === "\"") {
        inString = false;
      }
      continue;
    }
    if (character === "\"") {
      inString = true;
    } else if (character === "{" || character === "[") {
      depth += 1;
      if (depth > maximumDepth) return true;
    } else if (character === "}" || character === "]") {
      depth -= 1;
    }
  }
  return false;
}

function findDuplicateJsonKey(text) {
  let index = 0;

  function skipWhitespace() {
    while (index < text.length && /[\t\n\r ]/.test(text[index])) index += 1;
  }

  function parseString() {
    const start = index;
    index += 1;
    while (index < text.length) {
      if (text[index] === "\\") {
        index += 2;
      } else if (text[index] === "\"") {
        index += 1;
        return JSON.parse(text.slice(start, index));
      } else {
        index += 1;
      }
    }
    return "";
  }

  function parseValue(pointerParts) {
    skipWhitespace();
    if (text[index] === "{") return parseObject(pointerParts);
    if (text[index] === "[") return parseArray(pointerParts);
    if (text[index] === "\"") {
      parseString();
      return null;
    }
    while (
      index < text.length
      && !/[\t\n\r ,\]}]/.test(text[index])
    ) {
      index += 1;
    }
    return null;
  }

  function parseObject(pointerParts) {
    index += 1;
    skipWhitespace();
    if (text[index] === "}") {
      index += 1;
      return null;
    }

    const keys = new Set();
    while (index < text.length) {
      skipWhitespace();
      const key = parseString();
      const keyPath = [...pointerParts, key];
      if (keys.has(key)) {
        return {
          key,
          path: jsonPointer(keyPath),
        };
      }
      keys.add(key);
      skipWhitespace();
      index += 1;
      const duplicate = parseValue(keyPath);
      if (duplicate) return duplicate;
      skipWhitespace();
      if (text[index] === "}") {
        index += 1;
        return null;
      }
      index += 1;
    }
    return null;
  }

  function parseArray(pointerParts) {
    index += 1;
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return null;
    }
    let itemIndex = 0;
    while (index < text.length) {
      const duplicate = parseValue([...pointerParts, String(itemIndex)]);
      if (duplicate) return duplicate;
      itemIndex += 1;
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return null;
      }
      index += 1;
    }
    return null;
  }

  return parseValue([]);
}

function validateClosedObject(value, expectedKeys, errorPath, errors) {
  if (!isPlainObject(value)) return;
  const actualKeys = Object.keys(value).sort();
  const sortedExpected = [...expectedKeys].sort();
  if (!isDeepStrictEqual(actualKeys, sortedExpected)) {
    addError(
      errors,
      "RESULT_REGISTRY_ENTRY_FIELDS_INVALID",
      errorPath,
      `expected fields ${sortedExpected.join(", ")}`,
    );
  }
}

function validateSortedUniqueStrings(values, errorPath, codePrefix, errors) {
  const seen = new Set();
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (seen.has(value)) {
      addError(
        errors,
        `${codePrefix}_DUPLICATE`,
        `${errorPath}/${index}`,
        `value ${value} appears more than once`,
      );
    }
    seen.add(value);
    if (index > 0 && compareAscii(values[index - 1], value) >= 0) {
      addError(
        errors,
        `${codePrefix}_NOT_SORTED`,
        `${errorPath}/${index}`,
        "set-like entries must be lexically sorted",
      );
    }
  }
}

function sameStringSet(left, right) {
  return isDeepStrictEqual([...new Set(left)].sort(), [...new Set(right)].sort());
}

function isNormalizedRelativePath(value) {
  if (typeof value !== "string") return false;
  return /^(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9._@+-]+(?:\/[A-Za-z0-9._@+-]+)*$/
    .test(value);
}

function appendNestedDiagnostics(errors, nestedErrors, prefix, codePrefix = "RESULT_") {
  for (const nested of nestedErrors ?? []) {
    const nestedPath = nested.path === "/" ? "" : nested.path;
    addError(
      errors,
      nested.code.startsWith("RESULT_") ? nested.code : `${codePrefix}${nested.code}`,
      `${prefix}${nestedPath}` || "/",
      nested.message,
    );
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function joinJsonPointer(base, token) {
  const prefix = base === "/" ? "" : base;
  return `${prefix}/${escapeJsonPointerToken(token)}`;
}

function jsonPointer(parts) {
  if (parts.length === 0) return "/";
  return `/${parts.map(escapeJsonPointerToken).join("/")}`;
}

function escapeJsonPointerToken(value) {
  return String(value).replaceAll("~", "~0").replaceAll("/", "~1");
}

function addError(errors, code, errorPath, message) {
  const candidate = {
    code: sanitizeDiagnosticText(code),
    path: sanitizeDiagnosticText(errorPath || "/"),
    message: sanitizeDiagnosticText(message),
  };
  let diagnosticKeys = diagnosticKeysByArray.get(errors);
  if (!diagnosticKeys) {
    diagnosticKeys = new Set(errors.map(diagnosticKey));
    diagnosticKeysByArray.set(errors, diagnosticKeys);
  }
  const candidateKey = diagnosticKey(candidate);
  if (diagnosticKeys.has(candidateKey)) return;
  if (errors.length >= MAXIMUM_DIAGNOSTICS - 1) {
    const truncated = {
      code: "RESULT_DIAGNOSTICS_TRUNCATED",
      path: "/",
      message: `validation stopped after ${MAXIMUM_DIAGNOSTICS - 1} diagnostics`,
    };
    const truncatedKey = diagnosticKey(truncated);
    if (!diagnosticKeys.has(truncatedKey)) {
      diagnosticKeys.add(truncatedKey);
      errors.push(truncated);
    }
    return;
  }
  diagnosticKeys.add(candidateKey);
  errors.push(candidate);
}

function diagnosticKey(diagnostic) {
  return `${diagnostic.code}\u0000${diagnostic.path}\u0000${diagnostic.message}`;
}

function sanitizeDiagnosticText(value) {
  return Array.from(String(value), (character) => {
    const codePoint = character.codePointAt(0);
    if (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f)) {
      return `\\u${codePoint.toString(16).padStart(4, "0")}`;
    }
    return character;
  }).join("");
}

function finishStructure(errors) {
  return finish(errors, "unverified");
}

function finishBound(errors, warnings) {
  const result = finish(errors, errors.length === 0 ? "exact_metadata" : "failed");
  result.authorization = "unverified";
  result.warnings = [...warnings].sort(compareDiagnostics);
  return result;
}

function finish(errors, binding = null) {
  const result = {
    valid: errors.length === 0,
    errors: [...errors].sort(compareDiagnostics),
  };
  if (binding !== null) result.binding = binding;
  return result;
}

function compareDiagnostics(left, right) {
  return compareAscii(left.code, right.code)
    || compareAscii(left.path, right.path)
    || compareAscii(left.message, right.message);
}

function compareAscii(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

async function readContractJson(filePath, label, errorPath) {
  try {
    return parseJsonObjectBytes(await readFile(filePath), label, errorPath);
  } catch {
    return {
      valid: false,
      value: null,
      errors: [{
        code: `${label}_READ_FAILED`,
        path: errorPath,
        message: "contract source could not be read",
      }],
    };
  }
}

function parseArguments(argv) {
  const options = {
    resultPath: null,
    metadataPaths: [],
    expectedContextPath: null,
    json: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--result") {
      options.resultPath = argv[index + 1] ?? null;
      index += 1;
    } else if (argument === "--metadata") {
      options.metadataPaths.push(argv[index + 1] ?? "");
      index += 1;
    } else if (argument === "--expected-context") {
      options.expectedContextPath = argv[index + 1] ?? null;
      index += 1;
    } else if (argument === "--json") {
      options.json = true;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }

  if (
    !options.resultPath
    || options.metadataPaths.length === 0
    || !options.expectedContextPath
  ) {
    throw new Error(
      "Usage: node scripts/ci/validate_clawsec_result_envelope.mjs "
      + "--result <path> --metadata <skill.json> [--metadata <skill.json>] "
      + "--expected-context <context.json> [--json]",
    );
  }
  return options;
}

async function main() {
  let options;
  let result;
  try {
    options = parseArguments(process.argv.slice(2));
    const [
      resultBytes,
      expectedContextBytes,
      ...metadataByteValues
    ] = await Promise.all([
      readFile(path.resolve(options.resultPath)),
      readFile(path.resolve(options.expectedContextPath)),
      ...options.metadataPaths.map((entry) => readFile(path.resolve(entry))),
    ]);
    const expected = parseJsonObjectBytes(
      expectedContextBytes,
      "EXPECTED_CONTEXT",
      "/",
    );
    if (!expected.valid) {
      result = finish(expected.errors);
    } else {
      const metadataBytesByDigest = new Map(
        metadataByteValues.map((bytes) => [digestBytes(bytes), bytes]),
      );
      result = validateBoundResultEnvelope({
        resultBytes,
        metadataBytesByDigest,
        expectedContext: expected.value,
      });
    }
  } catch {
    result = finish([{
      code: "RESULT_VALIDATOR_ERROR",
      path: "/",
      message: "validator invocation failed; check arguments and readable input files",
    }]);
  }

  if (options?.json) {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } else if (result.valid) {
    process.stdout.write(
      "CONTRACT_VALID: ClawSec base result v1 with exact metadata bytes; "
      + "release authorization and operation proof remain unverified\n",
    );
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
