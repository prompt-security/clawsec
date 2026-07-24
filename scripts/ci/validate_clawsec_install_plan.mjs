#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

import Ajv from "ajv";

import {
  classifyLifecycleVersion,
  parseSemverV2,
} from "./lifecycle_semver.mjs";
import {
  digestBytes,
  parseJsonObjectBytes,
  validateBoundResultEnvelope,
  validateUnboundResultEnvelope,
} from "./validate_clawsec_result_envelope.mjs";
import {
  validateBoundInstallPlanAdapter,
  validateInstallPlanAdapter,
} from "./install-plan-adapters/registry.mjs";

export { digestBytes };

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const MAXIMUM_DIAGNOSTICS = 64;
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BUFFER_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "buffer",
).get;
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "byteLength",
).get;
const TYPED_ARRAY_BYTE_OFFSET_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "byteOffset",
).get;
const EXPECTED_POLICY = Object.freeze({
  maximumPlanBytes: 1024 * 1024,
  maximumValiditySeconds: 900,
  maximumActions: 64,
  maximumBlockers: 64,
  maximumArrayItems: 64,
  maximumObjectKeys: 64,
  maximumDocumentNodes: 4096,
  maximumArchiveBytes: 128 * 1024 * 1024,
  maximumInstalledFileBytes: 64 * 1024 * 1024,
  maximumInstallTreeBytes: 256 * 1024 * 1024,
  maximumInstallTreeEntries: 4096,
  maximumPlannedOutputBytes: 256 * 1024 * 1024,
  maximumPlannedOutputEntries: 64,
  maximumCapturedPreimageBytes: 256 * 1024 * 1024,
  maximumCapturedPreimageEntries: 64,
  maximumExpansionRatio: 100,
});
const EXPECTED_ASSURANCE = Object.freeze({
  provenance: "unverified",
  catalog_authorization: "unverified",
  release_signature_authorization: "unverified",
  advisory_verification: "unverified",
  operator_authorization: "unverified",
  artifact_source_membership: "unverified",
  action_state_derivation: "verified_when_bound",
  installation_authorization: "not_granted",
  execution: "not_executed",
  preconditions_at_apply_time: "unverified",
});
const EXPECTED_BINDING_KEYS = Object.freeze([
  "adapter",
  "apply_context",
  "artifact",
  "staged_input",
  "target_state",
  "verification_refs",
]);

const planSchemaPath = path.join(
  repositoryRoot,
  "contracts/schemas/install/install-plan-v1.schema.json",
);
const resultSchemaPath = path.join(
  repositoryRoot,
  "contracts/schemas/result/result-v1.schema.json",
);
const componentRefSchemaPath = path.join(
  repositoryRoot,
  "contracts/schemas/component/component-ref-v1.schema.json",
);
const adapterSchemaPaths = [
  ["openclaw", "openclaw-v1.schema.json"],
  ["hermes", "hermes-v1.schema.json"],
  ["picoclaw", "picoclaw-v1.schema.json"],
  ["nanoclaw", "nanoclaw-v2.schema.json"],
].map(([harness, fileName]) => [
  harness,
  path.join(repositoryRoot, "contracts/schemas/install/adapters", fileName),
  `/contracts/schemas/install/adapters/${fileName}`,
]);
const planPolicyPath = path.join(repositoryRoot, "contracts/install-plan-policy.json");

const loadedContracts = await Promise.all([
  readContractJson(
    planSchemaPath,
    "INSTALL_PLAN_SCHEMA_SOURCE",
    "/contracts/schemas/install/install-plan-v1.schema.json",
  ),
  readContractJson(
    resultSchemaPath,
    "INSTALL_PLAN_RESULT_SCHEMA_SOURCE",
    "/contracts/schemas/result/result-v1.schema.json",
  ),
  readContractJson(
    componentRefSchemaPath,
    "INSTALL_PLAN_COMPONENT_SCHEMA_SOURCE",
    "/contracts/schemas/component/component-ref-v1.schema.json",
  ),
  ...adapterSchemaPaths.map(([harness, filePath, errorPath]) => (
    readContractJson(
      filePath,
      `INSTALL_PLAN_${harness.toUpperCase()}_ADAPTER_SCHEMA_SOURCE`,
      errorPath,
    )
  )),
  readContractJson(
    planPolicyPath,
    "INSTALL_PLAN_POLICY_SOURCE",
    "/contracts/install-plan-policy.json",
  ),
]);

const initializationErrors = loadedContracts.flatMap((entry) => entry.errors);
const [
  planSchema,
  resultSchema,
  componentRefSchema,
  openclawAdapterSchema,
  hermesAdapterSchema,
  picoclawAdapterSchema,
  nanoclawAdapterSchema,
  planPolicy,
] = loadedContracts.map((entry) => entry.value ?? {});

let validatePlanSchema = null;
if (initializationErrors.length === 0) {
  try {
    const ajv = new Ajv({
      allErrors: false,
      jsonPointers: true,
      schemaId: "auto",
    });
    ajv.addSchema(componentRefSchema);
    ajv.addSchema(resultSchema);
    for (const adapterSchema of [
      openclawAdapterSchema,
      hermesAdapterSchema,
      picoclawAdapterSchema,
      nanoclawAdapterSchema,
    ]) {
      ajv.addSchema(adapterSchema);
    }
    validatePlanSchema = ajv.compile(planSchema);
  } catch {
    addError(
      initializationErrors,
      "INSTALL_PLAN_SCHEMA_COMPILE_FAILED",
      "/contracts/schemas/install/install-plan-v1.schema.json",
      "install-plan schema could not be compiled with the result and component schemas",
    );
  }
}

export function validateInstallPlanContractSources() {
  const errors = [...initializationErrors];
  if (errors.length > 0) return finishUnbound(errors);

  validateClosedObject(
    planPolicy,
    [
      "assurance",
      "confirmation",
      "contract",
      "contract_version",
      "dispositions",
      "filesystem",
      "maximum_actions",
      "maximum_archive_bytes",
      "maximum_array_items",
      "maximum_blockers",
      "maximum_captured_preimage_bytes",
      "maximum_captured_preimage_entries",
      "maximum_document_nodes",
      "maximum_expansion_ratio",
      "maximum_install_tree_bytes",
      "maximum_install_tree_entries",
      "maximum_installed_file_bytes",
      "maximum_object_keys",
      "maximum_plan_bytes",
      "maximum_planned_output_bytes",
      "maximum_planned_output_entries",
      "maximum_validity_seconds",
      "rollback",
    ],
    "/contracts/install-plan-policy.json",
    errors,
  );
  if (planPolicy.contract !== "clawsec.install-plan-policy/v1") {
    addError(
      errors,
      "INSTALL_PLAN_POLICY_CONTRACT_MISMATCH",
      "/contracts/install-plan-policy.json/contract",
      "expected clawsec.install-plan-policy/v1",
    );
  }
  if (planPolicy.contract_version !== "1") {
    addError(
      errors,
      "INSTALL_PLAN_POLICY_VERSION_MISMATCH",
      "/contracts/install-plan-policy.json/contract_version",
      "expected contract version 1",
    );
  }
  if (planPolicy.maximum_plan_bytes !== EXPECTED_POLICY.maximumPlanBytes) {
    addError(
      errors,
      "INSTALL_PLAN_POLICY_BYTE_LIMIT_MISMATCH",
      "/contracts/install-plan-policy.json/maximum_plan_bytes",
      `maximum plan size must be ${EXPECTED_POLICY.maximumPlanBytes} bytes`,
    );
  }
  if (
    planPolicy.maximum_validity_seconds
    !== EXPECTED_POLICY.maximumValiditySeconds
  ) {
    addError(
      errors,
      "INSTALL_PLAN_POLICY_VALIDITY_LIMIT_MISMATCH",
      "/contracts/install-plan-policy.json/maximum_validity_seconds",
      `maximum validity must be ${EXPECTED_POLICY.maximumValiditySeconds} seconds`,
    );
  }
  if (planPolicy.maximum_actions !== EXPECTED_POLICY.maximumActions) {
    addError(
      errors,
      "INSTALL_PLAN_POLICY_ACTION_LIMIT_MISMATCH",
      "/contracts/install-plan-policy.json/maximum_actions",
      `maximum action count must be ${EXPECTED_POLICY.maximumActions}`,
    );
  }
  if (planPolicy.maximum_blockers !== EXPECTED_POLICY.maximumBlockers) {
    addError(
      errors,
      "INSTALL_PLAN_POLICY_BLOCKER_LIMIT_MISMATCH",
      "/contracts/install-plan-policy.json/maximum_blockers",
      `maximum blocker count must be ${EXPECTED_POLICY.maximumBlockers}`,
    );
  }
  for (const [policyKey, expectedValue, label] of [
    ["maximum_array_items", EXPECTED_POLICY.maximumArrayItems, "array item"],
    ["maximum_object_keys", EXPECTED_POLICY.maximumObjectKeys, "object key"],
    ["maximum_document_nodes", EXPECTED_POLICY.maximumDocumentNodes, "document node"],
    ["maximum_archive_bytes", EXPECTED_POLICY.maximumArchiveBytes, "archive byte"],
    [
      "maximum_installed_file_bytes",
      EXPECTED_POLICY.maximumInstalledFileBytes,
      "installed file byte",
    ],
    [
      "maximum_install_tree_bytes",
      EXPECTED_POLICY.maximumInstallTreeBytes,
      "install-tree byte",
    ],
    [
      "maximum_install_tree_entries",
      EXPECTED_POLICY.maximumInstallTreeEntries,
      "install-tree entry",
    ],
    [
      "maximum_planned_output_bytes",
      EXPECTED_POLICY.maximumPlannedOutputBytes,
      "planned output byte",
    ],
    [
      "maximum_planned_output_entries",
      EXPECTED_POLICY.maximumPlannedOutputEntries,
      "planned output entry",
    ],
    [
      "maximum_captured_preimage_bytes",
      EXPECTED_POLICY.maximumCapturedPreimageBytes,
      "captured preimage byte",
    ],
    [
      "maximum_captured_preimage_entries",
      EXPECTED_POLICY.maximumCapturedPreimageEntries,
      "captured preimage entry",
    ],
    [
      "maximum_expansion_ratio",
      EXPECTED_POLICY.maximumExpansionRatio,
      "archive expansion ratio",
    ],
  ]) {
    if (planPolicy[policyKey] !== expectedValue) {
      addError(
        errors,
        "INSTALL_PLAN_POLICY_RESOURCE_LIMIT_MISMATCH",
        `/contracts/install-plan-policy.json/${policyKey}`,
        `${label} limit must be ${expectedValue}`,
      );
    }
  }

  validateDispositionPolicy(errors);
  validateConfirmationPolicy(errors);
  validateFilesystemPolicy(errors);
  validateRollbackPolicy(errors);
  validateAssurancePolicy(errors);
  validateSchemaPolicyAlignment(errors);
  return finishUnbound(errors);
}

function validateTrustedUnboundInstallPlanObject(document) {
  const sourceResult = validateInstallPlanContractSources();
  const errors = [...sourceResult.errors];
  if (!sourceResult.valid || validatePlanSchema === null) {
    return finishUnbound(errors);
  }

  preflightDocumentShape(document, errors);
  if (errors.length > 0) return finishUnbound(errors);
  preflightPortablePaths(document, errors);
  preflightRemovedNativeOperations(document, errors);
  preflightPrototypeAdapters(document, errors);
  preflightCodingHarnessReferences(document, errors);
  if (errors.length > 0) return finishUnbound(errors);

  if (!validatePlanSchema(document)) {
    appendSchemaDiagnostics(validatePlanSchema.errors, errors);
    return finishUnbound(errors);
  }

  appendNestedDiagnostics(
    errors,
    validateUnboundResultEnvelope(document.result).errors,
    "/result",
  );
  validatePlanSemantics(document, errors);
  return finishUnbound(errors);
}

export function validateUnboundInstallPlanBytes(planBytes) {
  const snapshot = snapshotInstallPlanBytes(planBytes);
  if (snapshot.errors.length > 0) return finishUnbound(snapshot.errors);
  const parsed = parseJsonObjectBytes(snapshot.bytes, "INSTALL_PLAN", "/");
  if (!parsed.valid) return finishUnbound(parsed.errors);
  return validateTrustedUnboundInstallPlanObject(parsed.value);
}

export function validateBoundInstallPlan({
  planBytes,
  metadataBytesByDigest,
  expectedContext,
  expectedPlanDigest,
  expectedBindings,
  evaluatedAt,
} = {}) {
  const snapshot = snapshotInstallPlanBytes(planBytes);
  if (snapshot.errors.length > 0) {
    return finishBound(snapshot.errors, [], null);
  }
  const stablePlanBytes = snapshot.bytes;
  const parsed = parseJsonObjectBytes(stablePlanBytes, "INSTALL_PLAN", "/");
  if (!parsed.valid) return finishBound(parsed.errors, [], null);

  const document = parsed.value;
  const structureResult = validateTrustedUnboundInstallPlanObject(document);
  const errors = [...structureResult.errors];
  const warnings = [];
  const actualPlanDigest = stablePlanBytes instanceof Uint8Array
    ? digestBytes(stablePlanBytes)
    : null;
  if (!structureResult.valid || validatePlanSchema === null) {
    return finishBound(errors, warnings, actualPlanDigest);
  }

  if (
    typeof expectedPlanDigest !== "string"
    || !/^sha256:[a-f0-9]{64}$/.test(expectedPlanDigest)
  ) {
    addError(
      errors,
      "INSTALL_PLAN_EXPECTED_DIGEST_REQUIRED",
      "/",
      "bound validation requires a caller-supplied SHA-256 digest of the exact plan bytes",
    );
  } else if (expectedPlanDigest !== actualPlanDigest) {
    addError(
      errors,
      "INSTALL_PLAN_DIGEST_MISMATCH",
      "/",
      "plan bytes do not match the caller-supplied expected plan digest",
    );
  }

  validateExpectedBindings(document, expectedBindings, errors);

  const requiredMetadataDigests = [document.result.executor.metadata_digest];
  if (document.result.subject.kind === "component") {
    requiredMetadataDigests.push(
      document.result.subject.component.metadata_digest,
    );
  }
  const stableMetadataBytesByDigest = snapshotDigestBytesResolver(
    metadataBytesByDigest,
    requiredMetadataDigests,
    errors,
  );
  const boundResult = validateBoundResultEnvelope({
    resultBytes: Buffer.from(JSON.stringify(document.result)),
    metadataBytesByDigest: stableMetadataBytesByDigest,
    expectedContext,
  });
  appendNestedDiagnostics(errors, boundResult.errors, "/result");
  for (const warning of boundResult.warnings ?? []) {
    warnings.push({
      code: warning.code,
      path: `/result${warning.path === "/" ? "" : warning.path}`,
      message: warning.message,
    });
  }

  validateEvaluationTime(document, evaluatedAt, errors);
  validateBoundTargetPaths(document, stableMetadataBytesByDigest, errors);
  return finishBound(errors, warnings, actualPlanDigest);
}

function validatePlanSemantics(document, errors) {
  const { result } = document;
  if (document.path_flavor !== "posix") {
    addError(
      errors,
      "INSTALL_PLAN_PATH_FLAVOR_INVALID",
      "/path_flavor",
      "install-plan v1 paths must use POSIX slash semantics",
    );
  }
  if (result.executor.role !== "core") {
    addError(
      errors,
      "INSTALL_PLAN_EXECUTOR_ROLE_INVALID",
      "/result/executor/role",
      "install plans must be produced by a core component",
    );
  }
  if (result.invocation.operation !== "core.plan-release") {
    addError(
      errors,
      "INSTALL_PLAN_OPERATION_INVALID",
      "/result/invocation/operation",
      "embedded result operation must be core.plan-release",
    );
  }
  if (result.subject.kind !== "component") {
    addError(
      errors,
      "INSTALL_PLAN_SUBJECT_INVALID",
      "/result/subject",
      "install plans require one exact component subject",
    );
  }

  validateApplyContext(document, errors);
  validateTargetInstanceBinding(document, errors);
  validateIdentifierSeparation(document, errors);
  validateDisposition(document, errors);
  validateValidityWindow(document, errors);
  validateArtifactLifecycle(document, errors);
  validateArtifactResources(document, errors);
  validateStagedInputBinding(document, errors);
  validateInstallPlanAdapter(document, errors, addError);
  validateActions(document, errors);
  validateResultEffects(document, errors);
  validateDerivedStateBindings(document, errors);
  validateBlockers(document.blockers, errors);
  validateRollbackOrder(document, errors);

  if (!isDeepStrictEqual(document.assurance, EXPECTED_ASSURANCE)) {
    addError(
      errors,
      "INSTALL_PLAN_ASSURANCE_MISMATCH",
      "/assurance",
      "install-plan assurance must explicitly remain unverified and not executed",
    );
  }
}

function validateApplyContext(document, errors) {
  if (document.disposition === "blocked") {
    if (document.apply_context !== null) {
      addError(
        errors,
        "INSTALL_PLAN_BLOCKED_APPLY_CONTEXT_FORBIDDEN",
        "/apply_context",
        "blocked plans cannot carry a future install invocation",
      );
    }
    if (document.confirmation_requirements !== null) {
      addError(
        errors,
        "INSTALL_PLAN_BLOCKED_CONFIRMATION_REQUIREMENTS_FORBIDDEN",
        "/confirmation_requirements",
        "blocked plans cannot carry confirmation requirements",
      );
    }
    return;
  }
  if (!isPlainObject(document.apply_context)) {
    addError(
      errors,
      "INSTALL_PLAN_READY_APPLY_CONTEXT_REQUIRED",
      "/apply_context",
      "ready plans require an exact future core.install-release context",
    );
    return;
  }
  if (!isPlainObject(document.confirmation_requirements)) {
    addError(
      errors,
      "INSTALL_PLAN_READY_CONFIRMATION_REQUIREMENTS_REQUIRED",
      "/confirmation_requirements",
      "ready plans must declare non-authorizing exact-byte confirmation requirements",
    );
  }
  const planningContext = {
    executor: document.result.executor,
    subject: document.result.subject,
  };
  if (!isDeepStrictEqual(document.apply_context.executor, planningContext.executor)) {
    addError(
      errors,
      "INSTALL_PLAN_APPLY_EXECUTOR_MISMATCH",
      "/apply_context/executor",
      "future install executor must exactly match the planning executor",
    );
  }
  if (!isDeepStrictEqual(document.apply_context.subject, planningContext.subject)) {
    addError(
      errors,
      "INSTALL_PLAN_APPLY_SUBJECT_MISMATCH",
      "/apply_context/subject",
      "future install subject must exactly match the planned component",
    );
  }
  if (document.apply_context.invocation.operation !== "core.install-release") {
    addError(
      errors,
      "INSTALL_PLAN_APPLY_OPERATION_INVALID",
      "/apply_context/invocation/operation",
      "apply context operation must be core.install-release",
    );
  }
  if (
    !isDeepStrictEqual(
      document.apply_context.invocation.harness,
      document.result.invocation.harness,
    )
  ) {
    addError(
      errors,
      "INSTALL_PLAN_APPLY_HARNESS_MISMATCH",
      "/apply_context/invocation/harness",
      "future install harness must exactly match the planning harness",
    );
  }
  if (
    !isDeepStrictEqual(
      document.apply_context.invocation.scope,
      document.result.invocation.scope,
    )
  ) {
    addError(
      errors,
      "INSTALL_PLAN_APPLY_SCOPE_MISMATCH",
      "/apply_context/invocation/scope",
      "future install scope must exactly match the planning scope",
    );
  }
}

function validateTargetInstanceBinding(document, errors) {
  const planningScopeRef = document.result.invocation.scope.ref;
  if (document.target_state.target_instance_id !== planningScopeRef) {
    addError(
      errors,
      "INSTALL_PLAN_TARGET_INSTANCE_MISMATCH",
      "/target_state/target_instance_id",
      "target instance must exactly match the selected planning scope reference",
    );
  }
  if (
    isPlainObject(document.apply_context)
    && document.target_state.target_instance_id
      !== document.apply_context.invocation.scope.ref
  ) {
    addError(
      errors,
      "INSTALL_PLAN_APPLY_TARGET_INSTANCE_MISMATCH",
      "/target_state/target_instance_id",
      "target instance must exactly match the selected apply scope reference",
    );
  }
}

function validateIdentifierSeparation(document, errors) {
  const identifiers = [
    ["plan_id", document.plan_id],
    ["planning invocation", document.result.invocation.id],
  ];
  if (isPlainObject(document.apply_context)) {
    identifiers.push(["install invocation", document.apply_context.invocation.id]);
  }
  const seen = new Map();
  for (const [label, value] of identifiers) {
    if (seen.has(value)) {
      addError(
        errors,
        "INSTALL_PLAN_IDENTIFIER_REUSED",
        "/",
        `${label} must not reuse the ${seen.get(value)} identifier`,
      );
    } else {
      seen.set(value, label);
    }
  }
}

function validateDisposition(document, errors) {
  const policy = planPolicy.dispositions?.[document.disposition];
  if (!policy) {
    addError(
      errors,
      "INSTALL_PLAN_DISPOSITION_UNKNOWN",
      "/disposition",
      `unknown disposition ${document.disposition}`,
    );
    return;
  }
  if (document.result.outcome !== policy.result_outcome) {
    addError(
      errors,
      "INSTALL_PLAN_DISPOSITION_OUTCOME_MISMATCH",
      "/result/outcome",
      `${document.disposition} plans require outcome ${policy.result_outcome}`,
    );
  }
  if (document.actions.length < policy.minimum_actions) {
    addError(
      errors,
      "INSTALL_PLAN_ACTIONS_REQUIRED",
      "/actions",
      `${document.disposition} plans require at least ${policy.minimum_actions} action`,
    );
  }
  if (document.actions.length > policy.maximum_actions) {
    addError(
      errors,
      "INSTALL_PLAN_ACTION_LIMIT_EXCEEDED",
      "/actions",
      `${document.disposition} plans permit at most ${policy.maximum_actions} actions`,
    );
  }
  if (document.blockers.length < policy.minimum_blockers) {
    addError(
      errors,
      "INSTALL_PLAN_BLOCKERS_REQUIRED",
      "/blockers",
      `${document.disposition} plans require at least ${policy.minimum_blockers} blocker`,
    );
  }
  if (document.blockers.length > policy.maximum_blockers) {
    addError(
      errors,
      "INSTALL_PLAN_BLOCKER_LIMIT_EXCEEDED",
      "/blockers",
      `${document.disposition} plans permit at most ${policy.maximum_blockers} blockers`,
    );
  }
  if (
    policy.authorizes_installation !== false
    || typeof policy.eligible_for_confirmation !== "boolean"
  ) {
    addError(
      errors,
      "INSTALL_PLAN_DISPOSITION_AUTHORIZATION_INVALID",
      `/contracts/install-plan-policy.json/dispositions/${document.disposition}`,
      "install-plan dispositions must never authorize installation",
    );
  }
  if (document.disposition === "ready" && document.blockers.length !== 0) {
    addError(
      errors,
      "INSTALL_PLAN_READY_HAS_BLOCKERS",
      "/blockers",
      "ready plans cannot contain blockers",
    );
  }
  if (document.disposition === "blocked") {
    if (document.actions.length !== 0) {
      addError(
        errors,
        "INSTALL_PLAN_BLOCKED_HAS_ACTIONS",
        "/actions",
        "blocked plans cannot carry executable actions",
      );
    }
    if (document.rollback_order.length !== 0) {
      addError(
        errors,
        "INSTALL_PLAN_BLOCKED_HAS_ROLLBACK_ORDER",
        "/rollback_order",
        "blocked plans are non-authorizing and cannot carry an executable rollback order",
      );
    }
  }
}

function validateValidityWindow(document, errors) {
  const reportedAt = parseTimestamp(document.result.reported_at);
  const expiresAt = parseTimestamp(document.expires_at);
  if (reportedAt === null || expiresAt === null) return;
  const durationMilliseconds = expiresAt - reportedAt;
  if (durationMilliseconds <= 0) {
    addError(
      errors,
      "INSTALL_PLAN_EXPIRY_ORDER_INVALID",
      "/expires_at",
      "plan expiry must be later than the planning result timestamp",
    );
  } else if (
    durationMilliseconds
    > planPolicy.maximum_validity_seconds * 1000
  ) {
    addError(
      errors,
      "INSTALL_PLAN_VALIDITY_TOO_LONG",
      "/expires_at",
      `plan validity cannot exceed ${planPolicy.maximum_validity_seconds} seconds`,
    );
  }
}

function validateArtifactLifecycle(document, errors) {
  if (document.result.subject.kind !== "component") return;
  if (
    !isDeepStrictEqual(
      document.artifact.component,
      document.result.subject.component,
    )
  ) {
    addError(
      errors,
      "INSTALL_PLAN_ARTIFACT_COMPONENT_MISMATCH",
      "/artifact/component",
      "artifact component must exactly match the planned result subject",
    );
  }
  const version = document.result.subject.component.version;
  let parsed;
  let lifecycleClass;
  try {
    parsed = parseSemverV2(version);
    lifecycleClass = classifyLifecycleVersion(version);
  } catch {
    addError(
      errors,
      "INSTALL_PLAN_ARTIFACT_VERSION_INVALID",
      "/result/subject/component/version",
      "planned component version must be strict SemVer",
    );
    return;
  }
  if (parsed.build.length > 0) {
    addError(
      errors,
      "INSTALL_PLAN_ARTIFACT_BUILD_METADATA_FORBIDDEN",
      "/result/subject/component/version",
      "planned artifact versions cannot contain build metadata",
    );
  }
  if (
    document.artifact.channel === "public_stable"
    && lifecycleClass !== "final"
  ) {
    addError(
      errors,
      "INSTALL_PLAN_PUBLIC_PRERELEASE_FORBIDDEN",
      "/artifact/channel",
      "public_stable plans require a final SemVer component version",
    );
  }
  if (
    document.artifact.channel === "private_lab"
    && !["beta", "rc", "final"].includes(lifecycleClass)
  ) {
    addError(
      errors,
      "INSTALL_PLAN_LAB_VERSION_CLASS_INVALID",
      "/result/subject/component/version",
      "private lab plans accept only beta.N, rc.N, or final stable-intent payload versions",
    );
  }

  const authority = document.artifact.authority;
  const expectedAuthorityKind = document.artifact.channel === "private_lab"
    ? "private_candidate"
    : "active_catalog_entry";
  const expectedAuthorityContract = document.artifact.channel === "private_lab"
    ? "clawsec.private-candidate/v1"
    : "clawsec.catalog-entry/v1";
  if (
    authority.kind !== expectedAuthorityKind
    || authority.contract !== expectedAuthorityContract
  ) {
    addError(
      errors,
      "INSTALL_PLAN_ARTIFACT_AUTHORITY_MISMATCH",
      "/artifact/authority",
      `${document.artifact.channel} artifacts require an exact ${expectedAuthorityContract} reference`,
    );
  }
  const authorityExpiresAt = parseTimestamp(authority.expires_at);
  const planExpiresAt = parseTimestamp(document.expires_at);
  if (
    authorityExpiresAt !== null
    && planExpiresAt !== null
    && planExpiresAt > authorityExpiresAt
  ) {
    addError(
      errors,
      "INSTALL_PLAN_AUTHORITY_EXPIRES_BEFORE_PLAN",
      "/artifact/authority/expires_at",
      "artifact authority must remain valid for the full plan lifetime",
    );
  }
}

function validateArtifactResources(document, errors) {
  const { artifact } = document;
  if (artifact.archive_byte_length > planPolicy.maximum_archive_bytes) {
    addError(
      errors,
      "INSTALL_PLAN_ARCHIVE_TOO_LARGE",
      "/artifact/archive_byte_length",
      `archive cannot exceed ${planPolicy.maximum_archive_bytes} bytes`,
    );
  }
  if (artifact.install_tree_entry_count > planPolicy.maximum_install_tree_entries) {
    addError(
      errors,
      "INSTALL_PLAN_INSTALL_TREE_ENTRY_LIMIT_EXCEEDED",
      "/artifact/install_tree_entry_count",
      `install tree cannot exceed ${planPolicy.maximum_install_tree_entries} entries`,
    );
  }
  if (artifact.install_tree_total_bytes > planPolicy.maximum_install_tree_bytes) {
    addError(
      errors,
      "INSTALL_PLAN_INSTALL_TREE_TOO_LARGE",
      "/artifact/install_tree_total_bytes",
      `install tree cannot exceed ${planPolicy.maximum_install_tree_bytes} bytes`,
    );
  }
  if (
    artifact.install_tree_total_bytes
    > artifact.archive_byte_length * planPolicy.maximum_expansion_ratio
  ) {
    addError(
      errors,
      "INSTALL_PLAN_ARCHIVE_EXPANSION_RATIO_EXCEEDED",
      "/artifact/install_tree_total_bytes",
      `install tree cannot exceed ${planPolicy.maximum_expansion_ratio} times the archive size`,
    );
  }

  let managedTreeEntryCount = 0;
  let managedTreeFileBytes = 0;
  let plannedOutputBytes = 0;
  let plannedOutputEntries = 0;
  let capturedPreimageBytes = 0;
  const capturedPreimagesByDigest = new Map();
  for (let index = 0; index < document.actions.length; index += 1) {
    const action = document.actions[index];
    if (
      action.kind === "managed_entry"
      || action.kind === "declared_transformation"
    ) {
      plannedOutputEntries += 1;
      if (action.after.kind === "file") {
        plannedOutputBytes += action.after.byte_length;
      }
    }
    if (action.kind === "managed_entry") {
      managedTreeEntryCount += 1;
      if (action.tree_entry.kind === "file") {
        managedTreeFileBytes += action.tree_entry.byte_length;
        if (
          action.tree_entry.byte_length
          > planPolicy.maximum_installed_file_bytes
        ) {
          addError(
            errors,
            "INSTALL_PLAN_INSTALLED_FILE_TOO_LARGE",
            `/actions/${index}/tree_entry/byte_length`,
            `installed files cannot exceed ${planPolicy.maximum_installed_file_bytes} bytes`,
          );
        }
      }
    }
    if (
      action.kind === "declared_transformation"
      && isPlainObject(action.rollback_source)
    ) {
      capturedPreimageBytes += action.rollback_source.byte_length;
      const prior = capturedPreimagesByDigest.get(action.rollback_source.digest);
      if (
        prior !== undefined
        && !isDeepStrictEqual(prior, action.rollback_source)
      ) {
        addError(
          errors,
          "INSTALL_PLAN_CAPTURED_PREIMAGE_AMBIGUOUS",
          `/actions/${index}/rollback_source`,
          "one captured preimage digest cannot describe different rollback material",
        );
      } else if (prior === undefined) {
        capturedPreimagesByDigest.set(
          action.rollback_source.digest,
          action.rollback_source,
        );
      }
    }
  }
  if (managedTreeEntryCount > artifact.install_tree_entry_count) {
    addError(
      errors,
      "INSTALL_PLAN_ARTIFACT_TREE_ENTRY_COUNT_EXCEEDED",
      "/actions",
      "managed tree entries cannot exceed the artifact install-tree entry count",
    );
  }
  if (managedTreeFileBytes > artifact.install_tree_total_bytes) {
    addError(
      errors,
      "INSTALL_PLAN_ARTIFACT_TREE_BYTES_EXCEED_DECLARATION",
      "/actions",
      "managed file tree-entry bytes cannot exceed the artifact install-tree size",
    );
  }
  if (document.disposition === "ready") {
    if (managedTreeEntryCount !== artifact.install_tree_entry_count) {
      addError(
        errors,
        "INSTALL_PLAN_READY_TREE_ENTRY_COVERAGE_MISMATCH",
        "/artifact/install_tree_entry_count",
        "ready plans require exactly one managed action for every staged install-tree entry",
      );
    }
    if (managedTreeFileBytes !== artifact.install_tree_total_bytes) {
      addError(
        errors,
        "INSTALL_PLAN_READY_TREE_BYTE_COVERAGE_MISMATCH",
        "/artifact/install_tree_total_bytes",
        "ready plans must match the exact byte total of managed file tree entries",
      );
    }
  }
  if (plannedOutputEntries > planPolicy.maximum_planned_output_entries) {
    addError(
      errors,
      "INSTALL_PLAN_OUTPUT_ENTRY_LIMIT_EXCEEDED",
      "/actions",
      `planned output cannot exceed ${planPolicy.maximum_planned_output_entries} entries`,
    );
  }
  if (plannedOutputBytes > planPolicy.maximum_planned_output_bytes) {
    addError(
      errors,
      "INSTALL_PLAN_OUTPUT_BYTES_LIMIT_EXCEEDED",
      "/actions",
      `planned output cannot exceed ${planPolicy.maximum_planned_output_bytes} bytes`,
    );
  }
  if (
    capturedPreimagesByDigest.size
    > planPolicy.maximum_captured_preimage_entries
  ) {
    addError(
      errors,
      "INSTALL_PLAN_CAPTURED_PREIMAGE_ENTRY_LIMIT_EXCEEDED",
      "/actions",
      `captured rollback material cannot exceed ${planPolicy.maximum_captured_preimage_entries} unique entries`,
    );
  }
  if (capturedPreimageBytes > planPolicy.maximum_captured_preimage_bytes) {
    addError(
      errors,
      "INSTALL_PLAN_CAPTURED_PREIMAGE_BYTES_LIMIT_EXCEEDED",
      "/actions",
      `total rollback capture work cannot exceed ${planPolicy.maximum_captured_preimage_bytes} bytes across all transformation targets`,
    );
  }
}

function validateStagedInputBinding(document, errors) {
  if (document.staged_input.archive_digest !== document.artifact.archive_digest) {
    addError(
      errors,
      "INSTALL_PLAN_STAGED_ARCHIVE_MISMATCH",
      "/staged_input/archive_digest",
      "staged archive digest must match the planned artifact archive digest",
    );
  }
  if (
    document.staged_input.install_tree_manifest_digest
    !== document.artifact.install_tree_manifest_digest
  ) {
    addError(
      errors,
      "INSTALL_PLAN_STAGED_TREE_MISMATCH",
      "/staged_input/install_tree_manifest_digest",
      "staged install-tree manifest must match the planned artifact",
    );
  }
}

function validateActions(document, errors) {
  const actionIds = new Set();
  const targetKeys = new Set();
  const pathTargets = [];
  const managedEntriesByCaseFoldedPath = new Map();
  const managedEntriesByManifestDigest = new Map();
  const earlierManagedActionsById = new Map();
  const transformationEntryDigests = new Set();
  let sawDeclaredTransformation = false;
  for (let index = 0; index < document.actions.length; index += 1) {
    const action = document.actions[index];
    const actionPath = `/actions/${index}`;
    if (actionIds.has(action.action_id)) {
      addError(
        errors,
        "INSTALL_PLAN_ACTION_ID_DUPLICATE",
        `${actionPath}/action_id`,
        `action id ${action.action_id} appears more than once`,
      );
    }
    actionIds.add(action.action_id);

    const targetKey = actionTargetKey(action);
    if (targetKey !== null) {
      if (targetKeys.has(targetKey)) {
        addError(
          errors,
          "INSTALL_PLAN_ACTION_TARGET_DUPLICATE",
          `${actionPath}/target`,
          "one plan cannot mutate the same target more than once",
        );
      }
      targetKeys.add(targetKey);
    }

    if (action.kind === "managed_entry") {
      if (sawDeclaredTransformation) {
        addError(
          errors,
          "INSTALL_PLAN_PACKAGE_ACTION_ORDER_INVALID",
          actionPath,
          "all managed package-tree actions must precede declared transformations",
        );
      }
      validateManagedEntryAction(action, actionPath, errors);
      const foldedTreePath = action.tree_entry.path.toLowerCase();
      if (managedEntriesByCaseFoldedPath.has(foldedTreePath)) {
        addError(
          errors,
          "INSTALL_PLAN_TREE_ENTRY_PATH_DUPLICATE",
          `${actionPath}/tree_entry/path`,
          "managed install-tree entry paths must be unique without case-folded collisions",
        );
      } else {
        managedEntriesByCaseFoldedPath.set(foldedTreePath, action.tree_entry);
      }
      const priorManifestEntry = managedEntriesByManifestDigest.get(
        action.tree_entry.manifest_entry_digest,
      );
      if (
        priorManifestEntry !== undefined
        && !isDeepStrictEqual(priorManifestEntry, action.tree_entry)
      ) {
        addError(
          errors,
          "INSTALL_PLAN_MANIFEST_ENTRY_DIGEST_AMBIGUOUS",
          `${actionPath}/tree_entry/manifest_entry_digest`,
          "one manifest-entry digest cannot describe different install-tree entries",
        );
      } else if (priorManifestEntry === undefined) {
        managedEntriesByManifestDigest.set(
          action.tree_entry.manifest_entry_digest,
          action.tree_entry,
        );
      }
      earlierManagedActionsById.set(action.action_id, action);
      pathTargets.push({ action, actionPath });
    } else if (action.kind === "declared_transformation") {
      sawDeclaredTransformation = true;
      if (
        transformationEntryDigests.has(
          action.declaration.transformation_entry_digest,
        )
      ) {
        addError(
          errors,
          "INSTALL_PLAN_TRANSFORMATION_ENTRY_DIGEST_DUPLICATE",
          `${actionPath}/declaration/transformation_entry_digest`,
          "one release-manifest transformation entry can appear only once in a plan",
        );
      }
      transformationEntryDigests.add(
        action.declaration.transformation_entry_digest,
      );
      validateTransformationAction(action, actionPath, document, errors);
      const managedSourceAction = earlierManagedActionsById.get(
        action.declaration.source.managed_action_id,
      );
      if (
        managedSourceAction === undefined
        || managedSourceAction.tree_entry.kind !== "file"
        || managedSourceAction.tree_entry.manifest_entry_digest
          !== action.declaration.source.manifest_entry_digest
      ) {
        addError(
          errors,
          "INSTALL_PLAN_TRANSFORMATION_SOURCE_NOT_MANAGED",
          `${actionPath}/declaration/source`,
          "transformation source must reference an earlier managed file action and its exact manifest-entry digest",
        );
      }
      pathTargets.push({ action, actionPath });
    } else if (action.kind === "native_operation") {
      validateNativeOperationAction(
        action,
        actionPath,
        document.result.invocation.harness.name,
        errors,
      );
      if (
        ["reload_harness", "restart_harness"].includes(action.operation)
        && index !== document.actions.length - 1
      ) {
        addError(
          errors,
          "INSTALL_PLAN_OPERATIONAL_ACTION_ORDER_INVALID",
          actionPath,
          "reload or restart must be the final action after every filesystem mutation",
        );
      }
    }

  }
  validatePathTargetGraph(pathTargets, errors);
  if (
    document.disposition === "ready"
    && !document.actions.some((action) => action.kind === "managed_entry")
  ) {
    addError(
      errors,
      "INSTALL_PLAN_SUBJECT_PACKAGE_ACTION_REQUIRED",
      "/actions",
      "ready plans require at least one managed mutation for the subject package",
    );
  }
}

function validateManagedEntryAction(action, actionPath, errors) {
  const beforeAbsent = action.before.kind === "absent";
  if (
    action.operation !== "create"
    || !beforeAbsent
    || !["file", "directory"].includes(action.after.kind)
  ) {
    addError(
      errors,
      "INSTALL_PLAN_FRESH_CREATE_REQUIRED",
      actionPath,
      "install-plan managed entries must create a file or directory over an absent target",
    );
  }
  if (action.rollback_source !== null) {
    addError(
      errors,
      "INSTALL_PLAN_CREATE_ROLLBACK_SOURCE_FORBIDDEN",
      `${actionPath}/rollback_source`,
      "fresh create rollback removes the new entry and cannot carry predecessor material",
    );
  }

  validateEntryStateSafety(action.before, `${actionPath}/before`, errors);
  validateEntryStateSafety(action.after, `${actionPath}/after`, errors);
  const stateFields = ["kind", "mode"];
  if (
    action.tree_entry.kind === "file"
    && action.after.kind === "file"
  ) {
    stateFields.push("digest", "byte_length");
  }
  for (const field of stateFields) {
    if (action.tree_entry[field] !== action.after[field]) {
      addError(
        errors,
        "INSTALL_PLAN_TREE_ENTRY_STATE_MISMATCH",
        `${actionPath}/tree_entry/${field}`,
        `install-tree entry ${field} must match the managed post-state`,
      );
    }
  }
}

function validateTransformationAction(action, actionPath, document, errors) {
  const allowedOutput = action.declaration.allowed_output;
  if (
    !isDeepStrictEqual(action.target, allowedOutput.target)
    || !isDeepStrictEqual(action.before, allowedOutput.before)
    || !isDeepStrictEqual(action.after, allowedOutput.after)
  ) {
    addError(
      errors,
      "INSTALL_PLAN_TRANSFORMATION_DECLARATION_MISMATCH",
      `${actionPath}/declaration/allowed_output`,
      "transformation target and states must exactly match the declared allowed output",
    );
  }
  if (
    action.declaration.release_manifest_digest
    !== document.artifact.release_manifest_digest
  ) {
    addError(
      errors,
      "INSTALL_PLAN_TRANSFORMATION_RELEASE_MANIFEST_MISMATCH",
      `${actionPath}/declaration/release_manifest_digest`,
      "transformation declaration must bind the artifact's exact release manifest",
    );
  }
  validateCodingHarness(
    action.declaration.coding_harness,
    `${actionPath}/declaration/coding_harness`,
    errors,
  );
  if (action.before.digest === action.after.digest) {
    addError(
      errors,
      "INSTALL_PLAN_TRANSFORMATION_NO_CHANGE",
      `${actionPath}/after/digest`,
      "declared transformation preimage and postimage digests must differ",
    );
  }
  validateEntryStateSafety(action.before, `${actionPath}/before`, errors);
  validateEntryStateSafety(action.after, `${actionPath}/after`, errors);
  validateRollbackSource(action.before, action.rollback_source, actionPath, errors);
}

function validateCodingHarness(codingHarness, harnessPath, errors) {
  if (!isPlainObject(codingHarness)) return;
  for (const field of [
    "implementation_digest",
    "toolchain_digest",
    "configuration_digest",
  ]) {
    if (
      typeof codingHarness[field] !== "string"
      || !/^sha256:[a-f0-9]{64}$/.test(codingHarness[field])
    ) {
      addError(
        errors,
        "INSTALL_PLAN_CODING_HARNESS_DIGEST_REQUIRED",
        `${harnessPath}/${field}`,
        `coding harness ${field} must be an exact SHA-256 digest`,
      );
    }
  }

  const reference = codingHarness.immutable_reference;
  if (!isPlainObject(reference)) return;
  if (
    typeof reference.value === "string"
    && isFloatingReference(reference.value)
  ) {
    addError(
      errors,
      "INSTALL_PLAN_CODING_HARNESS_REFERENCE_NOT_IMMUTABLE",
      `${harnessPath}/immutable_reference/value`,
      "coding harness identity cannot use latest, stable, main, master, head, or trunk",
    );
    return;
  }
  let immutable = false;
  if (reference.kind === "exact_version") {
    try {
      immutable = parseSemverV2(reference.value).build.length === 0;
    } catch {
      immutable = false;
    }
  } else if (reference.kind === "commit") {
    immutable = (
      typeof reference.value === "string"
      && /^[a-f0-9]{40}$/.test(reference.value)
    );
  } else if (reference.kind === "content_digest") {
    immutable = (
      typeof reference.value === "string"
      && /^sha256:[a-f0-9]{64}$/.test(reference.value)
    );
    if (
      immutable
      && reference.value !== codingHarness.implementation_digest
    ) {
      addError(
        errors,
        "INSTALL_PLAN_CODING_HARNESS_CONTENT_IDENTITY_MISMATCH",
        `${harnessPath}/immutable_reference/value`,
        "content-addressed coding harness reference must equal its implementation digest",
      );
    }
  }
  if (!immutable) {
    addError(
      errors,
      "INSTALL_PLAN_CODING_HARNESS_REFERENCE_NOT_IMMUTABLE",
      `${harnessPath}/immutable_reference`,
      "coding harness must use an exact SemVer without build metadata, a full commit, or a content digest",
    );
  }
}

function validateNativeOperationAction(
  action,
  actionPath,
  harness,
  errors,
) {
  const expectedAdapter = `clawsec.${harness}-install-adapter/v1`;
  if (action.adapter_contract !== expectedAdapter) {
    addError(
      errors,
      "INSTALL_PLAN_NATIVE_ADAPTER_MISMATCH",
      `${actionPath}/adapter_contract`,
      `native operation must use ${expectedAdapter}`,
    );
  }
  if (action.state_effect === "operational_non_mutating") {
    if (
      !["reload_harness", "restart_harness"].includes(action.operation)
      || action.rollback !== null
      || action.precondition_digest !== action.expected_postcondition_digest
    ) {
      addError(
        errors,
        "INSTALL_PLAN_NATIVE_OPERATIONAL_ACTION_INVALID",
        actionPath,
        "reload and restart must target the selected harness resource, preserve state, and carry no rollback",
      );
    }
    return;
  }
  addError(
    errors,
    "INSTALL_PLAN_NATIVE_OPERATION_UNSUPPORTED",
    actionPath,
    "install-plan v1 native operations are limited to non-mutating reload or restart",
  );
}

function validateResultEffects(document, errors) {
  const effects = document.result.effects;
  if (document.disposition === "blocked") {
    if (effects.length !== 0) {
      addError(
        errors,
        "INSTALL_PLAN_BLOCKED_HAS_EFFECTS",
        "/result/effects",
        "blocked plans cannot report proposed effects",
      );
    }
    return;
  }
  if (document.confirmation_requirements.disclosure_source !== "install_plan_actions") {
    addError(
      errors,
      "INSTALL_PLAN_CONFIRMATION_DISCLOSURE_INVALID",
      "/confirmation_requirements/disclosure_source",
      "confirmation must disclose the complete install-plan action list",
    );
  }
  if (effects.length !== document.actions.length) {
    addError(
      errors,
      "INSTALL_PLAN_EFFECT_ACTION_COUNT_MISMATCH",
      "/result/effects",
      "ready plans require exactly one reported effect for every planned action",
    );
  }
  const effectsById = new Map();
  for (let index = 0; index < effects.length; index += 1) {
    const effect = effects[index];
    if (effectsById.has(effect.effect_id)) {
      addError(
        errors,
        "INSTALL_PLAN_EFFECT_ID_DUPLICATE",
        `/result/effects/${index}/effect_id`,
        "reported plan effect identifiers must be unique",
      );
    }
    effectsById.set(effect.effect_id, effect);
  }
  for (let index = 0; index < document.actions.length; index += 1) {
    const action = document.actions[index];
    const effect = effectsById.get(action.action_id);
    const expectedTarget = actionEffectTarget(action);
    if (
      effect === undefined
      || effect.state !== "proposed"
      || !isDeepStrictEqual(effect.target, expectedTarget)
    ) {
      addError(
        errors,
        "INSTALL_PLAN_EFFECT_ACTION_MISMATCH",
        `/result/effects`,
        `action ${action.action_id} requires one proposed effect against its exact compatible target`,
      );
    }
  }
}

export function computeInstallPlanStateBindings(documentOrActions) {
  const actions = Array.isArray(documentOrActions)
    ? documentOrActions
    : documentOrActions.actions;
  const prestate = [];
  const poststate = [];
  for (const action of actions) {
    const target = action.target;
    if (
      action.kind === "managed_entry"
      || action.kind === "declared_transformation"
    ) {
      prestate.push({
        action_id: action.action_id,
        target,
        state: action.before,
      });
      poststate.push({
        action_id: action.action_id,
        target,
        state: action.after,
      });
    } else if (action.kind === "native_operation") {
      prestate.push({
        action_id: action.action_id,
        target,
        state: {
          kind: "native_condition",
          digest: action.precondition_digest,
        },
      });
      poststate.push({
        action_id: action.action_id,
        target,
        state: {
          kind: "native_condition",
          digest: action.expected_postcondition_digest,
        },
      });
    }
  }
  const sortRecords = (records) => records.sort((left, right) => {
    const leftJson = canonicalJson(left);
    const rightJson = canonicalJson(right);
    return leftJson < rightJson ? -1 : leftJson > rightJson ? 1 : 0;
  });
  return {
    action_set_digest: digestCanonical(actions),
    touched_prestate_digest: digestCanonical(sortRecords(prestate)),
    touched_expected_poststate_digest: digestCanonical(sortRecords(poststate)),
  };
}

function validateDerivedStateBindings(document, errors) {
  const expected = computeInstallPlanStateBindings(document);
  for (const [field, digest] of Object.entries(expected)) {
    if (document.target_state[field] !== digest) {
      addError(
        errors,
        "INSTALL_PLAN_DERIVED_STATE_MISMATCH",
        `/target_state/${field}`,
        `${field} must be derived deterministically from the exact planned actions`,
      );
    }
  }
}

function validateRollbackSource(before, rollbackSource, actionPath, errors) {
  if (
    before.kind !== "file"
    || !isPlainObject(rollbackSource)
    || rollbackSource.kind !== "captured_file"
  ) {
    addError(
      errors,
      "INSTALL_PLAN_ROLLBACK_SOURCE_REQUIRED",
      `${actionPath}/rollback_source`,
      "declared transformations require a captured file matching the exact pre-state",
    );
    return;
  }
  const stateFields = [
    "digest",
    "byte_length",
    "mode",
    "owner_identity_digest",
    "group_identity_digest",
  ];
  for (const field of stateFields) {
    if (rollbackSource[field] !== before[field]) {
      addError(
        errors,
        "INSTALL_PLAN_ROLLBACK_SOURCE_MISMATCH",
        `${actionPath}/rollback_source/${field}`,
        `captured rollback ${field} must match the exact pre-state`,
      );
    }
  }
}

function validateEntryStateSafety(state, statePath, errors) {
  if (state.kind === "absent") return;
  const mode = Number.parseInt(state.mode, 8);
  if (!Number.isInteger(mode) || (mode & 0o022) !== 0) {
    addError(
      errors,
      "INSTALL_PLAN_UNSAFE_MODE_FORBIDDEN",
      `${statePath}/mode`,
      "planned filesystem state cannot be group-writable or world-writable",
    );
  }
  if (
    state.kind === "file"
    && state.byte_length > planPolicy.maximum_installed_file_bytes
  ) {
    addError(
      errors,
      "INSTALL_PLAN_INSTALLED_FILE_TOO_LARGE",
      `${statePath}/byte_length`,
      `installed files cannot exceed ${planPolicy.maximum_installed_file_bytes} bytes`,
    );
  }
}

function validatePathTargetGraph(pathTargets, errors) {
  for (let leftIndex = 0; leftIndex < pathTargets.length; leftIndex += 1) {
    const left = pathTargets[leftIndex];
    const leftTarget = left.action.target;
    const leftFolded = leftTarget.path.toLowerCase();
    for (
      let rightIndex = leftIndex + 1;
      rightIndex < pathTargets.length;
      rightIndex += 1
    ) {
      const right = pathTargets[rightIndex];
      const rightTarget = right.action.target;
      if (leftTarget.anchor !== rightTarget.anchor) continue;
      const rightFolded = rightTarget.path.toLowerCase();
      if (leftFolded === rightFolded) {
        if (leftTarget.path !== rightTarget.path) {
          addError(
            errors,
            "INSTALL_PLAN_PATH_CASE_COLLISION",
            `${right.actionPath}/target/path`,
            "planned paths cannot differ only by case",
          );
        }
        continue;
      }

      const [ancestor, descendant] = leftFolded.length < rightFolded.length
        ? [left, right]
        : [right, left];
      const ancestorPath = ancestor.action.target.path.toLowerCase();
      const descendantPath = descendant.action.target.path.toLowerCase();
      if (!descendantPath.startsWith(`${ancestorPath}/`)) continue;
      if (
        actionExpectedEntryKind(descendant.action) !== "absent"
        && actionExpectedEntryKind(ancestor.action) !== "directory"
      ) {
        addError(
          errors,
          "INSTALL_PLAN_PATH_ANCESTOR_CONFLICT",
          `${descendant.actionPath}/target/path`,
          "a planned child path cannot exist below a non-directory or removed planned ancestor",
        );
      }
    }
  }
}

function actionExpectedEntryKind(action) {
  if (action.kind === "managed_entry") return action.after.kind;
  if (action.kind === "declared_transformation") return "file";
  return null;
}

function validateBlockers(blockers, errors) {
  const blockerIds = new Set();
  for (let index = 0; index < blockers.length; index += 1) {
    const blocker = blockers[index];
    if (blockerIds.has(blocker.blocker_id)) {
      addError(
        errors,
        "INSTALL_PLAN_BLOCKER_ID_DUPLICATE",
        `/blockers/${index}/blocker_id`,
        `blocker id ${blocker.blocker_id} appears more than once`,
      );
    }
    blockerIds.add(blocker.blocker_id);
  }
}

function validateRollbackOrder(document, errors) {
  if (document.disposition !== "ready") return;
  const expected = document.actions
    .filter((action) => action.kind !== "native_operation")
    .map((action) => action.action_id)
    .reverse();
  if (!isDeepStrictEqual(document.rollback_order, expected)) {
    addError(
      errors,
      "INSTALL_PLAN_ROLLBACK_ORDER_MISMATCH",
      "/rollback_order",
      "ready plans must roll back every filesystem mutation exactly once in reverse execution order",
    );
  }
}

function validateExpectedBindings(document, expectedBindings, errors) {
  if (
    !isPlainObject(expectedBindings)
    || !isDeepStrictEqual(Object.keys(expectedBindings).sort(), EXPECTED_BINDING_KEYS)
  ) {
    addError(
      errors,
      "INSTALL_PLAN_EXPECTED_BINDINGS_REQUIRED",
      "/",
      `bound validation requires caller-owned ${EXPECTED_BINDING_KEYS.join(", ")}`,
    );
    return;
  }
  for (const key of EXPECTED_BINDING_KEYS) {
    if (!isDeepStrictEqual(document[key], expectedBindings[key])) {
      addError(
        errors,
        "INSTALL_PLAN_EXPECTED_BINDING_MISMATCH",
        `/${key}`,
        `${key} does not match the caller-owned expected value`,
      );
    }
  }
}

function validateEvaluationTime(document, evaluatedAt, errors) {
  const evaluationTime = parseTimestamp(evaluatedAt);
  if (evaluationTime === null) {
    addError(
      errors,
      "INSTALL_PLAN_EVALUATION_TIME_REQUIRED",
      "/",
      "bound validation requires a caller-supplied UTC evaluation timestamp",
    );
    return;
  }
  const reportedAt = parseTimestamp(document.result.reported_at);
  const expiresAt = parseTimestamp(document.expires_at);
  if (reportedAt !== null && evaluationTime < reportedAt) {
    addError(
      errors,
      "INSTALL_PLAN_EVALUATION_BEFORE_PLAN",
      "/",
      "evaluation time cannot precede the planning result",
    );
  }
  if (expiresAt !== null && evaluationTime >= expiresAt) {
    addError(
      errors,
      "INSTALL_PLAN_EXPIRED",
      "/expires_at",
      "plan expired before the caller's evaluation time",
    );
  }
  const authorityExpiresAt = parseTimestamp(
    document.artifact.authority.expires_at,
  );
  if (authorityExpiresAt !== null && evaluationTime >= authorityExpiresAt) {
    addError(
      errors,
      "INSTALL_PLAN_ARTIFACT_AUTHORITY_EXPIRED",
      "/artifact/authority/expires_at",
      "artifact authority expired before evaluation",
    );
  }
}

function validateBoundTargetPaths(document, metadataBytesByDigest, errors) {
  if (document.result.subject.kind !== "component") return;
  const component = document.result.subject.component;
  const metadataBytes = resolveDigestBytes(
    metadataBytesByDigest,
    component.metadata_digest,
  );
  if (!(metadataBytes instanceof Uint8Array)) return;
  const parsedMetadata = parseJsonObjectBytes(
    metadataBytes,
    "INSTALL_PLAN_SUBJECT_METADATA",
    "/result/subject/component",
  );
  if (!parsedMetadata.valid) return;

  validateBoundInstallPlanAdapter({
    document,
    metadata: parsedMetadata.value,
    errors,
    addError,
    pathIsAtOrBelow,
    validatePortablePosixPath,
  });
}

function validateDispositionPolicy(errors) {
  const expected = {
    blocked: {
      result_outcome: "blocked",
      eligible_for_confirmation: false,
      authorizes_installation: false,
      minimum_actions: 0,
      maximum_actions: 0,
      minimum_blockers: 1,
      maximum_blockers: 64,
    },
    ready: {
      result_outcome: "pass",
      eligible_for_confirmation: true,
      authorizes_installation: false,
      minimum_actions: 1,
      maximum_actions: 64,
      minimum_blockers: 0,
      maximum_blockers: 0,
    },
  };
  if (!isDeepStrictEqual(planPolicy.dispositions, expected)) {
    addError(
      errors,
      "INSTALL_PLAN_DISPOSITION_POLICY_MISMATCH",
      "/contracts/install-plan-policy.json/dispositions",
      "disposition policy does not match the required v1 ready and blocked invariants",
    );
  }
}

function validateConfirmationPolicy(errors) {
  const expected = {
    binding: "sha256_exact_plan_bytes",
    disclosure_source: "install_plan_actions",
    external_nonce_required: true,
    authenticated_principal_required: true,
    target_instance_binding_required: true,
    one_time_ledger_required: true,
    expires_with_plan: true,
    confirmation_authorizes_installation: false,
    apply_reverification_required: true,
  };
  if (!isDeepStrictEqual(planPolicy.confirmation, expected)) {
    addError(
      errors,
      "INSTALL_PLAN_CONFIRMATION_POLICY_MISMATCH",
      "/contracts/install-plan-policy.json/confirmation",
      "confirmation requirements must be external, exact-byte-bound, single-use, non-authorizing, and apply-reverified",
    );
  }
}

function validateFilesystemPolicy(errors) {
  const expected = {
    path_flavor: "posix",
    target_anchor: "scope_root",
    paths_are_scope_relative: true,
    symlinks_allowed: false,
    special_files_allowed: false,
    group_or_other_write_allowed: false,
    trailing_dot_segments_allowed: false,
    windows_device_basenames_allowed: false,
    managed_entries_are_fresh_create_only: true,
    managed_entries_require_absent_prestate: true,
    existing_target_entries_are_blockers: true,
    install_tree_entries_require_manifest_entry_digest: true,
  };
  if (!isDeepStrictEqual(planPolicy.filesystem, expected)) {
    addError(
      errors,
      "INSTALL_PLAN_FILESYSTEM_POLICY_MISMATCH",
      "/contracts/install-plan-policy.json/filesystem",
      "filesystem policy must require scope-relative fresh creates over absent targets",
    );
  }
}

function validateRollbackPolicy(errors) {
  const expected = {
    state_mutating_actions_require_rollback: true,
    managed_create_rolls_back_by_removal: true,
    declared_transformation_requires_captured_preimage: true,
    non_state_mutating_actions_have_null_rollback: true,
    non_state_mutating_actions_excluded_from_rollback_order: true,
  };
  if (!isDeepStrictEqual(planPolicy.rollback, expected)) {
    addError(
      errors,
      "INSTALL_PLAN_ROLLBACK_POLICY_MISMATCH",
      "/contracts/install-plan-policy.json/rollback",
      "rollback policy must require exact reversible state changes and exclude operational actions",
    );
  }
}

function validateAssurancePolicy(errors) {
  const expected = {
    exact_plan_bytes: "verified",
    exact_component_metadata: "verified_when_bound",
    caller_expected_artifact: "verified_when_bound",
    future_install_context: "verified_when_ready",
    provenance: "unverified",
    catalog_authorization: "unverified",
    release_signature_authorization: "unverified",
    advisory_verification: "unverified",
    operator_authorization: "unverified",
    artifact_source_membership: "unverified",
    action_state_derivation: "verified_when_bound",
    installation_authorization: "not_granted",
    execution: "not_executed",
    preconditions_at_apply_time: "unverified",
  };
  if (!isDeepStrictEqual(planPolicy.assurance, expected)) {
    addError(
      errors,
      "INSTALL_PLAN_ASSURANCE_POLICY_MISMATCH",
      "/contracts/install-plan-policy.json/assurance",
      "assurance policy must preserve the exact-byte binding and unverified security boundaries",
    );
  }
}

function validateSchemaPolicyAlignment(errors) {
  if (planSchema?.properties?.actions?.maxItems !== planPolicy.maximum_actions) {
    addError(
      errors,
      "INSTALL_PLAN_SCHEMA_ACTION_LIMIT_MISMATCH",
      "/contracts/schemas/install/install-plan-v1.schema.json/properties/actions/maxItems",
      "schema action limit must match install-plan policy",
    );
  }
  if (planSchema?.properties?.blockers?.maxItems !== planPolicy.maximum_blockers) {
    addError(
      errors,
      "INSTALL_PLAN_SCHEMA_BLOCKER_LIMIT_MISMATCH",
      "/contracts/schemas/install/install-plan-v1.schema.json/properties/blockers/maxItems",
      "schema blocker limit must match install-plan policy",
    );
  }
  if (
    !isDeepStrictEqual(
      planSchema?.properties?.disposition?.enum,
      ["blocked", "ready"],
    )
  ) {
    addError(
      errors,
      "INSTALL_PLAN_SCHEMA_DISPOSITION_MISMATCH",
      "/contracts/schemas/install/install-plan-v1.schema.json/properties/disposition/enum",
      "schema dispositions must be blocked and ready",
    );
  }
  if (
    planSchema?.properties?.path_flavor?.const
      !== planPolicy.filesystem?.path_flavor
    || planSchema?.definitions?.anchoredPath?.properties?.anchor?.const
      !== planPolicy.filesystem?.target_anchor
  ) {
    addError(
      errors,
      "INSTALL_PLAN_SCHEMA_PATH_MODEL_MISMATCH",
      "/contracts/schemas/install/install-plan-v1.schema.json",
      "schema and policy must use POSIX paths in one canonical scope_root target space",
    );
  }
  const nativeActionRefs = (
    planSchema?.definitions?.nativeOperationAction?.oneOf ?? []
  ).map((entry) => entry.$ref);
  if (
    !isDeepStrictEqual(nativeActionRefs, [
      "#/definitions/reloadHarnessAction",
      "#/definitions/restartHarnessAction",
    ])
  ) {
    addError(
      errors,
      "INSTALL_PLAN_SCHEMA_NATIVE_OPERATION_SET_MISMATCH",
      "/contracts/schemas/install/install-plan-v1.schema.json/definitions/nativeOperationAction",
      "install-plan v1 native operations must be limited to reload and restart",
    );
  }
}

async function readContractJson(filePath, label, errorPath) {
  try {
    const bytes = await readFile(filePath);
    const parsed = parseJsonObjectBytes(bytes, label, errorPath);
    return {
      value: parsed.valid ? parsed.value : null,
      errors: parsed.errors,
    };
  } catch {
    return {
      value: null,
      errors: [{
        code: `${label}_READ_FAILED`,
        path: errorPath,
        message: "contract source could not be read",
      }],
    };
  }
}

function appendSchemaDiagnostics(schemaErrors, errors) {
  for (const schemaError of schemaErrors ?? []) {
    const additionalProperty = schemaError.keyword === "additionalProperties"
      ? schemaError.params?.additionalProperty
      : null;
    const errorPath = additionalProperty
      ? joinJsonPointer(schemaError.dataPath || "", additionalProperty)
      : schemaError.dataPath || "/";
    addError(
      errors,
      "INSTALL_PLAN_SCHEMA_INVALID",
      errorPath,
      `${schemaError.keyword}: ${schemaError.message}`,
    );
    if (errors.length >= MAXIMUM_DIAGNOSTICS) break;
  }
}

function appendNestedDiagnostics(errors, nestedErrors, prefix) {
  for (const nested of nestedErrors ?? []) {
    const nestedPath = nested.path === "/" ? "" : nested.path;
    addError(
      errors,
      nested.code,
      `${prefix}${nestedPath}` || prefix,
      nested.message,
    );
  }
}

function finishUnbound(errors) {
  return {
    valid: errors.length === 0,
    errors: errors.slice(0, MAXIMUM_DIAGNOSTICS),
    binding: "unverified",
    authorization: "not_granted",
    execution: "not_executed",
    warnings: [],
  };
}

function finishBound(errors, warnings, planDigest) {
  return {
    valid: errors.length === 0,
    errors: errors.slice(0, MAXIMUM_DIAGNOSTICS),
    plan_digest: planDigest,
    binding: errors.length === 0
      ? "exact_plan_bytes_metadata_and_caller_inputs"
      : "unverified",
    provenance: "unverified",
    catalog_authorization: "unverified",
    release_signature_authorization: "unverified",
    advisory_verification: "unverified",
    operator_authorization: "unverified",
    artifact_source_membership: "unverified",
    action_state_derivation: errors.length === 0
      ? "verified_from_plan_actions"
      : "unverified",
    installation_authorization: "not_granted",
    execution: "not_executed",
    preconditions_at_apply_time: "unverified",
    warnings: warnings.slice(0, MAXIMUM_DIAGNOSTICS),
  };
}

function addError(errors, code, errorPath, message) {
  if (errors.length >= MAXIMUM_DIAGNOSTICS) return;
  if (
    errors.some((entry) => (
      entry.code === code
      && entry.path === errorPath
      && entry.message === message
    ))
  ) {
    return;
  }
  errors.push({ code, path: errorPath, message });
}

function validateClosedObject(value, expectedKeys, errorPath, errors) {
  if (!isPlainObject(value)) {
    addError(errors, "INSTALL_PLAN_POLICY_INVALID", errorPath, "policy must be an object");
    return;
  }
  if (!isDeepStrictEqual(Object.keys(value).sort(), [...expectedKeys].sort())) {
    addError(
      errors,
      "INSTALL_PLAN_POLICY_FIELDS_INVALID",
      errorPath,
      `expected fields ${[...expectedKeys].sort().join(", ")}`,
    );
  }
}

function preflightDocumentShape(document, errors) {
  const maximumArrayItems = planPolicy.maximum_array_items
    ?? EXPECTED_POLICY.maximumArrayItems;
  const maximumObjectKeys = planPolicy.maximum_object_keys
    ?? EXPECTED_POLICY.maximumObjectKeys;
  const maximumDocumentNodes = planPolicy.maximum_document_nodes
    ?? EXPECTED_POLICY.maximumDocumentNodes;
  const stack = [{ path: "/", value: document }];
  const seen = new WeakSet();
  let nodeCount = 0;

  while (stack.length > 0) {
    const current = stack.pop();
    nodeCount += 1;
    if (nodeCount > maximumDocumentNodes) {
      addError(
        errors,
        "INSTALL_PLAN_DOCUMENT_NODE_LIMIT_EXCEEDED",
        "/",
        `plan cannot contain more than ${maximumDocumentNodes} JSON nodes`,
      );
      return;
    }

    const { value } = current;
    if (value === null || typeof value !== "object") continue;
    if (seen.has(value)) {
      addError(
        errors,
        "INSTALL_PLAN_DOCUMENT_CYCLE_FORBIDDEN",
        current.path,
        "plan must be an acyclic JSON document",
      );
      return;
    }
    seen.add(value);

    if (Array.isArray(value)) {
      if (value.length > maximumArrayItems) {
        addError(
          errors,
          "INSTALL_PLAN_ARRAY_LIMIT_EXCEEDED",
          current.path,
          `plan arrays cannot contain more than ${maximumArrayItems} items`,
        );
        return;
      }
      for (let index = value.length - 1; index >= 0; index -= 1) {
        stack.push({
          path: joinJsonPointer(current.path === "/" ? "" : current.path, index),
          value: value[index],
        });
      }
      continue;
    }

    let keyCount = 0;
    for (const key in value) {
      if (!Object.hasOwn(value, key)) continue;
      keyCount += 1;
      if (keyCount > maximumObjectKeys) {
        addError(
          errors,
          "INSTALL_PLAN_OBJECT_KEY_LIMIT_EXCEEDED",
          current.path,
          `plan objects cannot contain more than ${maximumObjectKeys} keys`,
        );
        return;
      }
      stack.push({
        path: joinJsonPointer(current.path === "/" ? "" : current.path, key),
        value: value[key],
      });
    }
  }
}

function preflightPortablePaths(document, errors) {
  if (!isPlainObject(document)) return;
  if (
    Object.hasOwn(document, "path_flavor")
    && document.path_flavor !== "posix"
  ) {
    addError(
      errors,
      "INSTALL_PLAN_PATH_FLAVOR_INVALID",
      "/path_flavor",
      "install-plan v1 paths must use POSIX slash semantics",
    );
  }

  const inspectAnchoredTarget = (target, targetPath) => {
    if (!isPlainObject(target)) return;
    if (
      typeof target.anchor === "string"
      && target.anchor !== "scope_root"
    ) {
      addError(
        errors,
        "INSTALL_PLAN_FILESYSTEM_ANCHOR_INVALID",
        `${targetPath}/anchor`,
        "install-plan v1 filesystem targets must use the one canonical scope_root anchor",
      );
    }
    validatePortablePosixPath(target.path, `${targetPath}/path`, errors);
  };

  const actions = Array.isArray(document.actions) ? document.actions : [];
  for (let index = 0; index < actions.length; index += 1) {
    const action = actions[index];
    if (!isPlainObject(action)) continue;
    const actionPath = `/actions/${index}`;
    if (
      action.kind === "managed_entry"
      || action.kind === "declared_transformation"
    ) {
      inspectAnchoredTarget(action.target, `${actionPath}/target`);
    }
    if (
      isPlainObject(action.tree_entry)
      && !(
        action.tree_entry.kind === "directory"
        && action.tree_entry.path === "."
      )
    ) {
      validatePortablePosixPath(
        action.tree_entry.path,
        `${actionPath}/tree_entry/path`,
        errors,
      );
    }
    if (isPlainObject(action.declaration?.allowed_output?.target)) {
      inspectAnchoredTarget(
        action.declaration.allowed_output.target,
        `${actionPath}/declaration/allowed_output/target`,
      );
    }
  }

  const blockers = Array.isArray(document.blockers) ? document.blockers : [];
  for (let index = 0; index < blockers.length; index += 1) {
    const target = blockers[index]?.target;
    if (!isPlainObject(target)) continue;
    if (typeof target.anchor === "string") {
      inspectAnchoredTarget(target, `/blockers/${index}/target`);
    } else if (target.kind === "relative_path") {
      validatePortablePosixPath(
        target.value,
        `/blockers/${index}/target/value`,
        errors,
      );
    }
  }

  const skillRootPath = document.adapter?.profile?.skill_root_path;
  if (typeof skillRootPath === "string") {
    validatePortablePosixPath(
      skillRootPath,
      "/adapter/profile/skill_root_path",
      errors,
    );
  }
}

function preflightRemovedNativeOperations(document, errors) {
  if (!isPlainObject(document)) return;
  const actions = Array.isArray(document.actions) ? document.actions : [];
  for (let index = 0; index < actions.length; index += 1) {
    const action = actions[index];
    if (
      isPlainObject(action)
      && ["activate_package", "deactivate_package"].includes(action.operation)
    ) {
      addError(
        errors,
        "INSTALL_PLAN_NATIVE_PACKAGE_ACTIVATION_UNSUPPORTED",
        `/actions/${index}/operation`,
        "exact-tree filesystem writes are package activation in install-plan v1; activate and deactivate operations are not supported",
      );
    }
  }
}

function preflightPrototypeAdapters(document, errors) {
  if (!isPlainObject(document)) return;
  const harness = document.result?.invocation?.harness?.name;
  if (!["hermes", "picoclaw"].includes(harness)) return;
  if (document.adapter?.profile?.native_install_status !== "prototype_pending") {
    addError(
      errors,
      "INSTALL_PLAN_PROTOTYPE_STATUS_INVALID",
      "/adapter/profile/native_install_status",
      `${harness} install planning must explicitly declare prototype_pending`,
    );
  }
  if (
    document.disposition !== "blocked"
    || (Array.isArray(document.actions) && document.actions.length !== 0)
    || document.apply_context !== null
    || document.confirmation_requirements !== null
  ) {
    addError(
      errors,
      "INSTALL_PLAN_PROTOTYPE_PENDING_DISPOSITION_INVALID",
      "/disposition",
      `${harness} native installation is prototype pending and can only produce a blocked plan`,
    );
  }
  if (
    !Array.isArray(document.blockers)
    || document.blockers.length === 0
    || document.blockers.some((blocker) => (
      blocker?.code !== "unsupported_native_operation"
    ))
  ) {
    addError(
      errors,
      "INSTALL_PLAN_PROTOTYPE_PENDING_BLOCKER_INVALID",
      "/blockers",
      `${harness} prototype-pending plans require only unsupported_native_operation blockers`,
    );
  }
}

function preflightCodingHarnessReferences(document, errors) {
  if (!isPlainObject(document)) return;
  const candidates = [{
    value: document.adapter?.profile?.coding_harness,
    path: "/adapter/profile/coding_harness",
  }];
  const actions = Array.isArray(document.actions) ? document.actions : [];
  for (let index = 0; index < actions.length; index += 1) {
    const codingHarness = actions[index]?.declaration?.coding_harness;
    candidates.push({
      value: codingHarness,
      path: `/actions/${index}/declaration/coding_harness`,
    });
  }
  for (const candidate of candidates) {
    validateCodingHarness(candidate.value, candidate.path, errors);
  }
}

function validatePortablePosixPath(candidate, errorPath, errors) {
  if (typeof candidate !== "string") return;
  const segments = candidate.split("/");
  if (
    candidate.length === 0
    || candidate.startsWith("/")
    || candidate.includes("\\")
    || segments.some((segment) => (
      segment.length === 0 || segment === "." || segment === ".."
    ))
  ) {
    addError(
      errors,
      "INSTALL_PLAN_PATH_NOT_POSIX",
      errorPath,
      "path must be a normalized non-empty relative POSIX path",
    );
    return;
  }
  if (segments.some((segment) => segment.endsWith("."))) {
    addError(
      errors,
      "INSTALL_PLAN_PATH_TRAILING_DOT_FORBIDDEN",
      errorPath,
      "POSIX path segments cannot end with a dot in a portable install plan",
    );
  }
  for (const segment of segments) {
    const basename = segment.split(".", 1)[0].replace(/[ .]+$/u, "");
    if (
      /^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])$/iu.test(basename)
    ) {
      addError(
        errors,
        "INSTALL_PLAN_WINDOWS_DEVICE_PATH_FORBIDDEN",
        errorPath,
        "portable install paths cannot use Windows device basenames",
      );
      break;
    }
  }
}

function isFloatingReference(value) {
  return /^(?:latest|stable|main|master|head|trunk)$/iu.test(value);
}

function actionTargetKey(action) {
  if (
    action.kind === "managed_entry"
    || action.kind === "declared_transformation"
  ) {
    return `${action.target.anchor}:${action.target.path}`;
  }
  if (action.kind === "native_operation") {
    if (typeof action.target.anchor === "string") {
      return `${action.target.anchor}:${action.target.path}:native:${action.operation}`;
    }
    return `${action.target.kind}:${action.target.value}:native:${action.operation}`;
  }
  return null;
}

function actionEffectTarget(action) {
  if (typeof action.target.anchor === "string") {
    return {
      kind: "relative_path",
      value: action.target.path,
    };
  }
  return {
    kind: "harness_resource",
    value: action.target.value,
  };
}

function digestCanonical(value) {
  return digestBytes(Buffer.from(canonicalJson(value), "utf8"));
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  )).join(",")}}`;
}

function parseTimestamp(value) {
  if (
    typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)
  ) {
    return null;
  }
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) ? milliseconds : null;
}

function resolveDigestBytes(resolver, digest) {
  if (resolver instanceof Map) {
    try {
      return Map.prototype.get.call(resolver, digest);
    } catch {
      return null;
    }
  }
  if (isPlainObject(resolver)) {
    try {
      const descriptor = Object.getOwnPropertyDescriptor(resolver, digest);
      if (descriptor && Object.hasOwn(descriptor, "value")) {
        return descriptor.value;
      }
    } catch {
      return null;
    }
  }
  return null;
}

function snapshotInstallPlanBytes(planBytes) {
  const errors = [];
  if (!(planBytes instanceof Uint8Array)) {
    return { bytes: planBytes, errors };
  }
  const view = fixedUint8ArrayView(planBytes);
  if (view === null) {
    addError(
      errors,
      "INSTALL_PLAN_BYTES_REQUIRED",
      "/",
      "input must be a stable Buffer or Uint8Array view",
    );
    return { bytes: null, errors };
  }
  if (view.byteLength > EXPECTED_POLICY.maximumPlanBytes) {
    addError(
      errors,
      "INSTALL_PLAN_TOO_LARGE",
      "/",
      `input exceeds the ${EXPECTED_POLICY.maximumPlanBytes}-byte contract limit`,
    );
    return { bytes: null, errors };
  }
  try {
    return { bytes: Buffer.from(view), errors };
  } catch {
    addError(
      errors,
      "INSTALL_PLAN_BYTES_SNAPSHOT_FAILED",
      "/",
      "input bytes changed shape before a bounded private snapshot could be made",
    );
    return { bytes: null, errors };
  }
}

function snapshotDigestBytesResolver(resolver, requiredDigests, errors) {
  const snapshot = new Map();
  for (const digest of new Set(requiredDigests)) {
    const bytes = resolveDigestBytes(resolver, digest);
    if (!(bytes instanceof Uint8Array)) continue;
    const view = fixedUint8ArrayView(bytes);
    if (view === null) continue;
    if (view.byteLength > EXPECTED_POLICY.maximumPlanBytes) {
      addError(
        errors,
        "INSTALL_PLAN_METADATA_TOO_LARGE",
        "/metadataBytesByDigest",
        `metadata ${digest} exceeds the ${EXPECTED_POLICY.maximumPlanBytes}-byte contract limit`,
      );
      continue;
    }
    try {
      snapshot.set(digest, Buffer.from(view));
    } catch {
      addError(
        errors,
        "INSTALL_PLAN_METADATA_SNAPSHOT_FAILED",
        "/metadataBytesByDigest",
        `metadata ${digest} changed shape before a bounded private snapshot could be made`,
      );
    }
  }
  return snapshot;
}

function fixedUint8ArrayView(bytes) {
  try {
    const buffer = TYPED_ARRAY_BUFFER_GETTER.call(bytes);
    const byteLength = TYPED_ARRAY_BYTE_LENGTH_GETTER.call(bytes);
    const byteOffset = TYPED_ARRAY_BYTE_OFFSET_GETTER.call(bytes);
    return new Uint8Array(buffer, byteOffset, byteLength);
  } catch {
    return null;
  }
}

function pathIsAtOrBelow(candidate, root) {
  return candidate === root || candidate.startsWith(`${root}/`);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function joinJsonPointer(base, token) {
  const prefix = base === "/" ? "" : base;
  return `${prefix}/${String(token).replaceAll("~", "~0").replaceAll("/", "~1")}`;
}
