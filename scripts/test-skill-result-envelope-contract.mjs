#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  digestBytes,
  exitCodeForOutcome,
  validateBoundResultEnvelope,
  validateUnboundResultEnvelope,
  validateUnboundResultEnvelopeBytes,
  validateResultEnvelopeRegistries,
} from "./ci/validate_clawsec_result_envelope.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const metadataFixtureRoot = path.join(
  repositoryRoot,
  "contracts/fixtures/component-metadata-v1/valid",
);
const resultFixtureRoot = path.join(
  repositoryRoot,
  "contracts/fixtures/result-v1/valid",
);

const [
  coreNanoclawBytes,
  coreOpenclawBytes,
  suiteNanoclawBytes,
  driftNanoclawBytes,
  driftPicoclawBytes,
  suiteHermesBytes,
  doctorErrorBytes,
  doctorPassBytes,
] = await Promise.all([
  readFile(path.join(metadataFixtureRoot, "core-nanoclaw-v2.json")),
  readFile(path.join(metadataFixtureRoot, "core-openclaw.json")),
  readFile(path.join(metadataFixtureRoot, "suite-nanoclaw-v2.json")),
  readFile(path.join(metadataFixtureRoot, "drift-nanoclaw-v2.json")),
  readFile(path.join(metadataFixtureRoot, "drift-picoclaw.json")),
  readFile(path.join(metadataFixtureRoot, "suite-hermes.json")),
  readFile(path.join(
    resultFixtureRoot,
    "core-doctor-error-unknown-version-nanoclaw-v2.json",
  )),
  readFile(path.join(
    resultFixtureRoot,
    "core-doctor-pass-nanoclaw-v2.json",
  )),
]);

const coreNanoclawRef = componentRefFromMetadata(coreNanoclawBytes);
const coreOpenclawRef = componentRefFromMetadata(coreOpenclawBytes);
const suiteNanoclawRef = componentRefFromMetadata(suiteNanoclawBytes);
const driftNanoclawRef = componentRefFromMetadata(driftNanoclawBytes);
const driftPicoclawRef = componentRefFromMetadata(driftPicoclawBytes);
const suiteHermesRef = componentRefFromMetadata(suiteHermesBytes);
const doctorPass = JSON.parse(doctorPassBytes);

assertValid(validateResultEnvelopeRegistries(), "result registries");
assert.equal(
  digestBytes(coreNanoclawBytes),
  `sha256:${createHash("sha256").update(coreNanoclawBytes).digest("hex")}`,
  "digestBytes must hash exact bytes",
);

for (const [bytes, exitCode] of [
  [doctorErrorBytes, 1],
  [doctorPassBytes, 0],
]) {
  const document = JSON.parse(bytes);
  const result = validateBoundResultEnvelope({
    resultBytes: bytes,
    metadataBytesByDigest: metadataMap(coreNanoclawBytes),
    expectedContext: expectedContextFor(document),
  });
  assertValid(result, `committed fixture ${document.invocation.id}`);
  assert.equal(result.binding, "exact_metadata");
  assert.equal(exitCodeForOutcome(document.outcome), exitCode);
}

const cliDirectory = await mkdtemp(path.join(tmpdir(), "clawsec-result-cli-"));
const cliContextPath = path.join(cliDirectory, "context.json");
await writeFile(
  cliContextPath,
  `${JSON.stringify(expectedContextFor(doctorPass))}\n`,
  "utf8",
);
const cliResult = spawnSync(process.execPath, [
  path.join(repositoryRoot, "scripts/ci/validate_clawsec_result_envelope.mjs"),
  "--result",
  path.join(resultFixtureRoot, "core-doctor-pass-nanoclaw-v2.json"),
  "--metadata",
  path.join(metadataFixtureRoot, "core-nanoclaw-v2.json"),
  "--expected-context",
  cliContextPath,
  "--json",
], {
  cwd: repositoryRoot,
  encoding: "utf8",
});
assert.equal(cliResult.status, 0, `CLI failed: ${cliResult.stderr}`);
assert.equal(cliResult.stderr, "");
assert.deepEqual(JSON.parse(cliResult.stdout), {
  valid: true,
  errors: [],
  binding: "exact_metadata",
  authorization: "unverified",
  warnings: [],
});

const unboundPass = validateUnboundResultEnvelopeBytes(doctorPassBytes);
assertValid(unboundPass, "unbound fixture");
assert.equal(
  unboundPass.binding,
  "unverified",
  "unbound validation must disclose that metadata is not bound",
);

const unresolvedDigest = clone(doctorPass);
unresolvedDigest.executor.metadata_digest = `sha256:${"0".repeat(64)}`;
const unresolvedUnbound = validateUnboundResultEnvelopeBytes(encode(unresolvedDigest));
assertValid(unresolvedUnbound, "unbound valid unresolved digest");
assert.equal(unresolvedUnbound.binding, "unverified");
assertCode(
  validateBoundResultEnvelope({
    resultBytes: encode(unresolvedDigest),
    metadataBytesByDigest: metadataMap(coreNanoclawBytes),
    expectedContext: expectedContextFor(unresolvedDigest),
  }),
  "RESULT_EXECUTOR_METADATA_MISSING",
  "unresolved digest under bound validation",
);

const stableMetadata = JSON.parse(coreNanoclawBytes);
stableMetadata.clawsec.maturity = "stable";
const stableMetadataBytes = encode(stableMetadata);
const stableResult = clone(doctorPass);
stableResult.executor = componentRefFromMetadata(stableMetadataBytes);
const stableBoundResult = validateBound(stableResult, [stableMetadataBytes]);
assertValid(stableBoundResult, "stable metadata warning propagation");
assert(
  stableBoundResult.warnings.some((entry) => (
    entry.code === "RESULT_EXECUTOR_STABLE_MATURITY_REQUIRES_CONFORMANCE"
  )),
  `stable metadata warning was dropped: ${JSON.stringify(stableBoundResult)}`,
);
assert.equal(stableBoundResult.authorization, "unverified");

const expectedExitCodes = {
  blocked: 3,
  confirmation_required: 42,
  degraded: 4,
  error: 1,
  finding: 2,
  not_applicable: 6,
  pass: 0,
  unsupported: 5,
};
for (const [outcome, exitCode] of Object.entries(expectedExitCodes)) {
  assert.equal(exitCodeForOutcome(outcome), exitCode, `exit code for ${outcome}`);
}
assert.equal(exitCodeForOutcome("unknown"), null);

const suiteStatus = makeResult({
  executor: suiteNanoclawRef,
  operation: "suite.status",
  subject: { kind: "scope" },
  summary: "Suite status invocation completed; aggregate evidence is not part of this base result.",
});
assertValid(
  validateBound(suiteStatus, [suiteNanoclawBytes]),
  "suite role binding",
);

const guardianStatus = makeResult({
  executor: driftNanoclawRef,
  operation: "guardian.status",
  subject: { kind: "executor" },
  outcome: "finding",
  reasonCode: "security_finding_detected",
  summary: "The guardian reports a security-relevant condition.",
});
assertValid(
  validateBound(guardianStatus, [driftNanoclawBytes]),
  "guardian role and family binding",
);

const openclawDoctor = applyFixtureHarness(
  makeResult({
    executor: coreOpenclawRef,
    operation: "core.doctor",
    subject: { kind: "executor" },
    summary: "OpenClaw core doctor invocation completed.",
  }),
  coreOpenclawBytes,
  {
    kind: "openclaw.workspace",
    ref: "fixture-workspace",
  },
);
assertValid(
  validateBound(openclawDoctor, [coreOpenclawBytes]),
  "OpenClaw workspace result",
);

const hermesStatus = applyFixtureHarness(
  makeResult({
    executor: suiteHermesRef,
    operation: "suite.status",
    subject: { kind: "scope" },
    summary: "Hermes suite status invocation completed.",
  }),
  suiteHermesBytes,
  {
    kind: "hermes.profile",
    ref: "fixture-profile",
  },
);
assertValid(
  validateBound(hermesStatus, [suiteHermesBytes]),
  "Hermes profile result",
);

const picoclawGuardianStatus = applyFixtureHarness(
  makeResult({
    executor: driftPicoclawRef,
    operation: "guardian.status",
    subject: { kind: "executor" },
    summary: "PicoClaw drift guardian status invocation completed.",
  }),
  driftPicoclawBytes,
  {
    kind: "picoclaw.home",
    ref: "fixture-home",
  },
);
assertValid(
  validateBound(picoclawGuardianStatus, [driftPicoclawBytes]),
  "PicoClaw home result",
);

const planningPass = makeResult({
  operation: "core.plan-release",
  subject: {
    kind: "component",
    component: suiteNanoclawRef,
  },
  summary: "The executor reports a proposed installation plan.",
  effects: [effect("plan.suite", "proposed")],
});
assertValid(
  validateBound(planningPass, [coreNanoclawBytes, suiteNanoclawBytes]),
  "planning pass with proposed effect",
);

const mutationPass = makeResult({
  operation: "core.install-release",
  subject: {
    kind: "component",
    component: suiteNanoclawRef,
  },
  summary: "The executor reports an applied installation effect; proof requires a receipt.",
  effects: [effect("install.suite", "applied")],
});
assertValid(
  validateBound(mutationPass, [coreNanoclawBytes, suiteNanoclawBytes]),
  "mutation pass with applied effect",
);

const nanoclawHostMutation = clone(mutationPass);
nanoclawHostMutation.invocation.scope = { kind: "host" };
assertCode(
  validateBound(
    nanoclawHostMutation,
    [coreNanoclawBytes, suiteNanoclawBytes],
  ),
  "RESULT_NANOCLAW_CHECKOUT_SCOPE_REQUIRED",
  "NanoClaw host-scope package mutation",
);

const unrelatedNanoclawEffect = clone(mutationPass);
unrelatedNanoclawEffect.effects[0].target.value = "unrelated/file";
assertCode(
  validateBound(
    unrelatedNanoclawEffect,
    [coreNanoclawBytes, suiteNanoclawBytes],
  ),
  "RESULT_NANOCLAW_PACKAGE_TREE_EFFECT_REQUIRED",
  "unrelated NanoClaw package effect",
);

const selfReleaseVerification = makeResult({
  operation: "core.verify-release",
  subject: {
    kind: "component",
    component: coreNanoclawRef,
  },
  summary: "The core reports verification of its own component identity.",
});
assertValid(
  validateBound(selfReleaseVerification, [coreNanoclawBytes]),
  "self component release verification",
);

const releasePassWithoutComponent = makeResult({
  operation: "core.verify-release",
  subject: { kind: "scope" },
  summary: "The executor reports release verification without a release identity.",
});
assertCode(
  validateBound(releasePassWithoutComponent, [coreNanoclawBytes]),
  "RESULT_RELEASE_COMPONENT_SUBJECT_REQUIRED",
  "release pass without component identity",
);

const unsupportedExecutorRange = clone(doctorPass);
unsupportedExecutorRange.invocation.harness.version = "2.2.0";
unsupportedExecutorRange.outcome = "unsupported";
unsupportedExecutorRange.reason_code = "intentionally_unsupported";
unsupportedExecutorRange.summary =
  "The core reports that NanoClaw 2.2.0 is outside its declared support range.";
assertValid(
  validateBound(unsupportedExecutorRange, [coreNanoclawBytes]),
  "safe out-of-range executor refusal",
);

const narrowSuite = JSON.parse(suiteNanoclawBytes);
narrowSuite.clawsec.supported_harness.maximum_version_exclusive = "2.1.18";
const narrowSuiteBytes = encode(narrowSuite);
const narrowSuiteRef = componentRefFromMetadata(narrowSuiteBytes);
const blockedSubjectRange = makeResult({
  operation: "core.install-release",
  subject: {
    kind: "component",
    component: narrowSuiteRef,
  },
  outcome: "blocked",
  reasonCode: "prerequisite_missing",
  summary: "The target suite does not support the detected NanoClaw version.",
});
blockedSubjectRange.invocation.harness.version = "2.1.18";
assertValid(
  validateBound(
    blockedSubjectRange,
    [coreNanoclawBytes, narrowSuiteBytes],
  ),
  "safe incompatible-subject refusal",
);

const outcomeCases = [
  ["blocked", "policy_blocked"],
  ["degraded", "assurance_unavailable"],
  ["error", "internal_failure"],
  ["finding", "security_finding_detected"],
  ["not_applicable", "operation_not_applicable"],
  ["pass", "operation_completed"],
  ["unsupported", "intentionally_unsupported"],
];
for (const [outcome, reasonCode] of outcomeCases) {
  const document = makeResult({
    outcome,
    reasonCode,
    summary: `Executor reports ${outcome}.`,
  });
  assertValid(
    validateBound(document, [coreNanoclawBytes]),
    `outcome ${outcome}`,
  );
}

const confirmation = makeResult({
  operation: "core.install-release",
  subject: {
    kind: "component",
    component: suiteNanoclawRef,
  },
  outcome: "confirmation_required",
  reasonCode: "user_confirmation_required",
  summary: "The executor reports that a typed installation plan needs confirmation.",
  effects: [effect("install.suite", "proposed")],
});
assertValid(
  validateBound(
    confirmation,
    [coreNanoclawBytes, suiteNanoclawBytes],
  ),
  "base confirmation summary",
);

assertCode(
  validateUnboundResultEnvelope({ ...clone(doctorPass), unknown: true }),
  "RESULT_SCHEMA_INVALID",
  "unknown top-level field",
);

const badUuid = clone(doctorPass);
badUuid.invocation.id = "not-a-uuid";
assertCode(validateUnboundResultEnvelope(badUuid), "RESULT_SCHEMA_INVALID", "UUID");

const badTimestamp = clone(doctorPass);
badTimestamp.reported_at = "2026-07-23 10:01:00";
assertCode(
  validateUnboundResultEnvelope(badTimestamp),
  "RESULT_SCHEMA_INVALID",
  "timestamp",
);

const unknownOperation = clone(doctorPass);
unknownOperation.invocation.operation = "core.unknown-operation";
assertCode(
  validateUnboundResultEnvelope(unknownOperation),
  "RESULT_OPERATION_UNKNOWN",
  "unknown operation",
);

const wrongRole = clone(doctorPass);
wrongRole.invocation.operation = "suite.status";
assertCode(
  validateUnboundResultEnvelope(wrongRole),
  "RESULT_OPERATION_ROLE_MISMATCH",
  "wrong operation role",
);

const undeclaredOptional = makeResult({
  executor: suiteNanoclawRef,
  operation: "suite.recurring-advisory-verification",
  subject: { kind: "scope" },
  outcome: "unsupported",
  reasonCode: "intentionally_unsupported",
  summary: "The optional operation is absent.",
});
assertCode(
  validateBound(undeclaredOptional, [suiteNanoclawBytes]),
  "RESULT_OPERATION_NOT_DECLARED",
  "undeclared optional capability",
);

const harnessMismatch = clone(doctorPass);
harnessMismatch.invocation.harness.name = "hermes";
assertCode(
  validateUnboundResultEnvelope(harnessMismatch),
  "RESULT_EXECUTOR_HARNESS_MISMATCH",
  "executor harness",
);

const badHarnessVersion = clone(doctorPass);
badHarnessVersion.invocation.harness.version = "2.1";
const badHarnessVersionResult = validateBound(
  badHarnessVersion,
  [coreNanoclawBytes],
);
assertCode(
  badHarnessVersionResult,
  "RESULT_HARNESS_VERSION_INVALID",
  "strict harness SemVer",
);
assert(
  !badHarnessVersionResult.errors.some((entry) => (
    entry.code === "RESULT_EXECUTOR_VERSION_UNSUPPORTED"
  )),
  `malformed SemVer produced range cascade: ${JSON.stringify(badHarnessVersionResult.errors)}`,
);

const missingHarnessVersion = clone(doctorPass);
missingHarnessVersion.invocation.harness.version = null;
assertCode(
  validateUnboundResultEnvelope(missingHarnessVersion),
  "RESULT_HARNESS_VERSION_REQUIRED",
  "null version on pass",
);

const unsupportedHarnessVersion = clone(doctorPass);
unsupportedHarnessVersion.invocation.harness.version = "2.2.0";
assertCode(
  validateBound(unsupportedHarnessVersion, [coreNanoclawBytes]),
  "RESULT_EXECUTOR_VERSION_UNSUPPORTED",
  "executor support range",
);

const scopeMismatch = clone(doctorPass);
scopeMismatch.invocation.scope = {
  kind: "hermes.profile",
  ref: "default",
};
assertCode(
  validateUnboundResultEnvelope(scopeMismatch),
  "RESULT_SCOPE_HARNESS_MISMATCH",
  "scope harness",
);

const hostWithRef = clone(doctorPass);
hostWithRef.invocation.scope = {
  kind: "host",
  ref: "forbidden",
};
assertCode(
  validateUnboundResultEnvelope(hostWithRef),
  "RESULT_SCHEMA_INVALID",
  "host scope ref",
);

const nonHostWithoutRef = clone(doctorPass);
nonHostWithoutRef.invocation.scope = {
  kind: "nanoclaw.checkout",
};
assertCode(
  validateUnboundResultEnvelope(nonHostWithoutRef),
  "RESULT_SCHEMA_INVALID",
  "non-host scope ref",
);

const unknownReason = clone(doctorPass);
unknownReason.reason_code = "unknown_reason";
assertCode(
  validateUnboundResultEnvelope(unknownReason),
  "RESULT_REASON_UNKNOWN",
  "unknown reason",
);

const wrongReasonOutcome = clone(doctorPass);
wrongReasonOutcome.reason_code = "policy_blocked";
assertCode(
  validateUnboundResultEnvelope(wrongReasonOutcome),
  "RESULT_REASON_OUTCOME_MISMATCH",
  "reason outcome",
);

const sameComponentSubject = clone(doctorPass);
sameComponentSubject.subject = {
  kind: "component",
  component: coreNanoclawRef,
};
assertCode(
  validateUnboundResultEnvelope(sameComponentSubject),
  "RESULT_SUBJECT_KIND_FORBIDDEN",
  "doctor component subject",
);

const crossHarnessSubject = makeResult({
  operation: "core.install-release",
  subject: {
    kind: "component",
    component: suiteHermesRef,
  },
  outcome: "blocked",
  reasonCode: "policy_blocked",
  summary: "Cross-harness installation is blocked.",
});
assertCode(
  validateBound(
    crossHarnessSubject,
    [coreNanoclawBytes, suiteHermesBytes],
  ),
  "RESULT_SUBJECT_HARNESS_MISMATCH",
  "cross-harness subject",
);

const confirmationWithoutEffect = clone(confirmation);
confirmationWithoutEffect.effects = [];
assertCode(
  validateUnboundResultEnvelope(confirmationWithoutEffect),
  "RESULT_EFFECT_COUNT_INSUFFICIENT",
  "confirmation without proposal",
);

const confirmationWithAppliedEffect = clone(confirmation);
confirmationWithAppliedEffect.effects[0].state = "applied";
assertCode(
  validateUnboundResultEnvelope(confirmationWithAppliedEffect),
  "RESULT_EFFECT_STATE_FORBIDDEN",
  "confirmation after mutation",
);

const unsupportedWithEffect = makeResult({
  outcome: "unsupported",
  reasonCode: "intentionally_unsupported",
  summary: "The declared operation is unsupported in this scope.",
  effects: [effect("unexpected.effect", "failed")],
});
assertCode(
  validateUnboundResultEnvelope(unsupportedWithEffect),
  "RESULT_EFFECT_STATE_FORBIDDEN",
  "unsupported effect",
);

const duplicateEffects = makeResult({
  outcome: "error",
  reasonCode: "internal_failure",
  summary: "The executor reports conflicting effect summaries.",
  effects: [
    effect("same.id", "failed"),
    effect("same.id", "rolled_back"),
  ],
});
assertCode(
  validateUnboundResultEnvelope(duplicateEffects),
  "RESULT_EFFECT_ID_DUPLICATE",
  "duplicate effect IDs",
);

const unsortedEffects = makeResult({
  outcome: "error",
  reasonCode: "internal_failure",
  summary: "The executor reports unsorted effect summaries.",
  effects: [
    effect("z.effect", "failed"),
    effect("a.effect", "rolled_back"),
  ],
});
assertCode(
  validateUnboundResultEnvelope(unsortedEffects),
  "RESULT_EFFECT_ID_NOT_SORTED",
  "effect ordering",
);

const maximumEffects = makeResult({
  operation: "core.install-release",
  subject: {
    kind: "component",
    component: suiteNanoclawRef,
  },
  outcome: "error",
  reasonCode: "internal_failure",
  summary: "The executor reports the maximum number of bounded effect summaries.",
  effects: Array.from(
    { length: 64 },
    (_, index) => effect(`bulk.${index.toString().padStart(3, "0")}`, "failed"),
  ),
});
assertValid(
  validateUnboundResultEnvelope(maximumEffects),
  "maximum effect summary count",
);

const excessiveEffects = clone(maximumEffects);
excessiveEffects.effects.push(effect("bulk.064", "failed"));
assertCode(
  validateUnboundResultEnvelope(excessiveEffects),
  "RESULT_SCHEMA_INVALID",
  "effect summary maximum",
);

for (const invalidPath of [
  "/absolute",
  "../traversal",
  "./dot",
  "a/../b",
  "a\\b",
  "a//b",
  "C:/drive",
  "https:/example",
  "file:secret",
  "%2e%2e/secret",
  "trailing/",
  "non-ascii-\u00e9",
]) {
  const document = makeResult({
    outcome: "error",
    reasonCode: "internal_failure",
    summary: "The executor reports a failed effect.",
    effects: [effect("bad.path", "failed", invalidPath)],
  });
  const result = validateUnboundResultEnvelope(document);
  assert.equal(result.valid, false, `invalid effect path accepted: ${invalidPath}`);
  assert(
    result.errors.some((entry) => (
      entry.code === "RESULT_SCHEMA_INVALID"
      || entry.code === "RESULT_EFFECT_PATH_INVALID"
    )),
    `missing path diagnostic for ${invalidPath}: ${JSON.stringify(result.errors)}`,
  );
}

const harnessResourceEffect = makeResult({
  operation: "core.install-release",
  subject: {
    kind: "component",
    component: suiteNanoclawRef,
  },
  outcome: "error",
  reasonCode: "internal_failure",
  summary: "The executor reports a failed harness resource operation.",
  effects: [{
    effect_id: "task.series",
    state: "failed",
    target: {
      kind: "harness_resource",
      value: "task-series:clawsec-01",
    },
    summary: "The harness resource operation failed.",
  }],
});
assertValid(
  validateUnboundResultEnvelope(harnessResourceEffect),
  "opaque harness resource effect",
);

const readOnlyAppliedEffect = clone(doctorPass);
readOnlyAppliedEffect.effects = [effect("doctor.write", "applied")];
assertCode(
  validateUnboundResultEnvelope(readOnlyAppliedEffect),
  "RESULT_EFFECT_STATE_FORBIDDEN",
  "read-only applied effect",
);

const mutationWithoutAppliedEffect = clone(mutationPass);
mutationWithoutAppliedEffect.effects = [];
assertCode(
  validateUnboundResultEnvelope(mutationWithoutAppliedEffect),
  "RESULT_EFFECT_COUNT_INSUFFICIENT",
  "mutation pass without effect",
);

const doctorScopeSubject = clone(doctorPass);
doctorScopeSubject.subject = { kind: "scope" };
assertCode(
  validateUnboundResultEnvelope(doctorScopeSubject),
  "RESULT_SUBJECT_KIND_FORBIDDEN",
  "doctor scope subject",
);

assertCode(
  validateBoundResultEnvelope({
    resultBytes: doctorPassBytes,
    metadataBytesByDigest: new Map(),
    expectedContext: expectedContextFor(doctorPass),
  }),
  "RESULT_EXECUTOR_METADATA_MISSING",
  "missing executor metadata",
);

const alteredCoreBytes = Buffer.concat([coreNanoclawBytes, Buffer.from("\n")]);
assertCode(
  validateBoundResultEnvelope({
    resultBytes: doctorPassBytes,
    metadataBytesByDigest: new Map([
      [coreNanoclawRef.metadata_digest, alteredCoreBytes],
    ]),
    expectedContext: expectedContextFor(doctorPass),
  }),
  "RESULT_EXECUTOR_METADATA_DIGEST_MISMATCH",
  "exact executor metadata digest",
);

const executorIdentityMismatch = clone(doctorPass);
executorIdentityMismatch.executor.version = "0.1.0-rc.2";
assertCode(
  validateBound(executorIdentityMismatch, [coreNanoclawBytes]),
  "RESULT_EXECUTOR_IDENTITY_MISMATCH",
  "executor metadata identity",
);

const malformedMetadataBytes = Buffer.from("{\"name\":");
const malformedMetadataResult = clone(doctorPass);
malformedMetadataResult.executor.metadata_digest = digestBytes(malformedMetadataBytes);
assertCode(
  validateBoundResultEnvelope({
    resultBytes: encode(malformedMetadataResult),
    metadataBytesByDigest: metadataMap(malformedMetadataBytes),
    expectedContext: expectedContextFor(malformedMetadataResult),
  }),
  "EXECUTOR_METADATA_JSON_INVALID",
  "malformed executor metadata",
);

assertCode(
  validateBoundResultEnvelope({
    resultBytes: encode(confirmation),
    metadataBytesByDigest: metadataMap(coreNanoclawBytes),
    expectedContext: expectedContextFor(confirmation),
  }),
  "RESULT_SUBJECT_METADATA_MISSING",
  "missing component subject metadata",
);

const alteredSuiteBytes = Buffer.concat([suiteNanoclawBytes, Buffer.from("\n")]);
assertCode(
  validateBoundResultEnvelope({
    resultBytes: encode(confirmation),
    metadataBytesByDigest: new Map([
      [coreNanoclawRef.metadata_digest, coreNanoclawBytes],
      [suiteNanoclawRef.metadata_digest, alteredSuiteBytes],
    ]),
    expectedContext: expectedContextFor(confirmation),
  }),
  "RESULT_SUBJECT_METADATA_DIGEST_MISMATCH",
  "exact subject metadata digest",
);

assertCode(
  validateBoundResultEnvelope({
    resultBytes: doctorPassBytes,
    metadataBytesByDigest: metadataMap(coreNanoclawBytes),
  }),
  "RESULT_EXPECTED_CONTEXT_REQUIRED",
  "expected context required",
);

const wrongExpectedInvocation = clone(doctorPass.invocation);
wrongExpectedInvocation.id = "99999999-9999-4999-8999-999999999999";
const wrongExpectedContext = expectedContextFor(doctorPass);
wrongExpectedContext.invocation = wrongExpectedInvocation;
assertCode(
  validateBoundResultEnvelope({
    resultBytes: doctorPassBytes,
    metadataBytesByDigest: metadataMap(coreNanoclawBytes),
    expectedContext: wrongExpectedContext,
  }),
  "RESULT_INVOCATION_MISMATCH",
  "expected invocation binding",
);

const substitutedExecutor = makeResult({
  executor: coreOpenclawRef,
  operation: "core.doctor",
  subject: { kind: "executor" },
  summary: "An internally consistent but unexpected executor produced this result.",
});
const coreOpenclawSkill = JSON.parse(coreOpenclawBytes);
substitutedExecutor.invocation.harness.version =
  coreOpenclawSkill.clawsec.supported_harness.minimum_version;
substitutedExecutor.invocation.scope = {
  kind: "openclaw.workspace",
  ref: "fixture-workspace",
};
assertCode(
  validateBound(
    substitutedExecutor,
    [coreOpenclawBytes],
    expectedContextFor(doctorPass),
  ),
  "RESULT_EXECUTOR_CONTEXT_MISMATCH",
  "executor substitution",
);

const substitutedSubject = clone(confirmation);
substitutedSubject.subject.component = driftNanoclawRef;
substitutedSubject.effects[0].target.value =
  JSON.parse(driftNanoclawBytes).clawsec.native.install_location;
assertCode(
  validateBound(
    substitutedSubject,
    [coreNanoclawBytes, driftNanoclawBytes],
    expectedContextFor(confirmation),
  ),
  "RESULT_SUBJECT_CONTEXT_MISMATCH",
  "component subject substitution",
);

assertCode(
  validateUnboundResultEnvelopeBytes("not bytes"),
  "RESULT_BYTES_REQUIRED",
  "byte-only parser",
);
assertCode(
  validateUnboundResultEnvelopeBytes(
    Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
  ),
  "RESULT_BOM_FORBIDDEN",
  "BOM",
);
assertCode(
  validateUnboundResultEnvelopeBytes(Buffer.from([0xc3, 0x28])),
  "RESULT_UTF8_INVALID",
  "invalid UTF-8",
);
assertCode(
  validateUnboundResultEnvelopeBytes(Buffer.from("{}{}")),
  "RESULT_JSON_INVALID",
  "trailing JSON",
);
assertCode(
  validateUnboundResultEnvelopeBytes(Buffer.from("[]")),
  "RESULT_ROOT_INVALID",
  "array root",
);
assertCode(
  validateUnboundResultEnvelopeBytes(Buffer.from(
    "{\"schema\":\"clawsec.result/v1\",\"schema\":\"clawsec.result/v1\"}",
  )),
  "RESULT_DUPLICATE_KEY",
  "duplicate key",
);

const deterministicInput = Buffer.from("{\"duplicate\":1,\"duplicate\":2}");
assert.deepEqual(
  validateUnboundResultEnvelopeBytes(deterministicInput),
  validateUnboundResultEnvelopeBytes(deterministicInput),
  "diagnostics must be deterministic",
);

const controlKeyDuplicate = Buffer.from(
  "{\"safe\":1,\"line\\nbreak\":1,\"line\\nbreak\":2}",
);
const controlKeyResult = validateUnboundResultEnvelopeBytes(controlKeyDuplicate);
assertCode(controlKeyResult, "RESULT_DUPLICATE_KEY", "control-key duplicate");
assert(
  controlKeyResult.errors.every((entry) => (
    !entry.path.includes("\n") && !entry.message.includes("\n")
  )),
  `duplicate-key diagnostic permits line injection: ${JSON.stringify(controlKeyResult)}`,
);

const controlProperty = clone(doctorPass);
controlProperty["line\nbreak"] = true;
const controlPropertyResult = validateUnboundResultEnvelopeBytes(encode(controlProperty));
assertCode(controlPropertyResult, "RESULT_SCHEMA_INVALID", "control property");
assert(
  controlPropertyResult.errors.every((entry) => (
    !entry.path.includes("\n") && !entry.message.includes("\n")
  )),
  `schema diagnostic permits line injection: ${JSON.stringify(controlPropertyResult)}`,
);

const diagnosticFanout = clone(doctorPass);
for (let index = 0; index < 5000; index += 1) {
  diagnosticFanout[`unknown_${index.toString().padStart(4, "0")}`] = true;
}
const diagnosticFanoutResult =
  validateUnboundResultEnvelopeBytes(encode(diagnosticFanout));
assert.equal(diagnosticFanoutResult.valid, false);
assert(
  diagnosticFanoutResult.errors.length <= 64,
  `diagnostic cap exceeded: ${diagnosticFanoutResult.errors.length}`,
);
assert(
  diagnosticFanoutResult.errors.some((entry) => (
    entry.code === "RESULT_DIAGNOSTICS_TRUNCATED"
  )),
  "diagnostic fanout was not marked as truncated",
);

const deeplyNestedInput = Buffer.from(
  `{"deep":${"[".repeat(20000)}0${"]".repeat(20000)}}`,
);
assertCode(
  validateUnboundResultEnvelopeBytes(deeplyNestedInput),
  "RESULT_NESTING_TOO_DEEP",
  "deep JSON input",
);

const oversizedInput = Buffer.alloc((1024 * 1024) + 1, 0x20);
assertCode(
  validateUnboundResultEnvelopeBytes(oversizedInput),
  "RESULT_TOO_LARGE",
  "oversized JSON input",
);

const multipleErrors = clone(doctorPass);
multipleErrors.reason_code = "policy_blocked";
multipleErrors.invocation.harness.name = "hermes";
multipleErrors.invocation.scope = {
  kind: "openclaw.workspace",
  ref: "workspace-01",
};
const multipleErrorResult = validateUnboundResultEnvelope(multipleErrors);
assert.deepEqual(
  multipleErrorResult.errors,
  [...multipleErrorResult.errors].sort(compareDiagnostics),
  "diagnostics must be sorted",
);

for (const guardedRoot of [
  path.join(repositoryRoot, "contracts"),
  path.join(repositoryRoot, "scripts/ci"),
]) {
  const appleDoubleFiles = await findAppleDoubleFiles(guardedRoot);
  assert.deepEqual(
    appleDoubleFiles,
    [],
    `AppleDouble files are forbidden: ${appleDoubleFiles.join(", ")}`,
  );
}

process.stdout.write(
  "PASS result-envelope contract: 2 committed fixtures, 3 roles, 4 harnesses, 8 outcomes, "
  + "exact metadata binding, invocation binding, parser hardening, and negative cases\n",
);

function makeResult({
  executor = coreNanoclawRef,
  operation = "core.doctor",
  subject = { kind: "executor" },
  outcome = "pass",
  reasonCode = "operation_completed",
  summary = "The executor reports that the operation completed.",
  effects = [],
} = {}) {
  return {
    schema: "clawsec.result/v1",
    executor: clone(executor),
    subject: clone(subject),
    invocation: {
      id: "55555555-5555-4555-8555-555555555555",
      operation,
      harness: {
        name: executor.harness,
        version: executor.harness === "nanoclaw" ? "2.1.17" : "1.0.0",
      },
      scope: defaultScope(executor.harness),
    },
    reported_at: "2026-07-23T11:00:00Z",
    outcome,
    reason_code: reasonCode,
    summary,
    effects: clone(effects),
  };
}

function defaultScope(harness) {
  const scopes = {
    hermes: {
      kind: "hermes.profile",
      ref: "fixture-profile",
    },
    nanoclaw: {
      kind: "nanoclaw.checkout",
      ref: "nanoclaw-v2-lab-01",
    },
    openclaw: {
      kind: "openclaw.workspace",
      ref: "fixture-workspace",
    },
    picoclaw: {
      kind: "picoclaw.home",
      ref: "fixture-home",
    },
  };
  return clone(scopes[harness]);
}

function effect(
  effectId,
  state,
  targetValue = ".claude/skills/clawsec-suite-nanoclaw",
) {
  return {
    effect_id: effectId,
    state,
    target: {
      kind: "relative_path",
      value: targetValue,
    },
    summary: `Executor reports effect ${effectId}.`,
  };
}

function componentRefFromMetadata(bytes) {
  const skill = JSON.parse(bytes);
  const reference = {
    schema: "clawsec.component-ref/v1",
    name: skill.name,
    version: skill.version,
    harness: skill.clawsec.supported_harness.name,
    role: skill.clawsec.role,
    metadata_digest: digestBytes(bytes),
  };
  if (skill.clawsec.family !== undefined) {
    reference.family = skill.clawsec.family;
  }
  return reference;
}

function applyFixtureHarness(document, metadataBytes, scope) {
  const skill = JSON.parse(metadataBytes);
  document.invocation.harness.version =
    skill.clawsec.supported_harness.minimum_version;
  document.invocation.scope = scope;
  return document;
}

function validateBound(
  document,
  metadataValues,
  expectedContext = expectedContextFor(document),
) {
  return validateBoundResultEnvelope({
    resultBytes: encode(document),
    metadataBytesByDigest: metadataMap(...metadataValues),
    expectedContext,
  });
}

function expectedContextFor(document) {
  return {
    executor: clone(document.executor),
    subject: clone(document.subject),
    invocation: clone(document.invocation),
  };
}

function metadataMap(...metadataValues) {
  return new Map(metadataValues.map((bytes) => [digestBytes(bytes), bytes]));
}

function encode(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertValid(result, label) {
  assert.equal(
    result.valid,
    true,
    `${label} should be valid: ${JSON.stringify(result.errors)}`,
  );
}

function assertCode(result, expectedCode, label) {
  assert.equal(result.valid, false, `${label} should be invalid`);
  assert(
    result.errors.some((entry) => entry.code === expectedCode),
    `${label} missing ${expectedCode}: ${JSON.stringify(result.errors)}`,
  );
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

async function findAppleDoubleFiles(directory) {
  const matches = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.name.startsWith("._")) matches.push(entryPath);
    if (entry.isDirectory()) matches.push(...await findAppleDoubleFiles(entryPath));
  }
  return matches.sort();
}
