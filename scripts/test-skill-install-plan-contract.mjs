#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";

import {
  computeInstallPlanStateBindings,
  digestBytes,
  validateBoundInstallPlan,
  validateInstallPlanContractSources,
  validateUnboundInstallPlanBytes,
} from "./ci/validate_clawsec_install_plan.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const metadataFixtureRoot = path.join(
  repositoryRoot,
  "contracts/fixtures/component-metadata-v1/valid",
);
const planFixtureRoot = path.join(
  repositoryRoot,
  "contracts/fixtures/install-plan-v1/valid",
);

const [
  coreNanoBytes,
  suiteNanoBytes,
  coreOpenclawSeedBytes,
  suiteHermesSeedBytes,
  readyFixtureBytes,
  blockedFixtureBytes,
] = await Promise.all([
  readFile(path.join(metadataFixtureRoot, "core-nanoclaw-v2.json")),
  readFile(path.join(metadataFixtureRoot, "suite-nanoclaw-v2.json")),
  readFile(path.join(metadataFixtureRoot, "core-openclaw.json")),
  readFile(path.join(metadataFixtureRoot, "suite-hermes.json")),
  readFile(path.join(planFixtureRoot, "nanoclaw-v2-ready.json")),
  readFile(path.join(
    planFixtureRoot,
    "nanoclaw-v2-blocked-unowned-path.json",
  )),
]);

const readyFixture = JSON.parse(readyFixtureBytes);
const blockedFixture = JSON.parse(blockedFixtureBytes);

assertValid(
  validateInstallPlanContractSources(),
  "install-plan contract sources",
);
assert.equal(
  digestBytes(readyFixtureBytes),
  `sha256:${createHash("sha256").update(readyFixtureBytes).digest("hex")}`,
  "the test must hash the exact committed fixture bytes",
);

for (const [label, bytes, document] of [
  ["ready fixture", readyFixtureBytes, readyFixture],
  ["blocked fixture", blockedFixtureBytes, blockedFixture],
]) {
  const unbound = validateUnboundInstallPlanBytes(bytes);
  assertValid(unbound, `${label} unbound`);
  assert.deepEqual(
    {
      binding: unbound.binding,
      authorization: unbound.authorization,
      execution: unbound.execution,
      warnings: unbound.warnings,
    },
    {
      binding: "unverified",
      authorization: "not_granted",
      execution: "not_executed",
      warnings: [],
    },
    `${label} must disclose what unbound validation does not establish`,
  );

  const bound = validateBoundInstallPlan({
    planBytes: bytes,
    metadataBytesByDigest: metadataMap(coreNanoBytes, suiteNanoBytes),
    expectedContext: expectedContextFor(document),
    expectedPlanDigest: digestBytes(bytes),
    expectedBindings: expectedBindingsFor(document),
    evaluatedAt: document.result.reported_at,
  });
  assertValid(bound, `${label} bound`);
  assert.equal(bound.plan_digest, digestBytes(bytes));
  assertBoundAssurance(bound, label);
}

assert.equal(
  readyFixture.apply_context.invocation.operation,
  "core.install-release",
  "a ready plan must bind the exact future install invocation",
);
assert.equal(
  readyFixture.confirmation_requirements.binding,
  "sha256_exact_plan_bytes",
  "a ready plan must require confirmation of the exact serialized plan bytes",
);
assert.equal(
  readyFixture.confirmation_requirements.disclosure_source,
  "install_plan_actions",
  "confirmation must display the typed actions rather than result summaries",
);
assert.equal(
  blockedFixture.apply_context,
  null,
  "a blocked plan must not claim a future install context",
);
assert.equal(
  blockedFixture.confirmation_requirements,
  null,
  "a blocked plan must not issue confirmation requirements",
);

const harnessBundles = new Map();
for (const harness of ["openclaw", "hermes", "picoclaw"]) {
  const coreBytes = syntheticMetadata(harness, "core");
  const suiteBytes = syntheticMetadata(harness, "suite");
  const document = planForHarness(
    readyFixture,
    harness,
    componentRefFromMetadata(coreBytes),
    componentRefFromMetadata(suiteBytes),
  );
  if (harness === "openclaw") {
    assertValid(
      validateBound(document, [coreBytes, suiteBytes]),
      "openclaw ready install plan",
    );
    harnessBundles.set(harness, { coreBytes, suiteBytes, document });
    continue;
  }

  assertCode(
    validateBound(document, [coreBytes, suiteBytes]),
    "INSTALL_PLAN_PROTOTYPE_PENDING_DISPOSITION_INVALID",
    `${harness} ready plan while native installation is prototype-pending`,
  );
  const blockedDocument = planForPrototypePendingHarness(
    blockedFixture,
    harness,
    componentRefFromMetadata(coreBytes),
    componentRefFromMetadata(suiteBytes),
  );
  assertValid(
    validateBound(blockedDocument, [coreBytes, suiteBytes]),
    `${harness} prototype-pending blocked plan`,
  );
  const wrongPrototypeBlocker = clone(blockedDocument);
  wrongPrototypeBlocker.blockers[0].code = "scope_ambiguous";
  assertCode(
    validateUnbound(wrongPrototypeBlocker),
    "INSTALL_PLAN_PROTOTYPE_PENDING_BLOCKER_INVALID",
    `${harness} prototype-pending plan with the wrong blocker`,
  );
  harnessBundles.set(harness, {
    blockedDocument,
    coreBytes,
    document,
    suiteBytes,
  });
}
assertValid(
  validateBound(readyFixture, [coreNanoBytes, suiteNanoBytes]),
  "nanoclaw ready install plan",
);
assert.deepEqual(
  [...harnessBundles.keys(), "nanoclaw"].sort(),
  ["hermes", "nanoclaw", "openclaw", "picoclaw"],
  "all four harness contexts must be exercised",
);

const digestMismatch = validateBoundInstallPlan({
  planBytes: readyFixtureBytes,
  metadataBytesByDigest: metadataMap(coreNanoBytes, suiteNanoBytes),
  expectedContext: expectedContextFor(readyFixture),
  expectedPlanDigest: `sha256:${"0".repeat(64)}`,
  expectedBindings: expectedBindingsFor(readyFixture),
  evaluatedAt: readyFixture.result.reported_at,
});
assertCode(
  digestMismatch,
  "INSTALL_PLAN_DIGEST_MISMATCH",
  "exact plan-byte digest substitution",
);

const contextMismatch = expectedContextFor(readyFixture);
contextMismatch.invocation.scope.ref = "different-checkout";
assertCode(
  validateBoundInstallPlan({
    planBytes: readyFixtureBytes,
    metadataBytesByDigest: metadataMap(coreNanoBytes, suiteNanoBytes),
    expectedContext: contextMismatch,
    expectedPlanDigest: digestBytes(readyFixtureBytes),
    expectedBindings: expectedBindingsFor(readyFixture),
    evaluatedAt: readyFixture.result.reported_at,
  }),
  "RESULT_INVOCATION_MISMATCH",
  "caller planning-context substitution",
);

const bindingMismatch = expectedBindingsFor(readyFixture);
bindingMismatch.adapter.configuration_digest = `sha256:${"0".repeat(64)}`;
assertCode(
  validateBoundInstallPlan({
    planBytes: readyFixtureBytes,
    metadataBytesByDigest: metadataMap(coreNanoBytes, suiteNanoBytes),
    expectedContext: expectedContextFor(readyFixture),
    expectedPlanDigest: digestBytes(readyFixtureBytes),
    expectedBindings: bindingMismatch,
    evaluatedAt: readyFixture.result.reported_at,
  }),
  "INSTALL_PLAN_EXPECTED_BINDING_MISMATCH",
  "caller-owned adapter binding substitution",
);

const missingAdapterBinding = expectedBindingsFor(readyFixture);
delete missingAdapterBinding.adapter;
assertCode(
  validateBoundInstallPlan({
    planBytes: readyFixtureBytes,
    metadataBytesByDigest: metadataMap(coreNanoBytes, suiteNanoBytes),
    expectedContext: expectedContextFor(readyFixture),
    expectedPlanDigest: digestBytes(readyFixtureBytes),
    expectedBindings: missingAdapterBinding,
    evaluatedAt: readyFixture.result.reported_at,
  }),
  "INSTALL_PLAN_EXPECTED_BINDINGS_REQUIRED",
  "incomplete expected-binding set",
);

assertCode(
  validateBoundInstallPlan({
    planBytes: readyFixtureBytes,
    metadataBytesByDigest: metadataMap(coreNanoBytes, suiteNanoBytes),
    expectedContext: expectedContextFor(readyFixture),
    expectedPlanDigest: digestBytes(readyFixtureBytes),
    expectedBindings: expectedBindingsFor(readyFixture),
    evaluatedAt: "2026-07-24T09:05:01Z",
  }),
  "INSTALL_PLAN_EXPIRED",
  "expired plan",
);
assertCode(
  validateBoundInstallPlan({
    planBytes: readyFixtureBytes,
    metadataBytesByDigest: metadataMap(coreNanoBytes, suiteNanoBytes),
    expectedContext: expectedContextFor(readyFixture),
    expectedPlanDigest: digestBytes(readyFixtureBytes),
    expectedBindings: expectedBindingsFor(readyFixture),
    evaluatedAt: readyFixture.expires_at,
  }),
  "INSTALL_PLAN_EXPIRED",
  "plan evaluated exactly at expiry",
);

const publicPrerelease = clone(readyFixture);
publicPrerelease.artifact.channel = "public_stable";
assertCode(
  validateUnbound(publicPrerelease),
  "INSTALL_PLAN_PUBLIC_PRERELEASE_FORBIDDEN",
  "public prerelease artifact",
);

const labAlpha = clone(readyFixture);
setSubjectVersion(labAlpha, "0.1.0-alpha.1");
assertCode(
  validateUnbound(labAlpha),
  "INSTALL_PLAN_LAB_VERSION_CLASS_INVALID",
  "private-lab alpha artifact",
);

const openclaw = harnessBundles.get("openclaw");
const stableSuiteBytes = setMetadataVersion(openclaw.suiteBytes, "0.1.0");
const publicStable = clone(openclaw.document);
const stableSuiteRef = componentRefFromMetadata(stableSuiteBytes);
replaceSubjectRef(publicStable, stableSuiteRef);
publicStable.artifact.channel = "public_stable";
publicStable.artifact.authority = {
  kind: "active_catalog_entry",
  contract: "clawsec.catalog-entry/v1",
  document_digest: `sha256:${"c".repeat(64)}`,
  signature_digest: `sha256:${"d".repeat(64)}`,
  root_fingerprint: `sha256:${"e".repeat(64)}`,
  expires_at: "2026-07-24T09:30:00Z",
};
assertValid(
  validateBound(publicStable, [openclaw.coreBytes, stableSuiteBytes]),
  "public stable final artifact",
);

const artifactComponentMismatch = clone(readyFixture);
artifactComponentMismatch.artifact.component.name = "clawsec-suite-picoclaw";
assertCode(
  validateUnbound(artifactComponentMismatch),
  "INSTALL_PLAN_ARTIFACT_COMPONENT_MISMATCH",
  "artifact component substitution",
);

const verificationDecision = clone(readyFixture);
verificationDecision.verification_refs.decision = "deny";
assertCode(
  validateUnbound(verificationDecision),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "non-reported verification decision",
);

const adapterMismatch = clone(readyFixture);
adapterMismatch.adapter.contract = "clawsec.openclaw-install-adapter/v1";
assertCode(
  validateUnbound(adapterMismatch),
  "INSTALL_PLAN_ADAPTER_MISMATCH",
  "wrong harness adapter",
);

const applyExecutorSubstitution = clone(readyFixture);
applyExecutorSubstitution.apply_context.executor.version = "0.1.0-rc.2";
assertCode(
  validateUnbound(applyExecutorSubstitution),
  "INSTALL_PLAN_APPLY_EXECUTOR_MISMATCH",
  "future install executor substitution",
);

const applyScopeSubstitution = clone(readyFixture);
applyScopeSubstitution.apply_context.invocation.scope.ref = "other-checkout";
assertCode(
  validateUnbound(applyScopeSubstitution),
  "INSTALL_PLAN_APPLY_SCOPE_MISMATCH",
  "future install scope substitution",
);

const targetInstanceSubstitution = clone(readyFixture);
targetInstanceSubstitution.target_state.target_instance_id =
  "other-nanoclaw-checkout";
assertCode(
  validateUnbound(targetInstanceSubstitution),
  "INSTALL_PLAN_TARGET_INSTANCE_MISMATCH",
  "target-instance substitution",
);

const readyWithoutChallenge = clone(readyFixture);
readyWithoutChallenge.confirmation_requirements = null;
assertCode(
  validateUnbound(readyWithoutChallenge),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "ready plan without confirmation requirements",
);

const blockedWithApplyContext = clone(blockedFixture);
blockedWithApplyContext.apply_context = clone(readyFixture.apply_context);
assertCode(
  validateUnbound(blockedWithApplyContext),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "blocked plan carrying an install context",
);

const blockedWithChallenge = clone(blockedFixture);
blockedWithChallenge.confirmation_requirements = clone(
  readyFixture.confirmation_requirements,
);
assertCode(
  validateUnbound(blockedWithChallenge),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "blocked plan carrying confirmation requirements",
);

const blockedWithActions = clone(blockedFixture);
blockedWithActions.actions = clone(readyFixture.actions);
blockedWithActions.rollback_order = clone(readyFixture.rollback_order);
blockedWithActions.result.effects = clone(readyFixture.result.effects);
refreshDerivedState(blockedWithActions);
assertCode(
  validateUnbound(blockedWithActions),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "blocked plan carrying executable actions",
);

const resourceLimitBlocked = clone(blockedFixture);
resourceLimitBlocked.artifact.install_tree_entry_count = 65;
resourceLimitBlocked.blockers[0] = {
  blocker_id: "install-resource-limit",
  code: "resource_limit",
  summary:
    "The candidate cannot be planned within the bounded install resources.",
};
assertValid(
  validateBound(resourceLimitBlocked, [coreNanoBytes, suiteNanoBytes]),
  "blocked plan for a 65-entry tree beyond the 64-action exact-disclosure limit",
);

const invalidCreatePrestate = clone(readyFixture);
invalidCreatePrestate.actions[0].before = {
  kind: "directory",
  mode: "0755",
};
assertCode(
  validateUnbound(invalidCreatePrestate),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "create action over an existing entry",
);

const missingTreeEntry = clone(readyFixture);
delete missingTreeEntry.actions[1].tree_entry;
assertCode(
  validateUnbound(missingTreeEntry),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "managed file action without an exact install-tree entry",
);

const treeEntryContentMismatch = clone(readyFixture);
treeEntryContentMismatch.actions[1].tree_entry.digest =
  `sha256:${"0".repeat(64)}`;
refreshDerivedState(treeEntryContentMismatch);
assertCode(
  validateUnbound(treeEntryContentMismatch),
  "INSTALL_PLAN_TREE_ENTRY_STATE_MISMATCH",
  "install-tree file digest that differs from its managed post-state",
);

const treeEntryWithoutManifestDigest = clone(readyFixture);
delete treeEntryWithoutManifestDigest.actions[1]
  .tree_entry.manifest_entry_digest;
assertCode(
  validateUnbound(treeEntryWithoutManifestDigest),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "install-tree entry without an exact manifest-entry digest",
);

const readyTreeEntryOverstatement = clone(readyFixture);
readyTreeEntryOverstatement.artifact.install_tree_entry_count += 1;
assertCode(
  validateUnbound(readyTreeEntryOverstatement),
  "INSTALL_PLAN_READY_TREE_ENTRY_COVERAGE_MISMATCH",
  "ready plan overstating the staged tree entry count",
);

const readyTreeByteOverstatement = clone(readyFixture);
readyTreeByteOverstatement.artifact.install_tree_total_bytes += 1;
assertCode(
  validateUnbound(readyTreeByteOverstatement),
  "INSTALL_PLAN_READY_TREE_BYTE_COVERAGE_MISMATCH",
  "ready plan overstating the staged tree byte total",
);

const managedReplacement = clone(readyFixture);
managedReplacement.actions[1].operation = "replace";
assertCode(
  validateUnbound(managedReplacement),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "managed replacement operation removed from fresh-install contract v1",
);

const duplicateAction = clone(readyFixture);
duplicateAction.actions[1].action_id = duplicateAction.actions[0].action_id;
duplicateAction.rollback_order = [
  duplicateAction.actions[1].action_id,
  duplicateAction.actions[0].action_id,
];
assertCode(
  validateUnbound(duplicateAction),
  "INSTALL_PLAN_ACTION_ID_DUPLICATE",
  "duplicate action identifier",
);

const wrongRollback = clone(readyFixture);
wrongRollback.rollback_order.reverse();
assertCode(
  validateUnbound(wrongRollback),
  "INSTALL_PLAN_ROLLBACK_ORDER_MISMATCH",
  "rollback order that is not the reverse of execution",
);

const duplicateBlocker = clone(blockedFixture);
duplicateBlocker.blockers.push(clone(duplicateBlocker.blockers[0]));
assertCode(
  validateUnbound(duplicateBlocker),
  "INSTALL_PLAN_BLOCKER_ID_DUPLICATE",
  "duplicate blocker identifier",
);

const tooManyActions = clone(readyFixture);
tooManyActions.actions = Array.from({ length: 65 }, (_, index) => {
  const action = clone(readyFixture.actions[0]);
  action.action_id = `create-directory-${index}`;
  action.target.path = `.claude/skills/clawsec-suite-nanoclaw/path-${index}`;
  return action;
});
tooManyActions.rollback_order = tooManyActions.actions
  .map((action) => action.action_id)
  .reverse();
tooManyActions.result.effects = effectsForActions(tooManyActions.actions);
refreshDerivedState(tooManyActions);
assertCode(
  validateUnbound(tooManyActions),
  "INSTALL_PLAN_ARRAY_LIMIT_EXCEEDED",
  "plan exceeding the 64-action limit",
);

const nanoTargetEscape = clone(readyFixture);
nanoTargetEscape.actions[0].target = {
  anchor: "scope_root",
  path: ".claude/skills/other-package",
};
nanoTargetEscape.result.effects = effectsForActions(nanoTargetEscape.actions);
refreshDerivedState(nanoTargetEscape);
assertCode(
  validateBound(nanoTargetEscape, [coreNanoBytes, suiteNanoBytes]),
  "INSTALL_PLAN_PACKAGE_TARGET_INVALID",
  "NanoClaw action outside the metadata-declared package root",
);

const packageTargetEscape = clone(openclaw.document);
packageTargetEscape.actions[0].target.path = "another-package";
packageTargetEscape.result.effects = effectsForActions(
  packageTargetEscape.actions,
);
refreshDerivedState(packageTargetEscape);
assertCode(
  validateBound(
    packageTargetEscape,
    [openclaw.coreBytes, openclaw.suiteBytes],
  ),
  "INSTALL_PLAN_PACKAGE_TARGET_INVALID",
  "non-Nano action outside the exact component directory",
);

const packageRootOmitted = clone(readyFixture);
packageRootOmitted.actions = packageRootOmitted.actions.slice(1);
packageRootOmitted.artifact.install_tree_entry_count = 1;
packageRootOmitted.artifact.install_tree_total_bytes = 1_024;
packageRootOmitted.rollback_order = rollbackOrderForActions(
  packageRootOmitted.actions,
);
packageRootOmitted.result.effects = effectsForActions(
  packageRootOmitted.actions,
);
refreshDerivedState(packageRootOmitted);
assertCode(
  validateBound(packageRootOmitted, [coreNanoBytes, suiteNanoBytes]),
  "INSTALL_PLAN_PACKAGE_ROOT_DIRECTORY_REQUIRED",
  "package file without an explicit package-root directory",
);

const missingIntermediateDirectories = clone(readyFixture);
missingIntermediateDirectories.actions[1].target.path =
  ".claude/skills/clawsec-suite-nanoclaw/nested/deeper/SKILL.md";
missingIntermediateDirectories.actions[1].tree_entry.path =
  "nested/deeper/SKILL.md";
missingIntermediateDirectories.result.effects = effectsForActions(
  missingIntermediateDirectories.actions,
);
refreshDerivedState(missingIntermediateDirectories);
assertCode(
  validateBound(
    missingIntermediateDirectories,
    [coreNanoBytes, suiteNanoBytes],
  ),
  "INSTALL_PLAN_PACKAGE_INTERMEDIATE_DIRECTORY_REQUIRED",
  "package file without every intermediate directory action",
);

const childBeforeParent = clone(readyFixture);
childBeforeParent.actions.reverse();
childBeforeParent.rollback_order = rollbackOrderForActions(
  childBeforeParent.actions,
);
childBeforeParent.result.effects = effectsForActions(
  childBeforeParent.actions,
);
refreshDerivedState(childBeforeParent);
assertCode(
  validateBound(childBeforeParent, [coreNanoBytes, suiteNanoBytes]),
  "INSTALL_PLAN_PACKAGE_PARENT_ORDER_INVALID",
  "package child action ordered before its parent directory",
);

const nestedPackageTree = planWithNestedPackageTree(readyFixture);
assertValid(
  validateBound(nestedPackageTree, [coreNanoBytes, suiteNanoBytes]),
  "package tree with every parent directory ordered first",
);

const permutedFileTargets = planWithSecondFileEntry(readyFixture);
const firstPermutedFile = permutedFileTargets.actions.find(
  (action) => action.action_id === "write-skill-document",
);
const secondPermutedFile = permutedFileTargets.actions.find(
  (action) => action.action_id === "write-copy-skill-document",
);
[
  firstPermutedFile.target,
  secondPermutedFile.target,
] = [
  secondPermutedFile.target,
  firstPermutedFile.target,
];
permutedFileTargets.result.effects = effectsForActions(
  permutedFileTargets.actions,
);
refreshDerivedState(permutedFileTargets);
assertCode(
  validateBound(permutedFileTargets, [coreNanoBytes, suiteNanoBytes]),
  "INSTALL_PLAN_TREE_ENTRY_TARGET_MISMATCH",
  "two signed file entries permuted across each other's targets",
);

const emptyDirectorySubstitution = clone(nestedPackageTree);
const substitutedEmptyDirectory = emptyDirectorySubstitution.actions.find(
  (action) => action.action_id === "create-empty-directory",
);
substitutedEmptyDirectory.target.path =
  ".claude/skills/clawsec-suite-nanoclaw/substituted-empty";
emptyDirectorySubstitution.result.effects = effectsForActions(
  emptyDirectorySubstitution.actions,
);
refreshDerivedState(emptyDirectorySubstitution);
assertCode(
  validateBound(
    emptyDirectorySubstitution,
    [coreNanoBytes, suiteNanoBytes],
  ),
  "INSTALL_PLAN_TREE_ENTRY_TARGET_MISMATCH",
  "signed empty-directory entry substituted onto another target",
);

const rootModeMismatch = clone(readyFixture);
rootModeMismatch.actions[0].tree_entry.mode = "0700";
refreshDerivedState(rootModeMismatch);
assertCode(
  validateUnbound(rootModeMismatch),
  "INSTALL_PLAN_TREE_ENTRY_STATE_MISMATCH",
  "package-root directory mode differs from its signed tree entry",
);

const directoryModeMismatch = clone(nestedPackageTree);
directoryModeMismatch.actions.find(
  (action) => action.action_id === "create-empty-directory",
).tree_entry.mode = "0700";
refreshDerivedState(directoryModeMismatch);
assertCode(
  validateUnbound(directoryModeMismatch),
  "INSTALL_PLAN_TREE_ENTRY_STATE_MISMATCH",
  "nested directory mode differs from its signed tree entry",
);

for (const [label, treeEntryPath, expectedCode] of [
  [
    "install-tree entry containing parent traversal",
    "../SKILL.md",
    "INSTALL_PLAN_PATH_NOT_POSIX",
  ],
  [
    "install-tree entry using a Windows device basename",
    "CON/config.json",
    "INSTALL_PLAN_WINDOWS_DEVICE_PATH_FORBIDDEN",
  ],
  [
    "install-tree entry containing a trailing-dot segment",
    "docs./SKILL.md",
    "INSTALL_PLAN_PATH_TRAILING_DOT_FORBIDDEN",
  ],
]) {
  const unsafeTreeEntryPath = clone(readyFixture);
  unsafeTreeEntryPath.actions[1].tree_entry.path = treeEntryPath;
  assertCode(
    validateUnbound(unsafeTreeEntryPath),
    expectedCode,
    label,
  );
}

const caseFoldedTreeEntryDuplicate = planWithSecondFileEntry(readyFixture);
const caseFoldedCopy = caseFoldedTreeEntryDuplicate.actions.find(
  (action) => action.action_id === "write-copy-skill-document",
);
caseFoldedCopy.target.path =
  ".claude/skills/clawsec-suite-nanoclaw/skill.md";
caseFoldedCopy.tree_entry.path = "skill.md";
caseFoldedTreeEntryDuplicate.result.effects = effectsForActions(
  caseFoldedTreeEntryDuplicate.actions,
);
refreshDerivedState(caseFoldedTreeEntryDuplicate);
assertCode(
  validateUnbound(caseFoldedTreeEntryDuplicate),
  "INSTALL_PLAN_TREE_ENTRY_PATH_DUPLICATE",
  "two install-tree paths that differ only by case",
);

const ambiguousManifestEntry = planWithSecondFileEntry(readyFixture);
ambiguousManifestEntry.actions.find(
  (action) => action.action_id === "write-copy-skill-document",
).tree_entry.manifest_entry_digest =
  readyFixture.actions[1].tree_entry.manifest_entry_digest;
refreshDerivedState(ambiguousManifestEntry);
assertCode(
  validateUnbound(ambiguousManifestEntry),
  "INSTALL_PLAN_MANIFEST_ENTRY_DIGEST_AMBIGUOUS",
  "one manifest-entry digest describing two distinct tree entries",
);

const emptyDirectoryOmitted = clone(nestedPackageTree);
emptyDirectoryOmitted.actions = emptyDirectoryOmitted.actions.filter(
  (action) => action.action_id !== "create-empty-directory",
);
emptyDirectoryOmitted.rollback_order = rollbackOrderForActions(
  emptyDirectoryOmitted.actions,
);
emptyDirectoryOmitted.result.effects = effectsForActions(
  emptyDirectoryOmitted.actions,
);
refreshDerivedState(emptyDirectoryOmitted);
assertCode(
  validateUnbound(emptyDirectoryOmitted),
  "INSTALL_PLAN_READY_TREE_ENTRY_COVERAGE_MISMATCH",
  "signed empty-directory tree entry omitted from managed actions",
);

const artifactActionOmitted = clone(readyFixture);
artifactActionOmitted.actions = artifactActionOmitted.actions.slice(0, 1);
artifactActionOmitted.rollback_order = rollbackOrderForActions(
  artifactActionOmitted.actions,
);
artifactActionOmitted.result.effects = effectsForActions(
  artifactActionOmitted.actions,
);
refreshDerivedState(artifactActionOmitted);
const artifactActionOmittedResult = validateUnbound(artifactActionOmitted);
assertCode(
  artifactActionOmittedResult,
  "INSTALL_PLAN_READY_TREE_ENTRY_COVERAGE_MISMATCH",
  "artifact tree entry omitted from the action set",
);
assertCode(
  artifactActionOmittedResult,
  "INSTALL_PLAN_READY_TREE_BYTE_COVERAGE_MISMATCH",
  "artifact file bytes omitted from the action set",
);

const removedPackageActivation = planWithRemovedPackageActivation(
  readyFixture,
);
assertCode(
  validateUnbound(removedPackageActivation),
  "INSTALL_PLAN_NATIVE_PACKAGE_ACTIVATION_UNSUPPORTED",
  "removed native package activation operation",
);

for (const operation of ["reload_harness", "restart_harness"]) {
  const operationalPlan = planWithOperationalAction(readyFixture, operation);
  const operationalAction = operationalPlan.actions.find(
    (action) => action.operation === operation,
  );
  assert.equal(
    operationalAction.rollback,
    null,
    `${operation} must carry no rollback operation`,
  );
  assert(
    !operationalPlan.rollback_order.includes(operationalAction.action_id),
    `${operation} must be excluded from rollback order`,
  );
  assertValid(
    validateBound(operationalPlan, [coreNanoBytes, suiteNanoBytes]),
    `${operation} non-state-mutating plan`,
  );

  const operationalActionBeforeMutations = clone(operationalPlan);
  operationalActionBeforeMutations.actions = [
    operationalActionBeforeMutations.actions.at(-1),
    ...operationalActionBeforeMutations.actions.slice(0, -1),
  ];
  operationalActionBeforeMutations.result.effects = effectsForActions(
    operationalActionBeforeMutations.actions,
  );
  refreshDerivedState(operationalActionBeforeMutations);
  assertCode(
    validateUnbound(operationalActionBeforeMutations),
    "INSTALL_PLAN_OPERATIONAL_ACTION_ORDER_INVALID",
    `${operation} before package mutations`,
  );

  const operationalActionInRollback = clone(operationalPlan);
  operationalActionInRollback.rollback_order.unshift(
    operationalAction.action_id,
  );
  assertCode(
    validateUnbound(operationalActionInRollback),
    "INSTALL_PLAN_ROLLBACK_ORDER_MISMATCH",
    `${operation} included in rollback order`,
  );
}

const reloadOnlyReady = planWithOperationalAction(
  readyFixture,
  "reload_harness",
);
reloadOnlyReady.actions = reloadOnlyReady.actions.filter(
  (action) => action.operation === "reload_harness",
);
reloadOnlyReady.rollback_order = [];
reloadOnlyReady.result.effects = effectsForActions(reloadOnlyReady.actions);
refreshDerivedState(reloadOnlyReady);
assertCode(
  validateUnbound(reloadOnlyReady),
  "INSTALL_PLAN_SUBJECT_PACKAGE_ACTION_REQUIRED",
  "reload-only ready plan",
);

const missingRequiredReload = clone(readyFixture);
missingRequiredReload.adapter.profile.reload_behavior = "reload_harness";
assertCode(
  validateUnbound(missingRequiredReload),
  "INSTALL_PLAN_RELOAD_ACTION_MISMATCH",
  "adapter-required reload omitted from the disclosed actions",
);

const unexpectedReload = planWithOperationalAction(
  readyFixture,
  "reload_harness",
);
unexpectedReload.adapter.profile.reload_behavior = "none";
assertCode(
  validateUnbound(unexpectedReload),
  "INSTALL_PLAN_RELOAD_ACTION_MISMATCH",
  "reload action forbidden by adapter profile",
);

const substitutedNativeInstance = planWithOperationalAction(
  readyFixture,
  "reload_harness",
);
substitutedNativeInstance.actions.find(
  (action) => action.operation === "reload_harness",
).target.identity_digest = `sha256:${"0".repeat(64)}`;
substitutedNativeInstance.result.effects = effectsForActions(
  substitutedNativeInstance.actions,
);
refreshDerivedState(substitutedNativeInstance);
assertCode(
  validateUnbound(substitutedNativeInstance),
  "INSTALL_PLAN_HARNESS_RESOURCE_IDENTITY_MISMATCH",
  "native harness target-instance identity substitution",
);

const transformationPlan = planWithNanoTransformation(readyFixture);
assertValid(
  validateBound(transformationPlan, [coreNanoBytes, suiteNanoBytes]),
  "NanoClaw declared transformation plan",
);
assert.equal(
  transformationPlan.actions.filter(
    (action) => action.kind === "managed_entry",
  ).length,
  transformationPlan.artifact.install_tree_entry_count,
  "transformation source must be counted once as its managed tree entry",
);
assert.equal(
  transformationPlan.actions.filter(
    (action) => action.kind === "declared_transformation",
  ).length,
  1,
  "transformation output is not a second staged install-tree entry",
);

const transformationFirst = clone(transformationPlan);
const transformationFirstIndex = transformationFirst.actions.findIndex(
  (action) => action.kind === "declared_transformation",
);
const [earlyTransformation] = transformationFirst.actions.splice(
  transformationFirstIndex,
  1,
);
transformationFirst.actions.unshift(earlyTransformation);
transformationFirst.rollback_order = rollbackOrderForActions(
  transformationFirst.actions,
);
transformationFirst.result.effects = effectsForActions(
  transformationFirst.actions,
);
refreshDerivedState(transformationFirst);
assertCode(
  validateUnbound(transformationFirst),
  "INSTALL_PLAN_PACKAGE_ACTION_ORDER_INVALID",
  "declared transformation before managed package actions",
);

const transformationSourceMissing = clone(transformationPlan);
declaredTransformationFor(transformationSourceMissing)
  .declaration.source.managed_action_id = "missing-source-action";
refreshDerivedState(transformationSourceMissing);
assertCode(
  validateUnbound(transformationSourceMissing),
  "INSTALL_PLAN_TRANSFORMATION_SOURCE_NOT_MANAGED",
  "transformation source referencing a missing managed action",
);

const transformationSourceWrongDigest = clone(transformationPlan);
declaredTransformationFor(transformationSourceWrongDigest)
  .declaration.source.manifest_entry_digest =
    `sha256:${"0".repeat(64)}`;
refreshDerivedState(transformationSourceWrongDigest);
assertCode(
  validateUnbound(transformationSourceWrongDigest),
  "INSTALL_PLAN_TRANSFORMATION_SOURCE_NOT_MANAGED",
  "transformation source using the wrong managed manifest-entry digest",
);

const transformationSourceDirectory = clone(transformationPlan);
const rootDirectoryAction = transformationSourceDirectory.actions.find(
  (action) => action.tree_entry?.path === ".",
);
declaredTransformationFor(transformationSourceDirectory)
  .declaration.source = {
    managed_action_id: rootDirectoryAction.action_id,
    manifest_entry_digest:
      rootDirectoryAction.tree_entry.manifest_entry_digest,
  };
refreshDerivedState(transformationSourceDirectory);
assertCode(
  validateUnbound(transformationSourceDirectory),
  "INSTALL_PLAN_TRANSFORMATION_SOURCE_NOT_MANAGED",
  "transformation source referencing a managed directory",
);

const transformationSourceLater = clone(transformationPlan);
const laterSourceId = declaredTransformationFor(
  transformationSourceLater,
).declaration.source.managed_action_id;
const laterSourceIndex = transformationSourceLater.actions.findIndex(
  (action) => action.action_id === laterSourceId,
);
const [laterSourceAction] = transformationSourceLater.actions.splice(
  laterSourceIndex,
  1,
);
transformationSourceLater.actions.push(laterSourceAction);
transformationSourceLater.rollback_order = rollbackOrderForActions(
  transformationSourceLater.actions,
);
transformationSourceLater.result.effects = effectsForActions(
  transformationSourceLater.actions,
);
refreshDerivedState(transformationSourceLater);
assertCode(
  validateUnbound(transformationSourceLater),
  "INSTALL_PLAN_TRANSFORMATION_SOURCE_NOT_MANAGED",
  "transformation source action disclosed only after the transformation",
);

const duplicatedTransformationEntry = clone(transformationPlan);
const secondTransformation = clone(
  declaredTransformationFor(duplicatedTransformationEntry),
);
secondTransformation.action_id = "transform-generated-config-second";
secondTransformation.target.path =
  "container/agent-runner/generated-config-second.json";
secondTransformation.after.digest = `sha256:${"4".repeat(64)}`;
secondTransformation.declaration.allowed_output = {
  target: clone(secondTransformation.target),
  before: clone(secondTransformation.before),
  after: clone(secondTransformation.after),
};
duplicatedTransformationEntry.actions.push(secondTransformation);
duplicatedTransformationEntry.rollback_order = rollbackOrderForActions(
  duplicatedTransformationEntry.actions,
);
duplicatedTransformationEntry.result.effects = effectsForActions(
  duplicatedTransformationEntry.actions,
);
refreshDerivedState(duplicatedTransformationEntry);
assertCode(
  validateUnbound(duplicatedTransformationEntry),
  "INSTALL_PLAN_TRANSFORMATION_ENTRY_DIGEST_DUPLICATE",
  "two transformations reusing one release-manifest entry digest",
);

const nanoSkillTreeCaseAlias = clone(transformationPlan);
const nanoCaseAliasTransformation = declaredTransformationFor(
  nanoSkillTreeCaseAlias,
);
nanoCaseAliasTransformation.target.path =
  ".CLAUDE/skills/unreviewed/generated-config.json";
nanoCaseAliasTransformation.declaration.allowed_output.target =
  clone(nanoCaseAliasTransformation.target);
nanoSkillTreeCaseAlias.result.effects = effectsForActions(
  nanoSkillTreeCaseAlias.actions,
);
refreshDerivedState(nanoSkillTreeCaseAlias);
assertCode(
  validateUnbound(nanoSkillTreeCaseAlias),
  "INSTALL_PLAN_NANOCLAW_TRANSFORMATION_PACKAGE_TREE_FORBIDDEN",
  "case-aliased NanoClaw skill-tree transformation target",
);

const transformationTargetEscape = clone(transformationPlan);
const escapedTransformation = declaredTransformationFor(
  transformationTargetEscape,
);
escapedTransformation.target.path =
  ".claude/skills/unreviewed-package/generated-config.json";
escapedTransformation.declaration.allowed_output.target =
  clone(escapedTransformation.target);
transformationTargetEscape.result.effects = effectsForActions(
  transformationTargetEscape.actions,
);
refreshDerivedState(transformationTargetEscape);
assertCode(
  validateBound(
    transformationTargetEscape,
    [coreNanoBytes, suiteNanoBytes],
  ),
  "INSTALL_PLAN_NANOCLAW_TRANSFORMATION_PACKAGE_TREE_FORBIDDEN",
  "declared transformation reaching into the selected skill tree",
);

for (const [label, forbiddenPath] of [
  ["Git metadata", ".git/config"],
  ["environment file", ".env"],
  ["live database", "runtime/sessions.sqlite"],
  [
    "container skill tree",
    "container/skills/unreviewed/SKILL.md",
  ],
  ["credential file", "credentials.json"],
  ["secret file", "secrets.yaml"],
  ["token file", "token.txt"],
  ["private key", "id_ed25519.pub"],
]) {
  const forbiddenTransformation = clone(transformationPlan);
  const forbiddenAction = declaredTransformationFor(
    forbiddenTransformation,
  );
  forbiddenAction.target = {
    anchor: "scope_root",
    path: forbiddenPath,
  };
  forbiddenAction.declaration.allowed_output.target =
    clone(forbiddenAction.target);
  forbiddenTransformation.result.effects = effectsForActions(
    forbiddenTransformation.actions,
  );
  refreshDerivedState(forbiddenTransformation);
  assertCode(
    validateUnbound(forbiddenTransformation),
    "INSTALL_PLAN_NANOCLAW_TRANSFORMATION_PATH_FORBIDDEN",
    `NanoClaw transformation targeting ${label}`,
  );
}

const ordinaryCredentialNamedSource = clone(transformationPlan);
const ordinaryCredentialAction = declaredTransformationFor(
  ordinaryCredentialNamedSource,
);
ordinaryCredentialAction.target.path =
  "src/credentials.ts";
ordinaryCredentialAction.declaration.allowed_output.target =
  clone(ordinaryCredentialAction.target);
ordinaryCredentialNamedSource.result.effects = effectsForActions(
  ordinaryCredentialNamedSource.actions,
);
refreshDerivedState(ordinaryCredentialNamedSource);
assertValid(
  validateBound(
    ordinaryCredentialNamedSource,
    [coreNanoBytes, suiteNanoBytes],
  ),
  "reviewed ordinary source module named credentials.ts",
);

const nonScopeManagedTarget = clone(readyFixture);
nonScopeManagedTarget.actions[1].target.anchor = "skill_root";
assertCode(
  validateUnbound(nonScopeManagedTarget),
  "INSTALL_PLAN_FILESYSTEM_ANCHOR_INVALID",
  "managed action using a non-scope root",
);

const nonScopeTransformationTarget = clone(transformationPlan);
const nonScopeTransformationAction = declaredTransformationFor(
  nonScopeTransformationTarget,
);
nonScopeTransformationAction.target.anchor = "harness_runtime_root";
nonScopeTransformationAction.declaration.allowed_output.target.anchor =
  "harness_runtime_root";
assertCode(
  validateUnbound(nonScopeTransformationTarget),
  "INSTALL_PLAN_FILESYSTEM_ANCHOR_INVALID",
  "declared transformation using a non-scope root",
);

const transformationDeclarationMismatch = clone(transformationPlan);
declaredTransformationFor(transformationDeclarationMismatch)
  .declaration.allowed_output.after.digest = `sha256:${"0".repeat(64)}`;
assertCode(
  validateUnbound(transformationDeclarationMismatch),
  "INSTALL_PLAN_TRANSFORMATION_DECLARATION_MISMATCH",
  "transformation output that differs from its exact declaration",
);

const transformationReleaseManifestMismatch = clone(transformationPlan);
declaredTransformationFor(transformationReleaseManifestMismatch)
  .declaration.release_manifest_digest =
  `sha256:${"0".repeat(64)}`;
assertCode(
  validateUnbound(transformationReleaseManifestMismatch),
  "INSTALL_PLAN_TRANSFORMATION_RELEASE_MANIFEST_MISMATCH",
  "transformation bound to a different release manifest",
);

const transformationEntryMismatch = clone(transformationPlan);
declaredTransformationFor(transformationEntryMismatch)
  .declaration.transformation_entry_digest =
    `sha256:${"0".repeat(64)}`;
assertCode(
  validateUnbound(transformationEntryMismatch),
  "INSTALL_PLAN_DERIVED_STATE_MISMATCH",
  "post-plan transformation-entry digest tampering",
);

const structurallyUniqueTransformationEntry = clone(transformationPlan);
declaredTransformationFor(structurallyUniqueTransformationEntry)
  .declaration.transformation_entry_digest =
    `sha256:${"0".repeat(64)}`;
refreshDerivedState(structurallyUniqueTransformationEntry);
assertValid(
  validateUnbound(structurallyUniqueTransformationEntry),
  "a unique transformation-entry digest is structurally valid while release-manifest membership remains unverified",
);

const transformationWithoutPreimage = clone(transformationPlan);
declaredTransformationFor(transformationWithoutPreimage).rollback_source =
  null;
assertCode(
  validateUnbound(transformationWithoutPreimage),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "declared transformation without captured preimage",
);

const transformationPreimageMismatch = clone(transformationPlan);
declaredTransformationFor(transformationPreimageMismatch)
  .rollback_source.digest =
  `sha256:${"0".repeat(64)}`;
assertCode(
  validateUnbound(transformationPreimageMismatch),
  "INSTALL_PLAN_ROLLBACK_SOURCE_MISMATCH",
  "declared transformation with mismatched captured preimage",
);

const transformationWithoutCodingHarness = clone(transformationPlan);
transformationWithoutCodingHarness.adapter.profile.coding_harness = null;
assertCode(
  validateUnbound(transformationWithoutCodingHarness),
  "INSTALL_PLAN_NANOCLAW_CODING_HARNESS_REQUIRED",
  "NanoClaw transformation without an adapter-bound coding harness",
);

for (const mutableReference of [
  { kind: "exact_version", value: "latest" },
  { kind: "commit", value: "main" },
  { kind: "exact_version", value: "stable" },
]) {
  const mutableCodingHarness = clone(transformationPlan);
  mutableCodingHarness.adapter.profile.coding_harness.immutable_reference =
    clone(mutableReference);
  declaredTransformationFor(mutableCodingHarness)
    .declaration.coding_harness.immutable_reference =
      clone(mutableReference);
  assertCode(
    validateUnbound(mutableCodingHarness),
    "INSTALL_PLAN_CODING_HARNESS_REFERENCE_NOT_IMMUTABLE",
    `mutable coding-harness reference ${mutableReference.value}`,
  );
}

for (const immutableReference of [
  {
    kind: "commit",
    value: "a".repeat(40),
  },
  {
    kind: "content_digest",
    value:
      transformationPlan.adapter.profile.coding_harness
        .implementation_digest,
  },
]) {
  const immutableCodingHarness = clone(transformationPlan);
  immutableCodingHarness.adapter.profile.coding_harness
    .immutable_reference = clone(immutableReference);
  declaredTransformationFor(immutableCodingHarness)
    .declaration.coding_harness.immutable_reference =
      clone(immutableReference);
  refreshDerivedState(immutableCodingHarness);
  assertValid(
    validateUnbound(immutableCodingHarness),
    `coding harness pinned by immutable ${immutableReference.kind}`,
  );
}

for (
  const digestField of [
    "implementation_digest",
    "toolchain_digest",
    "configuration_digest",
  ]
) {
  const codingHarnessWithoutDigest = clone(transformationPlan);
  delete codingHarnessWithoutDigest.adapter.profile
    .coding_harness[digestField];
  delete declaredTransformationFor(codingHarnessWithoutDigest)
    .declaration.coding_harness[digestField];
  assertCode(
    validateUnbound(codingHarnessWithoutDigest),
    "INSTALL_PLAN_CODING_HARNESS_DIGEST_REQUIRED",
    `coding harness without ${digestField}`,
  );
}

const transformationCodingHarnessMismatch = clone(transformationPlan);
declaredTransformationFor(transformationCodingHarnessMismatch)
  .declaration.coding_harness
  .configuration_digest = `sha256:${"0".repeat(64)}`;
refreshDerivedState(transformationCodingHarnessMismatch);
assertCode(
  validateUnbound(transformationCodingHarnessMismatch),
  "INSTALL_PLAN_NANOCLAW_CODING_HARNESS_MISMATCH",
  "transformation coding harness that differs from its adapter binding",
);

const codingHarnessContentIdentityMismatch = clone(transformationPlan);
const mismatchedContentReference = {
  kind: "content_digest",
  value: `sha256:${"0".repeat(64)}`,
};
codingHarnessContentIdentityMismatch.adapter.profile.coding_harness
  .immutable_reference = clone(mismatchedContentReference);
declaredTransformationFor(codingHarnessContentIdentityMismatch)
  .declaration.coding_harness
  .immutable_reference = clone(mismatchedContentReference);
refreshDerivedState(codingHarnessContentIdentityMismatch);
assertCode(
  validateUnbound(codingHarnessContentIdentityMismatch),
  "INSTALL_PLAN_CODING_HARNESS_CONTENT_IDENTITY_MISMATCH",
  "content-addressed coding harness whose reference differs from its implementation",
);

for (const requiredStep of ["host_build", "host_tests", "skill_tests"]) {
  const nanoWithoutBaselineValidation = clone(readyFixture);
  nanoWithoutBaselineValidation.adapter.profile.validation_steps =
    nanoWithoutBaselineValidation.adapter.profile.validation_steps
      .filter((step) => step !== requiredStep);
  assertCode(
    validateUnbound(nanoWithoutBaselineValidation),
    "INSTALL_PLAN_NANOCLAW_VALIDATION_STEP_REQUIRED",
    `NanoClaw v2 plan without ${requiredStep}`,
  );
}

for (
  const requiredStep of [
    "container_build",
    "container_typecheck",
    "container_tests",
  ]
) {
  const transformationWithoutRequiredValidation = clone(transformationPlan);
  transformationWithoutRequiredValidation.adapter.profile.validation_steps =
    transformationWithoutRequiredValidation.adapter.profile.validation_steps
      .filter((step) => step !== requiredStep);
  assertCode(
    validateUnbound(transformationWithoutRequiredValidation),
    "INSTALL_PLAN_NANOCLAW_VALIDATION_STEP_REQUIRED",
    `agent-runner transformation without ${requiredStep}`,
  );
}

const genericContainerTransformation = clone(transformationPlan);
const genericContainerAction = declaredTransformationFor(
  genericContainerTransformation,
);
genericContainerAction.target.path =
  "container/generated-config.json";
genericContainerAction.declaration.allowed_output.target =
  clone(genericContainerAction.target);
genericContainerTransformation.adapter.profile.validation_steps =
  genericContainerTransformation.adapter.profile.validation_steps.filter(
    (step) => !["container_typecheck", "container_tests"].includes(step),
  );
genericContainerTransformation.result.effects = effectsForActions(
  genericContainerTransformation.actions,
);
refreshDerivedState(genericContainerTransformation);
assertValid(
  validateBound(
    genericContainerTransformation,
    [coreNanoBytes, suiteNanoBytes],
  ),
  "generic container transformation with build validation",
);

const genericContainerWithoutBuild = clone(genericContainerTransformation);
genericContainerWithoutBuild.adapter.profile.validation_steps =
  genericContainerWithoutBuild.adapter.profile.validation_steps.filter(
    (step) => step !== "container_build",
  );
assertCode(
  validateUnbound(genericContainerWithoutBuild),
  "INSTALL_PLAN_NANOCLAW_VALIDATION_STEP_REQUIRED",
  "generic container transformation without container_build",
);

const nonNanoExternalTransformation = clone(openclaw.document);
const nonNanoTransformation = clone(
  declaredTransformationFor(transformationPlan),
);
const nonNanoSourceAction = nonNanoExternalTransformation.actions.find(
  (action) => action.tree_entry?.kind === "file",
);
nonNanoTransformation.declaration.source = {
  managed_action_id: nonNanoSourceAction.action_id,
  manifest_entry_digest:
    nonNanoSourceAction.tree_entry.manifest_entry_digest,
};
nonNanoExternalTransformation.actions.push(nonNanoTransformation);
nonNanoTransformation.declaration.release_manifest_digest =
    nonNanoExternalTransformation.artifact.release_manifest_digest;
nonNanoExternalTransformation.rollback_order = rollbackOrderForActions(
  nonNanoExternalTransformation.actions,
);
nonNanoExternalTransformation.result.effects = effectsForActions(
  nonNanoExternalTransformation.actions,
);
refreshDerivedState(nonNanoExternalTransformation);
assertCode(
  validateBound(
    nonNanoExternalTransformation,
    [openclaw.coreBytes, openclaw.suiteBytes],
  ),
  "INSTALL_PLAN_ADAPTER_TRANSFORMATION_FORBIDDEN",
  "external transformation on a non-NanoClaw adapter",
);

const nanoCorePlan = planForNanoCore(readyFixture, coreNanoBytes);
assertValid(
  validateBound(nanoCorePlan, [coreNanoBytes]),
  "NanoClaw core plan with required REMOVE.md",
);
const nanoCoreWithoutRemoveDocument = clone(nanoCorePlan);
nanoCoreWithoutRemoveDocument.actions = nanoCoreWithoutRemoveDocument.actions
  .filter((action) => action.action_id !== "write-remove-document");
nanoCoreWithoutRemoveDocument.artifact.install_tree_entry_count = 2;
nanoCoreWithoutRemoveDocument.artifact.install_tree_total_bytes = 1_024;
nanoCoreWithoutRemoveDocument.rollback_order = nanoCoreWithoutRemoveDocument
  .actions.map((action) => action.action_id).reverse();
nanoCoreWithoutRemoveDocument.result.effects = effectsForActions(
  nanoCoreWithoutRemoveDocument.actions,
);
refreshDerivedState(nanoCoreWithoutRemoveDocument);
assertCode(
  validateBound(nanoCoreWithoutRemoveDocument, [coreNanoBytes]),
  "INSTALL_PLAN_NANOCLAW_REMOVE_DOCUMENT_REQUIRED",
  "NanoClaw package that omits its metadata-required REMOVE.md",
);

const rawCommand = clone(readyFixture);
rawCommand.actions[0].command = "cp staged target";
assertCode(
  validateUnbound(rawCommand),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "raw command field",
);

const nonPosixPlan = clone(readyFixture);
nonPosixPlan.path_flavor = "windows";
assertCode(
  validateUnbound(nonPosixPlan),
  "INSTALL_PLAN_PATH_FLAVOR_INVALID",
  "non-POSIX install plan",
);

for (const [label, unsafePath] of [
  ["absolute path", "/tmp/clawsec"],
  ["parent traversal", "../clawsec"],
]) {
  const unsafePlan = clone(readyFixture);
  unsafePlan.actions[0].target.path = unsafePath;
  assertCode(
    validateUnbound(unsafePlan),
    "INSTALL_PLAN_PATH_NOT_POSIX",
    label,
  );
}

for (const [label, unsafePath, code] of [
  [
    "POSIX trailing-dot segment",
    ".claude/skills/clawsec-suite-nanoclaw/SKILL.",
    "INSTALL_PLAN_PATH_TRAILING_DOT_FORBIDDEN",
  ],
  [
    "Windows device basename",
    ".claude/skills/clawsec-suite-nanoclaw/NUL.txt",
    "INSTALL_PLAN_WINDOWS_DEVICE_PATH_FORBIDDEN",
  ],
  [
    "non-POSIX separator",
    ".claude\\skills\\clawsec-suite-nanoclaw\\SKILL.md",
    "INSTALL_PLAN_PATH_NOT_POSIX",
  ],
]) {
  const nonPortablePath = clone(readyFixture);
  nonPortablePath.actions[1].target.path = unsafePath;
  assertCode(
    validateUnbound(nonPortablePath),
    code,
    label,
  );
}

const symlinkState = clone(readyFixture);
symlinkState.actions[0].after = {
  kind: "symlink",
  target: "SKILL.md",
};
assertCode(
  validateUnbound(symlinkState),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "symlink post-state",
);

const embeddedConfirmation = clone(readyFixture);
embeddedConfirmation.confirmation_requirements.confirmed = true;
assertCode(
  validateUnbound(embeddedConfirmation),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "embedded confirmed field",
);

const effectOmission = clone(readyFixture);
effectOmission.result.effects.pop();
assertCode(
  validateUnbound(effectOmission),
  "INSTALL_PLAN_EFFECT_ACTION_MISMATCH",
  "result effects that omit an action",
);

const stateBindingSubstitution = clone(readyFixture);
stateBindingSubstitution.target_state.action_set_digest =
  `sha256:${"0".repeat(64)}`;
assertCode(
  validateUnbound(stateBindingSubstitution),
  "INSTALL_PLAN_DERIVED_STATE_MISMATCH",
  "action-set state substitution",
);

const caseFoldCollision = clone(readyFixture);
const collidingAction = clone(caseFoldCollision.actions[1]);
collidingAction.action_id = "write-case-colliding-skill-document";
collidingAction.target.path =
  ".claude/skills/clawsec-suite-nanoclaw/skill.md";
collidingAction.tree_entry.path = "skill.md";
collidingAction.tree_entry.manifest_entry_digest =
  `sha256:${"3".repeat(64)}`;
caseFoldCollision.actions.push(collidingAction);
caseFoldCollision.artifact.install_tree_entry_count = 3;
caseFoldCollision.artifact.install_tree_total_bytes = 2_048;
caseFoldCollision.rollback_order =
  caseFoldCollision.actions.map((action) => action.action_id).reverse();
caseFoldCollision.result.effects = effectsForActions(caseFoldCollision.actions);
refreshDerivedState(caseFoldCollision);
assertCode(
  validateUnbound(caseFoldCollision),
  "INSTALL_PLAN_PATH_CASE_COLLISION",
  "case-folding filesystem collision",
);

const fileDescendantCollision = clone(readyFixture);
const fileDescendant = clone(fileDescendantCollision.actions[1]);
fileDescendant.action_id = "write-file-descendant";
fileDescendant.target.path =
  ".claude/skills/clawsec-suite-nanoclaw/SKILL.md/child.txt";
fileDescendant.tree_entry.path = "SKILL.md/child.txt";
fileDescendant.tree_entry.manifest_entry_digest =
  `sha256:${"b".repeat(64)}`;
fileDescendantCollision.actions.push(fileDescendant);
fileDescendantCollision.artifact.install_tree_entry_count = 3;
fileDescendantCollision.artifact.install_tree_total_bytes = 2_048;
fileDescendantCollision.rollback_order = rollbackOrderForActions(
  fileDescendantCollision.actions,
);
fileDescendantCollision.result.effects = effectsForActions(
  fileDescendantCollision.actions,
);
refreshDerivedState(fileDescendantCollision);
assertCode(
  validateUnbound(fileDescendantCollision),
  "INSTALL_PLAN_PATH_ANCESTOR_CONFLICT",
  "file target with a planned descendant",
);

const managedRemoval = clone(readyFixture);
managedRemoval.actions[1].operation = "remove";
managedRemoval.actions[1].after = {
  kind: "absent",
};
assertCode(
  validateUnbound(managedRemoval),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "fresh-install plan carrying a managed removal",
);

const secondFileEntry = planWithSecondFileEntry(readyFixture);
assertValid(
  validateBound(secondFileEntry, [coreNanoBytes, suiteNanoBytes]),
  "two exact managed file entries with distinct tree identities",
);

const unsafeMode = clone(readyFixture);
unsafeMode.actions[1].after.mode = "0777";
unsafeMode.actions[1].tree_entry.mode = "0777";
refreshDerivedState(unsafeMode);
assertCode(
  validateUnbound(unsafeMode),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "world-writable installed file",
);

const expiredCandidateManifest = clone(readyFixture);
expiredCandidateManifest.artifact.authority.expires_at =
  expiredCandidateManifest.result.reported_at;
assertCode(
  validateBound(expiredCandidateManifest, [coreNanoBytes, suiteNanoBytes]),
  "INSTALL_PLAN_AUTHORITY_EXPIRES_BEFORE_PLAN",
  "private candidate authority shorter than the plan lifetime",
);

const mismatchedPublicAuthority = clone(readyFixture);
mismatchedPublicAuthority.artifact.channel = "public_stable";
assertCode(
  validateUnbound(mismatchedPublicAuthority),
  "INSTALL_PLAN_ARTIFACT_AUTHORITY_MISMATCH",
  "public channel carrying private-candidate authority",
);

const embeddedCandidateLifecycle = clone(readyFixture);
embeddedCandidateLifecycle.artifact.authority.candidate_id =
  "11111111-1111-4111-8111-111111111111";
assertCode(
  validateUnbound(embeddedCandidateLifecycle),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "authority reference carrying embedded candidate lifecycle state",
);

const stagedInputHandle = clone(readyFixture);
stagedInputHandle.staged_input.ref =
  "nano-lab-01:stage:44444444";
assertCode(
  validateUnbound(stagedInputHandle),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "staged input carrying a live mutable handle",
);

const stagedInputWithoutSnapshot = clone(readyFixture);
delete stagedInputWithoutSnapshot.staged_input.snapshot_digest;
assertCode(
  validateUnbound(stagedInputWithoutSnapshot),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "staged input without an immutable snapshot digest",
);

const conflictedNanoCheckout = clone(readyFixture);
conflictedNanoCheckout.adapter.profile.checkout_status = "conflicted";
assertCode(
  validateUnbound(conflictedNanoCheckout),
  "INSTALL_PLAN_NANOCLAW_CHECKOUT_CONFLICTED",
  "NanoClaw v2 conflicted checkout",
);

const nanoWithoutPostimageValidation = clone(readyFixture);
nanoWithoutPostimageValidation.adapter.profile.validation_steps = [
  "host_tests",
];
assertCode(
  validateUnbound(nanoWithoutPostimageValidation),
  "INSTALL_PLAN_SCHEMA_INVALID",
  "NanoClaw v2 plan without postimage-manifest validation",
);

for (const [label, mutate] of [
  [
    "archive exceeding the byte limit",
    (document) => {
      document.artifact.archive_byte_length = 134_217_729;
    },
  ],
  [
    "install tree exceeding the entry limit",
    (document) => {
      document.artifact.install_tree_entry_count = 4_097;
    },
  ],
  [
    "install tree exceeding the byte limit",
    (document) => {
      document.artifact.install_tree_total_bytes = 268_435_457;
    },
  ],
  [
    "installed file exceeding the byte limit",
    (document) => {
      document.actions[1].after.byte_length = 67_108_865;
      document.actions[1].tree_entry.byte_length = 67_108_865;
      refreshDerivedState(document);
    },
  ],
]) {
  const overLimit = clone(readyFixture);
  mutate(overLimit);
  assertCode(
    validateUnbound(overLimit),
    "INSTALL_PLAN_SCHEMA_INVALID",
    label,
  );
}

const excessiveExpansion = clone(readyFixture);
excessiveExpansion.artifact.archive_byte_length = 10;
assertCode(
  validateUnbound(excessiveExpansion),
  "INSTALL_PLAN_ARCHIVE_EXPANSION_RATIO_EXCEEDED",
  "archive expansion exceeding 100 times compressed size",
);

const excessivePlannedOutput = planWithExcessiveOutput(transformationPlan);
assertCode(
  validateUnbound(excessivePlannedOutput),
  "INSTALL_PLAN_OUTPUT_BYTES_LIMIT_EXCEEDED",
  "combined transformation output exceeding the planned postimage limit",
);

const excessiveCapturedPreimages =
  planWithExcessiveCapturedPreimages(transformationPlan);
assertCode(
  validateUnbound(excessiveCapturedPreimages),
  "INSTALL_PLAN_CAPTURED_PREIMAGE_BYTES_LIMIT_EXCEEDED",
  "combined captured preimages exceeding the rollback byte limit",
);

const repeatedCapturedPreimageWork =
  planWithRepeatedCapturedPreimageWork(transformationPlan);
assertCode(
  validateUnbound(repeatedCapturedPreimageWork),
  "INSTALL_PLAN_CAPTURED_PREIMAGE_BYTES_LIMIT_EXCEEDED",
  "five distinct transformation targets reusing one content digest still count as five rollback captures",
);

const ambiguousCapturedPreimage =
  planWithAmbiguousCapturedPreimage(transformationPlan);
assertCode(
  validateUnbound(ambiguousCapturedPreimage),
  "INSTALL_PLAN_CAPTURED_PREIMAGE_AMBIGUOUS",
  "one preimage digest carrying contradictory captured metadata",
);

const underreportedTreeEntryCount = planWithSecondFileEntry(readyFixture);
underreportedTreeEntryCount.artifact.install_tree_entry_count = 2;
assertCode(
  validateUnbound(underreportedTreeEntryCount),
  "INSTALL_PLAN_ARTIFACT_TREE_ENTRY_COUNT_EXCEEDED",
  "managed tree-entry count exceeding the artifact declaration",
);

const underreportedTreeBytes = clone(readyFixture);
underreportedTreeBytes.artifact.install_tree_total_bytes = 1_023;
assertCode(
  validateUnbound(underreportedTreeBytes),
  "INSTALL_PLAN_ARTIFACT_TREE_BYTES_EXCEED_DECLARATION",
  "managed tree-entry bytes exceeding the artifact declaration",
);

const undisclosedTreeEntry = clone(readyFixture);
undisclosedTreeEntry.artifact.install_tree_entry_count = 3;
assertCode(
  validateUnbound(undisclosedTreeEntry),
  "INSTALL_PLAN_READY_TREE_ENTRY_COVERAGE_MISMATCH",
  "ready plan omitting one staged install-tree entry",
);

const undisclosedTreeBytes = clone(readyFixture);
undisclosedTreeBytes.artifact.install_tree_total_bytes = 1_025;
assertCode(
  validateUnbound(undisclosedTreeBytes),
  "INSTALL_PLAN_READY_TREE_BYTE_COVERAGE_MISMATCH",
  "ready plan omitting staged install-tree bytes",
);

const effectTargetMismatch = clone(readyFixture);
effectTargetMismatch.result.effects[0].target.value =
  ".claude/skills/unreviewed-package";
assertCode(
  validateUnbound(effectTargetMismatch),
  "INSTALL_PLAN_EFFECT_ACTION_MISMATCH",
  "reported effect target that differs from its action",
);

const amplifiedSchemaInput = clone(readyFixture);
amplifiedSchemaInput.actions = Array.from({ length: 10_000 }, () => null);
const amplifiedStart = performance.now();
const amplifiedResult = validateUnbound(amplifiedSchemaInput);
const amplifiedElapsed = performance.now() - amplifiedStart;
assertCode(
  amplifiedResult,
  "INSTALL_PLAN_ARRAY_LIMIT_EXCEEDED",
  "pre-schema action amplification",
);
assert(
  amplifiedElapsed < 1_500,
  `shape preflight took ${amplifiedElapsed.toFixed(1)}ms`,
);

const racePlanByteLength = 1024 * 1024;
const racePlanBytes = Buffer.concat([
  readyFixtureBytes,
  Buffer.alloc(racePlanByteLength - readyFixtureBytes.byteLength, 0x20),
]);
const pathFlavorOffset = racePlanBytes.indexOf(Buffer.from("posix"));
assert(pathFlavorOffset >= 0, "race fixture must contain path_flavor posix");
const invalidRacePlanBytes = Buffer.from(racePlanBytes);
invalidRacePlanBytes[pathFlavorOffset] = "n".charCodeAt(0);
const validRacePlanDigest = digestBytes(racePlanBytes);
const invalidRacePlanDigest = digestBytes(invalidRacePlanBytes);
const racePlanStorage = new globalThis.SharedArrayBuffer(
  racePlanBytes.byteLength,
);
const mutableRacePlanBytes = new Uint8Array(racePlanStorage);
mutableRacePlanBytes.set(racePlanBytes);
const raceControlStorage = new globalThis.SharedArrayBuffer(
  Int32Array.BYTES_PER_ELEMENT * 3,
);
const raceControl = new Int32Array(raceControlStorage);
const planRaceWorker = new Worker(`
  const { workerData } = require("node:worker_threads");
  const bytes = new Uint8Array(workerData.planStorage);
  const control = new Int32Array(workerData.controlStorage);
  let next = 0x6e;
  Atomics.store(bytes, workerData.pathFlavorOffset, next);
  Atomics.add(control, 2, 1);
  next = 0x70;
  Atomics.store(control, 0, 1);
  Atomics.notify(control, 0);
  while (Atomics.load(control, 1) === 0) {
    Atomics.store(bytes, workerData.pathFlavorOffset, next);
    Atomics.add(control, 2, 1);
    next = next === 0x6e ? 0x70 : 0x6e;
  }
`, {
  eval: true,
  workerData: {
    planStorage: racePlanStorage,
    controlStorage: raceControlStorage,
    pathFlavorOffset,
  },
});
if (Atomics.load(raceControl, 0) === 0) {
  Atomics.wait(raceControl, 0, 0, 5_000);
}
assert.equal(
  Atomics.load(raceControl, 0),
  1,
  "plan mutation worker must start before validation",
);
const observedPlanDigests = new Set();
const validateRacingPlan = () => validateBoundInstallPlan({
  planBytes: mutableRacePlanBytes,
  metadataBytesByDigest: metadataMap(coreNanoBytes, suiteNanoBytes),
  expectedContext: expectedContextFor(readyFixture),
  expectedPlanDigest: validRacePlanDigest,
  expectedBindings: expectedBindingsFor(readyFixture),
  evaluatedAt: readyFixture.result.reported_at,
});
const assertCoherentRacedPlan = (racedResult) => {
  observedPlanDigests.add(racedResult.plan_digest);
  const errorCodes = new Set(racedResult.errors.map((error) => error.code));
  assert(
    racedResult.plan_digest === validRacePlanDigest
      || racedResult.plan_digest === invalidRacePlanDigest,
    "bound validation must hash the same bounded private plan snapshot it parsed",
  );
  if (racedResult.plan_digest === validRacePlanDigest) {
    assert(
      !errorCodes.has("INSTALL_PLAN_PATH_FLAVOR_INVALID"),
      "a posix plan digest cannot be paired with parsed non-posix content",
    );
  } else {
    assert(
      errorCodes.has("INSTALL_PLAN_PATH_FLAVOR_INVALID"),
      "a non-posix plan digest must be paired with parsed non-posix content",
    );
  }
};
const planMutationCountBeforeRace = Atomics.load(raceControl, 2);
let planMutationCountAfterRace;
try {
  for (let index = 0; index < 128; index += 1) {
    assertCoherentRacedPlan(validateRacingPlan());
  }
  planMutationCountAfterRace = Atomics.load(raceControl, 2);
} finally {
  Atomics.store(raceControl, 1, 1);
  await planRaceWorker.terminate();
}
assert(
  planMutationCountAfterRace > planMutationCountBeforeRace,
  "plan mutation worker must change bytes during concurrent validation",
);
assert.deepEqual(
  [...observedPlanDigests].sort(),
  [validRacePlanDigest, invalidRacePlanDigest].sort(),
  "the concurrent plan snapshot race must observe both complete plan states",
);
for (const byte of [0x70, 0x6e]) {
  Atomics.store(mutableRacePlanBytes, pathFlavorOffset, byte);
  assertCoherentRacedPlan(validateRacingPlan());
}

const raceMetadataByteLength = 1024 * 1024;
const validRaceMetadataBytes = Buffer.concat([
  suiteNanoBytes,
  Buffer.alloc(raceMetadataByteLength - suiteNanoBytes.byteLength, 0x20),
]);
const installLocationMarker = Buffer.from(
  '"install_location": ".claude/skills/',
);
const installLocationMarkerOffset =
  validRaceMetadataBytes.indexOf(installLocationMarker);
assert(
  installLocationMarkerOffset >= 0,
  "metadata race fixture must contain the NanoClaw install location",
);
const installLocationByteOffset = installLocationMarkerOffset
  + Buffer.byteLength('"install_location": "');
const invalidRaceMetadataBytes = Buffer.from(validRaceMetadataBytes);
invalidRaceMetadataBytes[installLocationByteOffset] = 0x2f;
const validRaceMetadataDigest = digestBytes(validRaceMetadataBytes);
const invalidRaceMetadataDigest = digestBytes(invalidRaceMetadataBytes);
assert.notEqual(
  validRaceMetadataDigest,
  invalidRaceMetadataDigest,
  "metadata race variants must have distinct content digests",
);
const metadataRacePlan = clone(readyFixture);
metadataRacePlan.result.subject.component.metadata_digest =
  validRaceMetadataDigest;
metadataRacePlan.artifact.component.metadata_digest =
  validRaceMetadataDigest;
metadataRacePlan.apply_context.subject.component.metadata_digest =
  validRaceMetadataDigest;
refreshDerivedState(metadataRacePlan);
const metadataRacePlanBytes = encode(metadataRacePlan);
const raceMetadataStorage = new globalThis.SharedArrayBuffer(
  validRaceMetadataBytes.byteLength,
);
const mutableRaceMetadataBytes = new Uint8Array(raceMetadataStorage);
mutableRaceMetadataBytes.set(validRaceMetadataBytes);
const metadataRaceControlStorage = new globalThis.SharedArrayBuffer(
  Int32Array.BYTES_PER_ELEMENT * 3,
);
const metadataRaceControl = new Int32Array(metadataRaceControlStorage);
const metadataRaceWorker = new Worker(`
  const { workerData } = require("node:worker_threads");
  const bytes = new Uint8Array(workerData.metadataStorage);
  const control = new Int32Array(workerData.controlStorage);
  let next = 0x2f;
  Atomics.store(bytes, workerData.installLocationByteOffset, next);
  Atomics.add(control, 2, 1);
  next = 0x2e;
  Atomics.store(control, 0, 1);
  Atomics.notify(control, 0);
  while (Atomics.load(control, 1) === 0) {
    Atomics.store(bytes, workerData.installLocationByteOffset, next);
    Atomics.add(control, 2, 1);
    next = next === 0x2f ? 0x2e : 0x2f;
  }
`, {
  eval: true,
  workerData: {
    metadataStorage: raceMetadataStorage,
    controlStorage: metadataRaceControlStorage,
    installLocationByteOffset,
  },
});
if (Atomics.load(metadataRaceControl, 0) === 0) {
  Atomics.wait(metadataRaceControl, 0, 0, 5_000);
}
assert.equal(
  Atomics.load(metadataRaceControl, 0),
  1,
  "metadata mutation worker must start before validation",
);
const observedMetadataStates = new Set();
const validateRacingMetadata = () => validateBoundInstallPlan({
  planBytes: metadataRacePlanBytes,
  metadataBytesByDigest: new Map([
    [digestBytes(coreNanoBytes), coreNanoBytes],
    [validRaceMetadataDigest, mutableRaceMetadataBytes],
  ]),
  expectedContext: expectedContextFor(metadataRacePlan),
  expectedPlanDigest: digestBytes(metadataRacePlanBytes),
  expectedBindings: expectedBindingsFor(metadataRacePlan),
  evaluatedAt: metadataRacePlan.result.reported_at,
});
const assertCoherentRacedMetadata = (racedResult) => {
  const errorCodes = new Set(racedResult.errors.map((error) => error.code));
  const digestMismatch = errorCodes.has(
    "RESULT_SUBJECT_METADATA_DIGEST_MISMATCH",
  );
  const invalidInstallLocation = errorCodes.has("INSTALL_PLAN_PATH_NOT_POSIX");
  assert.equal(
    digestMismatch,
    invalidInstallLocation,
    "metadata digest validation and adapter path validation must consume one private metadata snapshot",
  );
  observedMetadataStates.add(digestMismatch ? "invalid" : "valid");
};
const metadataMutationCountBeforeRace =
  Atomics.load(metadataRaceControl, 2);
let metadataMutationCountAfterRace;
try {
  for (let index = 0; index < 128; index += 1) {
    assertCoherentRacedMetadata(validateRacingMetadata());
  }
  metadataMutationCountAfterRace = Atomics.load(metadataRaceControl, 2);
} finally {
  Atomics.store(metadataRaceControl, 1, 1);
  await metadataRaceWorker.terminate();
}
assert(
  metadataMutationCountAfterRace > metadataMutationCountBeforeRace,
  "metadata mutation worker must change bytes during concurrent validation",
);
assert.deepEqual(
  [...observedMetadataStates].sort(),
  ["invalid", "valid"],
  "the concurrent metadata snapshot race must observe both complete byte states",
);
for (const byte of [0x2e, 0x2f]) {
  Atomics.store(mutableRaceMetadataBytes, installLocationByteOffset, byte);
  assertCoherentRacedMetadata(validateRacingMetadata());
}

class HostileMetadataResolver extends Map {
  entries() {
    throw new Error("bound validation iterated the caller-owned resolver");
  }

  get() {
    throw new Error("bound validation read through the caller-owned resolver");
  }
}

const hostileMetadataResolver = new HostileMetadataResolver(
  metadataMap(coreNanoBytes, suiteNanoBytes),
);
Map.prototype.set.call(
  hostileMetadataResolver,
  `sha256:${"f".repeat(64)}`,
  new Uint8Array((4 * 1024 * 1024) + 1),
);
const hostileMetadataResult = validateBoundInstallPlan({
  planBytes: readyFixtureBytes,
  metadataBytesByDigest: hostileMetadataResolver,
  expectedContext: expectedContextFor(readyFixture),
  expectedPlanDigest: digestBytes(readyFixtureBytes),
  expectedBindings: expectedBindingsFor(readyFixture),
  evaluatedAt: readyFixture.result.reported_at,
});
assertValid(
  hostileMetadataResult,
  "bound validation must snapshot only exact referenced metadata through non-virtual Map access",
);

const oversizedRelevantMetadata = metadataMap(
  coreNanoBytes,
  suiteNanoBytes,
);
Map.prototype.set.call(
  oversizedRelevantMetadata,
  digestBytes(coreNanoBytes),
  new Uint8Array((1024 * 1024) + 1),
);
assertCode(
  validateBoundInstallPlan({
    planBytes: readyFixtureBytes,
    metadataBytesByDigest: oversizedRelevantMetadata,
    expectedContext: expectedContextFor(readyFixture),
    expectedPlanDigest: digestBytes(readyFixtureBytes),
    expectedBindings: expectedBindingsFor(readyFixture),
    evaluatedAt: readyFixture.result.reported_at,
  }),
  "INSTALL_PLAN_METADATA_TOO_LARGE",
  "oversized referenced metadata rejected before snapshot copying",
);

const shadowedOversizedMetadataBytes =
  new Uint8Array((1024 * 1024) + 1);
Object.defineProperty(shadowedOversizedMetadataBytes, "byteLength", {
  value: 1,
});
const shadowedOversizedMetadata = metadataMap(
  coreNanoBytes,
  suiteNanoBytes,
);
Map.prototype.set.call(
  shadowedOversizedMetadata,
  digestBytes(coreNanoBytes),
  shadowedOversizedMetadataBytes,
);
assertCode(
  validateBoundInstallPlan({
    planBytes: readyFixtureBytes,
    metadataBytesByDigest: shadowedOversizedMetadata,
    expectedContext: expectedContextFor(readyFixture),
    expectedPlanDigest: digestBytes(readyFixtureBytes),
    expectedBindings: expectedBindingsFor(readyFixture),
    evaluatedAt: readyFixture.result.reported_at,
  }),
  "INSTALL_PLAN_METADATA_TOO_LARGE",
  "intrinsic metadata view length defeats a shadowed byteLength",
);

assertCode(
  validateBoundInstallPlan({
    planBytes: new Uint8Array((1024 * 1024) + 1),
  }),
  "INSTALL_PLAN_TOO_LARGE",
  "oversized bound plan rejected before snapshot copying",
);

const shadowedOversizedPlanBytes = new Uint8Array((1024 * 1024) + 1);
Object.defineProperty(shadowedOversizedPlanBytes, "byteLength", {
  value: 1,
});
assertCode(
  validateBoundInstallPlan({
    planBytes: shadowedOversizedPlanBytes,
  }),
  "INSTALL_PLAN_TOO_LARGE",
  "intrinsic plan view length defeats a shadowed byteLength",
);

assertCode(
  validateUnboundInstallPlanBytes({}),
  "INSTALL_PLAN_BYTES_REQUIRED",
  "non-byte parser input",
);
assertCode(
  validateUnboundInstallPlanBytes(
    Buffer.from('{"schema":"first","schema":"second"}'),
  ),
  "INSTALL_PLAN_DUPLICATE_KEY",
  "duplicate JSON key",
);
assertCode(
  validateUnboundInstallPlanBytes(Buffer.alloc((1024 * 1024) + 1, 0x20)),
  "INSTALL_PLAN_TOO_LARGE",
  "oversized plan bytes",
);
assertCode(
  validateUnboundInstallPlanBytes(
    Buffer.from(`${"[".repeat(66)}0${"]".repeat(66)}`),
  ),
  "INSTALL_PLAN_NESTING_TOO_DEEP",
  "excessive JSON nesting",
);
assertCode(
  validateUnboundInstallPlanBytes(
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), readyFixtureBytes]),
  ),
  "INSTALL_PLAN_BOM_FORBIDDEN",
  "UTF-8 BOM",
);

const deterministicDocument = clone(readyFixture);
deterministicDocument.actions[0].target.path = "../escape";
const deterministicBytes = encode(deterministicDocument);
assert.deepEqual(
  validateUnboundInstallPlanBytes(deterministicBytes),
  validateUnboundInstallPlanBytes(deterministicBytes),
  "invalid input must produce deterministic diagnostics",
);

console.log("install-plan contract tests passed");

function validateUnbound(document) {
  return validateUnboundInstallPlanBytes(encode(document));
}

function validateBound(document, metadataBytes) {
  const planBytes = encode(document);
  return validateBoundInstallPlan({
    planBytes,
    metadataBytesByDigest: metadataMap(...metadataBytes),
    expectedContext: expectedContextFor(document),
    expectedPlanDigest: digestBytes(planBytes),
    expectedBindings: expectedBindingsFor(document),
    evaluatedAt: document.result.reported_at,
  });
}

function expectedContextFor(document) {
  return clone({
    executor: document.result.executor,
    subject: document.result.subject,
    invocation: document.result.invocation,
  });
}

function expectedBindingsFor(document) {
  return clone({
    adapter: document.adapter,
    apply_context: document.apply_context,
    artifact: document.artifact,
    staged_input: document.staged_input,
    target_state: document.target_state,
    verification_refs: document.verification_refs,
  });
}

function metadataMap(...metadataBytes) {
  return new Map(metadataBytes.map((bytes) => [digestBytes(bytes), bytes]));
}

function syntheticMetadata(harness, role) {
  const seedBytes = role === "core"
    ? coreOpenclawSeedBytes
    : suiteHermesSeedBytes;
  const metadata = JSON.parse(seedBytes);
  for (const platform of ["openclaw", "hermes", "nanoclaw", "picoclaw"]) {
    delete metadata[platform];
  }
  metadata[harness] = {};
  metadata.name = `clawsec-${role}-${harness}`;
  metadata.platform = harness;
  metadata.description = `Synthetic ${harness} ${role} metadata for install-plan contract tests.`;
  metadata.clawsec.supported_harness = {
    name: harness,
    minimum_version: "0.0.0",
    maximum_version_exclusive: "0.0.1",
  };
  metadata.clawsec.legacy_names = [];
  delete metadata.clawsec.native;
  if (role === "core") {
    metadata.clawsec.runtime_requires = [];
  } else {
    metadata.clawsec.runtime_requires = [{
      name: `clawsec-core-${harness}`,
      minimum_version: "0.1.0-rc.1",
      maximum_version_exclusive: "1.0.0",
    }];
  }
  return encode(metadata);
}

function componentRefFromMetadata(metadataBytes) {
  const metadata = JSON.parse(metadataBytes);
  return {
    schema: "clawsec.component-ref/v1",
    name: metadata.name,
    version: metadata.version,
    harness: metadata.clawsec.supported_harness.name,
    role: metadata.clawsec.role,
    metadata_digest: digestBytes(metadataBytes),
  };
}

function planForHarness(base, harness, executorRef, subjectRef) {
  const document = clone(base);
  const harnessVersion = harness === "nanoclaw" ? "2.1.17" : "0.0.0";
  const scope = {
    openclaw: { kind: "openclaw.workspace", ref: "fixture-workspace" },
    hermes: { kind: "hermes.profile", ref: "fixture-profile" },
    nanoclaw: { kind: "nanoclaw.checkout", ref: "fixture-checkout" },
    picoclaw: { kind: "picoclaw.home", ref: "fixture-home" },
  }[harness];
  const adapterProfile = adapterProfileFor(harness);
  const packageRoot = harness === "nanoclaw"
    ? `.claude/skills/${subjectRef.name}`
    : harness === "openclaw"
    ? `${adapterProfile.skill_root_path}/${subjectRef.name}`
    : subjectRef.name;
  const anchor = "scope_root";

  document.result.executor = clone(executorRef);
  document.result.subject.component = clone(subjectRef);
  document.result.invocation.harness = {
    name: harness,
    version: harnessVersion,
  };
  document.result.invocation.scope = clone(scope);
  document.artifact.component = clone(subjectRef);
  document.adapter.contract = `clawsec.${harness}-install-adapter/v1`;
  document.adapter.profile = adapterProfile;
  document.apply_context.executor = clone(executorRef);
  document.apply_context.subject.component = clone(subjectRef);
  document.apply_context.invocation.harness = {
    name: harness,
    version: harnessVersion,
  };
  document.apply_context.invocation.scope = clone(scope);
  document.target_state.target_instance_id = scope.ref;
  document.target_state.scope_root_identity_digest =
    scopeRootIdentityForProfile(adapterProfile);
  document.actions[0].target = { anchor, path: packageRoot };
  document.actions[1].target = {
    anchor,
    path: `${packageRoot}/SKILL.md`,
  };
  document.rollback_order = rollbackOrderForActions(document.actions);
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function planForPrototypePendingHarness(
  base,
  harness,
  executorRef,
  subjectRef,
) {
  const document = clone(base);
  const scope = {
    hermes: { kind: "hermes.profile", ref: "fixture-profile" },
    picoclaw: { kind: "picoclaw.home", ref: "fixture-home" },
  }[harness];
  const profile = adapterProfileFor(harness);

  document.disposition = "blocked";
  document.result.executor = clone(executorRef);
  document.result.subject.component = clone(subjectRef);
  document.result.invocation.harness = {
    name: harness,
    version: "0.0.0",
  };
  document.result.invocation.scope = clone(scope);
  document.result.outcome = "blocked";
  document.result.reason_code = "prerequisite_missing";
  document.result.summary =
    `${harness} native installation remains a prototype.`;
  document.result.effects = [];
  document.artifact.component = clone(subjectRef);
  document.adapter.contract = `clawsec.${harness}-install-adapter/v1`;
  document.adapter.profile = profile;
  document.apply_context = null;
  document.target_state.target_instance_id = scope.ref;
  document.target_state.scope_root_identity_digest =
    scopeRootIdentityForProfile(profile);
  document.actions = [];
  document.rollback_order = [];
  document.blockers = [{
    blocker_id: `${harness}-native-install-prototype`,
    code: "unsupported_native_operation",
    summary:
      `${harness} native installation is not implemented in contract v1.`,
  }];
  document.confirmation_requirements = null;
  refreshDerivedState(document);
  return document;
}

function planForNanoCore(base, coreMetadataBytes) {
  const coreRef = componentRefFromMetadata(coreMetadataBytes);
  const document = planForHarness(
    base,
    "nanoclaw",
    coreRef,
    coreRef,
  );
  const packageRoot = ".claude/skills/clawsec-core-nanoclaw";
  const removeAction = clone(document.actions[1]);
  removeAction.action_id = "write-remove-document";
  removeAction.target.path = `${packageRoot}/REMOVE.md`;
  removeAction.after.digest = `sha256:${"a".repeat(64)}`;
  removeAction.after.byte_length = 768;
  removeAction.tree_entry.path = "REMOVE.md";
  removeAction.tree_entry.digest = removeAction.after.digest;
  removeAction.tree_entry.byte_length = removeAction.after.byte_length;
  removeAction.tree_entry.manifest_entry_digest =
    `sha256:${"b".repeat(64)}`;
  document.actions.push(removeAction);
  document.artifact.install_tree_entry_count = 3;
  document.artifact.install_tree_total_bytes = 1792;
  document.rollback_order = document.actions
    .map((action) => action.action_id)
    .reverse();
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function planWithNestedPackageTree(base) {
  const document = clone(base);
  const packageRoot =
    ".claude/skills/clawsec-suite-nanoclaw";
  const nestedDirectory = clone(document.actions[0]);
  nestedDirectory.action_id = "create-nested-directory";
  nestedDirectory.target.path = `${packageRoot}/lib`;
  nestedDirectory.tree_entry.path = "lib";
  nestedDirectory.tree_entry.manifest_entry_digest =
    `sha256:${"3".repeat(64)}`;
  const deepDirectory = clone(document.actions[0]);
  deepDirectory.action_id = "create-deep-directory";
  deepDirectory.target.path = `${packageRoot}/lib/security`;
  deepDirectory.tree_entry.path = "lib/security";
  deepDirectory.tree_entry.manifest_entry_digest =
    `sha256:${"4".repeat(64)}`;
  const deepFile = clone(document.actions[1]);
  deepFile.action_id = "write-deep-file";
  deepFile.target.path = `${packageRoot}/lib/security/config.json`;
  deepFile.after.digest = `sha256:${"9".repeat(64)}`;
  deepFile.after.byte_length = 512;
  deepFile.tree_entry.path = "lib/security/config.json";
  deepFile.tree_entry.digest = deepFile.after.digest;
  deepFile.tree_entry.byte_length = deepFile.after.byte_length;
  deepFile.tree_entry.manifest_entry_digest =
    `sha256:${"a".repeat(64)}`;
  const emptyDirectory = clone(document.actions[0]);
  emptyDirectory.action_id = "create-empty-directory";
  emptyDirectory.target.path = `${packageRoot}/empty`;
  emptyDirectory.tree_entry.path = "empty";
  emptyDirectory.tree_entry.manifest_entry_digest =
    `sha256:${"5".repeat(64)}`;
  document.actions.push(
    nestedDirectory,
    deepDirectory,
    deepFile,
    emptyDirectory,
  );
  document.artifact.install_tree_entry_count = 6;
  document.artifact.install_tree_total_bytes = 1_536;
  document.rollback_order = rollbackOrderForActions(document.actions);
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function planWithRemovedPackageActivation(base) {
  const document = clone(base);
  const target = {
    anchor: "scope_root",
    path: ".claude/skills/clawsec-suite-nanoclaw",
  };
  const argumentsValue = { activation_mode: "exact_tree" };
  const preconditionDigest = `sha256:${"4".repeat(64)}`;
  const postconditionDigest = `sha256:${"5".repeat(64)}`;
  document.actions.push({
    action_id: "activate-package",
    kind: "native_operation",
    adapter_contract: document.adapter.contract,
    operation: "activate_package",
    state_effect: "mutating",
    target,
    arguments: argumentsValue,
    precondition_digest: preconditionDigest,
    expected_postcondition_digest: postconditionDigest,
    rollback: {
      operation: "deactivate_package",
      target: clone(target),
      arguments: clone(argumentsValue),
      precondition_digest: postconditionDigest,
      expected_postcondition_digest: preconditionDigest,
    },
  });
  document.rollback_order = rollbackOrderForActions(document.actions);
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function planWithOperationalAction(base, operation) {
  const document = clone(base);
  const conditionDigest = `sha256:${"4".repeat(64)}`;
  document.adapter.profile.reload_behavior = operation;
  document.actions.push({
    action_id: `${operation.replace("_", "-")}-after-install`,
    kind: "native_operation",
    adapter_contract: document.adapter.contract,
    operation,
    state_effect: "operational_non_mutating",
    target: {
      kind: "harness_resource",
      value: "nanoclaw.host",
      identity_digest:
        document.adapter.profile.checkout_identity_digest,
    },
    arguments: {},
    precondition_digest: conditionDigest,
    expected_postcondition_digest: conditionDigest,
    rollback: null,
  });
  document.rollback_order = rollbackOrderForActions(document.actions);
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function declaredTransformationFor(document) {
  return document.actions.find(
    (action) => action.kind === "declared_transformation",
  );
}

function planWithNanoTransformation(base) {
  const document = clone(base);
  const target = {
    anchor: "scope_root",
    path:
      "container/agent-runner/generated-config.json",
  };
  const codingHarness = {
    name: "codex",
    immutable_reference: {
      kind: "exact_version",
      value: "1.0.0",
    },
    implementation_digest: `sha256:${"c".repeat(64)}`,
    toolchain_digest: `sha256:${"d".repeat(64)}`,
    configuration_digest: `sha256:${"e".repeat(64)}`,
  };
  const before = {
    kind: "file",
    digest: `sha256:${"a".repeat(64)}`,
    byte_length: 256,
    mode: "0644",
    owner_identity_digest: `sha256:${"7".repeat(64)}`,
    group_identity_digest: `sha256:${"8".repeat(64)}`,
  };
  const after = {
    kind: "file",
    digest: `sha256:${"b".repeat(64)}`,
    byte_length: 384,
    mode: "0644",
    owner_identity_digest: `sha256:${"7".repeat(64)}`,
    group_identity_digest: `sha256:${"8".repeat(64)}`,
  };
  const packageRoot = document.actions[0].target.path;
  const sourceDirectory = clone(document.actions[0]);
  sourceDirectory.action_id = "create-transformations-directory";
  sourceDirectory.target.path = `${packageRoot}/transformations`;
  sourceDirectory.tree_entry.path = "transformations";
  sourceDirectory.tree_entry.manifest_entry_digest =
    `sha256:${"1".repeat(64)}`;
  const sourceFile = clone(document.actions[1]);
  sourceFile.action_id = "install-transformation-declaration";
  sourceFile.target.path =
    `${packageRoot}/transformations/nanoclaw-generated-config.json`;
  sourceFile.after.digest = `sha256:${"d".repeat(64)}`;
  sourceFile.after.byte_length = 512;
  sourceFile.tree_entry.path =
    "transformations/nanoclaw-generated-config.json";
  sourceFile.tree_entry.digest = sourceFile.after.digest;
  sourceFile.tree_entry.byte_length = sourceFile.after.byte_length;
  sourceFile.tree_entry.manifest_entry_digest =
    `sha256:${"e".repeat(64)}`;
  const declarationSource = {
    managed_action_id: sourceFile.action_id,
    manifest_entry_digest:
      sourceFile.tree_entry.manifest_entry_digest,
  };
  document.adapter.profile.coding_harness = clone(codingHarness);
  document.adapter.profile.validation_steps = [
    "postimage_manifest",
    "host_build",
    "host_tests",
    "skill_tests",
    "container_typecheck",
    "container_build",
    "container_tests",
  ];
  const transformation = {
    action_id: "transform-generated-config",
    kind: "declared_transformation",
    target,
    declaration: {
      source: declarationSource,
      release_manifest_digest:
        document.artifact.release_manifest_digest,
      transformation_entry_digest: `sha256:${"f".repeat(64)}`,
      allowed_output: {
        target: clone(target),
        before: clone(before),
        after: clone(after),
      },
      coding_harness: clone(codingHarness),
    },
    before,
    after,
    rollback_source: {
      kind: "captured_file",
      digest: before.digest,
      byte_length: before.byte_length,
      mode: before.mode,
      owner_identity_digest: before.owner_identity_digest,
      group_identity_digest: before.group_identity_digest,
    },
  };
  document.actions = [
    ...document.actions,
    sourceDirectory,
    sourceFile,
    transformation,
  ];
  document.artifact.install_tree_entry_count = 4;
  document.artifact.install_tree_total_bytes = 1_536;
  document.rollback_order = rollbackOrderForActions(document.actions);
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function planWithSecondFileEntry(base) {
  const document = clone(base);
  const duplicate = clone(document.actions[1]);
  duplicate.action_id = "write-copy-skill-document";
  duplicate.target.path =
    ".claude/skills/clawsec-suite-nanoclaw/COPY.md";
  duplicate.tree_entry.path = "COPY.md";
  duplicate.tree_entry.manifest_entry_digest =
    `sha256:${"4".repeat(64)}`;
  document.actions.push(duplicate);
  document.artifact.install_tree_entry_count = 3;
  document.artifact.install_tree_total_bytes = 2_048;
  document.rollback_order = rollbackOrderForActions(document.actions);
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function planWithExcessiveOutput(base) {
  const document = clone(base);
  const beforeDigests = ["b", "c", "d", "e", "f"];
  const afterDigests = ["0", "1", "2", "3", "4"];
  const transformationEntryDigests = ["6", "7", "8", "9", "a"];
  const transformations = beforeDigests.map((character, index) => {
    const action = clone(declaredTransformationFor(base));
    action.action_id = `transform-large-output-${index}`;
    action.target.path = `container/generated-${index}.json`;
    action.declaration.transformation_entry_digest =
      `sha256:${transformationEntryDigests[index].repeat(64)}`;
    action.before.digest =
      `sha256:${character.repeat(64)}`;
    action.before.byte_length = 0;
    action.after.digest =
      `sha256:${afterDigests[index].repeat(64)}`;
    action.after.byte_length = 67_108_864;
    action.declaration.allowed_output = {
      target: clone(action.target),
      before: clone(action.before),
      after: clone(action.after),
    };
    action.rollback_source = {
      kind: "captured_file",
      digest: action.before.digest,
      byte_length: action.before.byte_length,
      mode: action.before.mode,
      owner_identity_digest: action.before.owner_identity_digest,
      group_identity_digest: action.before.group_identity_digest,
    };
    return action;
  });
  document.actions = [
    ...document.actions.filter(
      (action) => action.kind === "managed_entry",
    ),
    ...transformations,
  ];
  document.rollback_order = rollbackOrderForActions(document.actions);
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function planWithExcessiveCapturedPreimages(base) {
  const document = clone(base);
  const beforeDigests = ["b", "c", "d", "e", "f"];
  const afterDigests = ["0", "1", "2", "3", "4"];
  const transformationEntryDigests = ["6", "7", "8", "9", "a"];
  const transformations = beforeDigests.map((character, index) => {
    const action = clone(declaredTransformationFor(base));
    action.action_id = `transform-large-preimage-${index}`;
    action.target.path = `container/preimage-${index}.json`;
    action.declaration.transformation_entry_digest =
      `sha256:${transformationEntryDigests[index].repeat(64)}`;
    action.before.digest =
      `sha256:${character.repeat(64)}`;
    action.before.byte_length = 67_108_864;
    action.after.digest =
      `sha256:${afterDigests[index].repeat(64)}`;
    action.after.byte_length = 1;
    action.declaration.allowed_output = {
      target: clone(action.target),
      before: clone(action.before),
      after: clone(action.after),
    };
    action.rollback_source = {
      kind: "captured_file",
      digest: action.before.digest,
      byte_length: action.before.byte_length,
      mode: action.before.mode,
      owner_identity_digest: action.before.owner_identity_digest,
      group_identity_digest: action.before.group_identity_digest,
    };
    return action;
  });
  document.actions = [
    ...document.actions.filter(
      (action) => action.kind === "managed_entry",
    ),
    ...transformations,
  ];
  document.rollback_order = rollbackOrderForActions(document.actions);
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function planWithRepeatedCapturedPreimageWork(base) {
  const document = clone(base);
  const afterDigests = ["0", "1", "2", "3", "4"];
  const transformationEntryDigests = ["6", "7", "8", "9", "a"];
  const transformations = afterDigests.map((character, index) => {
    const action = clone(declaredTransformationFor(base));
    action.action_id = `transform-repeated-preimage-${index}`;
    action.target.path = `container/repeated-preimage-${index}.json`;
    action.declaration.transformation_entry_digest =
      `sha256:${transformationEntryDigests[index].repeat(64)}`;
    action.before.byte_length = 67_108_864;
    action.after.digest = `sha256:${character.repeat(64)}`;
    action.after.byte_length = 1;
    action.declaration.allowed_output = {
      target: clone(action.target),
      before: clone(action.before),
      after: clone(action.after),
    };
    action.rollback_source = {
      kind: "captured_file",
      digest: action.before.digest,
      byte_length: action.before.byte_length,
      mode: action.before.mode,
      owner_identity_digest: action.before.owner_identity_digest,
      group_identity_digest: action.before.group_identity_digest,
    };
    return action;
  });
  document.actions = [
    ...document.actions.filter(
      (action) => action.kind === "managed_entry",
    ),
    ...transformations,
  ];
  document.rollback_order = rollbackOrderForActions(document.actions);
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function planWithAmbiguousCapturedPreimage(base) {
  const document = clone(base);
  const duplicate = clone(declaredTransformationFor(document));
  duplicate.action_id = "transform-generated-config-second-capture";
  duplicate.target.path = "container/generated-config-second.json";
  duplicate.declaration.transformation_entry_digest =
    `sha256:${"3".repeat(64)}`;
  duplicate.before.byte_length += 1;
  duplicate.after.digest = `sha256:${"4".repeat(64)}`;
  duplicate.declaration.allowed_output = {
    target: clone(duplicate.target),
    before: clone(duplicate.before),
    after: clone(duplicate.after),
  };
  duplicate.rollback_source = {
    kind: "captured_file",
    digest: duplicate.before.digest,
    byte_length: duplicate.before.byte_length,
    mode: duplicate.before.mode,
    owner_identity_digest: duplicate.before.owner_identity_digest,
    group_identity_digest: duplicate.before.group_identity_digest,
  };
  const transformationIndex = document.actions.findIndex(
    (action) => action.kind === "declared_transformation",
  );
  document.actions.splice(transformationIndex, 0, duplicate);
  document.rollback_order = rollbackOrderForActions(document.actions);
  document.result.effects = effectsForActions(document.actions);
  refreshDerivedState(document);
  return document;
}

function adapterProfileFor(harness) {
  const digest = (character) => `sha256:${character.repeat(64)}`;
  if (harness === "openclaw") {
    return {
      kind: "openclaw",
      scope_identity_digest: digest("1"),
      skill_root_identity_digest: digest("7"),
      skill_root_path: "skills",
      reload_behavior: "none",
    };
  }
  if (harness === "hermes") {
    return {
      kind: "hermes",
      profile_identity_digest: digest("2"),
      profile_config_digest: digest("3"),
      skill_root_identity_digest: digest("7"),
      native_install_status: "prototype_pending",
      reload_behavior: "none",
    };
  }
  if (harness === "picoclaw") {
    return {
      kind: "picoclaw",
      home_identity_digest: digest("4"),
      config_schema_version: "1",
      config_digest: digest("5"),
      skill_root_identity_digest: digest("7"),
      native_install_status: "prototype_pending",
      reload_behavior: "none",
    };
  }
  return clone(readyFixture.adapter.profile);
}

function scopeRootIdentityForProfile(profile) {
  if (profile.kind === "openclaw") {
    return profile.scope_identity_digest;
  }
  if (profile.kind === "hermes") {
    return profile.profile_identity_digest;
  }
  if (profile.kind === "picoclaw") {
    return profile.home_identity_digest;
  }
  return profile.checkout_identity_digest;
}

function effectsForActions(actions) {
  return actions.map((action) => {
    const target = action.target.anchor === undefined
      ? {
          kind: "harness_resource",
          value: action.target.value,
        }
      : {
          kind: "relative_path",
          value: action.target.path,
        };
    return {
      effect_id: action.action_id,
      state: "proposed",
      target,
      summary: `Propose ${action.operation} for ${target.value}.`,
    };
  }).sort((left, right) => left.effect_id.localeCompare(right.effect_id));
}

function rollbackOrderForActions(actions) {
  return actions
    .filter((action) => (
      action.kind !== "native_operation"
      || action.state_effect === "mutating"
    ))
    .map((action) => action.action_id)
    .reverse();
}

function refreshDerivedState(document) {
  Object.assign(
    document.target_state,
    computeInstallPlanStateBindings(document),
  );
  return document;
}

function setSubjectVersion(document, version) {
  document.result.subject.component.version = version;
  document.artifact.component.version = version;
  if (document.apply_context !== null) {
    document.apply_context.subject.component.version = version;
  }
}

function setMetadataVersion(metadataBytes, version) {
  const metadata = JSON.parse(metadataBytes);
  metadata.version = version;
  return encode(metadata);
}

function replaceSubjectRef(document, subjectRef) {
  document.result.subject.component = clone(subjectRef);
  document.artifact.component = clone(subjectRef);
  document.apply_context.subject.component = clone(subjectRef);
}

function assertValid(result, label) {
  assert.equal(
    result.valid,
    true,
    `${label} failed: ${JSON.stringify(result.errors)}`,
  );
  assert.deepEqual(result.errors, [], `${label} returned diagnostics`);
}

function assertCode(result, code, label) {
  assert.equal(
    result.valid,
    false,
    `${label} unexpectedly passed`,
  );
  assert(
    result.errors.some((entry) => entry.code === code),
    `${label} did not report ${code}: ${JSON.stringify(result.errors)}`,
  );
}

function assertBoundAssurance(result, label) {
  assert.deepEqual(
    {
      binding: result.binding,
      provenance: result.provenance,
      catalog_authorization: result.catalog_authorization,
      release_signature_authorization:
        result.release_signature_authorization,
      advisory_verification: result.advisory_verification,
      operator_authorization: result.operator_authorization,
      artifact_source_membership: result.artifact_source_membership,
      action_state_derivation: result.action_state_derivation,
      installation_authorization: result.installation_authorization,
      execution: result.execution,
      preconditions_at_apply_time: result.preconditions_at_apply_time,
      warnings: result.warnings,
    },
    {
      binding: "exact_plan_bytes_metadata_and_caller_inputs",
      provenance: "unverified",
      catalog_authorization: "unverified",
      release_signature_authorization: "unverified",
      advisory_verification: "unverified",
      operator_authorization: "unverified",
      artifact_source_membership: "unverified",
      action_state_derivation: "verified_from_plan_actions",
      installation_authorization: "not_granted",
      execution: "not_executed",
      preconditions_at_apply_time: "unverified",
      warnings: [],
    },
    `${label} must preserve the assurance boundary`,
  );
}

function encode(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}
