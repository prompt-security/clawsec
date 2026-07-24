import { openclawInstallPlanAdapter } from "./openclaw.mjs";
import { hermesInstallPlanAdapter } from "./hermes.mjs";
import { nanoclawV2InstallPlanAdapter } from "./nanoclaw-v2.mjs";
import { picoclawInstallPlanAdapter } from "./picoclaw.mjs";

const adapterByHarness = new Map([
  ["openclaw", openclawInstallPlanAdapter],
  ["hermes", hermesInstallPlanAdapter],
  ["nanoclaw", nanoclawV2InstallPlanAdapter],
  ["picoclaw", picoclawInstallPlanAdapter],
]);

export function validateInstallPlanAdapter(document, errors, addError) {
  const harness = document.result.invocation.harness.name;
  const definition = adapterByHarness.get(harness);
  if (definition === undefined) {
    addError(
      errors,
      "INSTALL_PLAN_ADAPTER_UNSUPPORTED",
      "/result/invocation/harness/name",
      `install-plan adapter semantics are not defined for ${harness}`,
    );
    return;
  }

  const expectedContract = `clawsec.${harness}-install-adapter/v1`;
  if (document.adapter.contract !== expectedContract) {
    addError(
      errors,
      "INSTALL_PLAN_ADAPTER_MISMATCH",
      "/adapter/contract",
      `install plan for ${harness} must bind ${expectedContract}`,
    );
  }
  const profile = document.adapter.profile;
  if (profile.kind !== definition.profileKind) {
    addError(
      errors,
      "INSTALL_PLAN_ADAPTER_PROFILE_MISMATCH",
      "/adapter/profile/kind",
      `install plan for ${harness} must use the typed ${definition.profileKind} profile`,
    );
    return;
  }
  if (
    profile[definition.scopeIdentityField]
    !== document.target_state.scope_root_identity_digest
  ) {
    addError(
      errors,
      "INSTALL_PLAN_TARGET_ROOT_IDENTITY_MISMATCH",
      "/target_state/scope_root_identity_digest",
      "target-state root identity must match the adapter-selected physical scope root",
    );
  }

  definition.validateUnbound({
    document,
    errors,
    addError,
    helpers: {
      rejectTransformations,
      validatePrototypePending,
      validateReloadBehavior,
    },
  });
}

export function validateBoundInstallPlanAdapter({
  document,
  metadata,
  errors,
  addError,
  pathIsAtOrBelow,
  validatePortablePosixPath,
}) {
  const definition = adapterByHarness.get(
    document.result.invocation.harness.name,
  );
  if (definition === undefined) return;
  definition.validateBound({
    document,
    metadata,
    errors,
    addError,
    helpers: {
      validatePackageTargets,
    },
    pathIsAtOrBelow,
    validatePortablePosixPath,
  });
}

function validateReloadBehavior({
  document,
  profile,
  runtimeResource,
  instanceIdentityDigest,
  errors,
  addError,
}) {
  const operationalActions = document.actions.filter((action) => (
    action.kind === "native_operation"
    && ["reload_harness", "restart_harness"].includes(action.operation)
  ));
  if (document.disposition !== "ready") return;

  const expectedOperation = profile.reload_behavior === "none"
    ? null
    : profile.reload_behavior;
  const expectedCount = expectedOperation === null ? 0 : 1;
  if (
    operationalActions.length !== expectedCount
    || (
      expectedOperation !== null
      && operationalActions[0]?.operation !== expectedOperation
    )
  ) {
    addError(
      errors,
      "INSTALL_PLAN_RELOAD_ACTION_MISMATCH",
      "/actions",
      expectedOperation === null
        ? "adapter reload behavior none forbids reload and restart actions"
        : `adapter reload behavior requires exactly one ${expectedOperation} action`,
    );
  }

  for (const action of operationalActions) {
    if (
      action.target.kind !== "harness_resource"
      || action.target.value !== runtimeResource
      || action.target.identity_digest !== instanceIdentityDigest
    ) {
      addError(
        errors,
        "INSTALL_PLAN_HARNESS_RESOURCE_IDENTITY_MISMATCH",
        `/actions/${document.actions.indexOf(action)}/target`,
        "harness operation must target the adapter-selected instance identity",
      );
    }
  }
}

function rejectTransformations({ document, errors, addError }) {
  for (let index = 0; index < document.actions.length; index += 1) {
    const action = document.actions[index];
    if (action.kind === "declared_transformation") {
      addError(
        errors,
        "INSTALL_PLAN_ADAPTER_TRANSFORMATION_FORBIDDEN",
        `/actions/${index}`,
        "this install adapter does not permit declared transformations",
      );
    }
  }
}

function validatePrototypePending({ document, profile, errors, addError }) {
  if (profile.native_install_status !== "prototype_pending") {
    addError(
      errors,
      "INSTALL_PLAN_PROTOTYPE_STATUS_INVALID",
      "/adapter/profile/native_install_status",
      "adapter must explicitly declare its native installer prototype pending",
    );
  }
  if (
    profile.reload_behavior !== "none"
    || document.disposition !== "blocked"
    || document.actions.length !== 0
    || document.apply_context !== null
    || document.confirmation_requirements !== null
  ) {
    addError(
      errors,
      "INSTALL_PLAN_PROTOTYPE_PENDING_DISPOSITION_INVALID",
      "/disposition",
      "prototype-pending adapters can only emit a blocked, non-actionable plan",
    );
  }
  if (
    document.blockers.length === 0
    || document.blockers.some((blocker) => (
      blocker.code !== "unsupported_native_operation"
    ))
  ) {
    addError(
      errors,
      "INSTALL_PLAN_PROTOTYPE_PENDING_BLOCKER_INVALID",
      "/blockers",
      "prototype-pending adapters require only unsupported_native_operation blockers",
    );
  }
}

function validatePackageTargets({
  document,
  packageRoot,
  errors,
  addError,
  pathIsAtOrBelow,
  validatePortablePosixPath,
}) {
  validatePortablePosixPath(
    packageRoot,
    "/result/subject/component",
    errors,
  );
  const managedActions = [];
  for (let index = 0; index < document.actions.length; index += 1) {
    const action = document.actions[index];
    if (action.kind === "declared_transformation") {
      continue;
    }
    if (action.kind !== "managed_entry") {
      continue;
    }
    managedActions.push({ action, index });

    const targetPath = `/actions/${index}/target`;
    const expectedTargetPath = action.tree_entry.path === "."
      ? packageRoot
      : `${packageRoot}/${action.tree_entry.path}`;
    if (
      action.target.anchor !== "scope_root"
      || !pathIsAtOrBelow(action.target.path, packageRoot)
    ) {
      addError(
        errors,
        "INSTALL_PLAN_PACKAGE_TARGET_INVALID",
        targetPath,
        "package writes must remain under the exact selected package root in scope_root",
      );
    }
    if (
      action.target.anchor !== "scope_root"
      || action.target.path !== expectedTargetPath
    ) {
      addError(
        errors,
        "INSTALL_PLAN_TREE_ENTRY_TARGET_MISMATCH",
        targetPath,
        "managed target must exactly equal the package root joined to its install-tree entry path",
      );
    }
  }
  if (document.disposition !== "ready") return;
  validateReadyPackageTree({
    managedActions,
    packageRoot,
    errors,
    addError,
    pathIsAtOrBelow,
  });
}

function validateReadyPackageTree({
  managedActions,
  packageRoot,
  errors,
  addError,
  pathIsAtOrBelow,
}) {
  if (managedActions.length === 0) {
    addError(
      errors,
      "INSTALL_PLAN_SUBJECT_PACKAGE_ACTION_REQUIRED",
      "/actions",
      "ready plans require at least one managed mutation for the subject package",
    );
    return;
  }

  const actionsByPath = new Map(managedActions.map((entry) => [
    entry.action.target.path,
    entry,
  ]));
  const packageRootAction = actionsByPath.get(packageRoot);
  if (
    packageRootAction === undefined
    || packageRootAction.action.after.kind !== "directory"
  ) {
    addError(
      errors,
      "INSTALL_PLAN_PACKAGE_ROOT_DIRECTORY_REQUIRED",
      "/actions",
      "ready plans must create the exact subject package root as a managed directory",
    );
  }

  const missingDirectories = new Set();
  for (const child of managedActions) {
    let parent = parentPosixPath(child.action.target.path);
    while (
      parent !== null
      && pathIsAtOrBelow(parent, packageRoot)
    ) {
      const parentAction = actionsByPath.get(parent);
      if (
        parentAction === undefined
        || parentAction.action.after.kind !== "directory"
      ) {
        if (!missingDirectories.has(parent)) {
          missingDirectories.add(parent);
          addError(
            errors,
            "INSTALL_PLAN_PACKAGE_INTERMEDIATE_DIRECTORY_REQUIRED",
            `/actions/${child.index}/target/path`,
            `managed package path requires an earlier managed directory action for ${parent}`,
          );
        }
      } else if (parentAction.index >= child.index) {
        addError(
          errors,
          "INSTALL_PLAN_PACKAGE_PARENT_ORDER_INVALID",
          `/actions/${child.index}/target/path`,
          `managed directory ${parent} must appear before its child`,
        );
      }
      if (parent === packageRoot) break;
      parent = parentPosixPath(parent);
    }
  }
}

function parentPosixPath(candidate) {
  const separator = candidate.lastIndexOf("/");
  return separator === -1 ? null : candidate.slice(0, separator);
}
