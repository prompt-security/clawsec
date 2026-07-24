import { isDeepStrictEqual } from "node:util";

const REQUIRED_VALIDATION_STEPS = Object.freeze([
  "postimage_manifest",
  "host_build",
  "host_tests",
  "skill_tests",
]);

export const nanoclawV2InstallPlanAdapter = Object.freeze({
  profileKind: "nanoclaw_v2_host",
  scopeIdentityField: "checkout_identity_digest",

  validateUnbound({ document, errors, addError, helpers }) {
    const profile = document.adapter.profile;
    if (
      profile.upstream_baseline.version
      !== document.result.invocation.harness.version
    ) {
      addError(
        errors,
        "INSTALL_PLAN_NANOCLAW_BASELINE_MISMATCH",
        "/adapter/profile/upstream_baseline/version",
        "NanoClaw v2 profile must bind the exact reported upstream version",
      );
    }
    if (profile.checkout_status === "conflicted") {
      addError(
        errors,
        "INSTALL_PLAN_NANOCLAW_CHECKOUT_CONFLICTED",
        "/adapter/profile/checkout_status",
        "NanoClaw v2 planning cannot target a conflicted checkout",
      );
    }
    if (
      profile.ancestor_chain_digest
      !== document.target_state.ancestor_chain_digest
    ) {
      addError(
        errors,
        "INSTALL_PLAN_NANOCLAW_ANCESTOR_IDENTITY_MISMATCH",
        "/target_state/ancestor_chain_digest",
        "NanoClaw target-state ancestors must match the selected checkout profile",
      );
    }
    for (const step of REQUIRED_VALIDATION_STEPS) {
      requireValidationStep(profile, step, errors, addError);
    }

    const transformations = document.actions.filter((action) => (
      action.kind === "declared_transformation"
    ));
    validateTransformations({
      document,
      profile,
      transformations,
      errors,
      addError,
    });
    helpers.validateReloadBehavior({
      document,
      profile,
      runtimeResource: "nanoclaw.host",
      instanceIdentityDigest: profile.checkout_identity_digest,
      errors,
      addError,
    });
  },

  validateBound({
    document,
    metadata,
    errors,
    addError,
    helpers,
    pathIsAtOrBelow,
    validatePortablePosixPath,
  }) {
    const profile = document.adapter.profile;
    const installLocation = metadata.clawsec?.native?.install_location;
    if (typeof installLocation !== "string") {
      addError(
        errors,
        "INSTALL_PLAN_NANOCLAW_INSTALL_LOCATION_REQUIRED",
        "/result/subject/component",
        "NanoClaw v2 metadata must declare the authoritative package install location",
      );
      return;
    }
    validatePortablePosixPath(
      installLocation,
      "/result/subject/component",
      errors,
    );
    if (!pathIsAtOrBelow(installLocation, profile.skill_root_path)) {
      addError(
        errors,
        "INSTALL_PLAN_NANOCLAW_INSTALL_LOCATION_INVALID",
        "/result/subject/component",
        "NanoClaw v2 metadata install location must remain under the adapter-selected skill root",
      );
      return;
    }
    helpers.validatePackageTargets({
      document,
      packageRoot: installLocation,
      errors,
      addError,
      pathIsAtOrBelow,
      validatePortablePosixPath,
    });

    if (
      document.disposition === "ready"
      && metadata.clawsec?.native?.remove_document_required === true
    ) {
      const removeDocumentPath = `${installLocation}/REMOVE.md`;
      const carriesRemoveDocument = document.actions.some((action) => (
        action.kind === "managed_entry"
        && action.after.kind === "file"
        && action.target.path === removeDocumentPath
        && action.tree_entry?.kind === "file"
        && action.tree_entry.path === "REMOVE.md"
        && action.tree_entry.digest === action.after.digest
      ));
      if (!carriesRemoveDocument) {
        addError(
          errors,
          "INSTALL_PLAN_NANOCLAW_REMOVE_DOCUMENT_REQUIRED",
          "/actions",
          "NanoClaw v2 stateful packages must install exact REMOVE.md bytes",
        );
      }
    }
  },
});

function validateTransformations({
  document,
  profile,
  transformations,
  errors,
  addError,
}) {
  if (transformations.length === 0) {
    if (profile.coding_harness !== null) {
      addError(
        errors,
        "INSTALL_PLAN_NANOCLAW_UNUSED_CODING_HARNESS",
        "/adapter/profile/coding_harness",
        "NanoClaw plans without transformations cannot bind a coding harness",
      );
    }
    return;
  }
  if (
    profile.coding_harness === null
    || typeof profile.coding_harness !== "object"
  ) {
    addError(
      errors,
      "INSTALL_PLAN_NANOCLAW_CODING_HARNESS_REQUIRED",
      "/adapter/profile/coding_harness",
      "NanoClaw transformations require one exact adapter-bound coding harness",
    );
    return;
  }

  for (const transformation of transformations) {
    const index = document.actions.indexOf(transformation);
    if (
      transformation.target.anchor !== "scope_root"
    ) {
      addError(
        errors,
        "INSTALL_PLAN_NANOCLAW_TRANSFORMATION_ANCHOR_INVALID",
        `/actions/${index}/target/anchor`,
        "NanoClaw transformations must remain inside the selected checkout scope",
      );
    }
    if (pathAtOrBelow(transformation.target.path, profile.skill_root_path)) {
      addError(
        errors,
        "INSTALL_PLAN_NANOCLAW_TRANSFORMATION_PACKAGE_TREE_FORBIDDEN",
        `/actions/${index}/target/path`,
        "NanoClaw transformations cannot mutate the host skill tree; package files must be exact managed entries",
      );
    }
    const forbiddenReason = forbiddenTransformationPath(
      transformation.target.path,
    );
    if (forbiddenReason !== null) {
      addError(
        errors,
        "INSTALL_PLAN_NANOCLAW_TRANSFORMATION_PATH_FORBIDDEN",
        `/actions/${index}/target/path`,
        forbiddenReason,
      );
    }
    if (
      !isDeepStrictEqual(
        transformation.declaration.coding_harness,
        profile.coding_harness,
      )
    ) {
      addError(
        errors,
        "INSTALL_PLAN_NANOCLAW_CODING_HARNESS_MISMATCH",
        `/actions/${index}/declaration/coding_harness`,
        "NanoClaw transformation must use the exact adapter-bound coding harness",
      );
    }

    if (touchesContainer(transformation)) {
      requireValidationStep(profile, "container_build", errors, addError);
    }
    if (touchesAgentRunner(transformation)) {
      requireValidationStep(profile, "container_typecheck", errors, addError);
      requireValidationStep(profile, "container_tests", errors, addError);
    }
  }
}

function requireValidationStep(profile, step, errors, addError) {
  if (!profile.validation_steps.includes(step)) {
    addError(
      errors,
      "INSTALL_PLAN_NANOCLAW_VALIDATION_STEP_REQUIRED",
      "/adapter/profile/validation_steps",
      `NanoClaw v2 plan requires ${step}`,
    );
  }
}

function touchesContainer(transformation) {
  const targetPath = transformation.target.path.toLowerCase();
  return (
    targetPath === "container"
    || targetPath.startsWith("container/")
  );
}

function touchesAgentRunner(transformation) {
  const targetPath = transformation.target.path.toLowerCase();
  return (
    targetPath === "container/agent-runner"
    || targetPath.startsWith("container/agent-runner/")
  );
}

function pathAtOrBelow(candidate, root) {
  const foldedCandidate = candidate.toLowerCase();
  const foldedRoot = root.toLowerCase();
  return (
    foldedCandidate === foldedRoot
    || foldedCandidate.startsWith(`${foldedRoot}/`)
  );
}

function forbiddenTransformationPath(candidate) {
  const normalized = candidate.toLowerCase();
  const segments = normalized.split("/");
  if (segments.includes(".git")) {
    return "NanoClaw transformations cannot target Git control state";
  }
  if (["data", "groups", "logs"].includes(segments[0])) {
    return "NanoClaw transformations cannot target live data, group, or log roots";
  }
  if (
    normalized === "container/skills"
    || normalized.startsWith("container/skills/")
  ) {
    return "NanoClaw transformations cannot target container skill state";
  }

  const basename = segments.at(-1);
  if (
    basename === ".env"
    || basename.startsWith(".env.")
    || basename === ".netrc"
    || basename === ".npmrc"
    || basename.startsWith("id_rsa")
    || basename.startsWith("id_ed25519")
    || /^(?:credentials|secrets|token)(?:\.(?:json|ya?ml|toml|ini|conf|txt|key|pem))?$/.test(
      basename,
    )
  ) {
    return "NanoClaw transformations cannot target secret-bearing files";
  }
  if (
    basename.endsWith(".db")
    || basename.endsWith(".sqlite")
    || basename.endsWith(".sqlite3")
  ) {
    return "NanoClaw transformations cannot target live database files";
  }
  return null;
}
