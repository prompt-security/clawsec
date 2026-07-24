export const openclawInstallPlanAdapter = Object.freeze({
  profileKind: "openclaw",
  scopeIdentityField: "scope_identity_digest",

  validateUnbound({ document, errors, addError, helpers }) {
    const profile = document.adapter.profile;
    helpers.rejectTransformations({ document, errors, addError });
    helpers.validateReloadBehavior({
      document,
      profile,
      runtimeResource: "openclaw.runtime",
      instanceIdentityDigest: profile.scope_identity_digest,
      errors,
      addError,
    });
  },

  validateBound({
    document,
    errors,
    addError,
    helpers,
    pathIsAtOrBelow,
    validatePortablePosixPath,
  }) {
    const profile = document.adapter.profile;
    helpers.validatePackageTargets({
      document,
      packageRoot: `${profile.skill_root_path}/${document.result.subject.component.name}`,
      errors,
      addError,
      pathIsAtOrBelow,
      validatePortablePosixPath,
    });
  },
});
