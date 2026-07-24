export const picoclawInstallPlanAdapter = Object.freeze({
  profileKind: "picoclaw",
  scopeIdentityField: "home_identity_digest",

  validateUnbound({ document, errors, addError, helpers }) {
    const profile = document.adapter.profile;
    helpers.validatePrototypePending({
      document,
      profile,
      errors,
      addError,
    });
  },

  validateBound() {},
});
