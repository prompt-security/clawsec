export const hermesInstallPlanAdapter = Object.freeze({
  profileKind: "hermes",
  scopeIdentityField: "profile_identity_digest",

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
