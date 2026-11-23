import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import {
  assertLifecycleBinding,
  classifyLifecycleVersion,
  compareSemverV2,
  evaluatePublicationVersion,
  formatPackageTag,
  parsePackageTag,
  parseSemverV2,
} from "./ci/lifecycle_semver.mjs";
import {
  assertSemverIncrement,
  nextSimulatedReleaseVersion,
  parseSemver as parseLegacySemver,
} from "./ci/semver_increment.mjs";

function readJson(relativePath) {
  return JSON.parse(readFileSync(new URL(relativePath, import.meta.url), "utf8"));
}

const contract = readJson("../contracts/lifecycle-semver-v1.json");
const fixtures = readJson("../contracts/fixtures/lifecycle-semver-v1.json");

assert.equal(contract.contract, "clawsec.lifecycle-semver/v1");
assert.equal(contract.contract_version, 1);
assert.deepEqual(Object.keys(contract.lifecycle_stages), ["beta", "rc", "stable_intent", "stable"]);
assert.equal(contract.lifecycle_stages.stable.requires_active_signed_catalog_authorization, true);
assert.equal(contract.publication_policy.syntactic_validity_implies_publication_eligibility, false);
assert.equal(contract.publication_policy.eligibility_is_stable_authorization, false);

for (const fixture of fixtures.valid_versions) {
  assert.deepEqual(parseSemverV2(fixture.input), {
    raw: fixture.input,
    core: fixture.core,
    prerelease: fixture.prerelease,
    build: fixture.build,
  });
}

for (const invalidVersion of fixtures.invalid_versions) {
  assert.throws(
    () => parseSemverV2(invalidVersion),
    /Invalid SemVer 2\.0 version/,
    `expected invalid SemVer: ${JSON.stringify(invalidVersion)}`,
  );
}

for (const chain of fixtures.precedence_chains) {
  for (let index = 1; index < chain.length; index += 1) {
    const lower = chain[index - 1];
    const higher = chain[index];
    assert.equal(compareSemverV2(lower, higher), -1, `${lower} must precede ${higher}`);
    assert.equal(compareSemverV2(higher, lower), 1, `${higher} must follow ${lower}`);
  }
}

for (const [left, right] of fixtures.equal_precedence) {
  assert.equal(compareSemverV2(left, right), 0, `${left} and ${right} must have equal precedence`);
  assert.equal(compareSemverV2(right, left), 0, `${right} and ${left} must have equal precedence`);
}

for (const fixture of fixtures.package_tags.valid) {
  const parsed = parsePackageTag(fixture.input);
  assert.equal(parsed.raw, fixture.input);
  assert.equal(parsed.packageName, fixture.package_name);
  assert.equal(parsed.version, fixture.version);
  assert.deepEqual(parsed.parsedVersion, parseSemverV2(fixture.version));
}

for (const invalidTag of fixtures.package_tags.invalid) {
  assert.throws(
    () => parsePackageTag(invalidTag),
    /Invalid package-qualified tag/,
    `expected invalid package tag: ${JSON.stringify(invalidTag)}`,
  );
}

for (const fixture of fixtures.format_tags.valid) {
  assert.equal(formatPackageTag(fixture.package_name, fixture.version), fixture.expected);
}

for (const packageName of fixtures.format_tags.invalid_package_names) {
  assert.throws(() => formatPackageTag(packageName, "1.2.3"), /Invalid package name/);
}
assert.throws(() => formatPackageTag("clawsec", "1.2"), /Invalid SemVer 2\.0 version/);

for (const fixture of fixtures.classifications) {
  assert.equal(classifyLifecycleVersion(fixture.version), fixture.expected);
}

for (const fixture of fixtures.publication_evaluations) {
  assert.deepEqual(evaluatePublicationVersion(fixture.version), {
    version: fixture.version,
    lifecycleClass: fixture.lifecycle_class,
    publicPublicationEligible: fixture.eligible,
    reasonCode: fixture.reason_code,
  });
}

for (const binding of fixtures.lifecycle_bindings.valid) {
  assert.equal(assertLifecycleBinding(binding), true);
}

for (const fixture of fixtures.lifecycle_bindings.invalid) {
  assert.throws(
    () => assertLifecycleBinding(fixture.input),
    new RegExp(fixture.error),
    `expected invalid lifecycle binding: ${JSON.stringify(fixture.input)}`,
  );
}

assert.throws(() => assertLifecycleBinding(), /Unknown lifecycle stage/);
assert.throws(
  () => assertLifecycleBinding({
    stage: "stable",
    artifactVersion: "1.0.0",
    intendedVersion: "1.0.0",
    activeCatalogAuthorized: "yes",
  }),
  /must be a boolean/,
);

assert.deepEqual(parseLegacySemver(" 0.0.1-beta5 "), {
  raw: "0.0.1-beta5",
  core: [0, 0, 1],
  prerelease: ["beta5"],
});
assert.throws(() => parseLegacySemver("1.2.3+build.1"), /Invalid semantic version/);
assert.throws(
  () => parseLegacySemver("1.2.3-beta.01"),
  /Invalid numeric prerelease identifier with leading zero: 01/,
);
assert.equal(nextSimulatedReleaseVersion("0.0.1-beta5"), "0.0.1-beta6");
assert.equal(nextSimulatedReleaseVersion("0.0.1-beta.5"), "0.0.1-beta.6");
assert.equal(nextSimulatedReleaseVersion("0.0.1-preview"), "0.0.1-preview1");
assert.equal(
  nextSimulatedReleaseVersion("1.2.9007199254740992"),
  "1.2.9007199254740993",
);
assert.equal(
  nextSimulatedReleaseVersion("1.2.3-beta.9007199254740992"),
  "1.2.3-beta.9007199254740993",
);
assert.equal(
  nextSimulatedReleaseVersion(`1.2.${"9".repeat(400)}`),
  `1.2.1${"0".repeat(400)}`,
);
assert.equal(
  assertSemverIncrement("9007199254740992.0.0", "9007199254740993.0.0"),
  true,
);

const longMalformedVersion = `1.2.3-${"a".repeat(50_000)}_`;
const longMalformedStart = performance.now();
assert.throws(() => parseSemverV2(longMalformedVersion), /Invalid SemVer 2\.0 version/);
const longMalformedDurationMs = performance.now() - longMalformedStart;
assert.ok(
  longMalformedDurationMs < 1_000,
  `long malformed SemVer must be rejected in bounded time; took ${longMalformedDurationMs}ms`,
);

const longMalformedTag = `a${"-v".repeat(50_000)}not-a-version`;
const longMalformedTagStart = performance.now();
assert.throws(() => parsePackageTag(longMalformedTag), /Invalid package-qualified tag/);
const longMalformedTagDurationMs = performance.now() - longMalformedTagStart;
assert.ok(
  longMalformedTagDurationMs < 1_000,
  `long malformed package tag must be rejected in bounded time; took ${longMalformedTagDurationMs}ms`,
);

const longNonnumericPrerelease = `1.2.3-${"1".repeat(50_000)}a`;
const longSimulationStart = performance.now();
assert.equal(
  nextSimulatedReleaseVersion(longNonnumericPrerelease),
  `${longNonnumericPrerelease}1`,
);
const longSimulationDurationMs = performance.now() - longSimulationStart;
assert.ok(
  longSimulationDurationMs < 1_000,
  `long prerelease simulation must complete in bounded time; took ${longSimulationDurationMs}ms`,
);
