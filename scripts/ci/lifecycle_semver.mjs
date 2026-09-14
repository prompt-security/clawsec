const CORE_IDENTIFIER_PATTERN = /^(?:0|[1-9]\d*)$/;
const VERSION_IDENTIFIER_PATTERN = /^[0-9A-Za-z-]+$/;
const NUMERIC_IDENTIFIER_PATTERN = /^\d+$/;
const PACKAGE_NAME_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const LIFECYCLE_STAGES = new Set(["beta", "rc", "stable_intent", "stable"]);

function invalidSemver(version) {
  return new Error(`Invalid SemVer 2.0 version: ${String(version)}`);
}

function compareDecimalStrings(left, right) {
  if (left.length !== right.length) {
    return left.length < right.length ? -1 : 1;
  }
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function comparePrereleaseIdentifiers(left, right) {
  const leftIsNumeric = matchesEntire(NUMERIC_IDENTIFIER_PATTERN, left);
  const rightIsNumeric = matchesEntire(NUMERIC_IDENTIFIER_PATTERN, right);

  if (leftIsNumeric && rightIsNumeric) {
    return compareDecimalStrings(left, right);
  }
  if (leftIsNumeric) return -1;
  if (rightIsNumeric) return 1;
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function matchesEntire(pattern, value) {
  const match = value.match(pattern);
  return match?.[0] === value;
}

function isValidPackageName(packageName) {
  if (typeof packageName !== "string") return false;
  return matchesEntire(PACKAGE_NAME_PATTERN, packageName);
}

function assertPackageName(packageName) {
  if (!isValidPackageName(packageName)) {
    throw new Error(`Invalid package name: ${String(packageName)}`);
  }
}

function hasBuildMetadata(parsedVersion) {
  return parsedVersion.build.length > 0;
}

function assertNoBuildMetadata(parsedVersion, label) {
  if (hasBuildMetadata(parsedVersion)) {
    throw new Error(`${label} must not contain build metadata: ${parsedVersion.raw}`);
  }
}

function assertFinalVersion(parsedVersion, label) {
  if (parsedVersion.prerelease.length > 0) {
    throw new Error(`${label} must be a final SemVer version: ${parsedVersion.raw}`);
  }
  assertNoBuildMetadata(parsedVersion, label);
}

function sameCore(left, right) {
  return left.core.every((identifier, index) => identifier === right.core[index]);
}

export function parseSemverV2(version) {
  if (typeof version !== "string") {
    throw invalidSemver(version);
  }

  const plusIndex = version.indexOf("+");
  if (plusIndex !== -1 && version.indexOf("+", plusIndex + 1) !== -1) {
    throw invalidSemver(version);
  }

  const coreAndPrerelease = plusIndex === -1 ? version : version.slice(0, plusIndex);
  const buildText = plusIndex === -1 ? null : version.slice(plusIndex + 1);
  const dashIndex = coreAndPrerelease.indexOf("-");
  const coreText = dashIndex === -1
    ? coreAndPrerelease
    : coreAndPrerelease.slice(0, dashIndex);
  const prereleaseText = dashIndex === -1
    ? null
    : coreAndPrerelease.slice(dashIndex + 1);

  const core = coreText.split(".");
  if (core.length !== 3 || core.some((identifier) => (
    !matchesEntire(CORE_IDENTIFIER_PATTERN, identifier)
  ))) {
    throw invalidSemver(version);
  }

  const prerelease = prereleaseText === null ? [] : prereleaseText.split(".");
  if (prereleaseText === "" || prerelease.some((identifier) => (
    !matchesEntire(VERSION_IDENTIFIER_PATTERN, identifier)
    || (
      matchesEntire(NUMERIC_IDENTIFIER_PATTERN, identifier)
      && identifier.length > 1
      && identifier.startsWith("0")
    )
  ))) {
    throw invalidSemver(version);
  }

  const build = buildText === null ? [] : buildText.split(".");
  if (buildText === "" || build.some((identifier) => (
    !matchesEntire(VERSION_IDENTIFIER_PATTERN, identifier)
  ))) {
    throw invalidSemver(version);
  }

  return {
    raw: version,
    core,
    prerelease,
    build,
  };
}

export function compareSemverV2(leftVersion, rightVersion) {
  const left = parseSemverV2(leftVersion);
  const right = parseSemverV2(rightVersion);

  for (let index = 0; index < left.core.length; index += 1) {
    const comparison = compareDecimalStrings(left.core[index], right.core[index]);
    if (comparison !== 0) return comparison;
  }

  if (left.prerelease.length === 0 && right.prerelease.length === 0) return 0;
  if (left.prerelease.length === 0) return 1;
  if (right.prerelease.length === 0) return -1;

  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftIdentifier = left.prerelease[index];
    const rightIdentifier = right.prerelease[index];
    if (leftIdentifier === undefined) return -1;
    if (rightIdentifier === undefined) return 1;

    const comparison = comparePrereleaseIdentifiers(leftIdentifier, rightIdentifier);
    if (comparison !== 0) return comparison;
  }

  return 0;
}

export function parsePackageTag(tag) {
  if (typeof tag !== "string") {
    throw new Error(`Invalid package-qualified tag: ${String(tag)}`);
  }

  const firstDotIndex = tag.indexOf(".");
  const delimiterIndex = firstDotIndex === -1
    ? -1
    : tag.lastIndexOf("-v", firstDotIndex);
  if (delimiterIndex <= 0) {
    throw new Error(`Invalid package-qualified tag: ${tag}`);
  }

  const packageName = tag.slice(0, delimiterIndex);
  const version = tag.slice(delimiterIndex + 2);
  if (!isValidPackageName(packageName)) {
    throw new Error(`Invalid package-qualified tag: ${tag}`);
  }

  try {
    const parsedVersion = parseSemverV2(version);
    return { raw: tag, packageName, version, parsedVersion };
  } catch {
    throw new Error(`Invalid package-qualified tag: ${tag}`);
  }
}

export function formatPackageTag(packageName, version) {
  assertPackageName(packageName);
  const parsedVersion = parseSemverV2(version);
  return `${packageName}-v${parsedVersion.raw}`;
}

export function classifyLifecycleVersion(version) {
  const parsed = parseSemverV2(version);
  if (parsed.prerelease.length === 0) return "final";

  if (
    parsed.prerelease.length === 2
    && (parsed.prerelease[0] === "beta" || parsed.prerelease[0] === "rc")
    && matchesEntire(NUMERIC_IDENTIFIER_PATTERN, parsed.prerelease[1])
  ) {
    return parsed.prerelease[0];
  }

  return "legacy_prerelease";
}

export function evaluatePublicationVersion(version) {
  const parsed = parseSemverV2(version);
  const lifecycleClass = classifyLifecycleVersion(version);

  if (hasBuildMetadata(parsed)) {
    return {
      version,
      lifecycleClass,
      publicPublicationEligible: false,
      reasonCode: "build_metadata_disallowed",
    };
  }

  if (lifecycleClass === "final") {
    return {
      version,
      lifecycleClass,
      publicPublicationEligible: true,
      reasonCode: "final_version_eligible_not_authorized",
    };
  }

  if (lifecycleClass === "beta" || lifecycleClass === "rc") {
    return {
      version,
      lifecycleClass,
      publicPublicationEligible: false,
      reasonCode: "candidate_prerelease_lab_only",
    };
  }

  return {
    version,
    lifecycleClass,
    publicPublicationEligible: false,
    reasonCode: "legacy_prerelease_non_authorized",
  };
}

export function assertLifecycleBinding({
  stage,
  artifactVersion,
  intendedVersion,
  activeCatalogAuthorized = false,
} = {}) {
  if (!LIFECYCLE_STAGES.has(stage)) {
    throw new Error(`Unknown lifecycle stage: ${String(stage)}`);
  }
  if (typeof activeCatalogAuthorized !== "boolean") {
    throw new Error("activeCatalogAuthorized must be a boolean");
  }

  const artifact = parseSemverV2(artifactVersion);
  const intended = parseSemverV2(intendedVersion);
  assertNoBuildMetadata(artifact, "artifactVersion");
  assertFinalVersion(intended, "intendedVersion");

  if (!sameCore(artifact, intended)) {
    throw new Error(
      `artifactVersion and intendedVersion must share the same core version: ${artifact.raw} != ${intended.raw}`,
    );
  }

  const lifecycleClass = classifyLifecycleVersion(artifactVersion);
  if (stage === "beta" || stage === "rc") {
    if (lifecycleClass !== stage) {
      throw new Error(`${stage} requires a canonical ${stage}.N artifactVersion`);
    }
    if (activeCatalogAuthorized) {
      throw new Error(`${stage} candidates cannot be authorized by the active public catalog`);
    }
    return true;
  }

  if (lifecycleClass !== "final" || artifact.raw !== intended.raw) {
    throw new Error(`${stage} requires artifactVersion to equal the final intendedVersion`);
  }

  if (stage === "stable_intent") {
    if (activeCatalogAuthorized) {
      throw new Error("stable_intent must remain outside the active public catalog");
    }
    return true;
  }

  if (!activeCatalogAuthorized) {
    throw new Error("stable requires active signed-catalog authorization");
  }
  return true;
}
