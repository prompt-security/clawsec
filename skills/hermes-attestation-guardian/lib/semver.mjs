const SEMVER_PATTERN = String.raw`[vV]?\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?`;
const SEMVER_REGEX = new RegExp(
  String.raw`^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`,
);
const CPE_COMPONENT_PATTERN = String.raw`(?:\\.|[^:\s])+`;
const CPE_23_REGEX = new RegExp(
  `^cpe:2\\.3:[aho]:${CPE_COMPONENT_PATTERN}(?::${CPE_COMPONENT_PATTERN}){9}$`,
  "i",
);

/**
 * @param {string} version
 * @returns {{core: [number, number, number], prerelease: string[]} | null}
 */
function parseSemverDetails(version) {
  const match = String(version || "").trim().match(SEMVER_REGEX);
  if (!match) return null;

  const core = /** @type {[number, number, number]} */ ([
    Number.parseInt(match[1], 10),
    Number.parseInt(match[2] || "0", 10),
    Number.parseInt(match[3] || "0", 10),
  ]);
  if (core.some((part) => Number.isNaN(part))) return null;

  return {
    core,
    prerelease: match[4] ? match[4].split(".") : [],
  };
}

/**
 * @param {string} left
 * @param {string} right
 * @returns {number}
 */
function comparePrereleaseIdentifier(left, right) {
  const leftIsNumeric = /^\d+$/.test(left);
  const rightIsNumeric = /^\d+$/.test(right);

  if (leftIsNumeric && rightIsNumeric) {
    const leftNumber = Number.parseInt(left, 10);
    const rightNumber = Number.parseInt(right, 10);
    if (leftNumber > rightNumber) return 1;
    if (leftNumber < rightNumber) return -1;
    return 0;
  }
  if (leftIsNumeric) return -1;
  if (rightIsNumeric) return 1;
  if (left > right) return 1;
  if (left < right) return -1;
  return 0;
}

/**
 * @param {string} version
 * @returns {[number, number, number] | null}
 */
export function parseSemver(version) {
  return parseSemverDetails(version)?.core || null;
}

/**
 * @param {string} left
 * @param {string} right
 * @returns {number | null}
 */
export function compareSemver(left, right) {
  const a = parseSemverDetails(left);
  const b = parseSemverDetails(right);
  if (!a || !b) return null;

  for (let index = 0; index < 3; index += 1) {
    if (a.core[index] > b.core[index]) return 1;
    if (a.core[index] < b.core[index]) return -1;
  }

  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0;
  if (a.prerelease.length === 0) return 1;
  if (b.prerelease.length === 0) return -1;

  const identifierCount = Math.max(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < identifierCount; index += 1) {
    const leftIdentifier = a.prerelease[index];
    const rightIdentifier = b.prerelease[index];
    if (leftIdentifier === undefined) return -1;
    if (rightIdentifier === undefined) return 1;

    const compared = comparePrereleaseIdentifier(leftIdentifier, rightIdentifier);
    if (compared !== 0) return compared;
  }

  return 0;
}

/**
 * @param {string} value
 * @returns {string}
 */
export function escapeRegex(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Return true for a structurally valid CPE 2.3 formatted-string binding.
 * CPE entries are feed metadata, not package@version selectors.
 *
 * @param {string} rawSpecifier
 * @returns {boolean}
 */
export function isCpeAffectedSpecifier(rawSpecifier) {
  return CPE_23_REGEX.test(String(rawSpecifier || "").trim());
}

/**
 * @param {string} rawSpecifier
 * @returns {{name: string, versionSpec: string} | null}
 */
export function parseAffectedSpecifier(rawSpecifier) {
  const specifier = String(rawSpecifier || "").trim();
  if (!specifier) return null;

  const atIndex = specifier.lastIndexOf("@");
  if (atIndex <= 0 || atIndex === specifier.length - 1) return null;

  const name = specifier.slice(0, atIndex).trim();
  const versionSpec = specifier.slice(atIndex + 1).trim();
  if (!name || !versionSpec) return null;
  return { name, versionSpec };
}

/**
 * @param {string} reason
 * @param {string} normalized
 * @returns {{supported: false, normalized: string, reason: string}}
 */
function unsupportedSpec(reason, normalized) {
  return { supported: false, normalized, reason };
}

/**
 * @param {string} normalized
 * @returns {{supported: true, normalized: string, reason: null}}
 */
function supportedSpec(normalized) {
  return { supported: true, normalized, reason: null };
}

/**
 * Parse an AND comparator set while rejecting partial parses and malformed separators.
 *
 * @param {string} range
 * @returns {string[] | null}
 */
function extractComparatorTokens(range) {
  const tokenPattern = new RegExp(`(?:<=|>=|<|>|=)\\s*${SEMVER_PATTERN}`, "g");
  const tokens = [];
  let cursor = 0;
  let match = tokenPattern.exec(range);

  while (match) {
    const gap = range.slice(cursor, match.index);
    if (tokens.length === 0) {
      if (!/^\s*$/.test(gap)) return null;
    } else if (!/^(?:\s+|\s*,\s*)$/.test(gap)) {
      return null;
    }

    tokens.push(match[0].trim());
    cursor = match.index + match[0].length;
    match = tokenPattern.exec(range);
  }

  if (!/^\s*$/.test(range.slice(cursor))) return null;
  return tokens.length > 0 ? tokens : null;
}

/**
 * @param {string} rawSpec
 * @returns {{supported: boolean, normalized: string, reason: string | null}}
 */
export function parseVersionSpec(rawSpec) {
  const spec = String(rawSpec || "").trim();
  if (!spec || spec === "*" || spec.toLowerCase() === "any") {
    return supportedSpec("*");
  }

  if (spec.includes("||") || spec.includes("&&") || /\s-\s/.test(spec)) {
    return unsupportedSpec("unsupported logical/composite semver range syntax", spec);
  }

  if (/^(?:>=|<=|>|<|=)/.test(spec)) {
    const comparatorTokens = extractComparatorTokens(spec);
    if (!comparatorTokens) {
      return unsupportedSpec("unsupported comparator-set semver range syntax", spec);
    }
    return supportedSpec(comparatorTokens.join(" "));
  }

  if (spec.includes("*")) {
    if (!/^[vV]?[0-9*]+(?:\.[0-9*]+){0,2}$/.test(spec)) {
      return unsupportedSpec("unsupported wildcard semver range syntax", spec);
    }
    return supportedSpec(spec);
  }

  if (spec.startsWith("^")) {
    if (!parseSemverDetails(spec.slice(1))) {
      return unsupportedSpec("invalid caret semver range syntax", spec);
    }
    return supportedSpec(spec);
  }

  if (spec.startsWith("~")) {
    if (!parseSemverDetails(spec.slice(1))) {
      return unsupportedSpec("invalid tilde semver range syntax", spec);
    }
    return supportedSpec(spec);
  }

  if (parseSemverDetails(spec)) return supportedSpec(spec);
  return unsupportedSpec("unsupported semver range syntax", spec);
}

/**
 * @param {number} compared
 * @param {string} operator
 * @returns {boolean}
 */
function comparatorMatches(compared, operator) {
  if (operator === ">=") return compared >= 0;
  if (operator === "<=") return compared <= 0;
  if (operator === ">") return compared > 0;
  if (operator === "<") return compared < 0;
  return compared === 0;
}

/**
 * @param {string} version
 * @param {string} comparator
 * @returns {boolean}
 */
function evaluateComparator(version, comparator) {
  const match = comparator.match(new RegExp(`^(>=|<=|>|<|=)\\s*(${SEMVER_PATTERN})$`));
  if (!match) return false;

  const compared = compareSemver(version, match[2]);
  return compared !== null && comparatorMatches(compared, match[1]);
}

/**
 * @param {string | null} version
 * @param {string} rawSpec
 * @returns {boolean}
 */
export function versionMatches(version, rawSpec) {
  const parsedSpec = parseVersionSpec(rawSpec);
  if (!parsedSpec.supported) return false;

  const spec = parsedSpec.normalized;
  if (spec === "*") return true;
  if (!version || String(version).trim().toLowerCase() === "unknown") return false;

  const normalizedVersion = String(version).trim().replace(/^v/i, "");

  if (spec.includes("*")) {
    const wildcardRegex = new RegExp(`^${escapeRegex(spec).replace(/\\\*/g, ".*")}$`);
    return wildcardRegex.test(normalizedVersion);
  }

  if (/^(?:>=|<=|>|<|=)/.test(spec)) {
    const comparatorTokens = extractComparatorTokens(spec);
    return comparatorTokens !== null && comparatorTokens.every((token) => evaluateComparator(normalizedVersion, token));
  }

  if (spec.startsWith("^")) {
    const target = parseSemverDetails(spec.slice(1));
    if (!target || !parseSemverDetails(normalizedVersion)) return false;

    const [major, minor, patch] = target.core;
    let upperBound;
    if (major > 0) {
      upperBound = `${major + 1}.0.0`;
    } else if (minor > 0) {
      upperBound = `0.${minor + 1}.0`;
    } else {
      upperBound = `0.0.${patch + 1}`;
    }

    const lowerCompared = compareSemver(normalizedVersion, spec.slice(1));
    const upperCompared = compareSemver(normalizedVersion, upperBound);
    return lowerCompared !== null && upperCompared !== null && lowerCompared >= 0 && upperCompared < 0;
  }

  if (spec.startsWith("~")) {
    const target = parseSemverDetails(spec.slice(1));
    const current = parseSemverDetails(normalizedVersion);
    if (!target || !current) return false;
    return (
      current.core[0] === target.core[0]
      && current.core[1] === target.core[1]
      && compareSemver(normalizedVersion, spec.slice(1)) >= 0
    );
  }

  return compareSemver(normalizedVersion, spec) === 0;
}
