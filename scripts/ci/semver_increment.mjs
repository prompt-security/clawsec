#!/usr/bin/env node

import path from "node:path";
import { pathToFileURL } from "node:url";
import { compareSemverV2, parseSemverV2 } from "./lifecycle_semver.mjs";

function parseIdentifier(identifier) {
  if (/^\d+$/.test(identifier)) {
    if (identifier.length > 1 && identifier.startsWith("0")) {
      throw new Error(`Invalid numeric prerelease identifier with leading zero: ${identifier}`);
    }
    return Number(identifier);
  }
  return identifier;
}

function incrementDecimalString(value) {
  const normalized = value.replace(/^0+(?=\d)/, "");
  const digits = normalized.split("");
  let carry = 1;

  for (let index = digits.length - 1; index >= 0 && carry === 1; index -= 1) {
    if (digits[index] === "9") {
      digits[index] = "0";
    } else {
      digits[index] = String(Number(digits[index]) + 1);
      carry = 0;
    }
  }

  if (carry === 1) digits.unshift("1");
  return digits.join("");
}

export function parseSemver(version) {
  const normalized = String(version ?? "").trim();
  const legacyShape = normalized.match(
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/,
  );
  if (legacyShape?.[4]) {
    for (const identifier of legacyShape[4].split(".")) {
      parseIdentifier(identifier);
    }
  }

  let parsed;
  try {
    parsed = parseSemverV2(normalized);
  } catch {
    throw new Error(`Invalid semantic version: ${version}`);
  }
  if (parsed.build.length > 0) {
    throw new Error(`Invalid semantic version: ${version}`);
  }
  return {
    raw: normalized,
    core: parsed.core.map(Number),
    prerelease: parsed.prerelease.map(parseIdentifier),
  };
}

export function compareSemver(leftVersion, rightVersion) {
  const left = parseSemver(leftVersion);
  const right = parseSemver(rightVersion);
  return compareSemverV2(left.raw, right.raw);
}

export function assertSemverIncrement(baseVersion, nextVersion) {
  const base = parseSemver(baseVersion);
  const next = parseSemver(nextVersion);
  if (base.prerelease.length > 0) {
    if (compareSemver(nextVersion, baseVersion) <= 0) {
      throw new Error(
        `Prerelease version must increase by SemVer precedence: base=${baseVersion}, next=${nextVersion}`,
      );
    }
    return true;
  }

  const baseCoreVersion = parseSemverV2(base.raw).core.join(".");
  const nextCoreVersion = parseSemverV2(next.raw).core.join(".");
  const coreIncreases = compareSemverV2(nextCoreVersion, baseCoreVersion) > 0;
  if (!coreIncreases) {
    throw new Error(
      `Skill core version must increase by at least a patch: base=${baseVersion}, next=${nextVersion}`,
    );
  }
  return true;
}

export function nextSimulatedReleaseVersion(version) {
  const parsed = parseSemver(version);
  const strict = parseSemverV2(parsed.raw);
  const [major, minor, patch] = strict.core;
  if (parsed.prerelease.length === 0) {
    return `${major}.${minor}.${incrementDecimalString(patch)}`;
  }

  const rawPrerelease = parsed.raw.slice(parsed.raw.indexOf("-") + 1);
  let trailingDigitsStart = rawPrerelease.length;
  while (
    trailingDigitsStart > 0
    && rawPrerelease[trailingDigitsStart - 1] >= "0"
    && rawPrerelease[trailingDigitsStart - 1] <= "9"
  ) {
    trailingDigitsStart -= 1;
  }

  if (trailingDigitsStart < rawPrerelease.length) {
    const prefix = rawPrerelease.slice(0, trailingDigitsStart);
    const digits = rawPrerelease.slice(trailingDigitsStart);
    return `${major}.${minor}.${patch}-${prefix}${incrementDecimalString(digits)}`;
  }
  return `${major}.${minor}.${patch}-${rawPrerelease}1`;
}

async function main() {
  const [baseVersion, nextVersion] = process.argv.slice(2);
  if (!baseVersion || !nextVersion) {
    throw new Error("Usage: node scripts/ci/semver_increment.mjs <base-version> <next-version>");
  }
  assertSemverIncrement(baseVersion, nextVersion);
  process.stdout.write(`SemVer increment verified: ${baseVersion} -> ${nextVersion}\n`);
}

const invokedUrl = process.argv[1]
  ? pathToFileURL(path.resolve(process.argv[1])).href
  : "";
if (import.meta.url === invokedUrl) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  });
}
