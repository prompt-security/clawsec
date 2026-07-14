#!/usr/bin/env node

import path from "node:path";
import { pathToFileURL } from "node:url";

function parseIdentifier(identifier) {
  if (/^\d+$/.test(identifier)) {
    if (identifier.length > 1 && identifier.startsWith("0")) {
      throw new Error(`Invalid numeric prerelease identifier with leading zero: ${identifier}`);
    }
    return Number(identifier);
  }
  return identifier;
}

export function parseSemver(version) {
  const normalized = String(version ?? "").trim();
  const match = normalized.match(
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/,
  );
  if (!match) {
    throw new Error(`Invalid semantic version: ${version}`);
  }
  return {
    raw: normalized,
    core: [Number(match[1]), Number(match[2]), Number(match[3])],
    prerelease: match[4] ? match[4].split(".").map(parseIdentifier) : [],
  };
}

export function compareSemver(leftVersion, rightVersion) {
  const left = parseSemver(leftVersion);
  const right = parseSemver(rightVersion);

  for (let index = 0; index < left.core.length; index += 1) {
    if (left.core[index] !== right.core[index]) {
      return left.core[index] < right.core[index] ? -1 : 1;
    }
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
    if (leftIdentifier === rightIdentifier) continue;
    if (typeof leftIdentifier === "number" && typeof rightIdentifier === "number") {
      return leftIdentifier < rightIdentifier ? -1 : 1;
    }
    if (typeof leftIdentifier === "number") return -1;
    if (typeof rightIdentifier === "number") return 1;
    return leftIdentifier < rightIdentifier ? -1 : 1;
  }

  return 0;
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

  const coreComparison = next.core.findIndex(
    (identifier, index) => identifier !== base.core[index],
  );
  const coreIncreases = coreComparison !== -1
    && next.core[coreComparison] > base.core[coreComparison];
  if (!coreIncreases) {
    throw new Error(
      `Skill core version must increase by at least a patch: base=${baseVersion}, next=${nextVersion}`,
    );
  }
  return true;
}

export function nextSimulatedReleaseVersion(version) {
  const parsed = parseSemver(version);
  const [major, minor, patch] = parsed.core;
  if (parsed.prerelease.length === 0) {
    return `${major}.${minor}.${patch + 1}`;
  }

  const rawPrerelease = parsed.raw.slice(parsed.raw.indexOf("-") + 1);
  const numberedPrerelease = rawPrerelease.match(/^(.*?)(\d+)$/);
  if (numberedPrerelease) {
    return `${major}.${minor}.${patch}-${numberedPrerelease[1]}${Number(numberedPrerelease[2]) + 1}`;
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
