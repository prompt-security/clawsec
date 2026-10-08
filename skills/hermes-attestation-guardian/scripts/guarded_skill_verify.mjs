#!/usr/bin/env node

import fs from "node:fs";
import { refreshAdvisoryFeed } from "../lib/feed.mjs";
import {
  hermesVersionIdentitiesAreIncomparable,
  isExactDateBuildVersion,
  parseAffectedSpecifier,
  parseVersionSpec,
  versionMatches,
} from "../lib/semver.mjs";

const EXIT_CONFIRM_REQUIRED = 42;

function usage() {
  process.stdout.write(
    [
      "Usage: node scripts/guarded_skill_verify.mjs --skill <name> [--version <semver-or-date-build>] [--confirm-advisory] [--allow-unsigned]",
      "",
      "Verifies advisory feed state using the Hermes feed verification pipeline, then gates",
      "a candidate skill by advisory match before install/verification flows continue.",
      "",
      "Exit codes:",
      "  0  no advisory match, or explicit advisory confirmation supplied",
      "  42 advisory match found and --confirm-advisory was not provided",
      "  1  verification/feed failure or invalid arguments",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const parsed = {
    skill: "",
    version: "",
    confirmAdvisory: false,
    allowUnsigned: undefined,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--skill") {
      parsed.skill = String(argv[i + 1] || "").trim();
      i += 1;
      continue;
    }
    if (token === "--version") {
      parsed.version = String(argv[i + 1] || "").trim();
      i += 1;
      continue;
    }
    if (token === "--confirm-advisory") {
      parsed.confirmAdvisory = true;
      continue;
    }
    if (token === "--allow-unsigned") {
      parsed.allowUnsigned = true;
      continue;
    }
    if (token === "--help" || token === "-h") {
      parsed.help = true;
      continue;
    }
    throw new Error(`Unknown argument: ${token}`);
  }

  if (parsed.help) return parsed;

  if (!parsed.skill) {
    throw new Error("Missing required argument: --skill");
  }
  if (!/^[a-z0-9-]+$/.test(parsed.skill)) {
    throw new Error("Invalid --skill value. Use lowercase letters, digits, and hyphens only.");
  }
  if (
    parsed.version
    && !/^v?\d+\.\d+\.\d+(?:[-+][0-9a-zA-Z.-]+)?$/.test(parsed.version)
    && !isExactDateBuildVersion(parsed.version)
  ) {
    throw new Error(
      "Invalid --version value. Expected semver or an exact Hermes date build (for example: 2026.5.29.2).",
    );
  }

  return parsed;
}

function normalizeSkillName(value) {
  return String(value || "").trim().toLowerCase();
}

function findAdvisoryMatches(feed, skillName, version = "") {
  const advisories = Array.isArray(feed?.advisories) ? feed.advisories : [];
  const targetName = normalizeSkillName(skillName);
  const matches = [];

  for (const advisory of advisories) {
    const affected = Array.isArray(advisory?.affected) ? advisory.affected : [];
    if (affected.length === 0) continue;

    const matchedAffected = [];
    const unsupportedSpecs = [];
    const indeterminateSpecs = [];
    for (const specifier of affected) {
      const parsed = parseAffectedSpecifier(specifier);
      if (!parsed) continue;
      if (normalizeSkillName(parsed.name) !== targetName) continue;

      const parsedSpec = parseVersionSpec(parsed.versionSpec);
      if (!parsedSpec.supported) {
        // Fail closed: unsupported range syntax is treated as a match to avoid bypass.
        matchedAffected.push(specifier);
        unsupportedSpecs.push(specifier);
        continue;
      }

      // Conservative default: if operator did not provide --version, any name match gates.
      if (!version || versionMatches(version, parsed.versionSpec)) {
        matchedAffected.push(specifier);
      } else if (
        (targetName === "hermes" || targetName === "hermes-agent")
        && hermesVersionIdentitiesAreIncomparable(version, parsed.versionSpec)
      ) {
        matchedAffected.push(specifier);
        indeterminateSpecs.push(specifier);
      }
    }

    if (matchedAffected.length > 0) {
      matches.push({ advisory, matchedAffected, unsupportedSpecs, indeterminateSpecs });
    }
  }

  return matches;
}

function printMatches(matches, args) {
  process.stdout.write("Advisory matches detected for requested candidate.\n");
  process.stdout.write(`Target: ${args.skill}${args.version ? `@${args.version}` : ""}\n`);

  for (const match of matches) {
    const advisory = match.advisory || {};
    const severity = String(advisory.severity || "unknown").toUpperCase();
    const advisoryId = String(advisory.id || "unknown-id");
    const title = String(advisory.title || "Untitled advisory");

    process.stdout.write(`- [${severity}] ${advisoryId}: ${title}\n`);
    process.stdout.write(`  matched: ${match.matchedAffected.join(", ")}\n`);
    if (Array.isArray(match.unsupportedSpecs) && match.unsupportedSpecs.length > 0) {
      process.stdout.write(
        `  warning: unsupported advisory version syntax treated as match (fail-closed): ${match.unsupportedSpecs.join(", ")}\n`,
      );
    }
    if (Array.isArray(match.indeterminateSpecs) && match.indeterminateSpecs.length > 0) {
      process.stdout.write(
        `  warning: installed and advisory Hermes versions use unmapped identities; treating as indeterminate/possibly affected: ${match.indeterminateSpecs.join(", ")}\n`,
      );
    }
    if (advisory.action) {
      process.stdout.write(`  action: ${advisory.action}\n`);
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    usage();
    return;
  }

  let refreshResult;
  try {
    refreshResult = await refreshAdvisoryFeed(args.allowUnsigned === true ? { allowUnsigned: true } : {});
  } catch (error) {
    process.stderr.write(`CRITICAL: advisory feed verification failed (fail-closed): ${error?.message || String(error)}\n`);
    process.exit(1);
  }

  if (refreshResult.status === "unverified") {
    const warningSource = args.allowUnsigned === true ? "--allow-unsigned" : "resolved env/config policy";
    process.stderr.write(
      `WARNING: unsigned advisory bypass enabled via ${warningSource}. This weakens supply-chain guarantees and should be emergency-only.\n`,
    );
  }

  let feed;
  try {
    feed = JSON.parse(fs.readFileSync(refreshResult.cachedFeedPath, "utf8"));
  } catch (error) {
    process.stderr.write(
      `CRITICAL: cached advisory feed load failed after verification: ${error?.message || String(error)}\n`,
    );
    process.exit(1);
  }

  process.stdout.write(`Advisory feed status: ${refreshResult.status} (${refreshResult.source})\n`);
  if (!args.version) {
    process.stdout.write("No --version provided; applying conservative name-based advisory gate.\n");
  }

  const matches = findAdvisoryMatches(feed, args.skill, args.version);
  if (matches.length === 0) {
    process.stdout.write("No advisory matches found for candidate.\n");
    return;
  }

  printMatches(matches, args);

  if (!args.confirmAdvisory) {
    process.stdout.write("Re-run with --confirm-advisory to proceed with explicit operator acknowledgement.\n");
    process.exit(EXIT_CONFIRM_REQUIRED);
  }

  process.stderr.write(
    `WARNING: proceeding despite ${matches.length} advisory match(es) because --confirm-advisory was provided.\n`,
  );
}

try {
  await main();
} catch (error) {
  process.stderr.write(`CRITICAL: ${error?.message || String(error)}\n`);
  process.exit(1);
}
