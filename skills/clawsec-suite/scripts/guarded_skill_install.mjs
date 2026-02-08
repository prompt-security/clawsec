#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const DEFAULT_FEED_URL =
  "https://raw.githubusercontent.com/prompt-security/clawsec/main/advisories/feed.json";
const DEFAULT_SUITE_DIR = path.join(os.homedir(), ".openclaw", "skills", "clawsec-suite");
const DEFAULT_LOCAL_FEED = path.join(DEFAULT_SUITE_DIR, "advisories", "feed.json");
const EXIT_CONFIRM_REQUIRED = 42;

function printUsage() {
  process.stderr.write(
    [
      "Usage:",
      "  node scripts/guarded_skill_install.mjs --skill <skill-name> [--version <version>] [--confirm-advisory] [--dry-run]",
      "",
      "Examples:",
      "  node scripts/guarded_skill_install.mjs --skill helper-plus --version 1.0.1",
      "  node scripts/guarded_skill_install.mjs --skill helper-plus --version 1.0.1 --confirm-advisory",
      "",
      "Exit codes:",
      "  0  success / no advisory block",
      "  42 advisory matched and second confirmation is required",
      "  1  error",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const parsed = {
    skill: "",
    version: "",
    confirmAdvisory: false,
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];

    if (token === "--skill") {
      parsed.skill = String(argv[i + 1] ?? "").trim();
      i += 1;
      continue;
    }
    if (token === "--version") {
      parsed.version = String(argv[i + 1] ?? "").trim();
      i += 1;
      continue;
    }
    if (token === "--confirm-advisory") {
      parsed.confirmAdvisory = true;
      continue;
    }
    if (token === "--dry-run") {
      parsed.dryRun = true;
      continue;
    }
    if (token === "--help" || token === "-h") {
      printUsage();
      process.exit(0);
    }

    throw new Error(`Unknown argument: ${token}`);
  }

  if (!parsed.skill) {
    throw new Error("Missing required argument: --skill");
  }
  if (!/^[a-z0-9-]+$/.test(parsed.skill)) {
    throw new Error("Invalid --skill value. Use lowercase letters, digits, and hyphens only.");
  }

  return parsed;
}

function isObject(value) {
  return typeof value === "object" && value !== null;
}

function normalizeSkillName(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function uniqueStrings(values) {
  return [...new Set(values)];
}

function parseSemver(version) {
  const cleaned = String(version ?? "")
    .trim()
    .replace(/^v/i, "")
    .split("-")[0];
  const parts = cleaned.split(".");
  if (parts.length === 0) return null;

  const normalized = parts.slice(0, 3).map((part) => Number.parseInt(part, 10));
  while (normalized.length < 3) normalized.push(0);
  if (normalized.some((part) => Number.isNaN(part))) return null;
  return normalized;
}

function compareSemver(left, right) {
  const a = parseSemver(left);
  const b = parseSemver(right);
  if (!a || !b) return null;
  for (let index = 0; index < 3; index += 1) {
    if (a[index] > b[index]) return 1;
    if (a[index] < b[index]) return -1;
  }
  return 0;
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function versionMatches(version, rawSpec) {
  const spec = String(rawSpec ?? "").trim();
  if (!spec || spec === "*" || spec.toLowerCase() === "any") return true;
  if (!version) return false;

  const normalizedVersion = String(version).trim();

  if (spec.includes("*")) {
    const regex = new RegExp(`^${escapeRegex(spec).replace(/\\\*/g, ".*")}$`);
    return regex.test(normalizedVersion);
  }

  const comparatorMatch = spec.match(/^(>=|<=|>|<|=)\s*(.+)$/);
  if (comparatorMatch) {
    const operator = comparatorMatch[1];
    const target = comparatorMatch[2].trim();
    const compared = compareSemver(normalizedVersion, target);
    if (compared === null) return false;
    if (operator === ">=") return compared >= 0;
    if (operator === "<=") return compared <= 0;
    if (operator === ">") return compared > 0;
    if (operator === "<") return compared < 0;
    return compared === 0;
  }

  if (spec.startsWith("^")) {
    const target = parseSemver(spec.slice(1));
    const current = parseSemver(normalizedVersion);
    if (!target || !current) return false;
    return current[0] === target[0] && compareSemver(normalizedVersion, spec.slice(1)) !== -1;
  }

  if (spec.startsWith("~")) {
    const target = parseSemver(spec.slice(1));
    const current = parseSemver(normalizedVersion);
    if (!target || !current) return false;
    return current[0] === target[0] && current[1] === target[1] && compareSemver(normalizedVersion, spec.slice(1)) !== -1;
  }

  return normalizedVersion === spec || normalizedVersion === spec.replace(/^v/i, "");
}

function parseAffectedSpecifier(rawSpecifier) {
  const specifier = String(rawSpecifier ?? "").trim();
  if (!specifier) return null;
  const atIndex = specifier.lastIndexOf("@");
  if (atIndex <= 0) {
    return { name: specifier, versionSpec: "*" };
  }
  return {
    name: specifier.slice(0, atIndex),
    versionSpec: specifier.slice(atIndex + 1),
  };
}

function affectedSpecifierMatches(specifier, skillName, version) {
  const parsed = parseAffectedSpecifier(specifier);
  if (!parsed) return false;
  if (normalizeSkillName(parsed.name) !== normalizeSkillName(skillName)) return false;
  return versionMatches(version, parsed.versionSpec);
}

function affectedSpecifierMatchesNameOnly(specifier, skillName) {
  const parsed = parseAffectedSpecifier(specifier);
  if (!parsed) return false;
  return normalizeSkillName(parsed.name) === normalizeSkillName(skillName);
}

function advisoryLooksHighRisk(advisory) {
  const type = String(advisory.type ?? "").toLowerCase();
  const severity = String(advisory.severity ?? "").toLowerCase();
  const combined = `${advisory.title ?? ""} ${advisory.description ?? ""} ${advisory.action ?? ""}`.toLowerCase();
  if (type === "malicious_skill" || type === "malicious_plugin") return true;
  if (/\b(malicious|exfiltrat|backdoor|trojan|stealer|credential theft)\b/.test(combined)) return true;
  if (/\b(remove|uninstall|disable|do not use|quarantine)\b/.test(combined)) return true;
  if (severity === "critical") return true;
  return false;
}

async function loadRemoteFeed(feedUrl) {
  const fetchFn = globalThis.fetch;
  if (typeof fetchFn !== "function") return null;

  const controller = new globalThis.AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetchFn(feedUrl, {
      method: "GET",
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
    if (!response.ok) return null;
    const payload = await response.json();
    if (!isObject(payload) || !Array.isArray(payload.advisories)) return null;
    return payload;
  } catch {
    return null;
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

async function loadFeed() {
  const feedUrl = process.env.CLAWSEC_FEED_URL || DEFAULT_FEED_URL;
  const localFeedPath = process.env.CLAWSEC_LOCAL_FEED || DEFAULT_LOCAL_FEED;

  const remoteFeed = await loadRemoteFeed(feedUrl);
  if (remoteFeed) return { feed: remoteFeed, source: `remote:${feedUrl}` };

  const raw = await fs.readFile(localFeedPath, "utf8");
  const payload = JSON.parse(raw);
  if (!isObject(payload) || !Array.isArray(payload.advisories)) {
    throw new Error(`Invalid fallback advisory feed format: ${localFeedPath}`);
  }
  return { feed: payload, source: `local:${localFeedPath}` };
}

function findMatches(feed, skillName, version) {
  const advisories = Array.isArray(feed.advisories) ? feed.advisories : [];
  const matches = [];

  for (const advisory of advisories) {
    const affected = Array.isArray(advisory.affected) ? advisory.affected : [];
    if (affected.length === 0) continue;

    const matchedAffected = uniqueStrings(
      affected.filter((specifier) =>
        version
          ? affectedSpecifierMatches(specifier, skillName, version)
          : affectedSpecifierMatchesNameOnly(specifier, skillName),
      ),
    );

    if (matchedAffected.length > 0) {
      matches.push({ advisory, matchedAffected });
    }
  }

  return matches;
}

function printMatches(matches, skillName, version) {
  process.stdout.write("Advisory matches detected for requested install target.\n");
  process.stdout.write(`Target: ${skillName}${version ? `@${version}` : ""}\n`);

  for (const entry of matches) {
    const advisory = entry.advisory;
    const severity = String(advisory.severity ?? "unknown").toUpperCase();
    const advisoryId = advisory.id ?? "unknown-id";
    const title = advisory.title ?? "Untitled advisory";
    process.stdout.write(`- [${severity}] ${advisoryId}: ${title}\n`);
    process.stdout.write(`  matched: ${entry.matchedAffected.join(", ")}\n`);
    if (advisory.action) {
      process.stdout.write(`  action: ${advisory.action}\n`);
    }
  }
}

function runInstall(skillName, version) {
  const target = version ? `${skillName}@${version}` : skillName;
  process.stdout.write(`Install target: ${target}\n`);

  const result = spawnSync("npx", ["clawhub@latest", "install", target], {
    stdio: "inherit",
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const { feed, source } = await loadFeed();
  const matches = findMatches(feed, args.skill, args.version);
  const highRisk = matches.some((entry) => advisoryLooksHighRisk(entry.advisory));

  process.stdout.write(`Advisory source: ${source}\n`);

  if (matches.length > 0) {
    printMatches(matches, args.skill, args.version);

    process.stdout.write("\n");
    process.stdout.write("Install request recognized as first confirmation.\n");
    process.stdout.write("Additional explicit confirmation is required with advisory context.\n");

    if (!args.confirmAdvisory) {
      process.stdout.write(
        "Re-run with --confirm-advisory to proceed after the user explicitly confirms.\n",
      );
      process.exit(EXIT_CONFIRM_REQUIRED);
    }
    process.stdout.write("Second confirmation provided via --confirm-advisory.\n");
  }

  if (args.dryRun) {
    process.stdout.write("Dry run only; install command was not executed.\n");
    return;
  }

  if (highRisk) {
    process.stdout.write(
      "High-risk advisory context acknowledged. Proceeding only because --confirm-advisory was provided.\n",
    );
  }

  runInstall(args.skill, args.version);
}

main().catch((error) => {
  process.stderr.write(`${String(error)}\n`);
  process.exit(1);
});
