#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

const DEFAULT_PRIMARY_PATH = path.join(os.homedir(), ".openclaw", "security-audit.json");
const DEFAULT_FALLBACK_PATH = ".clawsec/allowlist.json";
const UNEXPANDED_HOME_TOKEN_PATTERN =
  /(?:^|[\\/])(?:\\?\$HOME|\\?\$\{HOME\}|\\?\$USERPROFILE|\\?\$\{USERPROFILE\}|%HOME%|%USERPROFILE%|\$env:HOME|\$env:USERPROFILE)(?:$|[\\/])/i;

function detectHomeDirectory(env = process.env) {
  if (typeof env.HOME === "string" && env.HOME.trim()) return env.HOME.trim();
  if (typeof env.USERPROFILE === "string" && env.USERPROFILE.trim()) return env.USERPROFILE.trim();
  if (
    typeof env.HOMEDRIVE === "string" &&
    env.HOMEDRIVE.trim() &&
    typeof env.HOMEPATH === "string" &&
    env.HOMEPATH.trim()
  ) {
    return `${env.HOMEDRIVE.trim()}${env.HOMEPATH.trim()}`;
  }
  return os.homedir();
}

function resolveUserPath(inputPath, label) {
  const raw = String(inputPath ?? "").trim();
  if (!raw) return raw;

  const homeDir = detectHomeDirectory(process.env);
  let expanded = raw;

  if (expanded === "~") {
    expanded = homeDir;
  } else if (expanded.startsWith("~/") || expanded.startsWith("~\\")) {
    expanded = path.join(homeDir, expanded.slice(2));
  }

  expanded = expanded
    .replace(/(?<!\\)\$\{HOME\}/g, homeDir)
    .replace(/(?<!\\)\$HOME(?=$|[\\/])/g, homeDir)
    .replace(/(?<!\\)\$\{USERPROFILE\}/gi, homeDir)
    .replace(/(?<!\\)\$USERPROFILE(?=$|[\\/])/gi, homeDir)
    .replace(/%HOME%/gi, homeDir)
    .replace(/%USERPROFILE%/gi, homeDir)
    .replace(/(?<!\\)\$env:HOME/gi, homeDir)
    .replace(/(?<!\\)\$env:USERPROFILE/gi, homeDir);

  const normalized = path.normalize(expanded);
  if (UNEXPANDED_HOME_TOKEN_PATTERN.test(normalized)) {
    throw new Error(
      `Unexpanded home token detected in ${label}: ${raw}. ` +
        "Use an absolute path or an unquoted home-path expression.",
    );
  }
  return normalized;
}

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeString(value, fallback = "") {
  return String(value ?? fallback).trim();
}

function normalizeDate(value) {
  const str = normalizeString(value);
  if (!str) return null;

  // Validate ISO 8601 date format (YYYY-MM-DD)
  const iso8601Pattern = /^\d{4}-\d{2}-\d{2}$/;
  if (!iso8601Pattern.test(str)) {
    return null;
  }

  return str;
}

function validateSuppression(entry, index) {
  if (!isObject(entry)) {
    throw new Error(`Suppression entry at index ${index} must be an object`);
  }

  const checkId = normalizeString(entry.checkId);
  if (!checkId) {
    throw new Error(`Suppression entry at index ${index} missing required field: checkId`);
  }

  const skill = normalizeString(entry.skill);
  if (!skill) {
    throw new Error(`Suppression entry at index ${index} missing required field: skill`);
  }

  const reason = normalizeString(entry.reason);
  if (!reason) {
    throw new Error(`Suppression entry at index ${index} missing required field: reason`);
  }

  if (!entry.suppressedAt) {
    throw new Error(`Suppression entry at index ${index} missing required field: suppressedAt`);
  }

  const suppressedAt = normalizeDate(entry.suppressedAt);
  if (!suppressedAt) {
    // Warn but don't fail - allow suppression to work with malformed date
    process.stderr.write(
      `Warning: Suppression entry at index ${index} has malformed date '${entry.suppressedAt}'. Expected ISO 8601 format (YYYY-MM-DD).\n`
    );
  }

  return {
    checkId,
    skill,
    reason,
    suppressedAt: suppressedAt || normalizeString(entry.suppressedAt),
  };
}

function normalizeSuppressionConfig(payload, source) {
  if (!isObject(payload)) {
    throw new Error(`Config file at ${source} must be a JSON object`);
  }

  const rawSuppressions = payload.suppressions;
  if (!Array.isArray(rawSuppressions)) {
    throw new Error(`Config file at ${source} missing 'suppressions' array`);
  }

  const suppressions = [];
  for (let i = 0; i < rawSuppressions.length; i++) {
    try {
      const normalized = validateSuppression(rawSuppressions[i], i);
      suppressions.push(normalized);
    } catch (err) {
      throw new Error(`Invalid suppression at index ${i} in ${source}: ${err.message}`, { cause: err });
    }
  }

  // Extract enabledFor sentinel (array of pipeline names this config activates for)
  const enabledFor = Array.isArray(payload.enabledFor)
    ? payload.enabledFor.filter((v) => typeof v === "string" && v.trim() !== "").map((v) => v.trim().toLowerCase())
    : [];

  return {
    suppressions,
    enabledFor,
    source,
  };
}

async function loadConfigFromPath(configPath) {
  try {
    const raw = await fs.readFile(configPath, "utf8");
    const parsed = JSON.parse(raw);
    return normalizeSuppressionConfig(parsed, configPath);
  } catch (err) {
    if (err.code === "ENOENT") {
      // File doesn't exist - return null to try fallback
      return null;
    }
    if (err.code === "EACCES") {
      throw new Error(`Permission denied reading config file: ${configPath}`, { cause: err });
    }
    if (err instanceof SyntaxError) {
      throw new Error(`Malformed JSON in config file ${configPath}: ${err.message}`, { cause: err });
    }
    // Re-throw validation errors or other errors
    throw err;
  }
}

const EMPTY_RESULT = Object.freeze({ suppressions: [], source: "none" });

/**
 * Resolve config from the 4-tier priority chain.
 * Returns the loaded config or null if no config found.
 */
async function resolveConfig(customPath) {
  // Priority 1: Custom path provided as argument
  if (customPath) {
    const resolved = resolveUserPath(customPath, "custom suppression config path");
    const config = await loadConfigFromPath(resolved);
    if (!config) {
      throw new Error(`Custom config file not found: ${resolved}`);
    }
    return config;
  }

  // Priority 2: Environment variable
  const envPath = process.env.OPENCLAW_AUDIT_CONFIG;
  if (envPath) {
    const resolved = resolveUserPath(envPath, "OPENCLAW_AUDIT_CONFIG");
    const config = await loadConfigFromPath(resolved);
    if (!config) {
      throw new Error(`Config file from OPENCLAW_AUDIT_CONFIG not found: ${resolved}`);
    }
    return config;
  }

  // Priority 3: Primary default path
  const primaryConfig = await loadConfigFromPath(DEFAULT_PRIMARY_PATH);
  if (primaryConfig) return primaryConfig;

  // Priority 4: Fallback path
  const fallbackConfig = await loadConfigFromPath(DEFAULT_FALLBACK_PATH);
  if (fallbackConfig) return fallbackConfig;

  return null;
}

/**
 * Load suppression configuration with multi-path fallback and opt-in gating.
 *
 * Suppression requires explicit opt-in to prevent ambient activation:
 *   1. The `enabled` flag must be true (set via --enable-suppressions CLI flag)
 *   2. The config file must contain an `enabledFor` array including "audit"
 *
 * Without both gates, returns empty suppressions.
 *
 * @param {string} [customPath] - Optional custom config file path
 * @param {object} [options]
 * @param {boolean} [options.enabled=false] - Whether suppression is explicitly enabled
 * @param {string} [options.pipeline="audit"] - Pipeline to check in enabledFor sentinel
 * @returns {Promise<{suppressions: Array, source: string}>}
 */
export async function loadSuppressionConfig(customPath = null, { enabled = false, pipeline = "audit" } = {}) {
  // Gate 1: suppression must be explicitly opted-in via CLI flag
  if (!enabled) {
    return EMPTY_RESULT;
  }

  const config = await resolveConfig(customPath);
  if (!config) {
    return EMPTY_RESULT;
  }

  // Gate 2: config must declare this pipeline in enabledFor sentinel
  if (!Array.isArray(config.enabledFor) || !config.enabledFor.includes(pipeline)) {
    return EMPTY_RESULT;
  }

  process.stderr.write(
    `WARNING: Suppression mechanism is enabled for "${pipeline}" pipeline via --enable-suppressions flag.\n`
  );

  return config;
}

// CLI usage when run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const enableFlag = args.includes("--enable-suppressions");
  const customPath = args.find((a) => !a.startsWith("--")) || null;

  if (!enableFlag) {
    process.stdout.write("Suppression is disabled. Pass --enable-suppressions to activate.\n");
    process.exit(0);
  }

  try {
    const config = await loadSuppressionConfig(customPath, { enabled: true });

    if (config.suppressions.length === 0) {
      process.stdout.write("No active suppressions (config missing, no enabledFor sentinel, or empty)\n");
      process.stdout.write(JSON.stringify(config, null, 2) + "\n");
      process.exit(0);
    }

    process.stdout.write(`Config loaded successfully from: ${config.source}\n`);
    process.stdout.write(`Found ${config.suppressions.length} suppression(s):\n`);
    process.stdout.write(JSON.stringify(config, null, 2) + "\n");
    process.exit(0);
  } catch (err) {
    process.stderr.write(`Error loading suppression config: ${err.message}\n`);
    process.exit(1);
  }
}
