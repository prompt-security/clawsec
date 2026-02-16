#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

const DEFAULT_PRIMARY_PATH = path.join(os.homedir(), ".openclaw", "security-audit.json");
const DEFAULT_FALLBACK_PATH = ".clawsec/allowlist.json";

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
      throw new Error(`Invalid suppression at index ${i} in ${source}: ${err.message}`);
    }
  }

  return {
    suppressions,
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
      throw new Error(`Permission denied reading config file: ${configPath}`);
    }
    if (err instanceof SyntaxError) {
      throw new Error(`Malformed JSON in config file ${configPath}: ${err.message}`);
    }
    // Re-throw validation errors or other errors
    throw err;
  }
}

/**
 * Load suppression configuration with multi-path fallback.
 *
 * Behavior:
 *   - Checks primary path: ~/.openclaw/security-audit.json (or OPENCLAW_AUDIT_CONFIG env var)
 *   - Falls back to: .clawsec/allowlist.json
 *   - Returns empty suppressions array if no config found
 *   - Throws on malformed JSON or validation errors
 *
 * @param {string} [customPath] - Optional custom config file path
 * @returns {Promise<{suppressions: Array, source: string}>}
 */
export async function loadSuppressionConfig(customPath = null) {
  // Priority 1: Custom path provided as argument
  if (customPath) {
    const config = await loadConfigFromPath(customPath);
    if (!config) {
      throw new Error(`Custom config file not found: ${customPath}`);
    }
    return config;
  }

  // Priority 2: Environment variable
  const envPath = process.env.OPENCLAW_AUDIT_CONFIG;
  if (envPath) {
    const config = await loadConfigFromPath(envPath);
    if (!config) {
      throw new Error(`Config file from OPENCLAW_AUDIT_CONFIG not found: ${envPath}`);
    }
    return config;
  }

  // Priority 3: Primary default path
  const primaryPath = DEFAULT_PRIMARY_PATH;
  const primaryConfig = await loadConfigFromPath(primaryPath);
  if (primaryConfig) {
    return primaryConfig;
  }

  // Priority 4: Fallback path
  const fallbackPath = DEFAULT_FALLBACK_PATH;
  const fallbackConfig = await loadConfigFromPath(fallbackPath);
  if (fallbackConfig) {
    return fallbackConfig;
  }

  // No config found - return empty suppressions (graceful fallback)
  return {
    suppressions: [],
    source: "none",
  };
}

// CLI usage when run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const customPath = process.argv[2];

  try {
    const config = await loadSuppressionConfig(customPath || null);

    if (config.suppressions.length === 0) {
      process.stdout.write("No suppression config found - graceful fallback to empty suppressions\n");
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
