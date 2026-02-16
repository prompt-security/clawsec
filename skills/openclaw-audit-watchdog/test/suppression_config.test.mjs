#!/usr/bin/env node

/**
 * Suppression config loading tests for openclaw-audit-watchdog.
 *
 * Tests cover:
 * - Valid config file loading and normalization
 * - Required field validation
 * - Date format validation with graceful fallback
 * - Malformed JSON error handling
 * - File not found graceful fallback
 * - Multi-path priority (custom path > env var > primary > fallback)
 *
 * Run: node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
 */

import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { loadSuppressionConfig } from "../scripts/load_suppression_config.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let passCount = 0;
let failCount = 0;

function pass(name) {
  passCount += 1;
  console.log(`✓ ${name}`);
}

function fail(name, error) {
  failCount += 1;
  console.error(`✗ ${name}`);
  console.error(`  ${String(error)}`);
}

async function withTempFile(content) {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-test-"));
  const tmpFile = path.join(tmpDir, "test-config.json");
  await fs.writeFile(tmpFile, content, "utf8");

  return {
    path: tmpFile,
    cleanup: async () => {
      try {
        await fs.rm(tmpDir, { recursive: true, force: true });
      } catch (err) {
        // Ignore cleanup errors
      }
    },
  };
}

async function withEnv(key, value, fn) {
  const oldValue = process.env[key];
  try {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
    return await fn();
  } finally {
    if (oldValue === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = oldValue;
    }
  }
}

// -----------------------------------------------------------------------------
// Test: valid config with all required fields
// -----------------------------------------------------------------------------
async function testValidConfig() {
  const testName = "loadSuppressionConfig: loads valid config with all required fields";
  let fixture = null;

  try {
    const validConfig = JSON.stringify({
      suppressions: [
        {
          checkId: "SCAN-001",
          skill: "soul-guardian",
          reason: "False positive - reviewed by security team",
          suppressedAt: "2026-02-15",
        },
        {
          checkId: "SCAN-002",
          skill: "clawtributor",
          reason: "Accepted risk for legacy code",
          suppressedAt: "2026-02-14",
        },
      ],
    });

    fixture = await withTempFile(validConfig);
    const config = await loadSuppressionConfig(fixture.path);

    if (
      config.source === fixture.path &&
      config.suppressions.length === 2 &&
      config.suppressions[0].checkId === "SCAN-001" &&
      config.suppressions[0].skill === "soul-guardian" &&
      config.suppressions[0].reason === "False positive - reviewed by security team" &&
      config.suppressions[0].suppressedAt === "2026-02-15" &&
      config.suppressions[1].checkId === "SCAN-002" &&
      config.suppressions[1].skill === "clawtributor"
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected config: ${JSON.stringify(config)}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.cleanup();
    }
  }
}

// -----------------------------------------------------------------------------
// Test: malformed date warns but doesn't fail
// -----------------------------------------------------------------------------
async function testMalformedDateWarning() {
  const testName = "loadSuppressionConfig: malformed date warns but doesn't fail";
  let fixture = null;

  try {
    const configWithBadDate = JSON.stringify({
      suppressions: [
        {
          checkId: "SCAN-003",
          skill: "soul-guardian",
          reason: "Test suppression",
          suppressedAt: "02/15/2026",
        },
      ],
    });

    fixture = await withTempFile(configWithBadDate);

    // Capture stderr to check for warning
    let stderrOutput = "";
    const originalStderrWrite = process.stderr.write;
    process.stderr.write = function (chunk) {
      stderrOutput += chunk.toString();
      return true;
    };

    try {
      const config = await loadSuppressionConfig(fixture.path);

      if (
        config.suppressions.length === 1 &&
        config.suppressions[0].checkId === "SCAN-003" &&
        config.suppressions[0].suppressedAt === "02/15/2026" &&
        stderrOutput.includes("Warning") &&
        stderrOutput.includes("malformed date")
      ) {
        pass(testName);
      } else {
        fail(testName, `Expected warning but got: ${stderrOutput}`);
      }
    } finally {
      process.stderr.write = originalStderrWrite;
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.cleanup();
    }
  }
}

// -----------------------------------------------------------------------------
// Test: missing required field fails
// -----------------------------------------------------------------------------
async function testMissingRequiredField() {
  const testName = "loadSuppressionConfig: missing required field fails";
  let fixture = null;

  try {
    const configMissingReason = JSON.stringify({
      suppressions: [
        {
          checkId: "SCAN-004",
          skill: "soul-guardian",
          suppressedAt: "2026-02-15",
        },
      ],
    });

    fixture = await withTempFile(configMissingReason);

    try {
      await loadSuppressionConfig(fixture.path);
      fail(testName, "Expected error for missing required field");
    } catch (err) {
      if (err.message.includes("missing required field: reason")) {
        pass(testName);
      } else {
        fail(testName, `Wrong error message: ${err.message}`);
      }
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.cleanup();
    }
  }
}

// -----------------------------------------------------------------------------
// Test: malformed JSON fails
// -----------------------------------------------------------------------------
async function testMalformedJSON() {
  const testName = "loadSuppressionConfig: malformed JSON fails";
  let fixture = null;

  try {
    const invalidJSON = "{ suppressions: [ { not valid json } ] }";

    fixture = await withTempFile(invalidJSON);

    try {
      await loadSuppressionConfig(fixture.path);
      fail(testName, "Expected error for malformed JSON");
    } catch (err) {
      if (err.message.includes("Malformed JSON")) {
        pass(testName);
      } else {
        fail(testName, `Wrong error message: ${err.message}`);
      }
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.cleanup();
    }
  }
}

// -----------------------------------------------------------------------------
// Test: file not found returns empty suppressions
// -----------------------------------------------------------------------------
async function testFileNotFoundGracefulFallback() {
  const testName = "loadSuppressionConfig: file not found returns empty suppressions";

  try {
    await withEnv("OPENCLAW_AUDIT_CONFIG", undefined, async () => {
      const nonExistentPath1 = path.join(os.homedir(), ".openclaw", "non-existent-12345.json");
      const nonExistentPath2 = ".clawsec/non-existent-12345.json";

      // Ensure neither path exists
      try {
        await fs.access(nonExistentPath1);
        fail(testName, "Test precondition failed: primary path should not exist");
        return;
      } catch (err) {
        // Expected - file should not exist
      }

      const config = await loadSuppressionConfig();

      if (config.source === "none" && Array.isArray(config.suppressions) && config.suppressions.length === 0) {
        pass(testName);
      } else {
        fail(testName, `Expected empty suppressions but got: ${JSON.stringify(config)}`);
      }
    });
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: custom path has highest priority
// -----------------------------------------------------------------------------
async function testCustomPathPriority() {
  const testName = "loadSuppressionConfig: custom path has highest priority";
  let fixture = null;

  try {
    const customConfig = JSON.stringify({
      suppressions: [
        {
          checkId: "CUSTOM-001",
          skill: "custom-skill",
          reason: "Custom path config",
          suppressedAt: "2026-02-15",
        },
      ],
    });

    fixture = await withTempFile(customConfig);
    const config = await loadSuppressionConfig(fixture.path);

    if (
      config.source === fixture.path &&
      config.suppressions.length === 1 &&
      config.suppressions[0].checkId === "CUSTOM-001"
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected config: ${JSON.stringify(config)}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.cleanup();
    }
  }
}

// -----------------------------------------------------------------------------
// Test: environment variable override
// -----------------------------------------------------------------------------
async function testEnvironmentVariableOverride() {
  const testName = "loadSuppressionConfig: environment variable overrides default paths";
  let fixture = null;

  try {
    const envConfig = JSON.stringify({
      suppressions: [
        {
          checkId: "ENV-001",
          skill: "env-skill",
          reason: "Environment variable config",
          suppressedAt: "2026-02-15",
        },
      ],
    });

    fixture = await withTempFile(envConfig);

    await withEnv("OPENCLAW_AUDIT_CONFIG", fixture.path, async () => {
      const config = await loadSuppressionConfig();

      if (
        config.source === fixture.path &&
        config.suppressions.length === 1 &&
        config.suppressions[0].checkId === "ENV-001"
      ) {
        pass(testName);
      } else {
        fail(testName, `Unexpected config: ${JSON.stringify(config)}`);
      }
    });
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.cleanup();
    }
  }
}

// -----------------------------------------------------------------------------
// Test: missing suppressions array fails
// -----------------------------------------------------------------------------
async function testMissingSuppressions() {
  const testName = "loadSuppressionConfig: missing suppressions array fails";
  let fixture = null;

  try {
    const configWithoutSuppressions = JSON.stringify({
      note: "This config is missing the suppressions array",
    });

    fixture = await withTempFile(configWithoutSuppressions);

    try {
      await loadSuppressionConfig(fixture.path);
      fail(testName, "Expected error for missing suppressions array");
    } catch (err) {
      if (err.message.includes("missing 'suppressions' array")) {
        pass(testName);
      } else {
        fail(testName, `Wrong error message: ${err.message}`);
      }
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.cleanup();
    }
  }
}

// -----------------------------------------------------------------------------
// Test: empty suppressions array is valid
// -----------------------------------------------------------------------------
async function testEmptySuppressions() {
  const testName = "loadSuppressionConfig: empty suppressions array is valid";
  let fixture = null;

  try {
    const emptyConfig = JSON.stringify({
      suppressions: [],
    });

    fixture = await withTempFile(emptyConfig);
    const config = await loadSuppressionConfig(fixture.path);

    if (config.source === fixture.path && config.suppressions.length === 0) {
      pass(testName);
    } else {
      fail(testName, `Unexpected config: ${JSON.stringify(config)}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.cleanup();
    }
  }
}

// -----------------------------------------------------------------------------
// Test: custom path not found throws error
// -----------------------------------------------------------------------------
async function testCustomPathNotFoundFails() {
  const testName = "loadSuppressionConfig: custom path not found throws error";

  try {
    const nonExistentPath = path.join(os.tmpdir(), "absolutely-does-not-exist-12345.json");

    try {
      await loadSuppressionConfig(nonExistentPath);
      fail(testName, "Expected error for custom path not found");
    } catch (err) {
      if (err.message.includes("Custom config file not found")) {
        pass(testName);
      } else {
        fail(testName, `Wrong error message: ${err.message}`);
      }
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Main test runner
// -----------------------------------------------------------------------------
async function runTests() {
  console.log("=== OpenClaw Audit Watchdog - Suppression Config Tests ===\n");

  await testValidConfig();
  await testMalformedDateWarning();
  await testMissingRequiredField();
  await testMalformedJSON();
  await testFileNotFoundGracefulFallback();
  await testCustomPathPriority();
  await testEnvironmentVariableOverride();
  await testMissingSuppressions();
  await testEmptySuppressions();
  await testCustomPathNotFoundFails();

  console.log(`\n=== Results: ${passCount} passed, ${failCount} failed ===`);

  if (failCount > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error("Test runner failed:", error);
  process.exit(1);
});
