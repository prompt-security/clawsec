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
 * - Opt-in gate (enabled flag must be true)
 * - enabledFor sentinel validation
 *
 * Run: node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
 */

import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { loadSuppressionConfig } from "../scripts/load_suppression_config.mjs";

let passCount = 0;
let failCount = 0;

function pass(name) {
  passCount += 1;
  console.log(`\u2713 ${name}`);
}

function fail(name, error) {
  failCount += 1;
  console.error(`\u2717 ${name}`);
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
      } catch {
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

/** Suppress stderr output during a function call (avoids noisy warnings in test output). */
async function silenceStderr(fn) {
  const original = process.stderr.write;
  process.stderr.write = () => true;
  try {
    return await fn();
  } finally {
    process.stderr.write = original;
  }
}

/** Create a valid config JSON string with enabledFor sentinel. */
function makeConfig(suppressions, enabledFor = ["audit"]) {
  return JSON.stringify({ enabledFor, suppressions });
}

// -----------------------------------------------------------------------------
// Test: valid config with all required fields
// -----------------------------------------------------------------------------
async function testValidConfig() {
  const testName = "loadSuppressionConfig: loads valid config with all required fields";
  let fixture = null;

  try {
    const validConfig = makeConfig([
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
    ]);

    fixture = await withTempFile(validConfig);
    const config = await silenceStderr(() =>
      loadSuppressionConfig(fixture.path, { enabled: true })
    );

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
    const configWithBadDate = makeConfig([
      {
        checkId: "SCAN-003",
        skill: "soul-guardian",
        reason: "Test suppression",
        suppressedAt: "02/15/2026",
      },
    ]);

    fixture = await withTempFile(configWithBadDate);

    // Capture stderr to check for warning
    let stderrOutput = "";
    const originalStderrWrite = process.stderr.write;
    process.stderr.write = function (chunk) {
      stderrOutput += chunk.toString();
      return true;
    };

    try {
      const config = await loadSuppressionConfig(fixture.path, { enabled: true });

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
    const configMissingReason = makeConfig([
      {
        checkId: "SCAN-004",
        skill: "soul-guardian",
        suppressedAt: "2026-02-15",
      },
    ]);

    fixture = await withTempFile(configMissingReason);

    try {
      await silenceStderr(() =>
        loadSuppressionConfig(fixture.path, { enabled: true })
      );
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
      await silenceStderr(() =>
        loadSuppressionConfig(fixture.path, { enabled: true })
      );
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

      // Ensure path does not exist
      try {
        await fs.access(nonExistentPath1);
        fail(testName, "Test precondition failed: primary path should not exist");
        return;
      } catch {
        // Expected - file should not exist
      }

      const config = await silenceStderr(() =>
        loadSuppressionConfig(null, { enabled: true })
      );

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
    const customConfig = makeConfig([
      {
        checkId: "CUSTOM-001",
        skill: "custom-skill",
        reason: "Custom path config",
        suppressedAt: "2026-02-15",
      },
    ]);

    fixture = await withTempFile(customConfig);
    const config = await silenceStderr(() =>
      loadSuppressionConfig(fixture.path, { enabled: true })
    );

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
    const envConfig = makeConfig([
      {
        checkId: "ENV-001",
        skill: "env-skill",
        reason: "Environment variable config",
        suppressedAt: "2026-02-15",
      },
    ]);

    fixture = await withTempFile(envConfig);

    await withEnv("OPENCLAW_AUDIT_CONFIG", fixture.path, async () => {
      const config = await silenceStderr(() =>
        loadSuppressionConfig(null, { enabled: true })
      );

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
// Test: environment variable path expands $HOME
// -----------------------------------------------------------------------------
async function testEnvironmentVariableHomeExpansion() {
  const testName = "loadSuppressionConfig: OPENCLAW_AUDIT_CONFIG expands $HOME path";
  let fixture = null;

  try {
    const envConfig = makeConfig([
      {
        checkId: "ENV-HOME-001",
        skill: "env-skill",
        reason: "Environment variable home expansion",
        suppressedAt: "2026-02-15",
      },
    ]);

    fixture = await withTempFile(envConfig);
    const fixtureDir = path.dirname(fixture.path);
    const fixtureBase = path.basename(fixture.path);

    await withEnv("HOME", fixtureDir, async () => {
      await withEnv("OPENCLAW_AUDIT_CONFIG", `$HOME/${fixtureBase}`, async () => {
        const config = await silenceStderr(() =>
          loadSuppressionConfig(null, { enabled: true })
        );

        if (
          config.source === fixture.path &&
          config.suppressions.length === 1 &&
          config.suppressions[0].checkId === "ENV-HOME-001"
        ) {
          pass(testName);
        } else {
          fail(testName, `Unexpected config: ${JSON.stringify(config)}`);
        }
      });
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
// Test: escaped token is rejected (no silent literal path use)
// -----------------------------------------------------------------------------
async function testEscapedHomeTokenRejected() {
  const testName = "loadSuppressionConfig: escaped $HOME token is rejected";
  try {
    await withEnv("OPENCLAW_AUDIT_CONFIG", "\\$HOME/config.json", async () => {
      try {
        await silenceStderr(() =>
          loadSuppressionConfig(null, { enabled: true })
        );
        fail(testName, "Expected error for escaped home token");
      } catch (err) {
        if (String(err.message || err).includes("Unexpanded home token")) {
          pass(testName);
        } else {
          fail(testName, `Wrong error message: ${err.message || err}`);
        }
      }
    });
  } catch (error) {
    fail(testName, error);
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
      enabledFor: ["audit"],
      note: "This config is missing the suppressions array",
    });

    fixture = await withTempFile(configWithoutSuppressions);

    try {
      await silenceStderr(() =>
        loadSuppressionConfig(fixture.path, { enabled: true })
      );
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
    const emptyConfig = makeConfig([], ["audit"]);

    fixture = await withTempFile(emptyConfig);
    const config = await silenceStderr(() =>
      loadSuppressionConfig(fixture.path, { enabled: true })
    );

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
      await silenceStderr(() =>
        loadSuppressionConfig(nonExistentPath, { enabled: true })
      );
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
// Test: disabled by default (enabled flag not set)
// -----------------------------------------------------------------------------
async function testDisabledByDefault() {
  const testName = "loadSuppressionConfig: returns empty when enabled flag is not set";
  let fixture = null;

  try {
    const validConfig = makeConfig([
      {
        checkId: "SCAN-001",
        skill: "test-skill",
        reason: "Should not be loaded",
        suppressedAt: "2026-02-15",
      },
    ]);
    fixture = await withTempFile(validConfig);

    // Custom path provided but enabled=false (default)
    const config1 = await loadSuppressionConfig(fixture.path);
    if (config1.source !== "none" || config1.suppressions.length !== 0) {
      fail(testName, "Custom path should be ignored when enabled is not set");
      return;
    }

    // Env var set but enabled=false (default)
    await withEnv("OPENCLAW_AUDIT_CONFIG", fixture.path, async () => {
      const config2 = await loadSuppressionConfig();
      if (config2.source !== "none" || config2.suppressions.length !== 0) {
        fail(testName, "Env var should be ignored when enabled is not set");
        return;
      }
    });

    pass(testName);
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) await fixture.cleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: enabled explicitly loads config
// -----------------------------------------------------------------------------
async function testEnabledExplicitly() {
  const testName = "loadSuppressionConfig: loads config when explicitly enabled with sentinel";
  let fixture = null;

  try {
    const validConfig = makeConfig([
      {
        checkId: "SCAN-001",
        skill: "test-skill",
        reason: "Should be loaded",
        suppressedAt: "2026-02-15",
      },
    ]);
    fixture = await withTempFile(validConfig);
    const config = await silenceStderr(() =>
      loadSuppressionConfig(fixture.path, { enabled: true })
    );

    if (config.source === fixture.path && config.suppressions.length === 1) {
      pass(testName);
    } else {
      fail(testName, `Expected config to be loaded: ${JSON.stringify(config)}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) await fixture.cleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: env var alone does not activate suppression
// -----------------------------------------------------------------------------
async function testEnvVarAloneDoesNotActivate() {
  const testName = "loadSuppressionConfig: OPENCLAW_AUDIT_CONFIG alone does not activate suppression";
  let fixture = null;

  try {
    const validConfig = makeConfig([
      {
        checkId: "ENV-ATTACK",
        skill: "target-skill",
        reason: "Attacker suppression",
        suppressedAt: "2026-02-15",
      },
    ]);
    fixture = await withTempFile(validConfig);

    await withEnv("OPENCLAW_AUDIT_CONFIG", fixture.path, async () => {
      // Without enabled: true, env var should be ignored
      const config = await loadSuppressionConfig(null, { enabled: false });
      if (config.source === "none" && config.suppressions.length === 0) {
        pass(testName);
      } else {
        fail(testName, `Env var should not activate suppression: ${JSON.stringify(config)}`);
      }
    });
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) await fixture.cleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: missing enabledFor sentinel returns empty
// -----------------------------------------------------------------------------
async function testMissingSentinel() {
  const testName = "loadSuppressionConfig: missing enabledFor sentinel returns empty";
  let fixture = null;

  try {
    // Config has suppressions but NO enabledFor field
    const configNoSentinel = JSON.stringify({
      suppressions: [
        {
          checkId: "SCAN-001",
          skill: "test-skill",
          reason: "Should not activate",
          suppressedAt: "2026-02-15",
        },
      ],
    });
    fixture = await withTempFile(configNoSentinel);
    const config = await silenceStderr(() =>
      loadSuppressionConfig(fixture.path, { enabled: true })
    );

    if (config.source === "none" && config.suppressions.length === 0) {
      pass(testName);
    } else {
      fail(testName, `Missing sentinel should return empty: ${JSON.stringify(config)}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) await fixture.cleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: wrong enabledFor sentinel returns empty
// -----------------------------------------------------------------------------
async function testWrongSentinel() {
  const testName = "loadSuppressionConfig: wrong enabledFor sentinel returns empty for audit";
  let fixture = null;

  try {
    // Config has enabledFor: ["advisory"] but not "audit"
    const configWrongSentinel = makeConfig(
      [
        {
          checkId: "SCAN-001",
          skill: "test-skill",
          reason: "Should not activate for audit",
          suppressedAt: "2026-02-15",
        },
      ],
      ["advisory"]
    );
    fixture = await withTempFile(configWrongSentinel);
    const config = await silenceStderr(() =>
      loadSuppressionConfig(fixture.path, { enabled: true })
    );

    if (config.source === "none" && config.suppressions.length === 0) {
      pass(testName);
    } else {
      fail(testName, `Wrong sentinel should return empty: ${JSON.stringify(config)}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) await fixture.cleanup();
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
  await testEnvironmentVariableHomeExpansion();
  await testEscapedHomeTokenRejected();
  await testMissingSuppressions();
  await testEmptySuppressions();
  await testCustomPathNotFoundFails();
  await testDisabledByDefault();
  await testEnabledExplicitly();
  await testEnvVarAloneDoesNotActivate();
  await testMissingSentinel();
  await testWrongSentinel();

  console.log(`\n=== Results: ${passCount} passed, ${failCount} failed ===`);

  if (failCount > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error("Test runner failed:", error);
  process.exit(1);
});
