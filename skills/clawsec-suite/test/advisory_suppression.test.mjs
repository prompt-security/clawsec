#!/usr/bin/env node

/**
 * Advisory suppression tests for clawsec-suite.
 *
 * Tests cover:
 * - isAdvisorySuppressed matching logic (exact checkId + normalized skill name)
 * - Partial matches do not suppress (checkId only, skill only)
 * - Empty suppressions never suppress
 * - loadAdvisorySuppression sentinel gating (enabledFor: ["advisory"])
 * - Missing sentinel returns empty config
 * - Wrong sentinel (only "audit") returns empty config
 *
 * Run: node skills/clawsec-suite/test/advisory_suppression.test.mjs
 */

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB_PATH = path.resolve(__dirname, "..", "hooks", "clawsec-advisory-guardian", "lib");

const { isAdvisorySuppressed, loadAdvisorySuppression } = await import(
  `${LIB_PATH}/suppression.mjs`
);

let tempDir;
let passCount = 0;
let failCount = 0;

function pass(name) {
  passCount++;
  console.log(`\u2713 ${name}`);
}

function fail(name, error) {
  failCount++;
  console.error(`\u2717 ${name}`);
  console.error(`  ${String(error)}`);
}

async function setupTestDir() {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "advisory-suppression-test-"));
}

async function cleanupTestDir() {
  if (tempDir) {
    await fs.rm(tempDir, { recursive: true, force: true });
  }
}

function makeMatch(advisoryId, skillName, version = "1.0.0") {
  return {
    advisory: { id: advisoryId, severity: "high", title: `Advisory ${advisoryId}` },
    skill: { name: skillName, dirName: skillName, version },
    matchedAffected: [`${skillName}@<=${version}`],
  };
}

function makeRules(entries) {
  return entries.map(([checkId, skill, reason]) => ({
    checkId,
    skill,
    reason: reason || "Test suppression",
    suppressedAt: "2026-02-15",
  }));
}

// ---------------------------------------------------------------------------
// isAdvisorySuppressed tests
// ---------------------------------------------------------------------------

async function testExactMatch() {
  const testName = "isAdvisorySuppressed: exact match suppresses";
  try {
    const match = makeMatch("CVE-2026-25593", "clawsec-suite");
    const rules = makeRules([["CVE-2026-25593", "clawsec-suite"]]);
    if (isAdvisorySuppressed(match, rules) === true) {
      pass(testName);
    } else {
      fail(testName, "Expected suppression but got false");
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testCaseInsensitiveSkillMatch() {
  const testName = "isAdvisorySuppressed: case-insensitive skill name match";
  try {
    const match = makeMatch("CVE-2026-25593", "ClawSec-Suite");
    const rules = makeRules([["CVE-2026-25593", "clawsec-suite"]]);
    if (isAdvisorySuppressed(match, rules) === true) {
      pass(testName);
    } else {
      fail(testName, "Expected case-insensitive match to suppress");
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testCheckIdMismatch() {
  const testName = "isAdvisorySuppressed: checkId mismatch does not suppress";
  try {
    const match = makeMatch("CVE-2026-99999", "clawsec-suite");
    const rules = makeRules([["CVE-2026-25593", "clawsec-suite"]]);
    if (isAdvisorySuppressed(match, rules) === false) {
      pass(testName);
    } else {
      fail(testName, "Expected no suppression for mismatched checkId");
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testSkillMismatch() {
  const testName = "isAdvisorySuppressed: skill mismatch does not suppress";
  try {
    const match = makeMatch("CVE-2026-25593", "other-skill");
    const rules = makeRules([["CVE-2026-25593", "clawsec-suite"]]);
    if (isAdvisorySuppressed(match, rules) === false) {
      pass(testName);
    } else {
      fail(testName, "Expected no suppression for mismatched skill");
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testEmptySuppressions() {
  const testName = "isAdvisorySuppressed: empty suppressions never suppress";
  try {
    const match = makeMatch("CVE-2026-25593", "clawsec-suite");
    if (isAdvisorySuppressed(match, []) === false) {
      pass(testName);
    } else {
      fail(testName, "Expected no suppression with empty rules");
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testMultipleRules() {
  const testName = "isAdvisorySuppressed: multiple rules match correct one";
  try {
    const match = makeMatch("CLAW-2026-0001", "openclaw-audit-watchdog");
    const rules = makeRules([
      ["CVE-2026-25593", "clawsec-suite"],
      ["CLAW-2026-0001", "openclaw-audit-watchdog"],
    ]);
    if (isAdvisorySuppressed(match, rules) === true) {
      pass(testName);
    } else {
      fail(testName, "Expected match against second rule");
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testMissingAdvisoryId() {
  const testName = "isAdvisorySuppressed: missing advisory.id does not suppress";
  try {
    const match = {
      advisory: { severity: "high", title: "No ID advisory" },
      skill: { name: "clawsec-suite", dirName: "clawsec-suite", version: "1.0.0" },
      matchedAffected: [],
    };
    const rules = makeRules([["CVE-2026-25593", "clawsec-suite"]]);
    if (isAdvisorySuppressed(match, rules) === false) {
      pass(testName);
    } else {
      fail(testName, "Expected no suppression when advisory has no id");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// ---------------------------------------------------------------------------
// loadAdvisorySuppression tests
// ---------------------------------------------------------------------------

async function testLoadWithAdvisorySentinel() {
  const testName = "loadAdvisorySuppression: loads config with advisory sentinel";
  try {
    const configFile = path.join(tempDir, "advisory-config.json");
    await fs.writeFile(configFile, JSON.stringify({
      enabledFor: ["advisory"],
      suppressions: [{
        checkId: "CVE-2026-25593",
        skill: "clawsec-suite",
        reason: "First-party tooling",
        suppressedAt: "2026-02-15",
      }],
    }));

    const config = await loadAdvisorySuppression(configFile);
    if (config.suppressions.length === 1 && config.source === configFile) {
      pass(testName);
    } else {
      fail(testName, `Expected 1 suppression from ${configFile}, got: ${JSON.stringify(config)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testLoadWithMissingSentinel() {
  const testName = "loadAdvisorySuppression: missing sentinel returns empty config";
  try {
    const configFile = path.join(tempDir, "no-sentinel.json");
    await fs.writeFile(configFile, JSON.stringify({
      suppressions: [{
        checkId: "CVE-2026-25593",
        skill: "clawsec-suite",
        reason: "First-party tooling",
        suppressedAt: "2026-02-15",
      }],
    }));

    const config = await loadAdvisorySuppression(configFile);
    if (config.suppressions.length === 0) {
      pass(testName);
    } else {
      fail(testName, `Expected empty suppressions without sentinel, got: ${JSON.stringify(config)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testLoadWithAuditOnlySentinel() {
  const testName = "loadAdvisorySuppression: audit-only sentinel returns empty for advisory";
  try {
    const configFile = path.join(tempDir, "audit-only.json");
    await fs.writeFile(configFile, JSON.stringify({
      enabledFor: ["audit"],
      suppressions: [{
        checkId: "CVE-2026-25593",
        skill: "clawsec-suite",
        reason: "First-party tooling",
        suppressedAt: "2026-02-15",
      }],
    }));

    const config = await loadAdvisorySuppression(configFile);
    if (config.suppressions.length === 0) {
      pass(testName);
    } else {
      fail(testName, `Expected empty for audit-only sentinel, got: ${JSON.stringify(config)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testLoadWithBothSentinels() {
  const testName = "loadAdvisorySuppression: both audit+advisory sentinels activates advisory";
  try {
    const configFile = path.join(tempDir, "both-sentinel.json");
    await fs.writeFile(configFile, JSON.stringify({
      enabledFor: ["audit", "advisory"],
      suppressions: [{
        checkId: "CVE-2026-25593",
        skill: "clawsec-suite",
        reason: "First-party tooling",
        suppressedAt: "2026-02-15",
      }],
    }));

    const config = await loadAdvisorySuppression(configFile);
    if (config.suppressions.length === 1) {
      pass(testName);
    } else {
      fail(testName, `Expected 1 suppression with both sentinels, got: ${JSON.stringify(config)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testLoadNonexistentExplicitPath() {
  const testName = "loadAdvisorySuppression: explicit nonexistent path throws";
  try {
    await loadAdvisorySuppression(path.join(tempDir, "does-not-exist.json"));
    fail(testName, "Expected error for nonexistent explicit path");
  } catch (error) {
    if (String(error).includes("not found")) {
      pass(testName);
    } else {
      fail(testName, `Unexpected error: ${error}`);
    }
  }
}

async function testLoadNoConfigReturnsEmpty() {
  const testName = "loadAdvisorySuppression: no config available returns empty";
  try {
    // Clear env var to ensure no ambient config
    const savedEnv = process.env.OPENCLAW_AUDIT_CONFIG;
    delete process.env.OPENCLAW_AUDIT_CONFIG;

    try {
      // Call without explicit path and with no env var — falls through to default paths
      // which likely don't exist in test environment
      const config = await loadAdvisorySuppression();
      if (config.suppressions.length === 0 && config.source === "none") {
        pass(testName);
      } else {
        fail(testName, `Expected empty config, got: ${JSON.stringify(config)}`);
      }
    } finally {
      if (savedEnv !== undefined) process.env.OPENCLAW_AUDIT_CONFIG = savedEnv;
      else delete process.env.OPENCLAW_AUDIT_CONFIG;
    }
  } catch (error) {
    fail(testName, error);
  }
}

// ---------------------------------------------------------------------------
// Main test runner
// ---------------------------------------------------------------------------
async function runAllTests() {
  console.log("=== Advisory Suppression Tests ===\n");

  await setupTestDir();

  try {
    // isAdvisorySuppressed tests
    await testExactMatch();
    await testCaseInsensitiveSkillMatch();
    await testCheckIdMismatch();
    await testSkillMismatch();
    await testEmptySuppressions();
    await testMultipleRules();
    await testMissingAdvisoryId();

    // loadAdvisorySuppression tests
    await testLoadWithAdvisorySentinel();
    await testLoadWithMissingSentinel();
    await testLoadWithAuditOnlySentinel();
    await testLoadWithBothSentinels();
    await testLoadNonexistentExplicitPath();
    await testLoadNoConfigReturnsEmpty();
  } finally {
    await cleanupTestDir();
  }

  console.log("");
  console.log(`=== Results: ${passCount} passed, ${failCount} failed ===`);

  if (failCount > 0) {
    process.exit(1);
  }
}

runAllTests().catch((err) => {
  console.error("Test runner failed:", err);
  process.exit(1);
});
