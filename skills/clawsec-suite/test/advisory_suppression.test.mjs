#!/usr/bin/env node

/**
 * Advisory suppression tests for clawsec-suite.
 *
 * Tests cover:
 * - isAdvisorySuppressed matching logic (canonical/alias checkId + normalized skill name)
 * - notification deduplication across GHSA-to-CVE canonical migration
 * - Partial matches do not suppress (checkId only, skill only)
 * - Empty suppressions never suppress
 * - loadAdvisorySuppression sentinel gating (enabledFor: ["advisory"])
 * - Missing sentinel returns empty config
 * - Wrong sentinel (only "audit") returns empty config
 *
 * Run: node skills/clawsec-suite/test/advisory_suppression.test.mjs
 */

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pass, fail, report, exitWithResults, createTempDir } from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB_PATH = path.resolve(__dirname, "..", "hooks", "clawsec-advisory-guardian", "lib");

const { isAdvisorySuppressed, loadAdvisorySuppression } = await import(
  `${LIB_PATH}/suppression.mjs`
);
const {
  affectedSpecifierMatchesSkill,
  buildAlertMessage,
  matchKeys,
  recordMatchNotification,
} = await import(`${LIB_PATH}/matching.ts`);

let tempDir;

function makeMatch(advisoryId, skillName, version = "1.0.0", advisoryFields = {}) {
  return {
    advisory: {
      id: advisoryId,
      severity: "high",
      title: `Advisory ${advisoryId}`,
      ...advisoryFields,
    },
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

async function testAlternateIdentifiersMatch() {
  const testName = "isAdvisorySuppressed: cve_id, ghsa_id, and aliases suppress canonical advisory";
  try {
    const match = makeMatch("CLAW-2026-0001", "clawsec-suite", "1.0.0", {
      cve_id: "CVE-2026-25593",
      ghsa_id: "GHSA-aaaa-bbbb-cccc",
      ghsa_ids: ["GHSA-gggg-hhhh-iiii"],
      aliases: ["GHSA-dddd-eeee-ffff"],
    });
    const alternateIds = [
      "CVE-2026-25593",
      "GHSA-aaaa-bbbb-cccc",
      "GHSA-dddd-eeee-ffff",
      "GHSA-gggg-hhhh-iiii",
    ];
    const allSuppressed = alternateIds.every((checkId) =>
      isAdvisorySuppressed(match, makeRules([[checkId, "clawsec-suite"]])),
    );

    if (allSuppressed) {
      pass(testName);
    } else {
      fail(testName, "Expected every alternate identifier to match the suppression rule");
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testNotificationDedupeAcrossCanonicalMigration() {
  const testName = "notification state: GHSA notification deduplicates CVE canonical migration";
  try {
    const match = makeMatch("CVE-2026-25593", "ClawSec-Suite", "1.0.0", {
      cve_id: "CVE-2026-25593",
      ghsa_id: "GHSA-aaaa-bbbb-cccc",
      aliases: ["GHSA-aaaa-bbbb-cccc"],
    });
    const keys = matchKeys(match);
    const previousTimestamp = "2026-02-15T00:00:00.000Z";
    const currentTimestamp = "2026-09-28T00:00:00.000Z";
    const notifiedMatches = {
      "GHSA-aaaa-bbbb-cccc::clawsec-suite@1.0.0": previousTimestamp,
    };

    const isNew = recordMatchNotification(match, notifiedMatches, currentTimestamp);
    const allKeysBackfilled = keys.every((key) => notifiedMatches[key] === previousTimestamp);
    if (isNew === false && allKeysBackfilled) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected existing GHSA timestamp to deduplicate and backfill all keys: ${JSON.stringify(notifiedMatches)}`,
      );
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testNewNotificationRecordsAllIdentifiers() {
  const testName = "notification state: new alert records canonical and alias keys";
  try {
    const match = makeMatch("CVE-2026-25593", "clawsec-suite", "1.0.0", {
      aliases: ["GHSA-aaaa-bbbb-cccc"],
    });
    const timestamp = "2026-09-28T00:00:00.000Z";
    const notifiedMatches = {};
    const isNew = recordMatchNotification(match, notifiedMatches, timestamp);
    const allKeysRecorded = matchKeys(match).every((key) => notifiedMatches[key] === timestamp);

    if (isNew === true && allKeysRecorded) {
      pass(testName);
    } else {
      fail(testName, `Expected canonical and alias keys to be recorded: ${JSON.stringify(notifiedMatches)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testUnknownInstalledVersionIsIndeterminate() {
  const testName = "matching: unknown installed version is surfaced as indeterminate";
  try {
    const skill = { name: "helper-plus", dirName: "helper-plus", version: "unknown" };
    const match = makeMatch("CVE-2026-25593", "helper-plus", "unknown", {
      action: "Upgrade helper-plus.",
    });
    match.matchedAffected = ["helper-plus@<2.0.0"];

    const candidateMatch = affectedSpecifierMatchesSkill("helper-plus@<2.0.0", skill);
    const knownSafeDoesNotMatch = affectedSpecifierMatchesSkill(
      "helper-plus@<2.0.0",
      { ...skill, version: "2.0.0" },
    ) === false;
    const alert = buildAlertMessage([match], "/tmp/skills");

    if (
      candidateMatch
      && knownSafeDoesNotMatch
      && alert.includes("INDETERMINATE: installed version unknown")
      && alert.includes("Version confirmation needed")
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected an explicit indeterminate alert, got: ${alert}`);
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
    const configFile = path.join(tempDir.path, "advisory-config.json");
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
    const configFile = path.join(tempDir.path, "no-sentinel.json");
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
    const configFile = path.join(tempDir.path, "audit-only.json");
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
    const configFile = path.join(tempDir.path, "both-sentinel.json");
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
    await loadAdvisorySuppression(path.join(tempDir.path, "does-not-exist.json"));
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

async function testEnvPathHomeExpansion() {
  const testName = "loadAdvisorySuppression: OPENCLAW_AUDIT_CONFIG expands $HOME";
  try {
    const configFile = path.join(tempDir.path, "env-home.json");
    await fs.writeFile(configFile, JSON.stringify({
      enabledFor: ["advisory"],
      suppressions: [{
        checkId: "CVE-2026-25593",
        skill: "clawsec-suite",
        reason: "Env home expansion",
        suppressedAt: "2026-02-15",
      }],
    }));

    const savedConfig = process.env.OPENCLAW_AUDIT_CONFIG;
    const savedHome = process.env.HOME;
    process.env.HOME = tempDir.path;
    process.env.OPENCLAW_AUDIT_CONFIG = "$HOME/env-home.json";
    try {
      const config = await loadAdvisorySuppression();
      if (config.suppressions.length === 1 && config.source === configFile) {
        pass(testName);
      } else {
        fail(testName, `Expected env-expanded config, got: ${JSON.stringify(config)}`);
      }
    } finally {
      if (savedConfig !== undefined) process.env.OPENCLAW_AUDIT_CONFIG = savedConfig;
      else delete process.env.OPENCLAW_AUDIT_CONFIG;
      if (savedHome !== undefined) process.env.HOME = savedHome;
      else delete process.env.HOME;
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testEscapedHomeTokenRejected() {
  const testName = "loadAdvisorySuppression: escaped home token is rejected";
  try {
    const savedEnv = process.env.OPENCLAW_AUDIT_CONFIG;
    process.env.OPENCLAW_AUDIT_CONFIG = "\\$HOME/not-real.json";
    try {
      await loadAdvisorySuppression();
      fail(testName, "Expected error for escaped token");
    } catch (error) {
      if (String(error).includes("Unexpanded home token")) {
        pass(testName);
      } else {
        fail(testName, `Unexpected error: ${error}`);
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

  tempDir = await createTempDir();

  try {
    // isAdvisorySuppressed tests
    await testExactMatch();
    await testCaseInsensitiveSkillMatch();
    await testAlternateIdentifiersMatch();
    await testNotificationDedupeAcrossCanonicalMigration();
    await testNewNotificationRecordsAllIdentifiers();
    await testUnknownInstalledVersionIsIndeterminate();
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
    await testEnvPathHomeExpansion();
    await testEscapedHomeTokenRejected();
  } finally {
    await tempDir.cleanup();
  }

  report();
  exitWithResults();
}

runAllTests().catch((err) => {
  console.error("Test runner failed:", err);
  process.exit(1);
});
