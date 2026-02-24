#!/usr/bin/env node

/**
 * Integration tests for render_report with suppression mechanism.
 *
 * Tests cover:
 * - Suppressed findings appear in INFO-SUPPRESSED section
 * - Active findings appear in CRITICAL/WARN section
 * - Summary counts exclude suppressed findings
 * - Backward compatibility (no config)
 * - Partial matches don't suppress
 * - Multiple suppressions
 * - Skill name extraction from different fields
 *
 * Run: node skills/openclaw-audit-watchdog/test/render_report_suppression.test.mjs
 */

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.resolve(__dirname, "..", "scripts", "render_report.mjs");
const NODE_BIN = process.execPath;

let tempDir;
let passCount = 0;
let failCount = 0;

function pass(name) {
  passCount++;
  console.log(`✓ ${name}`);
}

function fail(name, error) {
  failCount++;
  console.error(`✗ ${name}`);
  console.error(`  ${String(error)}`);
}

async function setupTestDir() {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "render-report-test-"));
}

async function cleanupTestDir() {
  if (tempDir) {
    await fs.rm(tempDir, { recursive: true, force: true });
  }
}

function createAuditJson(findings) {
  return JSON.stringify({
    findings: findings,
    summary: {
      critical: findings.filter((f) => f.severity === "critical").length,
      warn: findings.filter((f) => f.severity === "warn").length,
      info: findings.filter((f) => f.severity === "info").length,
    },
  });
}

function createConfigJson(suppressions, enabledFor = ["audit"]) {
  return JSON.stringify({
    enabledFor,
    suppressions,
  });
}

async function runRenderReport(args) {
  return new Promise((resolve) => {
    const proc = spawn(NODE_BIN, [SCRIPT_PATH, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

// -----------------------------------------------------------------------------
// Test: Suppressed findings appear in INFO-SUPPRESSED section
// -----------------------------------------------------------------------------
async function testSuppressedFindingsDisplayed() {
  const testName = "render_report: suppressed findings appear in INFO-SUPPRESSED section";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");
    const configFile = path.join(tempDir, "config.json");

    const findings = [
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        title: "dangerous-exec detected",
      },
    ];

    const suppressions = [
      {
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));
    await fs.writeFile(configFile, createConfigJson(suppressions));

    const result = await runRenderReport([
      "--audit",
      auditFile,
      "--deep",
      deepFile,
      "--enable-suppressions",
      "--config",
      configFile,
    ]);

    if (
      result.stdout.includes("INFO-SUPPRESSED:") &&
      result.stdout.includes("dangerous-exec detected") &&
      result.stdout.includes("First-party security tooling") &&
      result.stdout.includes("2026-02-13")
    ) {
      pass(testName);
    } else {
      fail(testName, `Missing INFO-SUPPRESSED section or metadata: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Active findings appear in CRITICAL/WARN section
// -----------------------------------------------------------------------------
async function testActiveFindingsDisplayed() {
  const testName = "render_report: active findings appear in CRITICAL/WARN section";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");
    const configFile = path.join(tempDir, "config.json");

    const findings = [
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "malicious-skill",
        title: "dangerous-exec detected",
      },
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        title: "dangerous-exec detected in clawsec",
      },
    ];

    const suppressions = [
      {
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));
    await fs.writeFile(configFile, createConfigJson(suppressions));

    const result = await runRenderReport([
      "--audit",
      auditFile,
      "--deep",
      deepFile,
      "--enable-suppressions",
      "--config",
      configFile,
    ]);

    // Check that the non-suppressed finding appears in active section
    // and the suppressed finding appears in INFO-SUPPRESSED section
    const hasActiveFindings = result.stdout.includes("Findings (critical/warn):");
    const hasInfoSuppressed = result.stdout.includes("INFO-SUPPRESSED:");
    const hasClawsecInSuppressed = result.stdout.includes("dangerous-exec detected in clawsec");

    if (hasActiveFindings && hasInfoSuppressed && hasClawsecInSuppressed) {
      pass(testName);
    } else {
      fail(testName, `Missing active findings or suppressed section: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Summary counts exclude suppressed findings
// -----------------------------------------------------------------------------
async function testSummaryExcludesSuppressed() {
  const testName = "render_report: summary counts exclude suppressed findings";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");
    const configFile = path.join(tempDir, "config.json");

    const findings = [
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        title: "dangerous-exec detected",
      },
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "openclaw-audit-watchdog",
        title: "dangerous-exec detected",
      },
    ];

    const suppressions = [
      {
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
      {
        checkId: "skills.code_safety",
        skill: "openclaw-audit-watchdog",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));
    await fs.writeFile(configFile, createConfigJson(suppressions));

    const result = await runRenderReport([
      "--audit",
      auditFile,
      "--deep",
      deepFile,
      "--enable-suppressions",
      "--config",
      configFile,
    ]);

    // Summary should show 0 critical (both suppressed)
    if (
      result.stdout.includes("Summary: 0 critical") &&
      result.stdout.includes("INFO-SUPPRESSED:")
    ) {
      pass(testName);
    } else {
      fail(testName, `Summary should show 0 critical: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Backward compatibility (no config)
// -----------------------------------------------------------------------------
async function testBackwardCompatibilityNoConfig() {
  const testName = "render_report: backward compatibility without config file";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");

    const findings = [
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        title: "dangerous-exec detected",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));

    const result = await runRenderReport(["--audit", auditFile, "--deep", deepFile]);

    // Without config, findings should appear in critical section, NOT suppressed
    if (
      result.stdout.includes("Summary: 1 critical") &&
      result.stdout.includes("Findings (critical/warn):") &&
      !result.stdout.includes("INFO-SUPPRESSED:")
    ) {
      pass(testName);
    } else {
      fail(testName, `Findings should not be suppressed without config: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Partial matches don't suppress (checkId only)
// -----------------------------------------------------------------------------
async function testPartialMatchCheckIdOnly() {
  const testName = "render_report: partial match (checkId only) does not suppress";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");
    const configFile = path.join(tempDir, "config.json");

    const findings = [
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "different-skill",
        title: "dangerous-exec detected",
      },
    ];

    const suppressions = [
      {
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));
    await fs.writeFile(configFile, createConfigJson(suppressions));

    const result = await runRenderReport([
      "--audit",
      auditFile,
      "--deep",
      deepFile,
      "--enable-suppressions",
      "--config",
      configFile,
    ]);

    // Finding should NOT be suppressed (skill name mismatch)
    if (
      result.stdout.includes("Summary: 1 critical") &&
      result.stdout.includes("Findings (critical/warn):") &&
      !result.stdout.includes("INFO-SUPPRESSED:")
    ) {
      pass(testName);
    } else {
      fail(testName, `Partial match should not suppress: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Partial matches don't suppress (skill only)
// -----------------------------------------------------------------------------
async function testPartialMatchSkillOnly() {
  const testName = "render_report: partial match (skill only) does not suppress";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");
    const configFile = path.join(tempDir, "config.json");

    const findings = [
      {
        severity: "critical",
        checkId: "different.check",
        skill: "clawsec-suite",
        title: "some finding",
      },
    ];

    const suppressions = [
      {
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));
    await fs.writeFile(configFile, createConfigJson(suppressions));

    const result = await runRenderReport([
      "--audit",
      auditFile,
      "--deep",
      deepFile,
      "--enable-suppressions",
      "--config",
      configFile,
    ]);

    // Finding should NOT be suppressed (checkId mismatch)
    if (
      result.stdout.includes("Summary: 1 critical") &&
      result.stdout.includes("Findings (critical/warn):") &&
      !result.stdout.includes("INFO-SUPPRESSED:")
    ) {
      pass(testName);
    } else {
      fail(testName, `Partial match should not suppress: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Multiple suppressions work correctly
// -----------------------------------------------------------------------------
async function testMultipleSuppressions() {
  const testName = "render_report: multiple suppressions work correctly";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");
    const configFile = path.join(tempDir, "config.json");

    const findings = [
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        title: "dangerous-exec detected",
      },
      {
        severity: "critical",
        checkId: "skills.env_harvesting",
        skill: "openclaw-audit-watchdog",
        title: "env access detected",
      },
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "malicious-skill",
        title: "dangerous-exec in bad skill",
      },
    ];

    const suppressions = [
      {
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
      {
        checkId: "skills.env_harvesting",
        skill: "openclaw-audit-watchdog",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));
    await fs.writeFile(configFile, createConfigJson(suppressions));

    const result = await runRenderReport([
      "--audit",
      auditFile,
      "--deep",
      deepFile,
      "--enable-suppressions",
      "--config",
      configFile,
    ]);

    // Should have 1 critical (malicious-skill), 2 suppressed
    const hasCorrectSummary = result.stdout.includes("Summary: 1 critical");
    const hasActiveFindings = result.stdout.includes("dangerous-exec in bad skill");
    const hasSuppressed = result.stdout.includes("INFO-SUPPRESSED:");
    const hasSuppressed1 = result.stdout.includes("dangerous-exec detected");
    const hasSuppressed2 = result.stdout.includes("env access detected");

    if (hasCorrectSummary && hasActiveFindings && hasSuppressed && hasSuppressed1 && hasSuppressed2) {
      pass(testName);
    } else {
      fail(testName, `Multiple suppressions not working correctly: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Skill name extraction from path field
// -----------------------------------------------------------------------------
async function testSkillNameExtractionFromPath() {
  const testName = "render_report: skill name extraction from path field";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");
    const configFile = path.join(tempDir, "config.json");

    const findings = [
      {
        severity: "critical",
        checkId: "skills.code_safety",
        path: "skills/clawsec-suite/some-file.js",
        title: "dangerous-exec detected",
      },
    ];

    const suppressions = [
      {
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));
    await fs.writeFile(configFile, createConfigJson(suppressions));

    const result = await runRenderReport([
      "--audit",
      auditFile,
      "--deep",
      deepFile,
      "--enable-suppressions",
      "--config",
      configFile,
    ]);

    // Should suppress based on path extraction
    if (
      result.stdout.includes("Summary: 0 critical") &&
      result.stdout.includes("INFO-SUPPRESSED:") &&
      result.stdout.includes("dangerous-exec detected")
    ) {
      pass(testName);
    } else {
      fail(testName, `Skill name extraction from path failed: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Skill name extraction from title field
// -----------------------------------------------------------------------------
async function testSkillNameExtractionFromTitle() {
  const testName = "render_report: skill name extraction from title field";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");
    const configFile = path.join(tempDir, "config.json");

    const findings = [
      {
        severity: "critical",
        checkId: "skills.code_safety",
        title: "[clawsec-suite] dangerous-exec detected",
      },
    ];

    const suppressions = [
      {
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));
    await fs.writeFile(configFile, createConfigJson(suppressions));

    const result = await runRenderReport([
      "--audit",
      auditFile,
      "--deep",
      deepFile,
      "--enable-suppressions",
      "--config",
      configFile,
    ]);

    // Should suppress based on title extraction
    if (
      result.stdout.includes("Summary: 0 critical") &&
      result.stdout.includes("INFO-SUPPRESSED:")
    ) {
      pass(testName);
    } else {
      fail(testName, `Skill name extraction from title failed: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Empty suppressions array works (no suppressions applied)
// -----------------------------------------------------------------------------
async function testEmptySuppressions() {
  const testName = "render_report: empty suppressions array behaves like no config";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");
    const configFile = path.join(tempDir, "config.json");

    const findings = [
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        title: "dangerous-exec detected",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));
    await fs.writeFile(configFile, createConfigJson([]));

    const result = await runRenderReport([
      "--audit",
      auditFile,
      "--deep",
      deepFile,
      "--enable-suppressions",
      "--config",
      configFile,
    ]);

    // Should NOT suppress with empty suppressions array
    if (
      result.stdout.includes("Summary: 1 critical") &&
      result.stdout.includes("Findings (critical/warn):") &&
      !result.stdout.includes("INFO-SUPPRESSED:")
    ) {
      pass(testName);
    } else {
      fail(testName, `Empty suppressions should not suppress findings: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Config without --enable-suppressions flag does NOT suppress
// -----------------------------------------------------------------------------
async function testConfigWithoutEnableFlagDoesNotSuppress() {
  const testName = "render_report: config without --enable-suppressions flag does not suppress";
  try {
    const auditFile = path.join(tempDir, "audit.json");
    const deepFile = path.join(tempDir, "deep.json");
    const configFile = path.join(tempDir, "config.json");

    const findings = [
      {
        severity: "critical",
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        title: "dangerous-exec detected",
      },
    ];

    const suppressions = [
      {
        checkId: "skills.code_safety",
        skill: "clawsec-suite",
        reason: "First-party security tooling",
        suppressedAt: "2026-02-13",
      },
    ];

    await fs.writeFile(auditFile, createAuditJson(findings));
    await fs.writeFile(deepFile, createAuditJson([]));
    await fs.writeFile(configFile, createConfigJson(suppressions));

    // Pass --config but NOT --enable-suppressions
    const result = await runRenderReport([
      "--audit",
      auditFile,
      "--deep",
      deepFile,
      "--config",
      configFile,
    ]);

    // Findings should NOT be suppressed without the explicit opt-in flag
    if (
      result.stdout.includes("Summary: 1 critical") &&
      result.stdout.includes("Findings (critical/warn):") &&
      !result.stdout.includes("INFO-SUPPRESSED:")
    ) {
      pass(testName);
    } else {
      fail(testName, `Config alone should not suppress without --enable-suppressions: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Main test runner
// -----------------------------------------------------------------------------
async function runAllTests() {
  await setupTestDir();

  try {
    await testSuppressedFindingsDisplayed();
    await testActiveFindingsDisplayed();
    await testSummaryExcludesSuppressed();
    await testBackwardCompatibilityNoConfig();
    await testPartialMatchCheckIdOnly();
    await testPartialMatchSkillOnly();
    await testMultipleSuppressions();
    await testSkillNameExtractionFromPath();
    await testSkillNameExtractionFromTitle();
    await testEmptySuppressions();
    await testConfigWithoutEnableFlagDoesNotSuppress();
  } finally {
    await cleanupTestDir();
  }

  console.log("");
  console.log(`Passed: ${passCount}`);
  console.log(`Failed: ${failCount}`);

  if (failCount > 0) {
    process.exit(1);
  }
}

runAllTests().catch((err) => {
  console.error("Test runner failed:", err);
  process.exit(1);
});
