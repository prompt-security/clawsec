#!/usr/bin/env node

/**
 * Risk assessor tests for clawsec-analyst.
 *
 * Tests cover:
 * - assessSkillRisk: skill.json parsing, advisory matching, risk scoring
 * - parseSkillJson: validation, missing fields, malformed JSON
 * - matchDependenciesAgainstFeed: dependency matching, version specs
 * - calculateFallbackRiskScore: risk score calculation, severity mapping
 * - generateFallbackAssessment: fallback analysis when Claude unavailable
 * - formatRiskAssessment: human-readable output formatting
 * - assessMultipleSkills: batch processing with partial failures
 *
 * Run: node skills/clawsec-analyst/test/risk-assessor.test.mjs
 */

import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";
import {
  pass,
  fail,
  report,
  exitWithResults,
  createTempDir,
} from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB_PATH = path.resolve(__dirname, "..", "lib");

// Set NODE_ENV to test to suppress console warnings during tests
process.env.NODE_ENV = "test";

// Import the risk-assessor module (compiled JS from TypeScript)
const {
  assessSkillRisk,
  assessMultipleSkills,
  formatRiskAssessment,
} = await import(`${LIB_PATH}/risk-assessor.js`);

// -----------------------------------------------------------------------------
// Mock implementations
// -----------------------------------------------------------------------------

/**
 * Mock Claude client for testing
 */
class MockClaudeClient {
  constructor() {
    this._response = null;
    this._error = null;
  }

  setResponse(response) {
    this._response = response;
    this._error = null;
    return this;
  }

  setError(error) {
    this._error = error;
    this._response = null;
    return this;
  }

  async assessSkillRisk(payload) {
    if (this._error) {
      throw this._error;
    }
    return this._response;
  }
}

// Helper to create valid skill.json
function createSkillJson(overrides = {}) {
  return JSON.stringify({
    name: "test-skill",
    version: "1.0.0",
    description: "Test skill for risk assessment",
    files: ["index.js", "README.md"],
    dependencies: {},
    openclaw: {
      required_bins: [],
    },
    ...overrides,
  }, null, 2);
}

// Helper to create valid SKILL.md
function createSkillMd() {
  return `---
name: test-skill
version: 1.0.0
description: Test skill for risk assessment
---

# Test Skill

This is a test skill for risk assessment testing.

## Features
- Feature 1
- Feature 2
`;
}

// Helper to create valid advisory feed
function createAdvisoryFeed(overrides = {}) {
  return {
    version: "1.0.0",
    updated: "2026-02-27T00:00:00Z",
    advisories: [],
    ...overrides,
  };
}

// Helper to create valid advisory
function createAdvisory(overrides = {}) {
  return {
    id: "CLAW-2026-001",
    severity: "high",
    type: "vulnerability",
    title: "Test Vulnerability",
    description: "A test vulnerability for testing",
    affected: ["test-package@1.0.0"],
    action: "update",
    published: "2026-02-27T00:00:00Z",
    ...overrides,
  };
}

// Helper to create valid risk assessment response
function createRiskAssessmentResponse(overrides = {}) {
  return JSON.stringify({
    riskScore: 50,
    severity: "medium",
    findings: [
      {
        category: "dependencies",
        severity: "medium",
        description: "Test finding",
        evidence: "Test evidence",
      },
    ],
    recommendation: "review",
    rationale: "Test rationale for risk assessment",
    ...overrides,
  });
}

// Helper to create temp skill directory
async function createTempSkill(skillJson, skillMd = null) {
  const tempDir = await createTempDir();
  const skillDir = path.join(tempDir.path, "test-skill");
  await fs.mkdir(skillDir, { recursive: true });
  await fs.writeFile(path.join(skillDir, "skill.json"), skillJson);
  if (skillMd) {
    await fs.writeFile(path.join(skillDir, "SKILL.md"), skillMd);
  }
  return { skillDir, cleanup: tempDir.cleanup };
}

// Helper to create temp advisory feed
async function createTempFeed(feedPayload) {
  const tempDir = await createTempDir();
  const feedPath = path.join(tempDir.path, "feed.json");
  await fs.writeFile(feedPath, JSON.stringify(feedPayload, null, 2));
  return { feedPath, cleanup: tempDir.cleanup };
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - valid skill with no vulnerabilities
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_NoVulnerabilities() {
  const testName = "assessSkillRisk: assesses skill with no vulnerabilities";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson();
    const skillMd = createSkillMd();
    const { skillDir, cleanup } = await createTempSkill(skillJson, skillMd);
    cleanup1 = cleanup;

    const feed = createAdvisoryFeed();
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setResponse(createRiskAssessmentResponse({
      riskScore: 10,
      severity: "low",
      recommendation: "approve",
    }));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    if (
      assessment.skillName === "test-skill" &&
      assessment.riskScore === 10 &&
      assessment.severity === "low" &&
      assessment.recommendation === "approve"
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected assessment: ${JSON.stringify(assessment)}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - skill with matched vulnerabilities
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_WithVulnerabilities() {
  const testName = "assessSkillRisk: detects matched vulnerabilities";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson({
      dependencies: {
        "vulnerable-package": "1.0.0",
      },
    });
    const { skillDir, cleanup } = await createTempSkill(skillJson);
    cleanup1 = cleanup;

    const advisory = createAdvisory({
      id: "CLAW-2026-002",
      severity: "critical",
      affected: ["vulnerable-package@1.0.0"],
      cvss_score: 9.8,
    });
    const feed = createAdvisoryFeed({ advisories: [advisory] });
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setResponse(createRiskAssessmentResponse({
      riskScore: 85,
      severity: "critical",
      recommendation: "block",
      findings: [
        {
          category: "dependencies",
          severity: "critical",
          description: "Critical vulnerability detected",
          evidence: "vulnerable-package@1.0.0 matches CLAW-2026-002",
        },
      ],
    }));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    if (
      assessment.riskScore === 85 &&
      assessment.severity === "critical" &&
      assessment.recommendation === "block" &&
      assessment.matchedAdvisories.length === 1 &&
      assessment.matchedAdvisories[0].advisory.id === "CLAW-2026-002"
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected assessment: ${JSON.stringify(assessment)}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - missing skill.json
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_MissingSkillJson() {
  const testName = "assessSkillRisk: fails when skill.json is missing";
  let cleanup;

  try {
    const tempDir = await createTempDir();
    cleanup = tempDir.cleanup;

    await assessSkillRisk(tempDir.path, { allowUnsigned: true });
    fail(testName, "Expected error for missing skill.json");
  } catch (error) {
    if (error.message.includes("skill.json not found")) {
      pass(testName);
    } else {
      fail(testName, `Wrong error: ${error.message}`);
    }
  } finally {
    if (cleanup) await cleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - malformed skill.json
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_MalformedSkillJson() {
  const testName = "assessSkillRisk: fails when skill.json is malformed";
  let cleanup;

  try {
    const { skillDir, cleanup: cleanupFn } = await createTempSkill("{ invalid json }");
    cleanup = cleanupFn;

    await assessSkillRisk(skillDir, { allowUnsigned: true });
    fail(testName, "Expected error for malformed skill.json");
  } catch (error) {
    if (error.message.includes("Failed to parse skill.json")) {
      pass(testName);
    } else {
      fail(testName, `Wrong error: ${error.message}`);
    }
  } finally {
    if (cleanup) await cleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - skill.json missing required field (name)
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_MissingName() {
  const testName = "assessSkillRisk: fails when skill.json missing name";
  let cleanup;

  try {
    const skillJson = createSkillJson({ name: undefined });
    const parsed = JSON.parse(skillJson);
    delete parsed.name;
    const { skillDir, cleanup: cleanupFn } = await createTempSkill(JSON.stringify(parsed));
    cleanup = cleanupFn;

    await assessSkillRisk(skillDir, { allowUnsigned: true });
    fail(testName, "Expected error for missing name");
  } catch (error) {
    if (error.message.includes("missing required field: name")) {
      pass(testName);
    } else {
      fail(testName, `Wrong error: ${error.message}`);
    }
  } finally {
    if (cleanup) await cleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - skill.json missing required field (version)
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_MissingVersion() {
  const testName = "assessSkillRisk: fails when skill.json missing version";
  let cleanup;

  try {
    const skillJson = createSkillJson();
    const parsed = JSON.parse(skillJson);
    delete parsed.version;
    const { skillDir, cleanup: cleanupFn } = await createTempSkill(JSON.stringify(parsed));
    cleanup = cleanupFn;

    await assessSkillRisk(skillDir, { allowUnsigned: true });
    fail(testName, "Expected error for missing version");
  } catch (error) {
    if (error.message.includes("missing required field: version")) {
      pass(testName);
    } else {
      fail(testName, `Wrong error: ${error.message}`);
    }
  } finally {
    if (cleanup) await cleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - skill.json missing required field (files)
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_MissingFiles() {
  const testName = "assessSkillRisk: fails when skill.json missing files";
  let cleanup;

  try {
    const skillJson = createSkillJson();
    const parsed = JSON.parse(skillJson);
    delete parsed.files;
    const { skillDir, cleanup: cleanupFn } = await createTempSkill(JSON.stringify(parsed));
    cleanup = cleanupFn;

    await assessSkillRisk(skillDir, { allowUnsigned: true });
    fail(testName, "Expected error for missing files");
  } catch (error) {
    if (error.message.includes("missing required field: files")) {
      pass(testName);
    } else {
      fail(testName, `Wrong error: ${error.message}`);
    }
  } finally {
    if (cleanup) await cleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - fallback when Claude API fails
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_ClaudeFallback() {
  const testName = "assessSkillRisk: uses fallback when Claude API fails";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson({
      dependencies: {
        "test-package": "1.0.0",
      },
    });
    const { skillDir, cleanup } = await createTempSkill(skillJson);
    cleanup1 = cleanup;

    const advisory = createAdvisory({
      id: "CLAW-2026-003",
      severity: "high",
      affected: ["test-package@1.0.0"],
    });
    const feed = createAdvisoryFeed({ advisories: [advisory] });
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setError(new Error("API unavailable"));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    // Should have fallback assessment
    if (
      (assessment.rationale.includes("Fallback assessment") ||
       assessment.rationale.includes("Claude API was unavailable")) &&
      assessment.matchedAdvisories.length === 1 &&
      assessment.riskScore > 10 // Should have increased score due to vulnerability
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected fallback assessment: ${JSON.stringify(assessment)}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - fallback risk score calculation
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_FallbackScoring() {
  const testName = "assessSkillRisk: fallback calculates risk score correctly";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson({
      dependencies: {
        "critical-vuln": "1.0.0",
        "high-vuln": "2.0.0",
        "medium-vuln": "3.0.0",
      },
    });
    const { skillDir, cleanup } = await createTempSkill(skillJson);
    cleanup1 = cleanup;

    const advisories = [
      createAdvisory({
        id: "CLAW-2026-004",
        severity: "critical",
        affected: ["critical-vuln@1.0.0"],
        cvss_score: 9.8,
      }),
      createAdvisory({
        id: "CLAW-2026-005",
        severity: "high",
        affected: ["high-vuln@2.0.0"],
        cvss_score: 7.5,
      }),
      createAdvisory({
        id: "CLAW-2026-006",
        severity: "medium",
        affected: ["medium-vuln@3.0.0"],
      }),
    ];
    const feed = createAdvisoryFeed({ advisories });
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setError(new Error("API unavailable"));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    // Fallback scoring: 10 (base) + 30 (critical) + 9 (cvss) + 20 (high) + 7 (cvss) + 10 (medium) = 86
    if (assessment.riskScore >= 80 && assessment.severity === "critical") {
      pass(testName);
    } else {
      fail(testName, `Expected critical risk score >= 80, got ${assessment.riskScore} (${assessment.severity})`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - wildcard version matching
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_WildcardMatching() {
  const testName = "assessSkillRisk: matches wildcard versions";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson({
      dependencies: {
        "any-version-package": "*",
      },
    });
    const { skillDir, cleanup } = await createTempSkill(skillJson);
    cleanup1 = cleanup;

    const advisory = createAdvisory({
      id: "CLAW-2026-007",
      severity: "high",
      affected: ["any-version-package@*"],
    });
    const feed = createAdvisoryFeed({ advisories: [advisory] });
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setError(new Error("API unavailable"));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    if (assessment.matchedAdvisories.length === 1) {
      pass(testName);
    } else {
      fail(testName, `Expected 1 matched advisory, got ${assessment.matchedAdvisories.length}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - skill name matching
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_SkillNameMatching() {
  const testName = "assessSkillRisk: matches against skill name";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson({ name: "vulnerable-skill" });
    const { skillDir, cleanup } = await createTempSkill(skillJson);
    cleanup1 = cleanup;

    const advisory = createAdvisory({
      id: "CLAW-2026-008",
      severity: "critical",
      affected: ["vulnerable-skill@*"],
    });
    const feed = createAdvisoryFeed({ advisories: [advisory] });
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setError(new Error("API unavailable"));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    if (
      assessment.matchedAdvisories.length === 1 &&
      assessment.matchedAdvisories[0].matchedDependency === "vulnerable-skill"
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected skill name match: ${JSON.stringify(assessment.matchedAdvisories)}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - invalid Claude response (missing riskScore)
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_InvalidClaudeResponse_MissingScore() {
  const testName = "assessSkillRisk: falls back on invalid Claude response (missing riskScore)";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson();
    const { skillDir, cleanup } = await createTempSkill(skillJson);
    cleanup1 = cleanup;

    const feed = createAdvisoryFeed();
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setResponse(JSON.stringify({
      // Missing riskScore
      severity: "medium",
      findings: [],
      recommendation: "review",
      rationale: "Test",
    }));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    // Should fall back due to invalid response
    // Fallback rationale includes "Claude API was unavailable" or "Base risk score assigned"
    if (assessment.rationale.includes("Claude API was unavailable") ||
        assessment.rationale.includes("Base risk score assigned")) {
      pass(testName);
    } else {
      fail(testName, `Expected fallback rationale, got: ${assessment.rationale}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - invalid Claude response (invalid severity)
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_InvalidClaudeResponse_InvalidSeverity() {
  const testName = "assessSkillRisk: falls back on invalid Claude response (invalid severity)";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson();
    const { skillDir, cleanup } = await createTempSkill(skillJson);
    cleanup1 = cleanup;

    const feed = createAdvisoryFeed();
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setResponse(createRiskAssessmentResponse({ severity: "extreme" }));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    // Should fall back due to invalid severity
    // Fallback rationale includes "Claude API was unavailable" or "Base risk score assigned"
    if (assessment.rationale.includes("Claude API was unavailable") ||
        assessment.rationale.includes("Base risk score assigned")) {
      pass(testName);
    } else {
      fail(testName, `Expected fallback rationale, got: ${assessment.rationale}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - invalid Claude response (invalid recommendation)
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_InvalidClaudeResponse_InvalidRecommendation() {
  const testName = "assessSkillRisk: falls back on invalid Claude response (invalid recommendation)";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson();
    const { skillDir, cleanup } = await createTempSkill(skillJson);
    cleanup1 = cleanup;

    const feed = createAdvisoryFeed();
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setResponse(createRiskAssessmentResponse({ recommendation: "allow" }));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    // Should fall back due to invalid recommendation
    // Fallback rationale includes "Claude API was unavailable" or "Base risk score assigned"
    if (assessment.rationale.includes("Claude API was unavailable") ||
        assessment.rationale.includes("Base risk score assigned")) {
      pass(testName);
    } else {
      fail(testName, `Expected fallback rationale, got: ${assessment.rationale}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Test: assessMultipleSkills - batch processing success
// -----------------------------------------------------------------------------
async function testAssessMultipleSkills_Success() {
  const testName = "assessMultipleSkills: processes multiple skills successfully";
  let cleanup1, cleanup2, cleanup3, cleanup4;

  try {
    const skillJson1 = createSkillJson({ name: "skill-1" });
    const { skillDir: dir1, cleanup } = await createTempSkill(skillJson1);
    cleanup1 = cleanup;

    const skillJson2 = createSkillJson({ name: "skill-2" });
    const { skillDir: dir2, cleanup: cleanup2Fn } = await createTempSkill(skillJson2);
    cleanup2 = cleanup2Fn;

    const skillJson3 = createSkillJson({ name: "skill-3" });
    const { skillDir: dir3, cleanup: cleanup3Fn } = await createTempSkill(skillJson3);
    cleanup3 = cleanup3Fn;

    const feed = createAdvisoryFeed();
    const { feedPath, cleanup: cleanup4Fn } = await createTempFeed(feed);
    cleanup4 = cleanup4Fn;

    const client = new MockClaudeClient();
    client.setResponse(createRiskAssessmentResponse());

    const assessments = await assessMultipleSkills([dir1, dir2, dir3], {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    if (assessments.length === 3 && assessments.every(a => a.skillName.startsWith("skill-"))) {
      pass(testName);
    } else {
      fail(testName, `Expected 3 assessments, got ${assessments.length}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
    if (cleanup3) await cleanup3();
    if (cleanup4) await cleanup4();
  }
}

// -----------------------------------------------------------------------------
// Test: assessMultipleSkills - partial failure continues
// -----------------------------------------------------------------------------
async function testAssessMultipleSkills_PartialFailure() {
  const testName = "assessMultipleSkills: continues on partial failures";
  let cleanup1, cleanup2, cleanup3, cleanup4;

  try {
    const skillJson1 = createSkillJson({ name: "skill-1" });
    const { skillDir: dir1, cleanup } = await createTempSkill(skillJson1);
    cleanup1 = cleanup;

    // Create directory without skill.json (will fail)
    const tempDir = await createTempDir();
    cleanup2 = tempDir.cleanup;
    const dir2 = tempDir.path;

    const skillJson3 = createSkillJson({ name: "skill-3" });
    const { skillDir: dir3, cleanup: cleanup3Fn } = await createTempSkill(skillJson3);
    cleanup3 = cleanup3Fn;

    const feed = createAdvisoryFeed();
    const { feedPath, cleanup: cleanup4Fn } = await createTempFeed(feed);
    cleanup4 = cleanup4Fn;

    const client = new MockClaudeClient();
    client.setResponse(createRiskAssessmentResponse());

    const assessments = await assessMultipleSkills([dir1, dir2, dir3], {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    // Should have 2 successful assessments (dir1 and dir3)
    if (assessments.length === 2) {
      pass(testName);
    } else {
      fail(testName, `Expected 2 assessments (1 failed), got ${assessments.length}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
    if (cleanup3) await cleanup3();
    if (cleanup4) await cleanup4();
  }
}

// -----------------------------------------------------------------------------
// Test: formatRiskAssessment - basic formatting
// -----------------------------------------------------------------------------
async function testFormatRiskAssessment() {
  const testName = "formatRiskAssessment: formats assessment as readable text";

  try {
    const assessment = {
      skillName: "test-skill",
      riskScore: 75,
      severity: "high",
      recommendation: "review",
      rationale: "Test rationale for formatting",
      findings: [
        {
          category: "dependencies",
          severity: "high",
          description: "Test finding",
          evidence: "Test evidence",
        },
      ],
      matchedAdvisories: [
        {
          advisory: {
            id: "CLAW-2026-009",
            severity: "high",
            title: "Test Advisory",
          },
          matchedDependency: "test-package@1.0.0",
          matchReason: "Dependency matches",
        },
      ],
    };

    const formatted = formatRiskAssessment(assessment);

    if (
      formatted.includes("# Risk Assessment: test-skill") &&
      formatted.includes("**Risk Score:** 75/100") &&
      formatted.includes("**Recommendation:** REVIEW") &&
      formatted.includes("## Security Findings") &&
      formatted.includes("## Matched Advisories") &&
      formatted.includes("CLAW-2026-009")
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected format: ${formatted}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: formatRiskAssessment - no findings
// -----------------------------------------------------------------------------
async function testFormatRiskAssessment_NoFindings() {
  const testName = "formatRiskAssessment: formats assessment with no findings";

  try {
    const assessment = {
      skillName: "clean-skill",
      riskScore: 10,
      severity: "low",
      recommendation: "approve",
      rationale: "No issues found",
      findings: [],
      matchedAdvisories: [],
    };

    const formatted = formatRiskAssessment(assessment);

    if (
      formatted.includes("# Risk Assessment: clean-skill") &&
      formatted.includes("**Risk Score:** 10/100") &&
      !formatted.includes("## Security Findings") &&
      !formatted.includes("## Matched Advisories")
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected format: ${formatted}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - recommendation mapping (approve)
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_RecommendationApprove() {
  const testName = "assessSkillRisk: fallback maps low risk to approve";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson();
    const { skillDir, cleanup } = await createTempSkill(skillJson);
    cleanup1 = cleanup;

    const feed = createAdvisoryFeed();
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setError(new Error("API unavailable"));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    // No vulnerabilities, should be low risk with approve recommendation
    if (
      assessment.riskScore < 30 &&
      assessment.severity === "low" &&
      assessment.recommendation === "approve"
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected approve recommendation, got: ${assessment.recommendation} (score: ${assessment.riskScore})`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Test: assessSkillRisk - recommendation mapping (block)
// -----------------------------------------------------------------------------
async function testAssessSkillRisk_RecommendationBlock() {
  const testName = "assessSkillRisk: fallback maps critical risk to block";
  let cleanup1, cleanup2;

  try {
    const skillJson = createSkillJson({
      dependencies: {
        "critical-vuln-1": "1.0.0",
        "critical-vuln-2": "2.0.0",
      },
    });
    const { skillDir, cleanup } = await createTempSkill(skillJson);
    cleanup1 = cleanup;

    const advisories = [
      createAdvisory({
        id: "CLAW-2026-010",
        severity: "critical",
        affected: ["critical-vuln-1@1.0.0"],
        cvss_score: 10.0,
      }),
      createAdvisory({
        id: "CLAW-2026-011",
        severity: "critical",
        affected: ["critical-vuln-2@2.0.0"],
        cvss_score: 9.8,
      }),
    ];
    const feed = createAdvisoryFeed({ advisories });
    const { feedPath, cleanup: cleanup2Fn } = await createTempFeed(feed);
    cleanup2 = cleanup2Fn;

    const client = new MockClaudeClient();
    client.setError(new Error("API unavailable"));

    const assessment = await assessSkillRisk(skillDir, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: true,
    });

    // Multiple critical vulnerabilities should result in block
    if (
      assessment.riskScore >= 80 &&
      assessment.severity === "critical" &&
      assessment.recommendation === "block"
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected block recommendation, got: ${assessment.recommendation} (score: ${assessment.riskScore})`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (cleanup1) await cleanup1();
    if (cleanup2) await cleanup2();
  }
}

// -----------------------------------------------------------------------------
// Run all tests
// -----------------------------------------------------------------------------
async function runAllTests() {
  console.log("=== Risk Assessor Tests ===\n");

  // assessSkillRisk tests
  await testAssessSkillRisk_NoVulnerabilities();
  await testAssessSkillRisk_WithVulnerabilities();
  await testAssessSkillRisk_MissingSkillJson();
  await testAssessSkillRisk_MalformedSkillJson();
  await testAssessSkillRisk_MissingName();
  await testAssessSkillRisk_MissingVersion();
  await testAssessSkillRisk_MissingFiles();
  await testAssessSkillRisk_ClaudeFallback();
  await testAssessSkillRisk_FallbackScoring();
  await testAssessSkillRisk_WildcardMatching();
  await testAssessSkillRisk_SkillNameMatching();
  await testAssessSkillRisk_InvalidClaudeResponse_MissingScore();
  await testAssessSkillRisk_InvalidClaudeResponse_InvalidSeverity();
  await testAssessSkillRisk_InvalidClaudeResponse_InvalidRecommendation();
  await testAssessSkillRisk_RecommendationApprove();
  await testAssessSkillRisk_RecommendationBlock();

  // assessMultipleSkills tests
  await testAssessMultipleSkills_Success();
  await testAssessMultipleSkills_PartialFailure();

  // formatRiskAssessment tests
  await testFormatRiskAssessment();
  await testFormatRiskAssessment_NoFindings();

  report();
  exitWithResults();
}

runAllTests();
