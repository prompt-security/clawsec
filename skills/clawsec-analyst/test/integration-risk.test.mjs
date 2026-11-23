#!/usr/bin/env node

/**
 * Integration test for risk assessment workflow in clawsec-analyst.
 *
 * Tests cover:
 * - End-to-end risk assessment workflow (skill.json parse -> feed load -> match -> analyze -> score)
 * - Multiple skills batch processing with different risk levels
 * - Advisory matching against dependencies and skill names
 * - Fallback assessment when Claude API is unavailable
 * - Feed signature verification in workflow context
 * - Risk score calculation and recommendation mapping
 *
 * Run: ANTHROPIC_API_KEY=test node skills/clawsec-analyst/test/integration-risk.test.mjs
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  pass,
  fail,
  report,
  exitWithResults,
  generateEd25519KeyPair,
  signPayload,
  createTempDir,
} from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB_PATH = path.resolve(__dirname, "..", "lib");

// Set NODE_ENV to test to suppress console warnings during tests
process.env.NODE_ENV = "test";

// Dynamic import to ensure we test the actual compiled modules
const { assessSkillRisk, assessMultipleSkills } = await import(`${LIB_PATH}/risk-assessor.js`);
const { loadLocalFeed: _loadLocalFeed } = await import(`${LIB_PATH}/feed-reader.js`);

let tempDirCleanup;

// -----------------------------------------------------------------------------
// Mock Claude Client
// -----------------------------------------------------------------------------

class MockClaudeClient {
  constructor() {
    this._responseMap = new Map();
    this._shouldFail = false;
  }

  /**
   * Set response for a specific skill name
   */
  setRiskAssessment(skillName, riskScore, severity, recommendation, rationale) {
    this._responseMap.set(skillName, {
      riskScore,
      severity,
      recommendation,
      rationale,
      findings: [
        {
          category: "dependencies",
          severity,
          description: `Risk assessment for ${skillName}`,
          evidence: `Analysis result: ${rationale}`,
        },
      ],
    });
    return this;
  }

  /**
   * Configure client to fail all requests
   */
  setShouldFail(shouldFail) {
    this._shouldFail = shouldFail;
    return this;
  }

  /**
   * Mock assessSkillRisk implementation
   */
  async assessSkillRisk(payload) {
    if (this._shouldFail) {
      throw new Error("Mock Claude API unavailable");
    }

    const skillName = payload.skillMetadata.name;
    const response = this._responseMap.get(skillName);

    if (!response) {
      // Return default assessment for unmapped skills
      return JSON.stringify({
        riskScore: 30,
        severity: "medium",
        recommendation: "review",
        rationale: `Default assessment for ${skillName}`,
        findings: [],
      });
    }

    return JSON.stringify(response);
  }
}

// -----------------------------------------------------------------------------
// Test Helpers
// -----------------------------------------------------------------------------

/**
 * Create a valid skill.json
 */
function createSkillJson(overrides = {}) {
  return JSON.stringify(
    {
      name: "test-skill",
      version: "1.0.0",
      description: "Test skill for risk assessment",
      files: ["index.js", "README.md"],
      dependencies: {},
      openclaw: {
        required_bins: [],
      },
      ...overrides,
    },
    null,
    2,
  );
}

/**
 * Create a valid SKILL.md
 */
function _createSkillMd(skillName = "test-skill") {
  return `---
name: ${skillName}
version: 1.0.0
description: Test skill for risk assessment
---

# Test Skill

This is a test skill for integration testing.
`;
}

/**
 * Create a valid advisory feed
 */
function createAdvisoryFeed(advisories = []) {
  return JSON.stringify(
    {
      version: "1.0.0",
      updated: "2026-02-27T00:00:00Z",
      advisories,
    },
    null,
    2,
  );
}

/**
 * Create a valid advisory
 */
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
    cvss_score: 7.5,
    ...overrides,
  };
}

/**
 * Create checksum manifest for feed files
 */
function createChecksumManifest(files) {
  const checksums = {};
  for (const [name, content] of Object.entries(files)) {
    checksums[name] = crypto.createHash("sha256").update(content).digest("hex");
  }
  return JSON.stringify(
    {
      schema_version: "1.0",
      algorithm: "sha256",
      files: checksums,
    },
    null,
    2,
  );
}

/**
 * Setup test environment with skill directory and signed feed
 */
async function setupTestEnvironment(skillJson, advisories = [], skillMd = null) {
  const { path: tmpDir, cleanup } = await createTempDir();

  // Create skill directory
  const skillDir = path.join(tmpDir, "test-skill");
  await fs.mkdir(skillDir, { recursive: true });
  await fs.writeFile(path.join(skillDir, "skill.json"), skillJson, "utf8");

  if (skillMd) {
    await fs.writeFile(path.join(skillDir, "SKILL.md"), skillMd, "utf8");
  }

  // Create signed feed
  const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
  const feedContent = createAdvisoryFeed(advisories);
  const signature = signPayload(feedContent, privateKeyPem);

  const checksumManifest = createChecksumManifest({
    "feed.json": feedContent,
    "feed.json.sig": signature,
  });
  const checksumSignature = signPayload(checksumManifest, privateKeyPem);

  const feedDir = path.join(tmpDir, "feed");
  await fs.mkdir(feedDir, { recursive: true });
  const feedPath = path.join(feedDir, "feed.json");
  const signaturePath = path.join(feedDir, "feed.json.sig");
  const checksumsPath = path.join(feedDir, "checksums.json");
  const checksumsSignaturePath = path.join(feedDir, "checksums.json.sig");

  await fs.writeFile(feedPath, feedContent, "utf8");
  await fs.writeFile(signaturePath, signature, "utf8");
  await fs.writeFile(checksumsPath, checksumManifest, "utf8");
  await fs.writeFile(checksumsSignaturePath, checksumSignature, "utf8");

  return {
    tmpDir,
    cleanup,
    skillDir,
    feedPath,
    publicKeyPem,
  };
}

// -----------------------------------------------------------------------------
// Test: Complete risk assessment workflow - skill parse to risk score
// -----------------------------------------------------------------------------
async function testCompleteRiskAssessmentWorkflow() {
  const testName = "Complete risk assessment workflow: skill.json -> feed -> match -> analyze -> score";

  try {
    const advisories = [
      createAdvisory({
        id: "CLAW-2026-100",
        severity: "critical",
        affected: ["vulnerable-package@1.0.0"],
        cvss_score: 9.8,
        description: "Critical vulnerability in test package",
      }),
    ];

    const skillJson = createSkillJson({
      name: "vulnerable-skill",
      dependencies: {
        "vulnerable-package": "1.0.0",
      },
    });

    const env = await setupTestEnvironment(skillJson, advisories);
    tempDirCleanup = env.cleanup;

    // Setup mock client
    const client = new MockClaudeClient();
    client.setRiskAssessment("vulnerable-skill", 85, "critical", "block", "Critical vulnerability detected");

    // Run risk assessment
    const assessment = await assessSkillRisk(env.skillDir, {
      localFeedPath: env.feedPath,
      claudeClient: client,
      allowUnsigned: false,
      publicKeyPem: env.publicKeyPem,
    });

    // Verify assessment results
    if (
      assessment.skillName === "vulnerable-skill" &&
      assessment.riskScore === 85 &&
      assessment.severity === "critical" &&
      assessment.recommendation === "block" &&
      assessment.matchedAdvisories.length === 1 &&
      assessment.matchedAdvisories[0].advisory.id === "CLAW-2026-100"
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected assessment: ${JSON.stringify(assessment)}`);
    }

    await env.cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: Multiple skills batch processing with different risk levels
// -----------------------------------------------------------------------------
async function testMultipleSkillsRiskAssessment() {
  const testName = "Multiple skills batch processing: different risk levels";

  try {
    const advisories = [
      createAdvisory({
        id: "CLAW-2026-101",
        severity: "critical",
        affected: ["critical-vuln@1.0.0"],
        cvss_score: 9.8,
      }),
      createAdvisory({
        id: "CLAW-2026-102",
        severity: "low",
        affected: ["low-vuln@1.0.0"],
        cvss_score: 3.0,
      }),
    ];

    // Create multiple skill directories
    const { path: tmpDir, cleanup } = await createTempDir();
    tempDirCleanup = cleanup;

    // Setup feed
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createAdvisoryFeed(advisories);
    const signature = signPayload(feedContent, privateKeyPem);

    const checksumManifest = createChecksumManifest({
      "feed.json": feedContent,
      "feed.json.sig": signature,
    });
    const checksumSignature = signPayload(checksumManifest, privateKeyPem);

    const feedDir = path.join(tmpDir, "feed");
    await fs.mkdir(feedDir, { recursive: true });
    const feedPath = path.join(feedDir, "feed.json");
    const signaturePath = path.join(feedDir, "feed.json.sig");
    const checksumsPath = path.join(feedDir, "checksums.json");
    const checksumsSignaturePath = path.join(feedDir, "checksums.json.sig");

    await fs.writeFile(feedPath, feedContent, "utf8");
    await fs.writeFile(signaturePath, signature, "utf8");
    await fs.writeFile(checksumsPath, checksumManifest, "utf8");
    await fs.writeFile(checksumsSignaturePath, checksumSignature, "utf8");

    // Create three skills with different risk profiles
    const skillDirs = [];

    // Skill 1: Critical risk
    const skill1Dir = path.join(tmpDir, "critical-skill");
    await fs.mkdir(skill1Dir, { recursive: true });
    await fs.writeFile(
      path.join(skill1Dir, "skill.json"),
      createSkillJson({
        name: "critical-skill",
        dependencies: { "critical-vuln": "1.0.0" },
      }),
      "utf8",
    );
    skillDirs.push(skill1Dir);

    // Skill 2: Low risk
    const skill2Dir = path.join(tmpDir, "low-risk-skill");
    await fs.mkdir(skill2Dir, { recursive: true });
    await fs.writeFile(
      path.join(skill2Dir, "skill.json"),
      createSkillJson({
        name: "low-risk-skill",
        dependencies: { "low-vuln": "1.0.0" },
      }),
      "utf8",
    );
    skillDirs.push(skill2Dir);

    // Skill 3: No vulnerabilities
    const skill3Dir = path.join(tmpDir, "clean-skill");
    await fs.mkdir(skill3Dir, { recursive: true });
    await fs.writeFile(
      path.join(skill3Dir, "skill.json"),
      createSkillJson({
        name: "clean-skill",
        dependencies: {},
      }),
      "utf8",
    );
    skillDirs.push(skill3Dir);

    // Setup mock client
    const client = new MockClaudeClient();
    client.setRiskAssessment("critical-skill", 90, "critical", "block", "Critical vulnerability");
    client.setRiskAssessment("low-risk-skill", 25, "low", "approve", "Low risk vulnerability");
    client.setRiskAssessment("clean-skill", 10, "low", "approve", "No vulnerabilities found");

    // Batch assess all skills
    const assessments = await assessMultipleSkills(skillDirs, {
      localFeedPath: feedPath,
      claudeClient: client,
      allowUnsigned: false,
      publicKeyPem,
    });

    // Verify batch results
    if (
      assessments.length === 3 &&
      assessments[0].skillName === "critical-skill" &&
      assessments[0].recommendation === "block" &&
      assessments[1].skillName === "low-risk-skill" &&
      assessments[1].recommendation === "approve" &&
      assessments[2].skillName === "clean-skill" &&
      assessments[2].recommendation === "approve"
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected 3 assessments with different risk levels, got: ${JSON.stringify(assessments.map(a => ({ name: a.skillName, rec: a.recommendation })))}`);
    }

    await cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: Fallback assessment when Claude API fails
// -----------------------------------------------------------------------------
async function testFallbackAssessment() {
  const testName = "Fallback assessment: uses rule-based scoring when Claude API fails";

  try {
    const advisories = [
      createAdvisory({
        id: "CLAW-2026-103",
        severity: "high",
        affected: ["test-package@1.0.0"],
        cvss_score: 8.5,
      }),
    ];

    const skillJson = createSkillJson({
      dependencies: { "test-package": "1.0.0" },
    });

    const env = await setupTestEnvironment(skillJson, advisories);
    tempDirCleanup = env.cleanup;

    // Configure client to fail
    const client = new MockClaudeClient();
    client.setShouldFail(true);

    // Run risk assessment - should use fallback
    const assessment = await assessSkillRisk(env.skillDir, {
      localFeedPath: env.feedPath,
      claudeClient: client,
      allowUnsigned: false,
      publicKeyPem: env.publicKeyPem,
    });

    // Verify fallback was used
    if (
      assessment.rationale.includes("Fallback assessment") &&
      assessment.matchedAdvisories.length === 1 &&
      assessment.riskScore > 10 && // Should have elevated score due to vulnerability
      (assessment.severity === "high" || assessment.severity === "medium")
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected fallback assessment, got: ${JSON.stringify(assessment)}`);
    }

    await env.cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: Skill name matching against advisories
// -----------------------------------------------------------------------------
async function testSkillNameMatching() {
  const testName = "Skill name matching: matches advisory against skill name itself";

  try {
    const advisories = [
      createAdvisory({
        id: "CLAW-2026-104",
        severity: "critical",
        affected: ["vulnerable-skill@*"],
        description: "The skill itself is vulnerable",
      }),
    ];

    const skillJson = createSkillJson({
      name: "vulnerable-skill",
      dependencies: {},
    });

    const env = await setupTestEnvironment(skillJson, advisories);
    tempDirCleanup = env.cleanup;

    const client = new MockClaudeClient();
    client.setRiskAssessment("vulnerable-skill", 95, "critical", "block", "Skill itself is vulnerable");

    const assessment = await assessSkillRisk(env.skillDir, {
      localFeedPath: env.feedPath,
      claudeClient: client,
      allowUnsigned: false,
      publicKeyPem: env.publicKeyPem,
    });

    // Verify skill name was matched
    if (
      assessment.matchedAdvisories.length === 1 &&
      assessment.matchedAdvisories[0].matchedDependency === "vulnerable-skill" &&
      assessment.matchedAdvisories[0].advisory.id === "CLAW-2026-104"
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected skill name match, got: ${JSON.stringify(assessment.matchedAdvisories)}`);
    }

    await env.cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: Feed signature verification in workflow
// -----------------------------------------------------------------------------
async function testFeedSignatureVerification() {
  const testName = "Feed signature verification: rejects tampered feed in workflow";

  try {
    const { path: tmpDir, cleanup } = await createTempDir();
    tempDirCleanup = cleanup;

    // Create skill directory
    const skillDir = path.join(tmpDir, "test-skill");
    await fs.mkdir(skillDir, { recursive: true });
    await fs.writeFile(path.join(skillDir, "skill.json"), createSkillJson(), "utf8");

    // Create signed feed then tamper with it
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createAdvisoryFeed([createAdvisory()]);
    const signature = signPayload(feedContent, privateKeyPem);

    // Tamper with feed after signing
    const tamperedFeed = feedContent.replace("CLAW-2026-001", "TAMPERED-001");

    const feedPath = path.join(tmpDir, "feed.json");
    const signaturePath = path.join(tmpDir, "feed.json.sig");

    await fs.writeFile(feedPath, tamperedFeed, "utf8");
    await fs.writeFile(signaturePath, signature, "utf8");

    const client = new MockClaudeClient();

    // Attempt to assess skill with tampered feed - should fail
    try {
      await assessSkillRisk(skillDir, {
        localFeedPath: feedPath,
        claudeClient: client,
        allowUnsigned: false,
        publicKeyPem,
      });
      fail(testName, "Expected error for tampered feed, but assessment succeeded");
    } catch (error) {
      if (error.message.includes("signature verification failed") ||
          error.message.includes("Failed to load advisory feed")) {
        pass(testName);
      } else {
        fail(testName, `Unexpected error: ${error.message}`);
      }
    }

    await cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: Risk score calculation with multiple severities
// -----------------------------------------------------------------------------
async function testRiskScoreCalculation() {
  const testName = "Risk score calculation: properly weights multiple vulnerabilities";

  try {
    const advisories = [
      createAdvisory({
        id: "CLAW-2026-105",
        severity: "critical",
        affected: ["critical-dep@1.0.0"],
        cvss_score: 9.8,
      }),
      createAdvisory({
        id: "CLAW-2026-106",
        severity: "high",
        affected: ["high-dep@1.0.0"],
        cvss_score: 7.5,
      }),
      createAdvisory({
        id: "CLAW-2026-107",
        severity: "medium",
        affected: ["medium-dep@1.0.0"],
        cvss_score: 5.0,
      }),
    ];

    const skillJson = createSkillJson({
      dependencies: {
        "critical-dep": "1.0.0",
        "high-dep": "1.0.0",
        "medium-dep": "1.0.0",
      },
    });

    const env = await setupTestEnvironment(skillJson, advisories);
    tempDirCleanup = env.cleanup;

    // Use fallback to test risk score calculation
    const client = new MockClaudeClient();
    client.setShouldFail(true);

    const assessment = await assessSkillRisk(env.skillDir, {
      localFeedPath: env.feedPath,
      claudeClient: client,
      allowUnsigned: false,
      publicKeyPem: env.publicKeyPem,
    });

    // Fallback should calculate: 10 (base) + 30 (critical) + 9 (cvss) + 20 (high) + 7 (cvss) + 10 (medium) + 5 (cvss) = 91
    // But capped at 100
    if (
      assessment.riskScore >= 80 &&
      assessment.severity === "critical" &&
      assessment.recommendation === "block" &&
      assessment.matchedAdvisories.length === 3
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected high risk score with block recommendation, got: score=${assessment.riskScore}, severity=${assessment.severity}, recommendation=${assessment.recommendation}`);
    }

    await env.cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: Wildcard version matching
// -----------------------------------------------------------------------------
async function testWildcardVersionMatching() {
  const testName = "Wildcard version matching: matches * version specifiers";

  try {
    const advisories = [
      createAdvisory({
        id: "CLAW-2026-108",
        severity: "high",
        affected: ["any-version-package@*"],
      }),
    ];

    const skillJson = createSkillJson({
      dependencies: {
        "any-version-package": "2.5.3",
      },
    });

    const env = await setupTestEnvironment(skillJson, advisories);
    tempDirCleanup = env.cleanup;

    const client = new MockClaudeClient();
    client.setRiskAssessment("test-skill", 65, "high", "review", "Wildcard vulnerability match");

    const assessment = await assessSkillRisk(env.skillDir, {
      localFeedPath: env.feedPath,
      claudeClient: client,
      allowUnsigned: false,
      publicKeyPem: env.publicKeyPem,
    });

    // Verify wildcard match
    if (
      assessment.matchedAdvisories.length === 1 &&
      assessment.matchedAdvisories[0].advisory.id === "CLAW-2026-108"
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected wildcard match, got ${assessment.matchedAdvisories.length} matches`);
    }

    await env.cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Run all tests
// -----------------------------------------------------------------------------
async function runAllTests() {
  console.log("=== Integration Test: Risk Assessment Workflow ===\n");

  try {
    await testCompleteRiskAssessmentWorkflow();
    await testMultipleSkillsRiskAssessment();
    await testFallbackAssessment();
    await testSkillNameMatching();
    await testFeedSignatureVerification();
    await testRiskScoreCalculation();
    await testWildcardVersionMatching();

    report();
  } finally {
    // Cleanup any remaining temp directories
    if (tempDirCleanup) {
      await tempDirCleanup();
    }
  }

  exitWithResults();
}

runAllTests();
