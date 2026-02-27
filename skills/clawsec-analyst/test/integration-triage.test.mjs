#!/usr/bin/env node

/**
 * Integration test for advisory triage workflow in clawsec-analyst.
 *
 * Tests cover:
 * - End-to-end triage workflow (feed load -> analyze -> filter -> cache -> persist)
 * - Multi-advisory batch processing with priority filtering
 * - State persistence and cache integration
 * - Feed signature verification in workflow context
 * - Error resilience with fallback analysis
 *
 * Run: ANTHROPIC_API_KEY=test node skills/clawsec-analyst/test/integration-triage.test.mjs
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
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

// Set up a temporary cache directory for tests BEFORE importing modules
const TEST_CACHE_DIR = path.join(os.tmpdir(), `clawsec-analyst-test-${Date.now()}`);

// Create test cache directory before tests
await fs.mkdir(TEST_CACHE_DIR, { recursive: true });

// Override HOME to use test cache location
const originalHome = process.env.HOME;
process.env.HOME = TEST_CACHE_DIR;

// Dynamic import to ensure we test the actual compiled modules
const { analyzeAdvisories, filterByPriority } = await import(`${LIB_PATH}/advisory-analyzer.js`);
const { loadLocalFeed } = await import(`${LIB_PATH}/feed-reader.js`);
const { loadState, persistState } = await import(`${LIB_PATH}/state.js`);
const { getCachedAnalysis } = await import(`${LIB_PATH}/cache.js`);

let tempDirCleanup;

// -----------------------------------------------------------------------------
// Mock Claude Client
// -----------------------------------------------------------------------------

class MockClaudeClient {
  constructor() {
    this._analysisMap = new Map();
    this._shouldFail = false;
  }

  /**
   * Set response for a specific advisory ID
   */
  setAnalysis(advisoryId, priority, rationale, confidence = 0.9) {
    this._analysisMap.set(advisoryId, {
      priority,
      rationale,
      affected_components: ["test-component"],
      recommended_actions: ["Update package", "Review configuration"],
      confidence,
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
   * Mock analyzeAdvisory implementation
   */
  async analyzeAdvisory(advisory) {
    if (this._shouldFail) {
      throw new Error("Mock Claude API unavailable");
    }

    const analysis = this._analysisMap.get(advisory.id);
    if (!analysis) {
      // Return default MEDIUM priority for unmapped advisories
      return JSON.stringify({
        priority: "MEDIUM",
        rationale: `Default analysis for ${advisory.id}`,
        affected_components: ["unknown"],
        recommended_actions: ["Review advisory details"],
        confidence: 0.7,
      });
    }

    return JSON.stringify(analysis);
  }
}

// -----------------------------------------------------------------------------
// Test Helpers
// -----------------------------------------------------------------------------

/**
 * Clear the cache directory for test isolation
 */
async function clearTestCache() {
  const cacheDir = path.join(TEST_CACHE_DIR, ".openclaw", "clawsec-analyst-cache");
  try {
    await fs.rm(cacheDir, { recursive: true, force: true });
    await fs.mkdir(cacheDir, { recursive: true });
  } catch {
    // Ignore errors - directory might not exist yet
  }
}

/**
 * Create a valid feed with multiple advisories
 */
function createMultiAdvisoryFeed(advisories) {
  return JSON.stringify(
    {
      version: "1.0.0",
      updated: "2026-02-27T00:00:00Z",
      advisories: advisories.map((adv) => ({
        id: adv.id,
        severity: adv.severity,
        type: adv.type || "vulnerability",
        title: adv.title || `Test Advisory ${adv.id}`,
        description: adv.description || `Test description for ${adv.id}`,
        affected: adv.affected || [`test-package@1.0.0`],
        action: adv.action || "update",
        published: adv.published || "2026-02-27T00:00:00Z",
        cvss_score: adv.cvss_score || 7.5,
      })),
    },
    null,
    2,
  );
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
 * Setup test environment with signed feed
 */
async function setupTestEnvironment(advisories) {
  const { path: tmpDir, cleanup } = await createTempDir();

  const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
  const feedContent = createMultiAdvisoryFeed(advisories);
  const signature = signPayload(feedContent, privateKeyPem);

  const checksumManifest = createChecksumManifest({
    "feed.json": feedContent,
    "feed.json.sig": signature,
  });
  const checksumSignature = signPayload(checksumManifest, privateKeyPem);

  const feedPath = path.join(tmpDir, "feed.json");
  const signaturePath = path.join(tmpDir, "feed.json.sig");
  const checksumsPath = path.join(tmpDir, "checksums.json");
  const checksumsSignaturePath = path.join(tmpDir, "checksums.json.sig");

  await fs.writeFile(feedPath, feedContent, "utf8");
  await fs.writeFile(signaturePath, signature, "utf8");
  await fs.writeFile(checksumsPath, checksumManifest, "utf8");
  await fs.writeFile(checksumsSignaturePath, checksumSignature, "utf8");

  return {
    tmpDir,
    cleanup,
    feedPath,
    publicKeyPem,
    advisories: JSON.parse(feedContent).advisories,
  };
}

// -----------------------------------------------------------------------------
// Test: Complete triage workflow - feed load to filtered results
// -----------------------------------------------------------------------------
async function testCompleteTriageWorkflow() {
  const testName = "Complete triage workflow: feed load -> analyze -> filter";

  try {
    const env = await setupTestEnvironment([
      { id: "CLAW-2026-001", severity: "critical", description: "Critical RCE vulnerability" },
      { id: "CLAW-2026-002", severity: "high", description: "High severity XSS issue" },
      { id: "CLAW-2026-003", severity: "medium", description: "Medium severity info leak" },
      { id: "CLAW-2026-004", severity: "low", description: "Low severity minor bug" },
    ]);
    tempDirCleanup = env.cleanup;

    // Setup mock client with different priorities
    const client = new MockClaudeClient();
    client.setAnalysis("CLAW-2026-001", "HIGH", "Critical but limited scope");
    client.setAnalysis("CLAW-2026-002", "HIGH", "High severity needs immediate action");
    client.setAnalysis("CLAW-2026-003", "MEDIUM", "Medium risk, monitor closely");
    client.setAnalysis("CLAW-2026-004", "LOW", "Low priority, can defer");

    // Step 1: Load feed with signature verification
    const feed = await loadLocalFeed(env.feedPath, {
      publicKeyPem: env.publicKeyPem,
      verifyChecksumManifest: false,
    });

    if (feed.advisories.length !== 4) {
      fail(testName, `Expected 4 advisories in feed, got ${feed.advisories.length}`);
      await env.cleanup();
      return;
    }

    // Step 2: Analyze all advisories
    const analyses = await analyzeAdvisories(feed.advisories, client);

    if (analyses.length !== 4) {
      fail(testName, `Expected 4 analyses, got ${analyses.length}`);
      await env.cleanup();
      return;
    }

    // Step 3: Filter by HIGH priority
    const highPriority = filterByPriority(analyses, "HIGH");

    if (highPriority.length !== 2) {
      fail(testName, `Expected 2 HIGH priority analyses, got ${highPriority.length}`);
      await env.cleanup();
      return;
    }

    // Step 4: Verify filtered results have correct IDs
    const highIds = highPriority.map((a) => a.advisoryId).sort();
    const expectedIds = ["CLAW-2026-001", "CLAW-2026-002"].sort();

    if (JSON.stringify(highIds) === JSON.stringify(expectedIds)) {
      pass(testName);
    } else {
      fail(testName, `Expected HIGH priority IDs ${expectedIds.join(", ")}, got ${highIds.join(", ")}`);
    }

    await env.cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: Batch processing with partial failures and fallback
// -----------------------------------------------------------------------------
async function testBatchProcessingWithFailures() {
  const testName = "Batch processing: handles partial failures with fallback analysis";

  try {
    const env = await setupTestEnvironment([
      { id: "CLAW-2026-010", severity: "critical", description: "Valid advisory" },
      { id: "CLAW-2026-011", severity: "high", description: "Will trigger fallback" },
      { id: "CLAW-2026-012", severity: "medium", description: "Valid advisory" },
    ]);
    tempDirCleanup = env.cleanup;

    const client = new MockClaudeClient();
    client.setAnalysis("CLAW-2026-010", "HIGH", "Valid analysis");
    // Don't set analysis for CLAW-2026-011 - mock client will throw for unmapped IDs
    client.setAnalysis("CLAW-2026-012", "MEDIUM", "Valid analysis");

    // Override default behavior to throw for unmapped advisories
    const originalAnalyze = client.analyzeAdvisory.bind(client);
    client.analyzeAdvisory = async function (advisory) {
      if (!this._analysisMap.has(advisory.id)) {
        throw new Error("Mock API failure for unmapped advisory");
      }
      return originalAnalyze(advisory);
    };

    const feed = await loadLocalFeed(env.feedPath, {
      publicKeyPem: env.publicKeyPem,
      verifyChecksumManifest: false,
    });

    const analyses = await analyzeAdvisories(feed.advisories, client);

    // Should have 3 results: 2 successful + 1 fallback
    if (analyses.length !== 3) {
      fail(testName, `Expected 3 analyses, got ${analyses.length}`);
      await env.cleanup();
      return;
    }

    // Second result should be fallback analysis with conservative priority
    const fallbackAnalysis = analyses[1];
    if (
      fallbackAnalysis.advisoryId === "CLAW-2026-011" &&
      fallbackAnalysis.rationale.includes("Fallback analysis") &&
      fallbackAnalysis.confidence === 0.5
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected fallback analysis for CLAW-2026-011, got: ${JSON.stringify(fallbackAnalysis)}`);
    }

    await env.cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: Cache integration in workflow
// -----------------------------------------------------------------------------
async function testCacheIntegration() {
  const testName = "Cache integration: analyses are cached and reused";

  try {
    await clearTestCache();

    const env = await setupTestEnvironment([
      { id: "CLAW-2026-020", severity: "high", description: "Cacheable advisory" },
    ]);
    tempDirCleanup = env.cleanup;

    const client = new MockClaudeClient();
    client.setAnalysis("CLAW-2026-020", "HIGH", "First analysis");

    const feed = await loadLocalFeed(env.feedPath, {
      publicKeyPem: env.publicKeyPem,
      verifyChecksumManifest: false,
    });

    // First analysis - should cache result
    await analyzeAdvisories(feed.advisories, client);

    // Check if analysis was cached
    const cached = await getCachedAnalysis("CLAW-2026-020");

    if (!cached) {
      fail(testName, "Analysis was not cached");
      await env.cleanup();
      tempDirCleanup = null;
      return;
    }

    // Modify mock client to return different result
    client.setAnalysis("CLAW-2026-020", "LOW", "Second analysis");

    // Second analysis - should use cache, not new result
    const secondAnalyses = await analyzeAdvisories(feed.advisories, client);

    if (
      secondAnalyses[0].priority === "HIGH" &&
      secondAnalyses[0].rationale === "First analysis"
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected cached result with HIGH priority, got: ${JSON.stringify(secondAnalyses[0])}`);
    }

    await env.cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: State persistence integration
// -----------------------------------------------------------------------------
async function testStatePersistence() {
  const testName = "State persistence: analysis history is persisted to state file";

  try {
    const { path: tmpDir, cleanup } = await createTempDir();
    tempDirCleanup = cleanup;

    const stateFile = path.join(tmpDir, "analyst-state.json");

    // Create initial state
    const initialState = {
      schema_version: "1.0",
      last_feed_check: "2026-02-27T00:00:00Z",
      last_feed_updated: "2026-02-27T00:00:00Z",
      cached_analyses: {},
      policies: [],
      analysis_history: [
        {
          timestamp: "2026-02-27T00:00:00Z",
          type: "advisory-triage",
          targetId: "CLAW-2026-030",
          result: "HIGH",
        },
      ],
    };

    // Persist state
    await persistState(stateFile, initialState);

    // Load state back
    const loadedState = await loadState(stateFile);

    // Verify state was persisted and loaded correctly
    if (
      loadedState.schema_version === "1.0" &&
      loadedState.analysis_history.length === 1 &&
      loadedState.analysis_history[0].targetId === "CLAW-2026-030"
    ) {
      pass(testName);
    } else {
      fail(testName, `State not persisted correctly: ${JSON.stringify(loadedState)}`);
    }

    await cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: Offline resilience with cached fallback
// -----------------------------------------------------------------------------
async function testOfflineResilience() {
  const testName = "Offline resilience: uses cached analysis when API fails";

  try {
    await clearTestCache();

    const env = await setupTestEnvironment([
      { id: "CLAW-2026-040", severity: "high", description: "Cached advisory" },
    ]);
    tempDirCleanup = env.cleanup;

    const client = new MockClaudeClient();
    client.setAnalysis("CLAW-2026-040", "HIGH", "Original analysis");

    const feed = await loadLocalFeed(env.feedPath, {
      publicKeyPem: env.publicKeyPem,
      verifyChecksumManifest: false,
    });

    // First analysis - caches result
    await analyzeAdvisories(feed.advisories, client);

    // Configure client to fail
    client.setShouldFail(true);

    // Second analysis - should use cache despite API failure
    const analyses = await analyzeAdvisories(feed.advisories, client);

    if (
      analyses[0].priority === "HIGH" &&
      analyses[0].rationale === "Original analysis"
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected cached fallback, got: ${JSON.stringify(analyses[0])}`);
    }

    await env.cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: Priority filtering with multiple thresholds
// -----------------------------------------------------------------------------
async function testPriorityFilteringThresholds() {
  const testName = "Priority filtering: correctly filters by different thresholds";

  try {
    const env = await setupTestEnvironment([
      { id: "CLAW-2026-050", severity: "critical", description: "Test" },
      { id: "CLAW-2026-051", severity: "high", description: "Test" },
      { id: "CLAW-2026-052", severity: "medium", description: "Test" },
      { id: "CLAW-2026-053", severity: "low", description: "Test" },
    ]);
    tempDirCleanup = env.cleanup;

    const client = new MockClaudeClient();
    client.setAnalysis("CLAW-2026-050", "HIGH", "Test");
    client.setAnalysis("CLAW-2026-051", "HIGH", "Test");
    client.setAnalysis("CLAW-2026-052", "MEDIUM", "Test");
    client.setAnalysis("CLAW-2026-053", "LOW", "Test");

    const feed = await loadLocalFeed(env.feedPath, {
      publicKeyPem: env.publicKeyPem,
      verifyChecksumManifest: false,
    });

    const analyses = await analyzeAdvisories(feed.advisories, client);

    // Test HIGH threshold
    const highFiltered = filterByPriority(analyses, "HIGH");
    const mediumFiltered = filterByPriority(analyses, "MEDIUM");
    const lowFiltered = filterByPriority(analyses, "LOW");

    if (
      highFiltered.length === 2 &&
      mediumFiltered.length === 3 &&
      lowFiltered.length === 4
    ) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected [2, 3, 4] for [HIGH, MEDIUM, LOW] thresholds, got [${highFiltered.length}, ${mediumFiltered.length}, ${lowFiltered.length}]`,
      );
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
async function testFeedSignatureVerificationInWorkflow() {
  const testName = "Feed signature verification: rejects tampered feed in workflow";

  try {
    const { path: tmpDir, cleanup } = await createTempDir();
    tempDirCleanup = cleanup;

    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createMultiAdvisoryFeed([
      { id: "CLAW-2026-060", severity: "high", description: "Test advisory" },
    ]);
    const signature = signPayload(feedContent, privateKeyPem);

    // Tamper with feed after signing
    const tamperedFeed = feedContent.replace("CLAW-2026-060", "TAMPERED-060");

    const feedPath = path.join(tmpDir, "feed.json");
    const signaturePath = path.join(tmpDir, "feed.json.sig");

    await fs.writeFile(feedPath, tamperedFeed, "utf8");
    await fs.writeFile(signaturePath, signature, "utf8");

    // Attempt to load tampered feed - should fail
    try {
      await loadLocalFeed(feedPath, {
        publicKeyPem,
        verifyChecksumManifest: false,
      });
      fail(testName, "Expected error for tampered feed, but it loaded");
    } catch (error) {
      if (error.message.includes("signature verification failed")) {
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
// Run all tests
// -----------------------------------------------------------------------------
async function runAllTests() {
  console.log("=== Integration Test: Advisory Triage Workflow ===\n");

  try {
    await testCompleteTriageWorkflow();
    await testBatchProcessingWithFailures();
    await testCacheIntegration();
    await testStatePersistence();
    await testOfflineResilience();
    await testPriorityFilteringThresholds();
    await testFeedSignatureVerificationInWorkflow();

    report();
  } finally {
    // Cleanup any remaining temp directories
    if (tempDirCleanup) {
      await tempDirCleanup();
    }

    // Cleanup test cache directory
    try {
      await fs.rm(TEST_CACHE_DIR, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }

    // Restore original HOME
    process.env.HOME = originalHome;
  }

  exitWithResults();
}

runAllTests();
