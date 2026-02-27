#!/usr/bin/env node

/**
 * Advisory analyzer tests for clawsec-analyst.
 *
 * Tests cover:
 * - analyzeAdvisory: validation, caching, API calls, error handling
 * - analyzeAdvisories: batch processing with partial failures
 * - filterByPriority: priority-based filtering
 * - Response parsing: JSON extraction, validation, error cases
 * - Fallback analysis: conservative priority mapping
 *
 * Run: node skills/clawsec-analyst/test/analyzer.test.mjs
 */

import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  pass,
  fail,
  report,
  exitWithResults,
} from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB_PATH = path.resolve(__dirname, "..", "lib");

// Set NODE_ENV to test to suppress console warnings during tests
process.env.NODE_ENV = "test";

// Import os and fs for cache directory setup
import os from "node:os";
import fs from "node:fs/promises";

// Set up a temporary cache directory for tests
const TEST_CACHE_DIR = path.join(os.tmpdir(), `clawsec-analyst-test-${Date.now()}`);

// Create test cache directory before tests
await fs.mkdir(TEST_CACHE_DIR, { recursive: true });

// Override HOME to use test cache location
const originalHome = process.env.HOME;
process.env.HOME = TEST_CACHE_DIR;

// Import the analyzer module (compiled JS from TypeScript)
const {
  analyzeAdvisory,
  analyzeAdvisories,
  filterByPriority,
} = await import(`${LIB_PATH}/advisory-analyzer.js`);

// Import cache module for manual cache manipulation in tests
const { getCachedAnalysis, setCachedAnalysis } = await import(`${LIB_PATH}/cache.js`);

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

  async analyzeAdvisory(advisory) {
    if (this._error) {
      throw this._error;
    }
    return this._response;
  }
}

// Helper to reset test state
async function resetTestState() {
  // Clear the cache directory
  const cacheDir = path.join(TEST_CACHE_DIR, ".openclaw", "clawsec-analyst-cache");
  try {
    await fs.rm(cacheDir, { recursive: true, force: true });
    await fs.mkdir(cacheDir, { recursive: true });
  } catch (error) {
    // Ignore errors - directory might not exist yet
  }
}

// Helper to create valid advisory
function createAdvisory(overrides = {}) {
  return {
    id: "TEST-001",
    severity: "high",
    type: "vulnerability",
    title: "Test Advisory",
    description: "Test description for advisory",
    affected: ["test-package@1.0.0"],
    action: "update",
    published: "2026-02-27T00:00:00Z",
    ...overrides,
  };
}

// Helper to create valid analysis response
function createAnalysisResponse(overrides = {}) {
  return JSON.stringify({
    priority: "HIGH",
    rationale: "This is a critical vulnerability that affects core systems",
    affected_components: ["test-component", "web-ui"],
    recommended_actions: [
      "Update immediately",
      "Review configurations",
      "Monitor for exploits",
    ],
    confidence: 0.9,
    ...overrides,
  });
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - valid advisory with successful analysis
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_Success() {
  const testName = "analyzeAdvisory: successfully analyzes valid advisory";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    client.setResponse(createAnalysisResponse());

    const advisory = createAdvisory();
    const result = await analyzeAdvisory(advisory, client);

    if (
      result.advisoryId === "TEST-001" &&
      result.priority === "HIGH" &&
      result.rationale.includes("critical vulnerability") &&
      result.affected_components.length === 2 &&
      result.recommended_actions.length === 3 &&
      result.confidence === 0.9
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected result structure: ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - missing required field (id)
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_MissingId() {
  const testName = "analyzeAdvisory: rejects advisory missing id";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    const advisory = createAdvisory({ id: null });

    await analyzeAdvisory(advisory, client);
    fail(testName, "Expected error for missing id, but succeeded");
  } catch (error) {
    if (error.code === "INVALID_ADVISORY_SCHEMA") {
      pass(testName);
    } else {
      fail(testName, `Wrong error code: ${error.code}`);
    }
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - missing required field (severity)
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_MissingSeverity() {
  const testName = "analyzeAdvisory: rejects advisory missing severity";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    const advisory = createAdvisory({ severity: undefined });

    await analyzeAdvisory(advisory, client);
    fail(testName, "Expected error for missing severity, but succeeded");
  } catch (error) {
    if (error.code === "INVALID_ADVISORY_SCHEMA") {
      pass(testName);
    } else {
      fail(testName, `Wrong error code: ${error.code}`);
    }
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - missing required field (description)
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_MissingDescription() {
  const testName = "analyzeAdvisory: rejects advisory missing description";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    const advisory = createAdvisory({ description: "" });

    await analyzeAdvisory(advisory, client);
    fail(testName, "Expected error for missing description, but succeeded");
  } catch (error) {
    if (error.code === "INVALID_ADVISORY_SCHEMA") {
      pass(testName);
    } else {
      fail(testName, `Wrong error code: ${error.code}`);
    }
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - uses cache when available
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_UsesCache() {
  const testName = "analyzeAdvisory: returns cached analysis when available";
  await resetTestState();

  try {
    const cachedAnalysis = {
      advisoryId: "TEST-001",
      priority: "MEDIUM",
      rationale: "Cached analysis",
      affected_components: ["cached-component"],
      recommended_actions: ["Cached action"],
      confidence: 0.8,
    };

    // Manually set cache
    await setCachedAnalysis("TEST-001", cachedAnalysis);

    const client = new MockClaudeClient();
    client.setResponse(createAnalysisResponse({ priority: "HIGH" })); // Should not be used

    const advisory = createAdvisory();
    const result = await analyzeAdvisory(advisory, client);

    // Should return cached version, not fresh API call
    if (
      result.priority === "MEDIUM" &&
      result.rationale === "Cached analysis"
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected cached result but got fresh analysis: ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - caches successful analysis
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_CachesResult() {
  const testName = "analyzeAdvisory: caches successful analysis";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    client.setResponse(createAnalysisResponse());

    const advisory = createAdvisory();
    await analyzeAdvisory(advisory, client);

    // Check if result was cached
    const cached = await getCachedAnalysis("TEST-001");
    if (cached) {
      pass(testName);
    } else {
      fail(testName, "Analysis was not cached");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - API error with cache fallback
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_ApiErrorWithCacheFallback() {
  const testName = "analyzeAdvisory: falls back to cache on API error";
  await resetTestState();

  try {
    const cachedAnalysis = {
      advisoryId: "TEST-002",
      priority: "LOW",
      rationale: "Fallback from cache",
      affected_components: [],
      recommended_actions: ["Use cached data"],
      confidence: 0.7,
    };

    // Manually set cache
    await setCachedAnalysis("TEST-002", cachedAnalysis);

    const client = new MockClaudeClient();
    client.setError(new Error("API unavailable"));

    const advisory = createAdvisory({ id: "TEST-002" });
    const result = await analyzeAdvisory(advisory, client);

    if (result.rationale === "Fallback from cache") {
      pass(testName);
    } else {
      fail(testName, `Expected cached fallback but got: ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - API error without cache
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_ApiErrorNoCache() {
  const testName = "analyzeAdvisory: throws error when API fails and no cache";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    client.setError(new Error("API unavailable"));

    const advisory = createAdvisory({ id: "TEST-003" });
    await analyzeAdvisory(advisory, client);

    fail(testName, "Expected error but succeeded");
  } catch (error) {
    if (error.code === "CLAUDE_API_ERROR") {
      pass(testName);
    } else {
      fail(testName, `Wrong error code: ${error.code}`);
    }
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - response with markdown code blocks
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_MarkdownCodeBlocks() {
  const testName = "analyzeAdvisory: extracts JSON from markdown code blocks";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    const jsonResponse = createAnalysisResponse();
    const markdownWrapped = "```json\n" + jsonResponse + "\n```";
    client.setResponse(markdownWrapped);

    const advisory = createAdvisory({ id: "TEST-004" });
    const result = await analyzeAdvisory(advisory, client);

    if (result.priority === "HIGH" && result.confidence === 0.9) {
      pass(testName);
    } else {
      fail(testName, `Failed to parse markdown-wrapped JSON: ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - response with generic code blocks
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_GenericCodeBlocks() {
  const testName = "analyzeAdvisory: extracts JSON from generic code blocks";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    const jsonResponse = createAnalysisResponse();
    const codeWrapped = "```\n" + jsonResponse + "\n```";
    client.setResponse(codeWrapped);

    const advisory = createAdvisory({ id: "TEST-005" });
    const result = await analyzeAdvisory(advisory, client);

    if (result.priority === "HIGH") {
      pass(testName);
    } else {
      fail(testName, `Failed to parse code block: ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - response missing required fields
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_ResponseMissingFields() {
  const testName = "analyzeAdvisory: rejects response missing required fields";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    client.setResponse(JSON.stringify({
      priority: "HIGH",
      rationale: "Some rationale",
      // Missing affected_components and recommended_actions
    }));

    const advisory = createAdvisory({ id: "TEST-006" });
    await analyzeAdvisory(advisory, client);

    fail(testName, "Expected error for missing fields, but succeeded");
  } catch (error) {
    if (error.code === "CLAUDE_API_ERROR") {
      pass(testName);
    } else {
      fail(testName, `Wrong error code: ${error.code}`);
    }
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - response with invalid priority
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_InvalidPriority() {
  const testName = "analyzeAdvisory: rejects response with invalid priority";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    client.setResponse(createAnalysisResponse({ priority: "EXTREME" }));

    const advisory = createAdvisory({ id: "TEST-007" });
    await analyzeAdvisory(advisory, client);

    fail(testName, "Expected error for invalid priority, but succeeded");
  } catch (error) {
    if (error.code === "CLAUDE_API_ERROR" && error.message.includes("Invalid priority")) {
      pass(testName);
    } else {
      fail(testName, `Wrong error: ${error.message}`);
    }
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - response with invalid confidence
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_InvalidConfidence() {
  const testName = "analyzeAdvisory: rejects response with invalid confidence";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    client.setResponse(createAnalysisResponse({ confidence: 1.5 }));

    const advisory = createAdvisory({ id: "TEST-008" });
    await analyzeAdvisory(advisory, client);

    fail(testName, "Expected error for invalid confidence, but succeeded");
  } catch (error) {
    if (error.code === "CLAUDE_API_ERROR" && error.message.includes("Invalid confidence")) {
      pass(testName);
    } else {
      fail(testName, `Wrong error: ${error.message}`);
    }
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - response with default confidence
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_DefaultConfidence() {
  const testName = "analyzeAdvisory: uses default confidence (0.8) when not provided";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    // Omit confidence field
    const response = createAnalysisResponse();
    const parsed = JSON.parse(response);
    delete parsed.confidence;
    client.setResponse(JSON.stringify(parsed));

    const advisory = createAdvisory({ id: "TEST-009" });
    const result = await analyzeAdvisory(advisory, client);

    if (result.confidence === 0.8) {
      pass(testName);
    } else {
      fail(testName, `Expected default confidence 0.8, got ${result.confidence}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisories - batch processing success
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisories_Success() {
  const testName = "analyzeAdvisories: processes multiple advisories successfully";
  await resetTestState();

  try {
    const client = new MockClaudeClient();
    client.setResponse(createAnalysisResponse());

    const advisories = [
      createAdvisory({ id: "TEST-010" }),
      createAdvisory({ id: "TEST-011" }),
      createAdvisory({ id: "TEST-012" }),
    ];

    const results = await analyzeAdvisories(advisories, client);

    if (results.length === 3 && results.every(r => r.priority === "HIGH")) {
      pass(testName);
    } else {
      fail(testName, `Expected 3 successful results, got: ${JSON.stringify(results)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisories - partial failure with fallback
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisories_PartialFailure() {
  const testName = "analyzeAdvisories: continues on partial failures with fallback";
  await resetTestState();

  try {
    const advisories = [
      createAdvisory({ id: "TEST-013", severity: "critical" }),
      createAdvisory({ id: "TEST-014", description: "" }), // This will fail
      createAdvisory({ id: "TEST-015", severity: "low" }),
    ];

    const client = new MockClaudeClient();
    client.setResponse(createAnalysisResponse());

    const results = await analyzeAdvisories(advisories, client);

    // Should have 3 results: 2 successful + 1 fallback
    if (results.length === 3) {
      const secondResult = results[1];
      // The failed advisory should have a fallback analysis
      if (
        secondResult.rationale.includes("Fallback analysis") &&
        secondResult.confidence === 0.5
      ) {
        pass(testName);
      } else {
        fail(testName, `Expected fallback analysis for failed advisory: ${JSON.stringify(secondResult)}`);
      }
    } else {
      fail(testName, `Expected 3 results, got ${results.length}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisories - fallback maps severity correctly
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisories_FallbackSeverityMapping() {
  const testName = "analyzeAdvisories: fallback maps severity to priority conservatively";
  await resetTestState();

  try {
    const advisories = [
      createAdvisory({ id: "TEST-016", severity: "critical", description: "" }),
      createAdvisory({ id: "TEST-017", severity: "high", description: "" }),
      createAdvisory({ id: "TEST-018", severity: "medium", description: "" }),
      createAdvisory({ id: "TEST-019", severity: "low", description: "" }),
    ];

    const client = new MockClaudeClient();
    client.setResponse(createAnalysisResponse());

    const results = await analyzeAdvisories(advisories, client);

    // All should fail and use fallback
    if (
      results.length === 4 &&
      results[0].priority === "HIGH" && // critical -> HIGH
      results[1].priority === "HIGH" && // high -> HIGH
      results[2].priority === "MEDIUM" && // medium -> MEDIUM
      results[3].priority === "LOW" // low -> LOW
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected priority mapping: ${JSON.stringify(results.map(r => ({ id: r.advisoryId, priority: r.priority })))}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: filterByPriority - HIGH threshold
// -----------------------------------------------------------------------------
async function testFilterByPriority_High() {
  const testName = "filterByPriority: filters by HIGH threshold correctly";

  try {
    const analyses = [
      { advisoryId: "A", priority: "HIGH", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.9 },
      { advisoryId: "B", priority: "MEDIUM", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.8 },
      { advisoryId: "C", priority: "HIGH", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.7 },
      { advisoryId: "D", priority: "LOW", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.6 },
    ];

    const filtered = filterByPriority(analyses, "HIGH");

    if (filtered.length === 2 && filtered.every(a => a.priority === "HIGH")) {
      pass(testName);
    } else {
      fail(testName, `Expected 2 HIGH priority results, got: ${JSON.stringify(filtered)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: filterByPriority - MEDIUM threshold
// -----------------------------------------------------------------------------
async function testFilterByPriority_Medium() {
  const testName = "filterByPriority: filters by MEDIUM threshold correctly";

  try {
    const analyses = [
      { advisoryId: "A", priority: "HIGH", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.9 },
      { advisoryId: "B", priority: "MEDIUM", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.8 },
      { advisoryId: "C", priority: "LOW", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.7 },
    ];

    const filtered = filterByPriority(analyses, "MEDIUM");

    if (filtered.length === 2 && filtered[0].priority === "HIGH" && filtered[1].priority === "MEDIUM") {
      pass(testName);
    } else {
      fail(testName, `Expected HIGH and MEDIUM results, got: ${JSON.stringify(filtered)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: filterByPriority - LOW threshold (includes all)
// -----------------------------------------------------------------------------
async function testFilterByPriority_Low() {
  const testName = "filterByPriority: LOW threshold includes all priorities";

  try {
    const analyses = [
      { advisoryId: "A", priority: "HIGH", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.9 },
      { advisoryId: "B", priority: "MEDIUM", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.8 },
      { advisoryId: "C", priority: "LOW", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.7 },
    ];

    const filtered = filterByPriority(analyses, "LOW");

    if (filtered.length === 3) {
      pass(testName);
    } else {
      fail(testName, `Expected 3 results, got: ${filtered.length}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: filterByPriority - default threshold (MEDIUM)
// -----------------------------------------------------------------------------
async function testFilterByPriority_DefaultThreshold() {
  const testName = "filterByPriority: defaults to MEDIUM threshold";

  try {
    const analyses = [
      { advisoryId: "A", priority: "HIGH", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.9 },
      { advisoryId: "B", priority: "MEDIUM", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.8 },
      { advisoryId: "C", priority: "LOW", rationale: "", affected_components: [], recommended_actions: [], confidence: 0.7 },
    ];

    const filtered = filterByPriority(analyses); // No threshold specified

    if (filtered.length === 2) {
      pass(testName);
    } else {
      fail(testName, `Expected 2 results (HIGH + MEDIUM), got: ${filtered.length}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: filterByPriority - empty array
// -----------------------------------------------------------------------------
async function testFilterByPriority_EmptyArray() {
  const testName = "filterByPriority: handles empty array";

  try {
    const filtered = filterByPriority([], "HIGH");

    if (filtered.length === 0) {
      pass(testName);
    } else {
      fail(testName, `Expected empty array, got: ${filtered.length} items`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: analyzeAdvisory - cache read error handling
// -----------------------------------------------------------------------------
async function testAnalyzeAdvisory_CacheReadError() {
  const testName = "analyzeAdvisory: continues on cache read error";
  await resetTestState();

  try {
    // Corrupt the cache directory to simulate cache error
    const cacheDir = path.join(TEST_CACHE_DIR, ".openclaw", "clawsec-analyst-cache");
    await fs.chmod(cacheDir, 0o000); // Remove all permissions

    const client = new MockClaudeClient();
    client.setResponse(createAnalysisResponse());

    const advisory = createAdvisory({ id: "TEST-020" });
    const result = await analyzeAdvisory(advisory, client);

    // Restore permissions
    await fs.chmod(cacheDir, 0o755);

    // Should succeed despite cache error
    if (result.priority === "HIGH") {
      pass(testName);
    } else {
      fail(testName, "Analysis should succeed despite cache error");
    }
  } catch (error) {
    // Restore permissions if test fails
    try {
      const cacheDir = path.join(TEST_CACHE_DIR, ".openclaw", "clawsec-analyst-cache");
      await fs.chmod(cacheDir, 0o755);
    } catch (e) {
      // Ignore
    }
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Run all tests
// -----------------------------------------------------------------------------
async function runAllTests() {
  console.log("=== Advisory Analyzer Tests ===\n");

  try {
    // analyzeAdvisory tests
    await testAnalyzeAdvisory_Success();
    await testAnalyzeAdvisory_MissingId();
    await testAnalyzeAdvisory_MissingSeverity();
    await testAnalyzeAdvisory_MissingDescription();
    await testAnalyzeAdvisory_UsesCache();
    await testAnalyzeAdvisory_CachesResult();
    await testAnalyzeAdvisory_ApiErrorWithCacheFallback();
    await testAnalyzeAdvisory_ApiErrorNoCache();
    await testAnalyzeAdvisory_MarkdownCodeBlocks();
    await testAnalyzeAdvisory_GenericCodeBlocks();
    await testAnalyzeAdvisory_ResponseMissingFields();
    await testAnalyzeAdvisory_InvalidPriority();
    await testAnalyzeAdvisory_InvalidConfidence();
    await testAnalyzeAdvisory_DefaultConfidence();
    await testAnalyzeAdvisory_CacheReadError();

    // analyzeAdvisories (batch) tests
    await testAnalyzeAdvisories_Success();
    await testAnalyzeAdvisories_PartialFailure();
    await testAnalyzeAdvisories_FallbackSeverityMapping();

    // filterByPriority tests
    await testFilterByPriority_High();
    await testFilterByPriority_Medium();
    await testFilterByPriority_Low();
    await testFilterByPriority_DefaultThreshold();
    await testFilterByPriority_EmptyArray();

    report();
  } finally {
    // Cleanup test cache directory
    try {
      await fs.rm(TEST_CACHE_DIR, { recursive: true, force: true });
    } catch (error) {
      // Ignore cleanup errors
    }

    // Restore original HOME
    process.env.HOME = originalHome;
  }

  exitWithResults();
}

runAllTests();
