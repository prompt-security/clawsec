#!/usr/bin/env node

/**
 * Integration test for policy parsing workflow in clawsec-analyst.
 *
 * Tests cover:
 * - End-to-end policy parsing workflow (NL input -> Claude API -> structured policy)
 * - Multiple policies batch processing with different confidence levels
 * - Policy validation workflow with suggestions
 * - Low confidence handling and rejection
 * - Error resilience with fallback
 * - Policy formatting and display output
 * - Complete integration of policy-engine with Claude API client
 *
 * Run: ANTHROPIC_API_KEY=test node skills/clawsec-analyst/test/integration-policy.test.mjs
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

// Dynamic import to ensure we test the actual compiled modules
const {
  parsePolicy,
  parsePolicies,
  validatePolicyStatement,
  formatPolicyResult,
  getConfidenceThreshold,
} = await import(`${LIB_PATH}/policy-engine.js`);

// -----------------------------------------------------------------------------
// Mock Claude Client
// -----------------------------------------------------------------------------

class MockClaudeClient {
  constructor() {
    this._responseFn = null;
    this._callCount = 0;
    this._shouldFail = false;
  }

  /**
   * Set response function for controlled responses
   */
  setResponseFn(fn) {
    this._responseFn = fn;
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
   * Mock parsePolicy implementation
   */
  async parsePolicy(nlPolicy) {
    this._callCount++;

    if (this._shouldFail) {
      throw new Error("Mock Claude API unavailable");
    }

    if (!this._responseFn) {
      throw new Error("No response function configured");
    }

    return this._responseFn(nlPolicy, this._callCount);
  }

  getCallCount() {
    return this._callCount;
  }
}

// -----------------------------------------------------------------------------
// Test Helpers
// -----------------------------------------------------------------------------

/**
 * Create a valid policy response with high confidence
 */
function createValidPolicyResponse(overrides = {}) {
  const defaults = {
    policy: {
      type: "advisory-severity",
      condition: {
        operator: "equals",
        field: "severity",
        value: "critical",
      },
      action: "block",
      description: "Block critical severity advisories",
    },
    confidence: 0.95,
    ambiguities: [],
  };

  return JSON.stringify({
    ...defaults,
    ...overrides,
    policy: {
      ...defaults.policy,
      ...(overrides.policy || {}),
      condition: {
        ...defaults.policy.condition,
        ...(overrides.policy?.condition || {}),
      },
    },
  });
}

/**
 * Create a low-confidence response
 */
function createLowConfidenceResponse(ambiguities = []) {
  return JSON.stringify({
    policy: {
      type: "custom",
      condition: {
        operator: "equals",
        field: "unknown",
        value: "something",
      },
      action: "log",
      description: "Ambiguous policy",
    },
    confidence: 0.3,
    ambiguities: ambiguities.length > 0
      ? ambiguities
      : ["Policy statement is too vague", "Unable to determine specific action"],
  });
}

/**
 * Create a response based on the NL input
 */
function createContextualResponse(nlPolicy) {
  // Simulate contextual responses based on input
  if (nlPolicy.toLowerCase().includes("critical") && nlPolicy.toLowerCase().includes("block")) {
    return createValidPolicyResponse({
      policy: {
        type: "advisory-severity",
        condition: {
          operator: "equals",
          field: "severity",
          value: "critical",
        },
        action: "block",
        description: "Block critical severity advisories",
      },
      confidence: 0.95,
    });
  }

  if (nlPolicy.toLowerCase().includes("high") && nlPolicy.toLowerCase().includes("warn")) {
    return createValidPolicyResponse({
      policy: {
        type: "advisory-severity",
        condition: {
          operator: "equals",
          field: "severity",
          value: "high",
        },
        action: "warn",
        description: "Warn on high severity advisories",
      },
      confidence: 0.88,
    });
  }

  if (nlPolicy.toLowerCase().includes("risk") && nlPolicy.toLowerCase().includes("score")) {
    return createValidPolicyResponse({
      policy: {
        type: "risk-score",
        condition: {
          operator: "greater_than",
          field: "riskScore",
          value: 75,
        },
        action: "require_approval",
        description: "Require approval for risk scores above 75",
      },
      confidence: 0.92,
    });
  }

  // Default to low confidence
  return createLowConfidenceResponse();
}

// -----------------------------------------------------------------------------
// Test: Complete policy parsing workflow - NL to structured policy
// -----------------------------------------------------------------------------
async function testCompletePolicyParsingWorkflow() {
  const testName = "Complete policy parsing workflow: NL input -> Claude -> structured policy";

  try {
    const nlPolicy = "Block all critical severity advisories";

    const client = new MockClaudeClient();
    client.setResponseFn((input) => {
      if (input === nlPolicy) {
        return createValidPolicyResponse({
          confidence: 0.95,
        });
      }
      return createLowConfidenceResponse();
    });

    // Parse the policy
    const result = await parsePolicy(nlPolicy, client);

    // Verify the complete workflow
    if (!result.policy) {
      fail(testName, "Expected policy to be defined");
      return;
    }

    if (
      result.policy.type === "advisory-severity" &&
      result.policy.condition.operator === "equals" &&
      result.policy.condition.field === "severity" &&
      result.policy.condition.value === "critical" &&
      result.policy.action === "block" &&
      result.policy.id &&
      result.policy.id.startsWith("policy-") &&
      result.policy.createdAt &&
      result.confidence === 0.95 &&
      client.getCallCount() === 1
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected result: ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Batch processing multiple policies with different confidence levels
// -----------------------------------------------------------------------------
async function testBatchPolicyProcessing() {
  const testName = "Batch processing: multiple policies with different confidence levels";

  try {
    const nlPolicies = [
      "Block all critical severity advisories",
      "Warn on high severity advisories",
      "Require approval for risk scores above 75",
      "Do something vague", // This should have low confidence
    ];

    const client = new MockClaudeClient();
    client.setResponseFn(createContextualResponse);

    // Parse all policies
    const results = await parsePolicies(nlPolicies, client);

    // Verify batch results
    if (results.length !== 4) {
      fail(testName, `Expected 4 results, got ${results.length}`);
      return;
    }

    // First three should succeed with high confidence
    const successCount = results.filter((r) => r.policy !== null).length;
    const lowConfidenceCount = results.filter((r) => r.confidence < getConfidenceThreshold()).length;

    if (
      successCount === 3 &&
      lowConfidenceCount === 1 &&
      results[0].policy?.type === "advisory-severity" &&
      results[1].policy?.type === "advisory-severity" &&
      results[2].policy?.type === "risk-score" &&
      results[3].policy === null &&
      client.getCallCount() === 4
    ) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected 3 successes and 1 low confidence, got ${successCount} successes, ${lowConfidenceCount} low confidence. Results: ${JSON.stringify(results.map(r => ({ type: r.policy?.type, conf: r.confidence })))}`
      );
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Policy validation workflow with suggestions
// -----------------------------------------------------------------------------
async function testPolicyValidationWorkflow() {
  const testName = "Policy validation workflow: provides suggestions for improvement";

  try {
    const validPolicy = "Block all critical severity advisories";
    const ambiguousPolicy = "Do something risky";

    const client = new MockClaudeClient();
    client.setResponseFn((input) => {
      if (input === validPolicy) {
        return createValidPolicyResponse({ confidence: 0.95 });
      }
      return createLowConfidenceResponse([
        "The term 'risky' is not specific enough",
        "No clear action specified",
      ]);
    });

    // Validate valid policy
    const validResult = await validatePolicyStatement(validPolicy, client);

    if (!validResult.valid) {
      fail(testName, "Expected valid policy to be marked as valid");
      return;
    }

    // Validate ambiguous policy
    const ambiguousResult = await validatePolicyStatement(ambiguousPolicy, client);

    if (
      validResult.valid === true &&
      validResult.suggestions.length === 0 &&
      ambiguousResult.valid === false &&
      ambiguousResult.suggestions.length > 0 &&
      ambiguousResult.suggestions.some(s => s.includes("specific"))
    ) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected validation workflow to work correctly. Valid: ${JSON.stringify(validResult)}, Ambiguous: ${JSON.stringify(ambiguousResult)}`
      );
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Low confidence handling and rejection
// -----------------------------------------------------------------------------
async function testLowConfidenceHandling() {
  const testName = "Low confidence handling: rejects ambiguous policies";

  try {
    const ambiguousPolicy = "Maybe block some stuff";

    const client = new MockClaudeClient();
    client.setResponseFn(() => createLowConfidenceResponse([
      "Policy is too ambiguous",
      "No clear condition or action",
    ]));

    const result = await parsePolicy(ambiguousPolicy, client);

    // Result should have null policy and low confidence
    if (
      result.policy === null &&
      result.confidence < getConfidenceThreshold() &&
      result.ambiguities.length > 0 &&
      result.ambiguities[0].includes("ambiguous")
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected null policy with low confidence, got: ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Error resilience with Claude API failure
// -----------------------------------------------------------------------------
async function testErrorResilience() {
  const testName = "Error resilience: handles Claude API failures gracefully";

  try {
    const nlPolicy = "Block critical advisories";

    const client = new MockClaudeClient();
    client.setShouldFail(true);

    // Attempt to parse - should throw
    try {
      await parsePolicy(nlPolicy, client);
      fail(testName, "Expected error when Claude API fails");
    } catch (error) {
      if (error.code === "CLAUDE_API_ERROR" && error.message.includes("Failed to parse policy")) {
        pass(testName);
      } else {
        fail(testName, `Expected CLAUDE_API_ERROR, got: ${error.message}`);
      }
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Policy formatting and display output
// -----------------------------------------------------------------------------
async function testPolicyFormatting() {
  const testName = "Policy formatting: generates human-readable output";

  try {
    const nlPolicy = "Block all critical severity advisories";

    const client = new MockClaudeClient();
    client.setResponseFn(() => createValidPolicyResponse({
      confidence: 0.92,
      ambiguities: ["Minor: could specify time window"],
    }));

    const result = await parsePolicy(nlPolicy, client);

    // Format the result
    const formatted = formatPolicyResult(result);

    // Verify formatting includes key elements
    if (
      formatted.includes("Policy Parse Result") &&
      formatted.includes("Confidence: 92.0%") &&
      formatted.includes("Structured Policy") &&
      formatted.includes("Type: advisory-severity") &&
      formatted.includes("Action: block") &&
      formatted.includes("Condition:") &&
      formatted.includes("Field: severity") &&
      formatted.includes("Ambiguities:") &&
      formatted.includes("Minor: could specify time window")
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected formatting: ${formatted}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Complete integration with all policy types
// -----------------------------------------------------------------------------
async function testComprehensivePolicyTypes() {
  const testName = "Comprehensive policy types: supports all policy type workflows";

  try {
    const policyTypes = [
      {
        nl: "Block critical advisories",
        type: "advisory-severity",
        action: "block",
      },
      {
        nl: "Prevent access to /etc/passwd",
        type: "filesystem-access",
        action: "block",
      },
      {
        nl: "Warn about connections to untrusted domains",
        type: "network-access",
        action: "warn",
      },
      {
        nl: "Require approval for vulnerabilities with CVSS > 7",
        type: "dependency-vulnerability",
        action: "require_approval",
      },
      {
        nl: "Block installations with risk score above 80",
        type: "risk-score",
        action: "block",
      },
    ];

    const client = new MockClaudeClient();
    client.setResponseFn((input, callCount) => {
      const policy = policyTypes[callCount - 1];
      return createValidPolicyResponse({
        policy: {
          type: policy.type,
          condition: {
            operator: "equals",
            field: "test",
            value: "test",
          },
          action: policy.action,
          description: input,
        },
        confidence: 0.90,
      });
    });

    const results = await parsePolicies(
      policyTypes.map(p => p.nl),
      client
    );

    // Verify all policies were parsed with correct types
    const allValid = results.every((r, idx) => {
      return (
        r.policy !== null &&
        r.policy.type === policyTypes[idx].type &&
        r.policy.action === policyTypes[idx].action &&
        r.confidence >= 0.90
      );
    });

    if (allValid && results.length === 5) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected all 5 policy types to parse successfully, got: ${JSON.stringify(results.map(r => ({ type: r.policy?.type, action: r.policy?.action })))}`
      );
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Input validation edge cases
// -----------------------------------------------------------------------------
async function testInputValidation() {
  const testName = "Input validation: handles edge cases (empty, too short)";

  try {
    const client = new MockClaudeClient();
    client.setResponseFn(() => createValidPolicyResponse());

    // Test empty string
    try {
      await parsePolicy("", client);
      fail(testName, "Expected error for empty policy");
      return;
    } catch (error) {
      if (!error.message.includes("cannot be empty")) {
        fail(testName, `Expected 'cannot be empty' error, got: ${error.message}`);
        return;
      }
    }

    // Test too short string
    try {
      await parsePolicy("block", client);
      fail(testName, "Expected error for too short policy");
      return;
    } catch (error) {
      if (!error.message.includes("too short")) {
        fail(testName, `Expected 'too short' error, got: ${error.message}`);
        return;
      }
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Run all tests
// -----------------------------------------------------------------------------
async function runAllTests() {
  console.log("=== Integration Test: Policy Parsing Workflow ===\n");

  await testCompletePolicyParsingWorkflow();
  await testBatchPolicyProcessing();
  await testPolicyValidationWorkflow();
  await testLowConfidenceHandling();
  await testErrorResilience();
  await testPolicyFormatting();
  await testComprehensivePolicyTypes();
  await testInputValidation();

  report();
  exitWithResults();
}

runAllTests();
