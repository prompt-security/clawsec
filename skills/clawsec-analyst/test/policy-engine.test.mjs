#!/usr/bin/env node

/**
 * Policy engine tests for clawsec-analyst.
 *
 * Tests cover:
 * - Policy parsing success and failure cases
 * - Confidence threshold enforcement
 * - Input validation (empty, too short)
 * - Response parsing (JSON, markdown-wrapped JSON)
 * - Policy structure validation (types, operators, actions)
 * - Batch policy parsing
 * - Policy validation without full parsing
 * - Error handling and recovery
 * - Policy ID generation uniqueness
 * - Format output for display
 *
 * Run: node skills/clawsec-analyst/test/policy-engine.test.mjs
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

// Dynamic import to ensure we test the actual module
const {
  parsePolicy,
  parsePolicies,
  validatePolicyStatement,
  formatPolicyResult,
  getConfidenceThreshold,
} = await import(`${LIB_PATH}/policy-engine.js`);

/**
 * Mock Claude API client for testing
 * Allows controlled responses and error injection
 */
class MockClaudeClient {
  constructor(responseFn = null) {
    this._responseFn = responseFn;
    this._callCount = 0;
  }

  async parsePolicy(nlPolicy) {
    this._callCount++;
    if (this._responseFn) {
      return this._responseFn(nlPolicy, this._callCount);
    }
    throw new Error("No response function configured");
  }

  getCallCount() {
    return this._callCount;
  }
}

/**
 * Helper: Create a valid policy response
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
 * Helper: Create a low-confidence response
 */
function createLowConfidenceResponse() {
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
    ambiguities: [
      "Policy statement is too vague",
      "Unable to determine specific action",
    ],
  });
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - valid high-confidence policy
// -----------------------------------------------------------------------------
async function testParsePolicy_ValidHighConfidence() {
  const testName = "parsePolicy: valid high-confidence policy succeeds";
  try {
    const mockClient = new MockClaudeClient(() => createValidPolicyResponse());

    const result = await parsePolicy(
      "Block all critical severity advisories",
      mockClient
    );

    if (!result.policy) {
      fail(testName, "Expected policy to be defined");
      return;
    }

    if (result.confidence < getConfidenceThreshold()) {
      fail(
        testName,
        `Expected confidence >= ${getConfidenceThreshold()}, got ${result.confidence}`
      );
      return;
    }

    if (result.policy.type !== "advisory-severity") {
      fail(testName, `Expected type 'advisory-severity', got ${result.policy.type}`);
      return;
    }

    if (result.policy.action !== "block") {
      fail(testName, `Expected action 'block', got ${result.policy.action}`);
      return;
    }

    if (!result.policy.id || !result.policy.id.startsWith("policy-")) {
      fail(testName, "Expected policy ID to be generated");
      return;
    }

    if (!result.policy.createdAt) {
      fail(testName, "Expected createdAt timestamp to be set");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - low confidence returns null policy
// -----------------------------------------------------------------------------
async function testParsePolicy_LowConfidence() {
  const testName = "parsePolicy: low confidence returns null policy";
  try {
    const mockClient = new MockClaudeClient(() => createLowConfidenceResponse());

    const result = await parsePolicy("Do something with advisories", mockClient);

    if (result.policy !== null) {
      fail(testName, "Expected policy to be null for low confidence");
      return;
    }

    if (result.confidence >= getConfidenceThreshold()) {
      fail(
        testName,
        `Expected confidence < ${getConfidenceThreshold()}, got ${result.confidence}`
      );
      return;
    }

    if (result.ambiguities.length === 0) {
      fail(testName, "Expected ambiguities to be present for low confidence");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - empty input
// -----------------------------------------------------------------------------
async function testParsePolicy_EmptyInput() {
  const testName = "parsePolicy: empty input throws POLICY_AMBIGUOUS error";
  try {
    const mockClient = new MockClaudeClient();

    try {
      await parsePolicy("", mockClient);
      fail(testName, "Expected error for empty input");
    } catch (error) {
      if (error.code !== "POLICY_AMBIGUOUS") {
        fail(testName, `Expected POLICY_AMBIGUOUS error, got ${error.code}`);
        return;
      }
      pass(testName);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - input too short
// -----------------------------------------------------------------------------
async function testParsePolicy_TooShort() {
  const testName = "parsePolicy: input too short throws POLICY_AMBIGUOUS error";
  try {
    const mockClient = new MockClaudeClient();

    try {
      await parsePolicy("block", mockClient);
      fail(testName, "Expected error for input too short");
    } catch (error) {
      if (error.code !== "POLICY_AMBIGUOUS") {
        fail(testName, `Expected POLICY_AMBIGUOUS error, got ${error.code}`);
        return;
      }
      if (!error.message.includes("minimum 10 characters")) {
        fail(testName, "Expected error message about minimum length");
        return;
      }
      pass(testName);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - markdown-wrapped JSON response
// -----------------------------------------------------------------------------
async function testParsePolicy_MarkdownWrappedJSON() {
  const testName = "parsePolicy: handles markdown-wrapped JSON response";
  try {
    const mockClient = new MockClaudeClient(() => {
      const json = createValidPolicyResponse();
      return `Here's the parsed policy:\n\`\`\`json\n${json}\n\`\`\`\n`;
    });

    const result = await parsePolicy(
      "Block all critical severity advisories",
      mockClient
    );

    if (!result.policy) {
      fail(testName, "Expected policy to be parsed from markdown-wrapped JSON");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - invalid policy type
// -----------------------------------------------------------------------------
async function testParsePolicy_InvalidType() {
  const testName = "parsePolicy: invalid policy type throws POLICY_AMBIGUOUS error";
  try {
    const mockClient = new MockClaudeClient(() =>
      createValidPolicyResponse({
        policy: { type: "invalid-type" },
      })
    );

    try {
      await parsePolicy("Some policy", mockClient);
      fail(testName, "Expected error for invalid policy type");
    } catch (error) {
      if (error.code !== "POLICY_AMBIGUOUS") {
        fail(testName, `Expected POLICY_AMBIGUOUS error, got ${error.code}`);
        return;
      }
      if (!error.message.includes("Invalid policy type")) {
        fail(testName, "Expected error message about invalid type");
        return;
      }
      pass(testName);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - invalid condition operator
// -----------------------------------------------------------------------------
async function testParsePolicy_InvalidOperator() {
  const testName = "parsePolicy: invalid operator throws POLICY_AMBIGUOUS error";
  try {
    const mockClient = new MockClaudeClient(() =>
      createValidPolicyResponse({
        policy: {
          condition: { operator: "invalid-op" },
        },
      })
    );

    try {
      await parsePolicy("Some policy", mockClient);
      fail(testName, "Expected error for invalid operator");
    } catch (error) {
      if (error.code !== "POLICY_AMBIGUOUS") {
        fail(testName, `Expected POLICY_AMBIGUOUS error, got ${error.code}`);
        return;
      }
      if (!error.message.includes("Invalid condition operator")) {
        fail(testName, "Expected error message about invalid operator");
        return;
      }
      pass(testName);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - invalid action
// -----------------------------------------------------------------------------
async function testParsePolicy_InvalidAction() {
  const testName = "parsePolicy: invalid action throws POLICY_AMBIGUOUS error";
  try {
    const mockClient = new MockClaudeClient(() =>
      createValidPolicyResponse({
        policy: { action: "invalid-action" },
      })
    );

    try {
      await parsePolicy("Some policy", mockClient);
      fail(testName, "Expected error for invalid action");
    } catch (error) {
      if (error.code !== "POLICY_AMBIGUOUS") {
        fail(testName, `Expected POLICY_AMBIGUOUS error, got ${error.code}`);
        return;
      }
      if (!error.message.includes("Invalid policy action")) {
        fail(testName, "Expected error message about invalid action");
        return;
      }
      pass(testName);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - missing condition field
// -----------------------------------------------------------------------------
async function testParsePolicy_MissingConditionField() {
  const testName = "parsePolicy: missing condition field throws POLICY_AMBIGUOUS error";
  try {
    const mockClient = new MockClaudeClient(() =>
      createValidPolicyResponse({
        policy: {
          condition: { field: "" },
        },
      })
    );

    try {
      await parsePolicy("Some policy", mockClient);
      fail(testName, "Expected error for missing condition field");
    } catch (error) {
      if (error.code !== "POLICY_AMBIGUOUS") {
        fail(testName, `Expected POLICY_AMBIGUOUS error, got ${error.code}`);
        return;
      }
      if (!error.message.includes("must specify a field")) {
        fail(testName, "Expected error message about missing field");
        return;
      }
      pass(testName);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - missing condition value
// -----------------------------------------------------------------------------
async function testParsePolicy_MissingConditionValue() {
  const testName = "parsePolicy: missing condition value throws POLICY_AMBIGUOUS error";
  try {
    const mockClient = new MockClaudeClient(() =>
      createValidPolicyResponse({
        policy: {
          condition: { value: null },
        },
      })
    );

    try {
      await parsePolicy("Some policy", mockClient);
      fail(testName, "Expected error for missing condition value");
    } catch (error) {
      if (error.code !== "POLICY_AMBIGUOUS") {
        fail(testName, `Expected POLICY_AMBIGUOUS error, got ${error.code}`);
        return;
      }
      if (!error.message.includes("must specify a value")) {
        fail(testName, "Expected error message about missing value");
        return;
      }
      pass(testName);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - malformed JSON response
// -----------------------------------------------------------------------------
async function testParsePolicy_MalformedJSON() {
  const testName = "parsePolicy: malformed JSON throws CLAUDE_API_ERROR";
  try {
    const mockClient = new MockClaudeClient(() => "not valid json {{{");

    try {
      await parsePolicy("Some policy", mockClient);
      fail(testName, "Expected error for malformed JSON");
    } catch (error) {
      if (error.code !== "CLAUDE_API_ERROR") {
        fail(testName, `Expected CLAUDE_API_ERROR, got ${error.code}`);
        return;
      }
      if (!error.message.includes("Failed to parse Claude API response")) {
        fail(testName, "Expected error message about parsing failure");
        return;
      }
      pass(testName);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - response missing policy field
// -----------------------------------------------------------------------------
async function testParsePolicy_MissingPolicyField() {
  const testName = "parsePolicy: response missing policy field throws CLAUDE_API_ERROR";
  try {
    const mockClient = new MockClaudeClient(() =>
      JSON.stringify({
        confidence: 0.9,
        ambiguities: [],
      })
    );

    try {
      await parsePolicy("Some policy", mockClient);
      fail(testName, "Expected error for missing policy field");
    } catch (error) {
      if (error.code !== "CLAUDE_API_ERROR") {
        fail(testName, `Expected CLAUDE_API_ERROR, got ${error.code}`);
        return;
      }
      if (!error.message.includes("missing policy or confidence")) {
        fail(testName, "Expected error message about missing policy");
        return;
      }
      pass(testName);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - response missing confidence field
// -----------------------------------------------------------------------------
async function testParsePolicy_MissingConfidenceField() {
  const testName = "parsePolicy: response missing confidence field throws CLAUDE_API_ERROR";
  try {
    const mockClient = new MockClaudeClient(() =>
      JSON.stringify({
        policy: {
          type: "custom",
          condition: { operator: "equals", field: "test", value: "test" },
          action: "log",
          description: "test",
        },
        ambiguities: [],
      })
    );

    try {
      await parsePolicy("Some policy", mockClient);
      fail(testName, "Expected error for missing confidence field");
    } catch (error) {
      if (error.code !== "CLAUDE_API_ERROR") {
        fail(testName, `Expected CLAUDE_API_ERROR, got ${error.code}`);
        return;
      }
      if (!error.message.includes("missing policy or confidence")) {
        fail(testName, "Expected error message about missing confidence");
        return;
      }
      pass(testName);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - all valid policy types
// -----------------------------------------------------------------------------
async function testParsePolicy_AllValidTypes() {
  const testName = "parsePolicy: accepts all valid policy types";
  const validTypes = [
    "advisory-severity",
    "filesystem-access",
    "network-access",
    "dependency-vulnerability",
    "risk-score",
    "custom",
  ];

  try {
    for (const type of validTypes) {
      const mockClient = new MockClaudeClient(() =>
        createValidPolicyResponse({ policy: { type } })
      );

      const result = await parsePolicy("Test policy", mockClient);

      if (!result.policy) {
        fail(testName, `Expected valid policy for type ${type}`);
        return;
      }

      if (result.policy.type !== type) {
        fail(testName, `Expected type ${type}, got ${result.policy.type}`);
        return;
      }
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - all valid operators
// -----------------------------------------------------------------------------
async function testParsePolicy_AllValidOperators() {
  const testName = "parsePolicy: accepts all valid operators";
  const validOperators = [
    "equals",
    "contains",
    "greater_than",
    "less_than",
    "matches_regex",
  ];

  try {
    for (const operator of validOperators) {
      const mockClient = new MockClaudeClient(() =>
        createValidPolicyResponse({
          policy: { condition: { operator } },
        })
      );

      const result = await parsePolicy("Test policy", mockClient);

      if (!result.policy) {
        fail(testName, `Expected valid policy for operator ${operator}`);
        return;
      }

      if (result.policy.condition.operator !== operator) {
        fail(
          testName,
          `Expected operator ${operator}, got ${result.policy.condition.operator}`
        );
        return;
      }
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - all valid actions
// -----------------------------------------------------------------------------
async function testParsePolicy_AllValidActions() {
  const testName = "parsePolicy: accepts all valid actions";
  const validActions = ["block", "warn", "require_approval", "log", "allow"];

  try {
    for (const action of validActions) {
      const mockClient = new MockClaudeClient(() =>
        createValidPolicyResponse({ policy: { action } })
      );

      const result = await parsePolicy("Test policy", mockClient);

      if (!result.policy) {
        fail(testName, `Expected valid policy for action ${action}`);
        return;
      }

      if (result.policy.action !== action) {
        fail(testName, `Expected action ${action}, got ${result.policy.action}`);
        return;
      }
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - policy ID uniqueness
// -----------------------------------------------------------------------------
async function testParsePolicy_PolicyIdUniqueness() {
  const testName = "parsePolicy: generates unique policy IDs";
  try {
    const mockClient = new MockClaudeClient(() => createValidPolicyResponse());

    const result1 = await parsePolicy("Test policy 1", mockClient);
    const result2 = await parsePolicy("Test policy 2", mockClient);

    if (!result1.policy || !result2.policy) {
      fail(testName, "Expected both policies to be defined");
      return;
    }

    if (result1.policy.id === result2.policy.id) {
      fail(testName, "Expected unique policy IDs");
      return;
    }

    if (!result1.policy.id.match(/^policy-[a-z0-9]+-[a-f0-9]+$/)) {
      fail(testName, "Expected policy ID to match format policy-{timestamp}-{random}");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicies - batch processing
// -----------------------------------------------------------------------------
async function testParsePolicies_Batch() {
  const testName = "parsePolicies: processes multiple policies in batch";
  try {
    let callCount = 0;
    const mockClient = new MockClaudeClient(() => {
      callCount++;
      return createValidPolicyResponse({
        policy: { description: `Policy ${callCount}` },
      });
    });

    const policies = [
      "Block critical advisories",
      "Warn on high severity",
      "Log all filesystem access",
    ];

    const results = await parsePolicies(policies, mockClient);

    if (results.length !== 3) {
      fail(testName, `Expected 3 results, got ${results.length}`);
      return;
    }

    if (!results.every((r) => r.policy !== null)) {
      fail(testName, "Expected all policies to be parsed successfully");
      return;
    }

    if (callCount !== 3) {
      fail(testName, `Expected 3 API calls, got ${callCount}`);
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicies - handles individual failures
// -----------------------------------------------------------------------------
async function testParsePolicies_IndividualFailures() {
  const testName = "parsePolicies: handles individual policy failures gracefully";
  try {
    let callCount = 0;
    const mockClient = new MockClaudeClient(() => {
      callCount++;
      if (callCount === 2) {
        throw new Error("API error");
      }
      return createValidPolicyResponse();
    });

    const policies = [
      "Block critical advisories policy 1",
      "Warn on high severity policy 2",
      "Log filesystem access policy 3",
    ];

    const results = await parsePolicies(policies, mockClient);

    if (results.length !== 3) {
      fail(testName, `Expected 3 results, got ${results.length}`);
      return;
    }

    if (results[0].policy === null) {
      fail(testName, "Expected first policy to succeed");
      return;
    }

    if (results[1].policy !== null) {
      fail(testName, "Expected second policy to fail");
      return;
    }

    if (results[1].confidence !== 0) {
      fail(testName, "Expected failed policy to have zero confidence");
      return;
    }

    if (results[1].ambiguities.length === 0) {
      fail(testName, "Expected failed policy to have error in ambiguities");
      return;
    }

    if (results[2].policy === null) {
      fail(testName, "Expected third policy to succeed");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: validatePolicyStatement - valid policy
// -----------------------------------------------------------------------------
async function testValidatePolicyStatement_Valid() {
  const testName = "validatePolicyStatement: returns valid for high-confidence policy";
  try {
    const mockClient = new MockClaudeClient(() => createValidPolicyResponse());

    const result = await validatePolicyStatement(
      "Block all critical severity advisories",
      mockClient
    );

    if (!result.valid) {
      fail(testName, "Expected validation to pass for high-confidence policy");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: validatePolicyStatement - invalid policy with suggestions
// -----------------------------------------------------------------------------
async function testValidatePolicyStatement_Invalid() {
  const testName = "validatePolicyStatement: returns invalid with suggestions";
  try {
    const mockClient = new MockClaudeClient(() => createLowConfidenceResponse());

    const result = await validatePolicyStatement("Do something", mockClient);

    if (result.valid) {
      fail(testName, "Expected validation to fail for low-confidence policy");
      return;
    }

    if (result.suggestions.length === 0) {
      fail(testName, "Expected suggestions for invalid policy");
      return;
    }

    if (!result.suggestions.some((s) => s.includes("ambiguous"))) {
      fail(testName, "Expected suggestions to mention ambiguity");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: validatePolicyStatement - handles errors gracefully
// -----------------------------------------------------------------------------
async function testValidatePolicyStatement_HandlesErrors() {
  const testName = "validatePolicyStatement: handles errors gracefully";
  try {
    const mockClient = new MockClaudeClient(() => {
      throw new Error("API error");
    });

    const result = await validatePolicyStatement("Test policy", mockClient);

    if (result.valid) {
      fail(testName, "Expected validation to fail when error occurs");
      return;
    }

    if (result.suggestions.length === 0) {
      fail(testName, "Expected error message in suggestions");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: formatPolicyResult - successful parse
// -----------------------------------------------------------------------------
async function testFormatPolicyResult_Success() {
  const testName = "formatPolicyResult: formats successful parse result";
  try {
    const result = {
      policy: {
        id: "policy-test-123",
        type: "advisory-severity",
        action: "block",
        description: "Block critical advisories",
        condition: {
          field: "severity",
          operator: "equals",
          value: "critical",
        },
        createdAt: "2026-02-27T00:00:00Z",
      },
      confidence: 0.95,
      ambiguities: [],
    };

    const formatted = formatPolicyResult(result);

    if (!formatted.includes("Policy Parse Result")) {
      fail(testName, "Expected formatted output to include title");
      return;
    }

    if (!formatted.includes("95.0%")) {
      fail(testName, "Expected formatted output to include confidence");
      return;
    }

    if (!formatted.includes("policy-test-123")) {
      fail(testName, "Expected formatted output to include policy ID");
      return;
    }

    if (!formatted.includes("advisory-severity")) {
      fail(testName, "Expected formatted output to include policy type");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: formatPolicyResult - failed parse
// -----------------------------------------------------------------------------
async function testFormatPolicyResult_Failure() {
  const testName = "formatPolicyResult: formats failed parse result";
  try {
    const result = {
      policy: null,
      confidence: 0.3,
      ambiguities: ["Policy is too vague", "Cannot determine action"],
    };

    const formatted = formatPolicyResult(result);

    if (!formatted.includes("Policy Parse Result")) {
      fail(testName, "Expected formatted output to include title");
      return;
    }

    if (!formatted.includes("30.0%")) {
      fail(testName, "Expected formatted output to include confidence");
      return;
    }

    if (!formatted.includes("Policy is too vague")) {
      fail(testName, "Expected formatted output to include ambiguities");
      return;
    }

    if (!formatted.includes("failed to parse")) {
      fail(testName, "Expected formatted output to indicate failure");
      return;
    }

    if (!formatted.includes("Suggestions:")) {
      fail(testName, "Expected formatted output to include suggestions");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: getConfidenceThreshold - returns correct value
// -----------------------------------------------------------------------------
async function testGetConfidenceThreshold() {
  const testName = "getConfidenceThreshold: returns correct threshold";
  try {
    const threshold = getConfidenceThreshold();

    if (typeof threshold !== "number") {
      fail(testName, "Expected threshold to be a number");
      return;
    }

    if (threshold !== 0.7) {
      fail(testName, `Expected threshold to be 0.7, got ${threshold}`);
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parsePolicy - ambiguities without low confidence
// -----------------------------------------------------------------------------
async function testParsePolicy_AmbiguitiesWithHighConfidence() {
  const testName = "parsePolicy: high confidence with ambiguities still succeeds";
  try {
    const mockClient = new MockClaudeClient(() =>
      createValidPolicyResponse({
        confidence: 0.85,
        ambiguities: ["Minor: Could be more specific about timeframe"],
      })
    );

    const result = await parsePolicy("Block recent critical advisories", mockClient);

    if (!result.policy) {
      fail(testName, "Expected policy to be defined with high confidence");
      return;
    }

    if (result.ambiguities.length === 0) {
      fail(testName, "Expected ambiguities to be preserved");
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Main test runner
// -----------------------------------------------------------------------------
async function runAllTests() {
  console.log("=== Policy Engine Tests ===\n");

  // Basic parsing tests
  await testParsePolicy_ValidHighConfidence();
  await testParsePolicy_LowConfidence();
  await testParsePolicy_EmptyInput();
  await testParsePolicy_TooShort();
  await testParsePolicy_MarkdownWrappedJSON();

  // Validation tests
  await testParsePolicy_InvalidType();
  await testParsePolicy_InvalidOperator();
  await testParsePolicy_InvalidAction();
  await testParsePolicy_MissingConditionField();
  await testParsePolicy_MissingConditionValue();

  // Error handling tests
  await testParsePolicy_MalformedJSON();
  await testParsePolicy_MissingPolicyField();
  await testParsePolicy_MissingConfidenceField();

  // Comprehensive validation tests
  await testParsePolicy_AllValidTypes();
  await testParsePolicy_AllValidOperators();
  await testParsePolicy_AllValidActions();

  // Policy ID tests
  await testParsePolicy_PolicyIdUniqueness();

  // Batch processing tests
  await testParsePolicies_Batch();
  await testParsePolicies_IndividualFailures();

  // Validation helper tests
  await testValidatePolicyStatement_Valid();
  await testValidatePolicyStatement_Invalid();
  await testValidatePolicyStatement_HandlesErrors();

  // Format tests
  await testFormatPolicyResult_Success();
  await testFormatPolicyResult_Failure();

  // Configuration tests
  await testGetConfidenceThreshold();

  // Edge case tests
  await testParsePolicy_AmbiguitiesWithHighConfidence();

  report();
  exitWithResults();
}

// Run all tests
runAllTests().catch((error) => {
  console.error("Fatal test error:", error);
  process.exit(1);
});
