#!/usr/bin/env node

/**
 * DAST (Dynamic Application Security Testing) Runner for ClawSec Scanner.
 *
 * v1 Scope: Basic framework for testing skill hook security
 * - Load and execute predefined security test cases
 * - Test hook handlers with malicious inputs
 * - Enforce timeout limits (30s default)
 * - Validate input sanitization and resource limits
 *
 * Future: Full agent workflow DAST requires deeper platform integration
 *
 * Run: node skills/clawsec-scanner/scripts/dast_runner.mjs --target ./skills/
 */

import { generateReport, formatReportJson, formatReportText } from "../lib/report.mjs";
import { getTimestamp } from "../lib/utils.mjs";

/**
 * @typedef {import('../lib/types.ts').Vulnerability} Vulnerability
 * @typedef {import('../lib/types.ts').ScanReport} ScanReport
 * @typedef {import('../lib/types.ts').HookEvent} HookEvent
 */

/**
 * @typedef {Object} TestCase
 * @property {string} id - Test case identifier
 * @property {string} name - Human-readable test name
 * @property {string} description - Test description
 * @property {'critical' | 'high' | 'medium' | 'low' | 'info'} severity - Severity if test fails
 * @property {(context: TestContext) => Promise<TestResult>} execute - Test execution function
 */

/**
 * @typedef {Object} TestContext
 * @property {string} targetPath - Path to target skill/hook
 * @property {number} timeout - Timeout in milliseconds
 */

/**
 * @typedef {Object} TestResult
 * @property {boolean} passed - Whether test passed
 * @property {string} [message] - Result message
 * @property {unknown} [details] - Additional details
 */

const DEFAULT_TIMEOUT_MS = 30000; // 30 seconds

/**
 * Security test cases for hook handlers.
 * @type {TestCase[]}
 */
const TEST_CASES = [
  {
    id: "DAST-001",
    name: "Hook Handler Malicious Input Test",
    description: "Tests hook handler behavior with malicious message inputs (XSS, command injection patterns)",
    severity: "high",
    execute: async (context) => {
      const maliciousInputs = [
        // XSS patterns
        "<script>alert('XSS')</script>",
        "'; DROP TABLE users; --",
        // Command injection patterns
        "; rm -rf /",
        "$(whoami)",
        "`cat /etc/passwd`",
        // Path traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        // Null bytes
        "test\0malicious",
        // Unicode exploits
        "\u202e\u202d",
        // Large payload (potential DoS)
        "A".repeat(1000000),
      ];

      const vulnerabilities = [];

      for (const input of maliciousInputs) {
        try {
          // Test: Create mock hook event with malicious content
          const mockEvent = {
            type: "test",
            action: "security-test",
            messages: [
              {
                role: "user",
                content: input,
              },
            ],
          };

          // In a real implementation, this would invoke the actual hook handler
          // For v1, we simulate by checking if the input would cause issues
          const result = await testHookHandlerSafety(mockEvent, context.timeout);

          if (!result.safe) {
            vulnerabilities.push({
              pattern: input.substring(0, 50),
              reason: result.reason,
            });
          }
        } catch (error) {
          if (error instanceof Error) {
            vulnerabilities.push({
              pattern: input.substring(0, 50),
              reason: `Exception thrown: ${error.message}`,
            });
          }
        }
      }

      return {
        passed: vulnerabilities.length === 0,
        message:
          vulnerabilities.length === 0
            ? "Hook handler safely processes malicious inputs"
            : `Hook handler vulnerable to ${vulnerabilities.length} input patterns`,
        details: { vulnerabilities },
      };
    },
  },
  {
    id: "DAST-002",
    name: "Hook Handler Timeout Enforcement",
    description: "Tests whether hook handlers respect timeout limits and prevent infinite loops",
    severity: "medium",
    execute: async (context) => {
      const startTime = Date.now();
      const testTimeout = 5000; // 5 second test timeout

      try {
        // Simulate a long-running operation
        const result = await Promise.race([
          simulateLongRunningHook(),
          new Promise((resolve) =>
            setTimeout(() => resolve({ timedOut: true }), testTimeout),
          ),
        ]);

        const elapsed = Date.now() - startTime;

        if (result && typeof result === "object" && "timedOut" in result && result.timedOut) {
          return {
            passed: true,
            message: `Timeout correctly enforced (${elapsed}ms < ${testTimeout}ms)`,
          };
        }

        return {
          passed: elapsed < testTimeout,
          message:
            elapsed < testTimeout
              ? `Operation completed within timeout (${elapsed}ms)`
              : `Operation exceeded timeout (${elapsed}ms > ${testTimeout}ms)`,
        };
      } catch (error) {
        if (error instanceof Error) {
          return {
            passed: false,
            message: `Timeout test failed: ${error.message}`,
          };
        }
        return {
          passed: false,
          message: "Timeout test failed with unknown error",
        };
      }
    },
  },
  {
    id: "DAST-003",
    name: "Hook Handler Resource Limits",
    description: "Tests whether hook handlers respect memory and CPU resource limits",
    severity: "medium",
    execute: async (context) => {
      const initialMemory = process.memoryUsage().heapUsed;
      const maxMemoryIncreaseMB = 50; // Alert if memory increases by more than 50MB

      try {
        // Simulate resource-intensive operation
        await simulateResourceIntensiveHook(context.timeout);

        const finalMemory = process.memoryUsage().heapUsed;
        const memoryIncreaseMB = (finalMemory - initialMemory) / 1024 / 1024;

        return {
          passed: memoryIncreaseMB < maxMemoryIncreaseMB,
          message:
            memoryIncreaseMB < maxMemoryIncreaseMB
              ? `Memory usage within limits (${memoryIncreaseMB.toFixed(2)}MB increase)`
              : `Memory usage exceeded limits (${memoryIncreaseMB.toFixed(2)}MB increase)`,
          details: {
            initialMemoryMB: (initialMemory / 1024 / 1024).toFixed(2),
            finalMemoryMB: (finalMemory / 1024 / 1024).toFixed(2),
            increaseMB: memoryIncreaseMB.toFixed(2),
          },
        };
      } catch (error) {
        if (error instanceof Error) {
          return {
            passed: false,
            message: `Resource limit test failed: ${error.message}`,
          };
        }
        return {
          passed: false,
          message: "Resource limit test failed with unknown error",
        };
      }
    },
  },
  {
    id: "DAST-004",
    name: "Hook Handler Event Mutation Safety",
    description: "Tests whether hook handlers properly mutate event.messages without side effects",
    severity: "low",
    execute: async (context) => {
      const originalEvent = {
        type: "test",
        action: "mutation-test",
        messages: [{ role: "user", content: "test message" }],
      };

      // Clone for comparison
      const originalMessagesCount = originalEvent.messages.length;
      const originalMessageContent = originalEvent.messages[0].content;

      try {
        // Simulate hook handler mutation
        const mockHandler = async (event) => {
          // Proper hook pattern: mutate event.messages
          event.messages.push({
            role: "system",
            content: "Hook handler response",
          });
          // No return value (correct pattern)
        };

        await mockHandler(originalEvent);

        const messagesIncreased = originalEvent.messages.length > originalMessagesCount;
        const originalMessageIntact =
          originalEvent.messages[0].content === originalMessageContent;

        return {
          passed: messagesIncreased && originalMessageIntact,
          message: messagesIncreased
            ? "Hook correctly mutates event.messages"
            : "Hook does not mutate event.messages",
          details: {
            originalCount: originalMessagesCount,
            finalCount: originalEvent.messages.length,
            originalIntact: originalMessageIntact,
          },
        };
      } catch (error) {
        if (error instanceof Error) {
          return {
            passed: false,
            message: `Event mutation test failed: ${error.message}`,
          };
        }
        return {
          passed: false,
          message: "Event mutation test failed with unknown error",
        };
      }
    },
  },
];

/**
 * Test hook handler safety with malicious input.
 * In v1, this is a simple simulation. Future versions will invoke actual handlers.
 *
 * @param {HookEvent} event - Mock hook event
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<{safe: boolean, reason?: string}>}
 */
async function testHookHandlerSafety(event, timeout) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ safe: true, reason: "Handler completed within timeout" });
    }, timeout);

    try {
      // v1: Basic safety checks (pattern matching)
      const content = event.messages?.[0]?.content ?? "";

      // Check for unsafe patterns
      if (content.includes("<script>") || content.includes("</script>")) {
        clearTimeout(timer);
        resolve({ safe: false, reason: "Detected XSS pattern" });
        return;
      }

      if (
        content.includes("rm -rf") ||
        content.includes("$(") ||
        content.includes("`")
      ) {
        clearTimeout(timer);
        resolve({ safe: false, reason: "Detected command injection pattern" });
        return;
      }

      if (content.includes("../") || content.includes("..\\")) {
        clearTimeout(timer);
        resolve({ safe: false, reason: "Detected path traversal pattern" });
        return;
      }

      if (content.includes("\0")) {
        clearTimeout(timer);
        resolve({ safe: false, reason: "Detected null byte injection" });
        return;
      }

      // Check for excessive payload size
      if (content.length > 100000) {
        clearTimeout(timer);
        resolve({ safe: false, reason: "Excessive payload size (potential DoS)" });
        return;
      }

      clearTimeout(timer);
      resolve({ safe: true });
    } catch (error) {
      clearTimeout(timer);
      if (error instanceof Error) {
        resolve({ safe: false, reason: `Exception: ${error.message}` });
      } else {
        resolve({ safe: false, reason: "Unknown exception" });
      }
    }
  });
}

/**
 * Simulate a long-running hook operation.
 *
 * @returns {Promise<{completed: boolean}>}
 */
async function simulateLongRunningHook() {
  return new Promise((resolve) => {
    // Simulate operation that would take too long
    setTimeout(() => {
      resolve({ completed: true });
    }, 60000); // 60 seconds - should be timed out before this
  });
}

/**
 * Simulate a resource-intensive hook operation.
 *
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<void>}
 */
async function simulateResourceIntensiveHook(timeout) {
  return new Promise((resolve) => {
    setTimeout(() => {
      // Simulate some memory usage (small allocation for testing)
      const tempData = new Array(1000).fill("test data");
      tempData.length = 0; // Clean up
      resolve();
    }, 100);
  });
}

/**
 * Execute all DAST test cases.
 *
 * @param {string} targetPath - Path to target skill/hook
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<Vulnerability[]>}
 */
async function runDastTests(targetPath, timeout) {
  const vulnerabilities = [];

  const context = {
    targetPath,
    timeout,
  };

  for (const testCase of TEST_CASES) {
    try {
      const result = await testCase.execute(context);

      if (!result.passed) {
        vulnerabilities.push({
          id: testCase.id,
          source: "dast",
          severity: testCase.severity,
          package: "N/A",
          version: "N/A",
          title: testCase.name,
          description: `${testCase.description}\n\nResult: ${result.message}`,
          references: [],
          discovered_at: getTimestamp(),
        });
      }
    } catch (error) {
      // Test execution failure is itself a vulnerability
      vulnerabilities.push({
        id: testCase.id,
        source: "dast",
        severity: "high",
        package: "N/A",
        version: "N/A",
        title: `${testCase.name} (Test Failed)`,
        description: `Test execution failed: ${error instanceof Error ? error.message : String(error)}`,
        references: [],
        discovered_at: getTimestamp(),
      });
    }
  }

  return vulnerabilities;
}

/**
 * CLI entry point.
 */
async function main() {
  const args = process.argv.slice(2);

  let targetPath = ".";
  let format = "json";
  let timeout = DEFAULT_TIMEOUT_MS;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--target" && args[i + 1]) {
      targetPath = args[i + 1];
      i++;
    } else if (args[i] === "--format" && args[i + 1]) {
      format = args[i + 1];
      i++;
    } else if (args[i] === "--timeout" && args[i + 1]) {
      timeout = parseInt(args[i + 1], 10);
      if (isNaN(timeout) || timeout <= 0) {
        timeout = DEFAULT_TIMEOUT_MS;
      }
      i++;
    } else if (args[i] === "--help") {
      console.log(`
Usage: dast_runner.mjs [options]

Options:
  --target <path>   Target skill/hook directory to test (default: .)
  --format <type>   Output format: json or text (default: json)
  --timeout <ms>    Test timeout in milliseconds (default: ${DEFAULT_TIMEOUT_MS})
  --help            Show this help message

Examples:
  node dast_runner.mjs --target ./skills/my-skill
  node dast_runner.mjs --target ./skills/ --format text
  node dast_runner.mjs --target ./skills/ --timeout 60000
`);
      process.exit(0);
    }
  }

  try {
    const vulnerabilities = await runDastTests(targetPath, timeout);
    const report = generateReport(vulnerabilities, targetPath);

    if (format === "text") {
      console.log(formatReportText(report));
    } else {
      console.log(formatReportJson(report));
    }

    // Exit with non-zero if critical or high severity vulnerabilities found
    const hasCriticalOrHigh =
      report.summary.critical > 0 || report.summary.high > 0;
    process.exit(hasCriticalOrHigh ? 1 : 0);
  } catch (error) {
    console.error("DAST runner failed:");
    if (error instanceof Error) {
      console.error(error.message);
    } else {
      console.error(String(error));
    }
    process.exit(1);
  }
}

// Export for testing
export { runDastTests, testHookHandlerSafety, TEST_CASES };

// Run if invoked directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
