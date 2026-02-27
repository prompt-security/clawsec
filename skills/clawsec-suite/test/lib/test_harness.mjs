/**
 * Shared test harness for clawsec-suite tests.
 * Provides consistent test reporting and runner utilities.
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

let passCount = 0;
let failCount = 0;

/**
 * Records a passing test.
 * @param {string} name - Test name
 */
export function pass(name) {
  passCount++;
  console.log(`✓ ${name}`);
}

/**
 * Records a failing test.
 * @param {string} name - Test name
 * @param {Error|string} error - Error details
 */
export function fail(name, error) {
  failCount++;
  console.error(`✗ ${name}`);
  console.error(`  ${String(error)}`);
}

/**
 * Gets current test statistics.
 * @returns {{passCount: number, failCount: number}}
 */
export function getStats() {
  return { passCount, failCount };
}

/**
 * Reports final test results to console.
 */
export function report() {
  console.log(`\n=== Results: ${passCount} passed, ${failCount} failed ===`);
}

/**
 * Exits with appropriate code based on test results.
 * Exit code 0 for success, 1 for failures.
 */
export function exitWithResults() {
  if (failCount > 0) {
    process.exit(1);
  }
}

/**
 * Creates an isolated test runner with its own pass/fail counters.
 * Useful for running independent test suites within the same process.
 * @returns {{pass: Function, fail: Function, getStats: Function, report: Function, exitWithResults: Function}}
 */
export function createTestRunner() {
  let localPassCount = 0;
  let localFailCount = 0;

  return {
    /**
     * Records a passing test.
     * @param {string} name - Test name
     */
    pass(name) {
      localPassCount++;
      console.log(`✓ ${name}`);
    },

    /**
     * Records a failing test.
     * @param {string} name - Test name
     * @param {Error|string} error - Error details
     */
    fail(name, error) {
      localFailCount++;
      console.error(`✗ ${name}`);
      console.error(`  ${String(error)}`);
    },

    /**
     * Gets current test statistics.
     * @returns {{passCount: number, failCount: number}}
     */
    getStats() {
      return { passCount: localPassCount, failCount: localFailCount };
    },

    /**
     * Reports final test results to console.
     */
    report() {
      console.log(`\n=== Results: ${localPassCount} passed, ${localFailCount} failed ===`);
    },

    /**
     * Exits with appropriate code based on test results.
     * Exit code 0 for success, 1 for failures.
     */
    exitWithResults() {
      if (localFailCount > 0) {
        process.exit(1);
      }
    },
  };
}

/**
 * Generates an Ed25519 keypair for test use.
 * @returns {{publicKeyPem: string, privateKeyPem: string}}
 */
export function generateEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  return { publicKeyPem, privateKeyPem };
}

/**
 * Signs a payload with an Ed25519 private key.
 * @param {string} data - Data to sign
 * @param {string} privateKeyPem - PEM-encoded private key
 * @returns {string} Base64-encoded signature
 */
export function signPayload(data, privateKeyPem) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign(null, Buffer.from(data, "utf8"), privateKey);
  return signature.toString("base64");
}

/**
 * Creates a temporary directory for test use.
 * @returns {Promise<{path: string, cleanup: Function}>} Object with temp dir path and cleanup function
 */
export async function createTempDir() {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawsec-test-"));

  return {
    path: tmpDir,
    cleanup: async () => {
      try {
        await fs.rm(tmpDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    },
  };
}

/**
 * Temporarily sets an environment variable for the duration of a function.
 * Restores the original value (or deletes the variable) after the function completes.
 * @param {string} key - Environment variable name
 * @param {string|undefined} value - Value to set (undefined to delete)
 * @param {Function} fn - Function to execute with the modified environment
 * @returns {Promise<*>} Result of the function
 */
export async function withEnv(key, value, fn) {
  const oldValue = process.env[key];
  try {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
    return await fn();
  } finally {
    if (oldValue === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = oldValue;
    }
  }
}
