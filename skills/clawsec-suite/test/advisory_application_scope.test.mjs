#!/usr/bin/env node

/**
 * Advisory application scope tests:
 * - openclaw advisories are considered
 * - nanoclaw advisories are ignored
 * - legacy advisories without application remain eligible
 *
 * Run: node skills/clawsec-suite/test/advisory_application_scope.test.mjs
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB_PATH = path.resolve(__dirname, "..", "hooks", "clawsec-advisory-guardian", "lib");
const { advisoryAppliesToOpenclaw } = await import(`${LIB_PATH}/advisory_scope.mjs`);

let passCount = 0;
let failCount = 0;

function pass(name) {
  passCount += 1;
  console.log(`\u2713 ${name}`);
}

function fail(name, error) {
  failCount += 1;
  console.error(`\u2717 ${name}`);
  console.error(`  ${String(error)}`);
}

function testFindMatchesFiltersByApplicationScope() {
  const testName = "advisoryAppliesToOpenclaw: openclaw + legacy advisories are considered";

  const inputs = [
    { id: "ADV-OPENCLAW-001", application: "openclaw", expect: true },
    { id: "ADV-NANOCLAW-001", application: "nanoclaw", expect: false },
    { id: "ADV-LEGACY-001", expect: true },
  ];

  for (const input of inputs) {
    const result = advisoryAppliesToOpenclaw({ application: input.application });
    if (result !== input.expect) {
      fail(testName, `Unexpected result for ${input.id}: expected ${input.expect}, got ${result}`);
      return;
    }
  }

  pass(testName);
}

function testApplicationAllAccepted() {
  const testName = "advisoryAppliesToOpenclaw: application=all is considered";
  const result = advisoryAppliesToOpenclaw({ application: "all" });
  if (!result) {
    fail(testName, "Expected true for application=all");
    return;
  }
  pass(testName);
}

function testFindMatchesAcceptsApplicationArray() {
  const testName = "advisoryAppliesToOpenclaw: application array containing openclaw is considered";
  const result = advisoryAppliesToOpenclaw({ application: ["nanoclaw", "openclaw"] });
  if (!result) {
    fail(testName, "Expected true for application array containing openclaw");
    return;
  }

  pass(testName);
}

function testInvalidApplicationValueFallsBackCompat() {
  const testName = "advisoryAppliesToOpenclaw: invalid application values keep legacy compatibility";
  const result = advisoryAppliesToOpenclaw({ application: { invalid: true } });
  if (!result) {
    fail(testName, "Expected true for non-string application to preserve backward compatibility");
    return;
  }
  pass(testName);
}

function runTests() {
  console.log("=== ClawSec Advisory Application Scope Tests ===\n");

  testFindMatchesFiltersByApplicationScope();
  testApplicationAllAccepted();
  testFindMatchesAcceptsApplicationArray();
  testInvalidApplicationValueFallsBackCompat();

  console.log(`\n=== Results: ${passCount} passed, ${failCount} failed ===`);
  if (failCount > 0) {
    process.exit(1);
  }
}

runTests();
