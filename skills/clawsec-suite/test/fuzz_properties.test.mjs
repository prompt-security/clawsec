#!/usr/bin/env node

/**
 * Property-based fuzzing checks for core advisory parsing/path helpers.
 *
 * Run: node skills/clawsec-suite/test/fuzz_properties.test.mjs
 */

import { pass, fail, report, exitWithResults } from "./lib/test_harness.mjs";
import { runFuzzProperties } from "./fuzz_properties.js";

console.log("=== ClawSec Fast-Check Fuzz Properties ===\n");

try {
  runFuzzProperties();
  pass("Property-based fuzz tests");
} catch (error) {
  fail("Property-based fuzz tests", error);
}

report();
exitWithResults();
