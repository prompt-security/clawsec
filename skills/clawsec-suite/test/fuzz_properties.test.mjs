#!/usr/bin/env node

/**
 * Property-based fuzzing checks for core advisory parsing/path helpers.
 *
 * Run: node skills/clawsec-suite/test/fuzz_properties.test.mjs
 */

import { runFuzzProperties } from "./fuzz_properties.js";

try {
  console.log("=== ClawSec Fast-Check Fuzz Properties ===\n");
  runFuzzProperties();
  console.log("=== Results: all fuzz properties passed ===");
} catch (error) {
  console.error("Fuzz property test failed:");
  console.error(error);
  process.exit(1);
}
