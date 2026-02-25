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
const { findMatches } = await import(`${LIB_PATH}/matching.ts`);

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

function extractIds(matches) {
  return matches
    .map((entry) => String(entry?.advisory?.id ?? ""))
    .filter(Boolean)
    .sort();
}

function testFindMatchesFiltersByApplicationScope() {
  const testName = "findMatches: only openclaw + legacy advisories are considered";

  const feed = {
    version: "1",
    advisories: [
      {
        id: "ADV-OPENCLAW-001",
        severity: "high",
        application: "openclaw",
        affected: ["clawsec-suite@*"],
      },
      {
        id: "ADV-NANOCLAW-001",
        severity: "high",
        application: "nanoclaw",
        affected: ["clawsec-suite@*"],
      },
      {
        id: "ADV-LEGACY-001",
        severity: "medium",
        affected: ["clawsec-suite@*"],
      },
    ],
  };

  const installedSkills = [
    { name: "clawsec-suite", dirName: "clawsec-suite", version: "0.1.3" },
  ];

  const matches = findMatches(feed, installedSkills);
  const ids = extractIds(matches);

  const expected = ["ADV-LEGACY-001", "ADV-OPENCLAW-001"];
  const ok = JSON.stringify(ids) === JSON.stringify(expected);
  if (!ok) {
    fail(testName, `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(ids)}`);
    return;
  }

  pass(testName);
}

function testFindMatchesAcceptsApplicationArray() {
  const testName = "findMatches: advisory with application array containing openclaw is considered";

  const feed = {
    version: "1",
    advisories: [
      {
        id: "ADV-MULTI-001",
        severity: "critical",
        application: ["nanoclaw", "openclaw"],
        affected: ["clawsec-suite@*"],
      },
    ],
  };

  const installedSkills = [
    { name: "clawsec-suite", dirName: "clawsec-suite", version: "0.1.3" },
  ];

  const matches = findMatches(feed, installedSkills);
  const ids = extractIds(matches);

  const expected = ["ADV-MULTI-001"];
  const ok = JSON.stringify(ids) === JSON.stringify(expected);
  if (!ok) {
    fail(testName, `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(ids)}`);
    return;
  }

  pass(testName);
}

function runTests() {
  console.log("=== ClawSec Advisory Application Scope Tests ===\n");

  testFindMatchesFiltersByApplicationScope();
  testFindMatchesAcceptsApplicationArray();

  console.log(`\n=== Results: ${passCount} passed, ${failCount} failed ===`);
  if (failCount > 0) {
    process.exit(1);
  }
}

runTests();
