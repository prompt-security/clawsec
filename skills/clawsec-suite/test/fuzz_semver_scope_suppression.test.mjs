#!/usr/bin/env node

/**
 * Property-based fuzz tests for semver matching, advisory scope, and suppression matching.
 *
 * Run: node skills/clawsec-suite/test/fuzz_semver_scope_suppression.test.mjs
 */

import assert from "node:assert/strict";
import fc from "fast-check";
import { advisoryAppliesToOpenclaw } from "../hooks/clawsec-advisory-guardian/lib/advisory_scope.mjs";
import { isAdvisorySuppressed } from "../hooks/clawsec-advisory-guardian/lib/suppression.mjs";
import { compareSemver, parseSemver, versionMatches } from "../hooks/clawsec-advisory-guardian/lib/version.mjs";

const semverCoreArb = fc.tuple(
  fc.integer({ min: 0, max: 999 }),
  fc.integer({ min: 0, max: 999 }),
  fc.integer({ min: 0, max: 999 }),
);

const semverArb = semverCoreArb.map(([major, minor, patch]) => `${major}.${minor}.${patch}`);
const idArb = fc.string({ minLength: 1, maxLength: 24 });
const skillArb = fc.string({ minLength: 1, maxLength: 24 });

function runSemverProperties() {
  fc.assert(
    fc.property(semverCoreArb, ([major, minor, patch]) => {
      const version = `v${major}.${minor}.${patch}`;
      assert.deepEqual(parseSemver(version), [major, minor, patch]);
    }),
    { numRuns: 250 },
  );

  fc.assert(
    fc.property(semverArb, semverArb, (left, right) => {
      const leftVsRight = compareSemver(left, right);
      const rightVsLeft = compareSemver(right, left);
      assert.notEqual(leftVsRight, null);
      assert.notEqual(rightVsLeft, null);
      assert.equal(leftVsRight, -rightVsLeft);
    }),
    { numRuns: 250 },
  );

  fc.assert(
    fc.property(semverArb, semverArb, (left, right) => {
      const compared = compareSemver(left, right);
      assert.notEqual(compared, null);

      assert.equal(versionMatches(left, `>=${right}`), compared >= 0);
      assert.equal(versionMatches(left, `<=${right}`), compared <= 0);
      assert.equal(versionMatches(left, `>${right}`), compared > 0);
      assert.equal(versionMatches(left, `<${right}`), compared < 0);
      assert.equal(versionMatches(left, `=${right}`), compared === 0);
    }),
    { numRuns: 250 },
  );
}

function runAdvisoryScopeProperties() {
  fc.assert(
    fc.property(fc.string(), (application) => {
      const normalized = application.trim().toLowerCase();
      const expected = normalized === "" || normalized === "openclaw" || normalized === "all";
      assert.equal(advisoryAppliesToOpenclaw({ application }), expected);
    }),
    { numRuns: 250 },
  );

  fc.assert(
    fc.property(fc.array(fc.string(), { maxLength: 8 }), (applications) => {
      const normalized = applications
        .map((entry) => entry.trim().toLowerCase())
        .filter(Boolean);
      const expected =
        normalized.length === 0 || normalized.includes("openclaw") || normalized.includes("all");
      assert.equal(advisoryAppliesToOpenclaw({ application: applications }), expected);
    }),
    { numRuns: 250 },
  );

  assert.equal(advisoryAppliesToOpenclaw({}), true);
  assert.equal(advisoryAppliesToOpenclaw({ application: null }), true);
}

function runSuppressionProperties() {
  fc.assert(
    fc.property(idArb, skillArb, (id, skill) => {
      const match = {
        advisory: { id },
        skill: { name: skill.toUpperCase() },
      };
      const suppressions = [
        {
          checkId: id,
          skill: skill.toLowerCase(),
          reason: "fuzz",
          suppressedAt: "2026-02-25",
        },
      ];
      assert.equal(isAdvisorySuppressed(match, suppressions), true);
    }),
    { numRuns: 250 },
  );

  fc.assert(
    fc.property(idArb, idArb, skillArb, (targetId, otherId, skill) => {
      const differentId = targetId === otherId ? `${otherId}-x` : otherId;
      const match = {
        advisory: { id: targetId },
        skill: { name: skill },
      };
      const suppressions = [
        {
          checkId: differentId,
          skill,
          reason: "fuzz",
          suppressedAt: "2026-02-25",
        },
      ];
      assert.equal(isAdvisorySuppressed(match, suppressions), false);
    }),
    { numRuns: 250 },
  );
}

try {
  console.log("=== ClawSec Semver/Scope/Suppression Fuzz Properties ===\n");
  runSemverProperties();
  runAdvisoryScopeProperties();
  runSuppressionProperties();
  console.log("=== Results: all fuzz properties passed ===");
} catch (error) {
  console.error("Fuzz property test failed:");
  console.error(error);
  process.exit(1);
}
