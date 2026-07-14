import assert from "node:assert/strict";
import { isTestReleasePath } from "./ci/release_path_policy.mjs";

for (const testOnlyPath of [
  "test/helper.py",
  "tests/helper.py",
  "__tests__/helper.js",
  "lib/test/helper.py",
  "lib/tests/helper.py",
  "lib/__tests__/helper.js",
  "test_helper.py",
  "test-helper.py",
  "spec_helper.py",
  "spec-helper.py",
  "helper.test.mjs",
  "helper.spec.mjs",
  "TESTS\\helper.py",
]) {
  assert.equal(isTestReleasePath(testOnlyPath), true, `expected test-only path: ${testOnlyPath}`);
}

for (const releasePath of [
  "SKILL.md",
  "attestation/verify.mjs",
  "contest/data.md",
  "latest/feed.json",
  "testing/guide.md",
]) {
  assert.equal(isTestReleasePath(releasePath), false, `expected release path: ${releasePath}`);
}

console.log("Release test-path policy tests passed");
