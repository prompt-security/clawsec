import assert from "node:assert/strict";
import {
  assertSemverIncrement,
  compareSemver,
  parseSemver,
} from "./ci/semver_increment.mjs";

assert.deepEqual(parseSemver("0.1.15"), {
  raw: "0.1.15",
  core: [0, 1, 15],
  prerelease: [],
});

for (const [baseVersion, nextVersion] of [
  ["0.1.14", "0.1.15"],
  ["1.2.3", "1.3.0"],
  ["1.2.3", "2.0.0"],
  ["1.2.3-beta.1", "1.2.3-beta.2"],
  ["1.2.3-beta.2", "1.2.3"],
  ["1.2.3", "1.2.4-rc.1"],
]) {
  assert.equal(assertSemverIncrement(baseVersion, nextVersion), true);
  assert.equal(compareSemver(nextVersion, baseVersion), 1);
}

for (const [baseVersion, nextVersion] of [
  ["0.1.14", "0.1.14"],
  ["0.1.14", "0.1.13"],
  ["1.2.3", "1.2.3-rc.1"],
  ["2.0.0", "1.99.99"],
]) {
  assert.throws(
    () => assertSemverIncrement(baseVersion, nextVersion),
    /must increase by at least a patch/,
  );
}

for (const [baseVersion, nextVersion] of [
  ["1.2.3-beta.2", "1.2.3-beta.1"],
  ["1.2.3-beta.2", "1.2.3-beta.2"],
]) {
  assert.throws(
    () => assertSemverIncrement(baseVersion, nextVersion),
    /Prerelease version must increase by SemVer precedence/,
  );
}

for (const invalidVersion of ["1.2", "01.2.3", "1.2.3-beta.01", "v1.2.3", "1.2.3+build"]) {
  assert.throws(() => parseSemver(invalidVersion), /Invalid/);
}
