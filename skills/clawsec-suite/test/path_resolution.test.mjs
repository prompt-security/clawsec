#!/usr/bin/env node

/**
 * Path resolution tests for shared home-path expansion logic.
 *
 * Run: node skills/clawsec-suite/test/path_resolution.test.mjs
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB_PATH = path.resolve(__dirname, "..", "hooks", "clawsec-advisory-guardian", "lib");
const { resolveUserPath, resolveConfiguredPath } = await import(`${LIB_PATH}/utils.mjs`);

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

async function withEnv(key, value, fn) {
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

async function testTildeExpansion() {
  const testName = "resolveUserPath: expands leading tilde";
  await withEnv("HOME", "/tmp/clawsec-home", async () => {
    const resolved = resolveUserPath("~/skills/clawsec-suite", { label: "test tilde" });
    const expected = path.normalize("/tmp/clawsec-home/skills/clawsec-suite");
    if (resolved === expected) {
      pass(testName);
    } else {
      fail(testName, `Expected ${expected}, got ${resolved}`);
    }
  });
}

async function testHomeVariableExpansion() {
  const testName = "resolveUserPath: expands $HOME and ${HOME}";
  await withEnv("HOME", "/tmp/clawsec-home", async () => {
    const resolved1 = resolveUserPath("$HOME/skills", { label: "test $HOME" });
    const resolved2 = resolveUserPath("${HOME}/skills", { label: "test ${HOME}" });
    const expected = path.normalize("/tmp/clawsec-home/skills");
    if (resolved1 === expected && resolved2 === expected) {
      pass(testName);
    } else {
      fail(testName, `Expected ${expected}, got ${resolved1} / ${resolved2}`);
    }
  });
}

async function testUserProfileExpansion() {
  const testName = "resolveUserPath: expands USERPROFILE syntaxes";
  await withEnv("HOME", undefined, async () => {
    await withEnv("USERPROFILE", "C:\\Users\\clawsec", async () => {
      const resolved1 = resolveUserPath("%USERPROFILE%\\skills", { label: "test %USERPROFILE%" });
      const resolved2 = resolveUserPath("$env:USERPROFILE\\skills", { label: "test $env:USERPROFILE" });
      const expected = path.normalize("C:\\Users\\clawsec\\skills");
      if (resolved1 === expected && resolved2 === expected) {
        pass(testName);
      } else {
        fail(testName, `Expected ${expected}, got ${resolved1} / ${resolved2}`);
      }
    });
  });
}

async function testEscapedTokenFails() {
  const testName = "resolveUserPath: rejects escaped or unresolved home tokens";
  try {
    resolveUserPath("\\$HOME/skills", { label: "test escaped token" });
    fail(testName, "Expected error for escaped token");
  } catch (error) {
    if (String(error).includes("Unexpanded home token")) {
      pass(testName);
    } else {
      fail(testName, `Unexpected error: ${error}`);
    }
  }
}

async function testConfiguredPathFallbackOnInvalidExplicit() {
  const testName = "resolveConfiguredPath: falls back when explicit env value is invalid";
  try {
    let fallbackReason = "";
    const resolved = resolveConfiguredPath("\\$HOME/skills", "/tmp/clawsec-default", {
      label: "CLAWSEC_LOCAL_FEED_SIG",
      onInvalid: (error, rawValue) => {
        fallbackReason = `${rawValue} :: ${String(error)}`;
      },
    });
    const expected = path.normalize("/tmp/clawsec-default");
    if (
      resolved === expected &&
      fallbackReason.includes("\\$HOME/skills") &&
      fallbackReason.includes("Unexpanded home token")
    ) {
      pass(testName);
    } else {
      fail(testName, `Expected fallback ${expected}, got ${resolved} (${fallbackReason})`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function testConfiguredPathUsesValidExplicit() {
  const testName = "resolveConfiguredPath: keeps valid explicit value";
  try {
    const resolved = resolveConfiguredPath("$HOME/skills", "/tmp/clawsec-default", {
      label: "CLAWSEC_INSTALL_ROOT",
      onInvalid: () => {
        throw new Error("onInvalid should not run for a valid explicit path");
      },
    });
    const expected = path.normalize(`${process.env.HOME || ""}/skills`);
    if (resolved === expected) {
      pass(testName);
    } else {
      fail(testName, `Expected ${expected}, got ${resolved}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

async function runTests() {
  console.log("=== ClawSec Path Resolution Tests ===\n");

  await testTildeExpansion();
  await testHomeVariableExpansion();
  await testUserProfileExpansion();
  await testEscapedTokenFails();
  await testConfiguredPathFallbackOnInvalidExplicit();
  await testConfiguredPathUsesValidExplicit();

  console.log(`\n=== Results: ${passCount} passed, ${failCount} failed ===`);
  if (failCount > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error("Test runner failed:", error);
  process.exit(1);
});
