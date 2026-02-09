#!/usr/bin/env node

/**
 * Guarded skill install tests for clawsec-suite.
 *
 * Tests cover:
 * - Conservative matching when version is omitted
 * - Precise version matching when version is provided
 * - Exit code 42 for advisory match requiring confirmation
 * - High-risk advisory detection
 *
 * Run: node skills/clawsec-suite/test/guarded_install.test.mjs
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.resolve(__dirname, "..", "scripts", "guarded_skill_install.mjs");

let tempDir;
let passCount = 0;
let failCount = 0;

function pass(name) {
  passCount++;
  console.log(`✓ ${name}`);
}

function fail(name, error) {
  failCount++;
  console.error(`✗ ${name}`);
  console.error(`  ${String(error)}`);
}

function generateEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  return { publicKeyPem, privateKeyPem };
}

function signPayload(data, privateKeyPem) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign(null, Buffer.from(data, "utf8"), privateKey);
  return signature.toString("base64");
}

function createFeed(advisories) {
  return JSON.stringify(
    {
      version: "1.0.0",
      updated: "2026-02-08T12:00:00Z",
      advisories,
    },
    null,
    2,
  );
}

function createChecksumManifest(files) {
  const checksums = {};
  for (const [name, content] of Object.entries(files)) {
    checksums[name] = crypto.createHash("sha256").update(content).digest("hex");
  }
  return JSON.stringify(
    {
      schema_version: "1.0",
      algorithm: "sha256",
      files: checksums,
    },
    null,
    2,
  );
}

async function setupTestDir() {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawsec-install-test-"));
}

async function cleanupTestDir() {
  if (tempDir) {
    await fs.rm(tempDir, { recursive: true, force: true });
  }
}

async function setupSignedFeed(advisories, keyPair) {
  const feedContent = createFeed(advisories);
  const feedSignature = signPayload(feedContent, keyPair.privateKeyPem);

  const checksumManifest = createChecksumManifest({
    "feed.json": feedContent,
    "feed.json.sig": feedSignature + "\n",
    "feed-signing-public.pem": keyPair.publicKeyPem,
  });
  const checksumSignature = signPayload(checksumManifest, keyPair.privateKeyPem);

  const advisoriesDir = path.join(tempDir, "advisories");
  await fs.mkdir(advisoriesDir, { recursive: true });

  await fs.writeFile(path.join(advisoriesDir, "feed.json"), feedContent);
  await fs.writeFile(path.join(advisoriesDir, "feed.json.sig"), feedSignature + "\n");
  await fs.writeFile(path.join(advisoriesDir, "checksums.json"), checksumManifest);
  await fs.writeFile(path.join(advisoriesDir, "checksums.json.sig"), checksumSignature + "\n");
  await fs.writeFile(path.join(advisoriesDir, "feed-signing-public.pem"), keyPair.publicKeyPem);

  return advisoriesDir;
}

function runGuardedInstall(args, env) {
  return new Promise((resolve) => {
    const proc = spawn("node", [SCRIPT_PATH, ...args], {
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
// Test: Conservative matching when version is omitted
// -----------------------------------------------------------------------------
async function testConservativeMatchingWithoutVersion() {
  const testName = "guarded_install: conservative matching without version triggers advisory";
  try {
    const keyPair = generateEd25519KeyPair();
    const advisoriesDir = await setupSignedFeed(
      [
        {
          id: "TEST-001",
          severity: "high",
          affected: ["test-skill@1.0.0", "test-skill@1.0.1"],
        },
      ],
      keyPair,
    );

    const result = await runGuardedInstall(["--skill", "test-skill", "--dry-run"], {
      CLAWSEC_LOCAL_FEED: path.join(advisoriesDir, "feed.json"),
      CLAWSEC_LOCAL_FEED_SIG: path.join(advisoriesDir, "feed.json.sig"),
      CLAWSEC_LOCAL_FEED_CHECKSUMS: path.join(advisoriesDir, "checksums.json"),
      CLAWSEC_LOCAL_FEED_CHECKSUMS_SIG: path.join(advisoriesDir, "checksums.json.sig"),
      CLAWSEC_FEED_PUBLIC_KEY: path.join(advisoriesDir, "feed-signing-public.pem"),
      CLAWSEC_FEED_URL: "file:///nonexistent", // Force local fallback
    });

    if (result.code === 42 && result.stdout.includes("Conservative")) {
      pass(testName);
    } else {
      fail(testName, `Expected exit 42 with conservative message, got ${result.code}: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Precise version matching
// -----------------------------------------------------------------------------
async function testPreciseVersionMatching() {
  const testName = "guarded_install: precise version matching only matches exact version";
  try {
    const keyPair = generateEd25519KeyPair();
    const advisoriesDir = await setupSignedFeed(
      [
        {
          id: "TEST-001",
          severity: "high",
          affected: ["test-skill@1.0.0"],
        },
      ],
      keyPair,
    );

    // Version 2.0.0 should NOT match advisory for 1.0.0
    const result = await runGuardedInstall(
      ["--skill", "test-skill", "--version", "2.0.0", "--dry-run"],
      {
        CLAWSEC_LOCAL_FEED: path.join(advisoriesDir, "feed.json"),
        CLAWSEC_LOCAL_FEED_SIG: path.join(advisoriesDir, "feed.json.sig"),
        CLAWSEC_LOCAL_FEED_CHECKSUMS: path.join(advisoriesDir, "checksums.json"),
        CLAWSEC_LOCAL_FEED_CHECKSUMS_SIG: path.join(advisoriesDir, "checksums.json.sig"),
        CLAWSEC_FEED_PUBLIC_KEY: path.join(advisoriesDir, "feed-signing-public.pem"),
        CLAWSEC_FEED_URL: "file:///nonexistent",
      },
    );

    if (result.code === 0 && !result.stdout.includes("Advisory matches")) {
      pass(testName);
    } else {
      fail(testName, `Expected exit 0 without match, got ${result.code}: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Version match triggers confirmation requirement
// -----------------------------------------------------------------------------
async function testVersionMatchTriggersConfirmation() {
  const testName = "guarded_install: matching version triggers exit 42";
  try {
    const keyPair = generateEd25519KeyPair();
    const advisoriesDir = await setupSignedFeed(
      [
        {
          id: "TEST-001",
          severity: "high",
          affected: ["test-skill@1.0.0"],
        },
      ],
      keyPair,
    );

    const result = await runGuardedInstall(
      ["--skill", "test-skill", "--version", "1.0.0", "--dry-run"],
      {
        CLAWSEC_LOCAL_FEED: path.join(advisoriesDir, "feed.json"),
        CLAWSEC_LOCAL_FEED_SIG: path.join(advisoriesDir, "feed.json.sig"),
        CLAWSEC_LOCAL_FEED_CHECKSUMS: path.join(advisoriesDir, "checksums.json"),
        CLAWSEC_LOCAL_FEED_CHECKSUMS_SIG: path.join(advisoriesDir, "checksums.json.sig"),
        CLAWSEC_FEED_PUBLIC_KEY: path.join(advisoriesDir, "feed-signing-public.pem"),
        CLAWSEC_FEED_URL: "file:///nonexistent",
      },
    );

    if (result.code === 42 && result.stdout.includes("Advisory matches")) {
      pass(testName);
    } else {
      fail(testName, `Expected exit 42 with advisory match, got ${result.code}: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: --confirm-advisory allows proceeding
// -----------------------------------------------------------------------------
async function testConfirmAdvisoryAllowsProceeding() {
  const testName = "guarded_install: --confirm-advisory with --dry-run proceeds";
  try {
    const keyPair = generateEd25519KeyPair();
    const advisoriesDir = await setupSignedFeed(
      [
        {
          id: "TEST-001",
          severity: "high",
          affected: ["test-skill@1.0.0"],
        },
      ],
      keyPair,
    );

    const result = await runGuardedInstall(
      ["--skill", "test-skill", "--version", "1.0.0", "--confirm-advisory", "--dry-run"],
      {
        CLAWSEC_LOCAL_FEED: path.join(advisoriesDir, "feed.json"),
        CLAWSEC_LOCAL_FEED_SIG: path.join(advisoriesDir, "feed.json.sig"),
        CLAWSEC_LOCAL_FEED_CHECKSUMS: path.join(advisoriesDir, "checksums.json"),
        CLAWSEC_LOCAL_FEED_CHECKSUMS_SIG: path.join(advisoriesDir, "checksums.json.sig"),
        CLAWSEC_FEED_PUBLIC_KEY: path.join(advisoriesDir, "feed-signing-public.pem"),
        CLAWSEC_FEED_URL: "file:///nonexistent",
      },
    );

    if (result.code === 0 && result.stdout.includes("Dry run")) {
      pass(testName);
    } else {
      fail(testName, `Expected exit 0 with dry run message, got ${result.code}: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: allowUnsigned bypass warning
// -----------------------------------------------------------------------------
async function testAllowUnsignedWarning() {
  const testName = "guarded_install: CLAWSEC_ALLOW_UNSIGNED_FEED shows warning";
  try {
    // Create unsigned feed (no signatures)
    const feedContent = createFeed([]);
    const feedPath = path.join(tempDir, "unsigned-feed.json");
    await fs.writeFile(feedPath, feedContent);

    const result = await runGuardedInstall(["--skill", "test-skill", "--dry-run"], {
      CLAWSEC_LOCAL_FEED: feedPath,
      CLAWSEC_ALLOW_UNSIGNED_FEED: "1",
      CLAWSEC_VERIFY_CHECKSUM_MANIFEST: "0",
      CLAWSEC_FEED_URL: "file:///nonexistent",
    });

    if (result.stderr.includes("CLAWSEC_ALLOW_UNSIGNED_FEED")) {
      pass(testName);
    } else {
      fail(testName, `Expected unsigned mode warning, got: ${result.stderr}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: Missing signature fails without allowUnsigned
// -----------------------------------------------------------------------------
async function testMissingSignatureFails() {
  const testName = "guarded_install: missing signature fails without allowUnsigned";
  try {
    const feedContent = createFeed([]);
    const feedPath = path.join(tempDir, "nosig-feed.json");
    await fs.writeFile(feedPath, feedContent);

    const result = await runGuardedInstall(["--skill", "test-skill", "--dry-run"], {
      CLAWSEC_LOCAL_FEED: feedPath,
      CLAWSEC_FEED_URL: "file:///nonexistent",
    });

    if (result.code === 1) {
      pass(testName);
    } else {
      fail(testName, `Expected exit 1 for missing signature, got ${result.code}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Main test runner
// -----------------------------------------------------------------------------
async function runTests() {
  console.log("=== ClawSec Guarded Install Tests ===\n");

  await setupTestDir();

  try {
    await testConservativeMatchingWithoutVersion();
    await testPreciseVersionMatching();
    await testVersionMatchTriggersConfirmation();
    await testConfirmAdvisoryAllowsProceeding();
    await testAllowUnsignedWarning();
    await testMissingSignatureFails();
  } finally {
    await cleanupTestDir();
  }

  console.log(`\n=== Results: ${passCount} passed, ${failCount} failed ===`);

  if (failCount > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error("Test runner failed:", error);
  process.exit(1);
});
