#!/usr/bin/env node

/**
 * Feed verification tests for clawsec-suite.
 *
 * Tests cover:
 * - Signature verification success/failure/tampered cases
 * - Checksum manifest verification success/failure/tampered cases
 * - Fail-closed behavior when signatures are missing/invalid
 * - Temporary compatibility flag behavior
 *
 * Run: node skills/clawsec-suite/test/feed_verification.test.mjs
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB_PATH = path.resolve(__dirname, "..", "hooks", "clawsec-advisory-guardian", "lib");

// Dynamic import to ensure we test the actual module
const { verifySignedPayload, loadLocalFeed, isValidFeedPayload } = await import(
  `${LIB_PATH}/feed.mjs`
);

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

function createValidFeed() {
  return JSON.stringify(
    {
      version: "1.0.0",
      updated: "2026-02-08T12:00:00Z",
      advisories: [
        {
          id: "TEST-001",
          severity: "high",
          affected: ["test-skill@1.0.0"],
        },
      ],
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
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawsec-test-"));
}

async function cleanupTestDir() {
  if (tempDir) {
    await fs.rm(tempDir, { recursive: true, force: true });
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - valid signature
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_ValidSignature() {
  const testName = "verifySignedPayload: valid signature passes";
  try {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const payload = "test payload content";
    const signature = signPayload(payload, privateKeyPem);

    const result = verifySignedPayload(payload, signature, publicKeyPem);

    if (result === true) {
      pass(testName);
    } else {
      fail(testName, "Expected true, got false");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - invalid signature
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_InvalidSignature() {
  const testName = "verifySignedPayload: invalid signature fails";
  try {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const payload = "test payload content";
    const signature = signPayload(payload, privateKeyPem);

    // Tamper with payload
    const tamperedPayload = "TAMPERED payload content";
    const result = verifySignedPayload(tamperedPayload, signature, publicKeyPem);

    if (result === false) {
      pass(testName);
    } else {
      fail(testName, "Expected false for tampered payload, got true");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - wrong key
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_WrongKey() {
  const testName = "verifySignedPayload: wrong key fails";
  try {
    const keyPair1 = generateEd25519KeyPair();
    const keyPair2 = generateEd25519KeyPair();
    const payload = "test payload content";
    const signature = signPayload(payload, keyPair1.privateKeyPem);

    // Verify with different public key
    const result = verifySignedPayload(payload, signature, keyPair2.publicKeyPem);

    if (result === false) {
      pass(testName);
    } else {
      fail(testName, "Expected false for wrong key, got true");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - malformed signature
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_MalformedSignature() {
  const testName = "verifySignedPayload: malformed signature fails";
  try {
    const { publicKeyPem } = generateEd25519KeyPair();
    const payload = "test payload content";

    const result = verifySignedPayload(payload, "not-valid-base64!!!", publicKeyPem);

    if (result === false) {
      pass(testName);
    } else {
      fail(testName, "Expected false for malformed signature, got true");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - empty signature
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_EmptySignature() {
  const testName = "verifySignedPayload: empty signature fails";
  try {
    const { publicKeyPem } = generateEd25519KeyPair();
    const payload = "test payload content";

    const result = verifySignedPayload(payload, "", publicKeyPem);

    if (result === false) {
      pass(testName);
    } else {
      fail(testName, "Expected false for empty signature, got true");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - JSON-wrapped signature format
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_JsonWrappedSignature() {
  const testName = "verifySignedPayload: JSON-wrapped signature passes";
  try {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const payload = "test payload content";
    const signatureBase64 = signPayload(payload, privateKeyPem);
    const jsonWrapped = JSON.stringify({ signature: signatureBase64 });

    const result = verifySignedPayload(payload, jsonWrapped, publicKeyPem);

    if (result === true) {
      pass(testName);
    } else {
      fail(testName, "Expected true for JSON-wrapped signature, got false");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - valid signed feed
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_ValidSignedFeed() {
  const testName = "loadLocalFeed: valid signed feed loads successfully";
  try {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createValidFeed();
    const feedSignature = signPayload(feedContent, privateKeyPem);

    // Create checksum manifest
    const checksumManifest = createChecksumManifest({
      "feed.json": feedContent,
      "feed.json.sig": feedSignature + "\n",
      "feed-signing-public.pem": publicKeyPem,
    });
    const checksumSignature = signPayload(checksumManifest, privateKeyPem);

    // Write files
    const feedPath = path.join(tempDir, "feed.json");
    const sigPath = path.join(tempDir, "feed.json.sig");
    const checksumPath = path.join(tempDir, "checksums.json");
    const checksumSigPath = path.join(tempDir, "checksums.json.sig");
    const keyPath = path.join(tempDir, "feed-signing-public.pem");

    await fs.writeFile(feedPath, feedContent);
    await fs.writeFile(sigPath, feedSignature + "\n");
    await fs.writeFile(checksumPath, checksumManifest);
    await fs.writeFile(checksumSigPath, checksumSignature + "\n");
    await fs.writeFile(keyPath, publicKeyPem);

    const feed = await loadLocalFeed(feedPath, {
      signaturePath: sigPath,
      checksumsPath: checksumPath,
      checksumsSignaturePath: checksumSigPath,
      publicKeyPem,
      verifyChecksumManifest: true,
      checksumPublicKeyEntry: "feed-signing-public.pem",
    });

    if (feed && feed.version === "1.0.0" && feed.advisories.length === 1) {
      pass(testName);
    } else {
      fail(testName, "Feed did not load with expected content");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - supports advisories/* checksum keys
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_AdvisoriesPrefixedChecksumKeys() {
  const testName = "loadLocalFeed: advisories/* checksum keys are accepted";
  try {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createValidFeed();
    const feedSignature = signPayload(feedContent, privateKeyPem);

    const advisoriesDir = path.join(tempDir, "advisories");
    await fs.mkdir(advisoriesDir, { recursive: true });

    const checksumManifest = createChecksumManifest({
      "advisories/feed.json": feedContent,
      "advisories/feed.json.sig": feedSignature + "\n",
      "advisories/feed-signing-public.pem": publicKeyPem,
    });
    const checksumSignature = signPayload(checksumManifest, privateKeyPem);

    const feedPath = path.join(advisoriesDir, "feed.json");
    const sigPath = path.join(advisoriesDir, "feed.json.sig");
    const checksumPath = path.join(advisoriesDir, "checksums.json");
    const checksumSigPath = path.join(advisoriesDir, "checksums.json.sig");
    const keyPath = path.join(advisoriesDir, "feed-signing-public.pem");

    await fs.writeFile(feedPath, feedContent);
    await fs.writeFile(sigPath, feedSignature + "\n");
    await fs.writeFile(checksumPath, checksumManifest);
    await fs.writeFile(checksumSigPath, checksumSignature + "\n");
    await fs.writeFile(keyPath, publicKeyPem);

    const feed = await loadLocalFeed(feedPath, {
      signaturePath: sigPath,
      checksumsPath: checksumPath,
      checksumsSignaturePath: checksumSigPath,
      publicKeyPem,
      verifyChecksumManifest: true,
      checksumPublicKeyEntry: path.basename(keyPath),
    });

    if (feed && feed.version === "1.0.0" && feed.advisories.length === 1) {
      pass(testName);
    } else {
      fail(testName, "Feed did not load with advisories/* checksum keys");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - tampered feed fails (fail-closed)
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_TamperedFeedFails() {
  const testName = "loadLocalFeed: tampered feed fails (fail-closed)";
  try {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createValidFeed();
    const feedSignature = signPayload(feedContent, privateKeyPem);

    // Tamper with feed after signing
    const tamperedFeed = feedContent.replace("TEST-001", "TAMPERED-001");

    const feedPath = path.join(tempDir, "tampered-feed.json");
    const sigPath = path.join(tempDir, "tampered-feed.json.sig");

    await fs.writeFile(feedPath, tamperedFeed);
    await fs.writeFile(sigPath, feedSignature + "\n");

    let didFail = false;
    try {
      await loadLocalFeed(feedPath, {
        signaturePath: sigPath,
        publicKeyPem,
        verifyChecksumManifest: false,
      });
    } catch {
      didFail = true;
    }

    if (didFail) {
      pass(testName);
    } else {
      fail(testName, "Expected failure for tampered feed, but it loaded");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - missing signature fails (fail-closed)
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_MissingSignatureFails() {
  const testName = "loadLocalFeed: missing signature fails (fail-closed)";
  try {
    const { publicKeyPem } = generateEd25519KeyPair();
    const feedContent = createValidFeed();

    const feedPath = path.join(tempDir, "nosig-feed.json");
    const sigPath = path.join(tempDir, "nosig-feed.json.sig");

    await fs.writeFile(feedPath, feedContent);
    // Don't write signature file

    let didFail = false;
    try {
      await loadLocalFeed(feedPath, {
        signaturePath: sigPath,
        publicKeyPem,
        verifyChecksumManifest: false,
      });
    } catch {
      didFail = true;
    }

    if (didFail) {
      pass(testName);
    } else {
      fail(testName, "Expected failure for missing signature, but it loaded");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - allowUnsigned bypasses verification
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_AllowUnsignedBypasses() {
  const testName = "loadLocalFeed: allowUnsigned=true bypasses verification";
  try {
    const feedContent = createValidFeed();

    const feedPath = path.join(tempDir, "unsigned-feed.json");
    await fs.writeFile(feedPath, feedContent);

    const feed = await loadLocalFeed(feedPath, {
      allowUnsigned: true,
      verifyChecksumManifest: false,
    });

    if (feed && feed.version === "1.0.0") {
      pass(testName);
    } else {
      fail(testName, "Feed did not load with allowUnsigned=true");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - checksum mismatch fails
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_ChecksumMismatchFails() {
  const testName = "loadLocalFeed: checksum mismatch fails";
  try {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createValidFeed();
    const feedSignature = signPayload(feedContent, privateKeyPem);

    // Create checksum manifest with WRONG hash
    const badChecksumManifest = JSON.stringify(
      {
        schema_version: "1.0",
        algorithm: "sha256",
        files: {
          "feed.json": "0".repeat(64), // Wrong hash
          "feed.json.sig":
            crypto.createHash("sha256").update(feedSignature + "\n").digest("hex"),
        },
      },
      null,
      2,
    );
    const checksumSignature = signPayload(badChecksumManifest, privateKeyPem);

    const feedPath = path.join(tempDir, "badcs-feed.json");
    const sigPath = path.join(tempDir, "badcs-feed.json.sig");
    const checksumPath = path.join(tempDir, "badcs-checksums.json");
    const checksumSigPath = path.join(tempDir, "badcs-checksums.json.sig");

    await fs.writeFile(feedPath, feedContent);
    await fs.writeFile(sigPath, feedSignature + "\n");
    await fs.writeFile(checksumPath, badChecksumManifest);
    await fs.writeFile(checksumSigPath, checksumSignature + "\n");

    let didFail = false;
    try {
      await loadLocalFeed(feedPath, {
        signaturePath: sigPath,
        checksumsPath: checksumPath,
        checksumsSignaturePath: checksumSigPath,
        publicKeyPem,
        verifyChecksumManifest: true,
      });
    } catch {
      didFail = true;
    }

    if (didFail) {
      pass(testName);
    } else {
      fail(testName, "Expected failure for checksum mismatch, but it loaded");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: isValidFeedPayload - valid feed
// -----------------------------------------------------------------------------
async function testIsValidFeedPayload_Valid() {
  const testName = "isValidFeedPayload: valid feed passes";
  try {
    const feed = {
      version: "1.0.0",
      advisories: [
        {
          id: "TEST-001",
          severity: "high",
          affected: ["test-skill@1.0.0"],
        },
      ],
    };

    if (isValidFeedPayload(feed)) {
      pass(testName);
    } else {
      fail(testName, "Expected valid feed to pass validation");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: isValidFeedPayload - missing version fails
// -----------------------------------------------------------------------------
async function testIsValidFeedPayload_MissingVersion() {
  const testName = "isValidFeedPayload: missing version fails";
  try {
    const feed = {
      advisories: [
        {
          id: "TEST-001",
          severity: "high",
          affected: [],
        },
      ],
    };

    if (!isValidFeedPayload(feed)) {
      pass(testName);
    } else {
      fail(testName, "Expected feed without version to fail validation");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: isValidFeedPayload - advisory missing id fails
// -----------------------------------------------------------------------------
async function testIsValidFeedPayload_AdvisoryMissingId() {
  const testName = "isValidFeedPayload: advisory missing id fails";
  try {
    const feed = {
      version: "1.0.0",
      advisories: [
        {
          severity: "high",
          affected: [],
        },
      ],
    };

    if (!isValidFeedPayload(feed)) {
      pass(testName);
    } else {
      fail(testName, "Expected advisory without id to fail validation");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Main test runner
// -----------------------------------------------------------------------------
async function runTests() {
  console.log("=== ClawSec Feed Verification Tests ===\n");

  await setupTestDir();

  try {
    // Signature verification tests
    await testVerifySignedPayload_ValidSignature();
    await testVerifySignedPayload_InvalidSignature();
    await testVerifySignedPayload_WrongKey();
    await testVerifySignedPayload_MalformedSignature();
    await testVerifySignedPayload_EmptySignature();
    await testVerifySignedPayload_JsonWrappedSignature();

    // Local feed loading tests
    await testLoadLocalFeed_ValidSignedFeed();
    await testLoadLocalFeed_AdvisoriesPrefixedChecksumKeys();
    await testLoadLocalFeed_TamperedFeedFails();
    await testLoadLocalFeed_MissingSignatureFails();
    await testLoadLocalFeed_AllowUnsignedBypasses();
    await testLoadLocalFeed_ChecksumMismatchFails();

    // Feed payload validation tests
    await testIsValidFeedPayload_Valid();
    await testIsValidFeedPayload_MissingVersion();
    await testIsValidFeedPayload_AdvisoryMissingId();
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
