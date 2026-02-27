#!/usr/bin/env node

/**
 * Feed reader tests for clawsec-analyst.
 *
 * Tests cover:
 * - Package specifier parsing
 * - Feed payload validation
 * - Signature verification (Ed25519)
 * - Checksum URL generation
 * - Local feed loading with signature/checksum verification
 * - Security domain validation
 *
 * Run: node skills/clawsec-analyst/test/feed-reader.test.mjs
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  pass,
  fail,
  report,
  exitWithResults,
  generateEd25519KeyPair,
  signPayload,
  createTempDir,
} from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB_PATH = path.resolve(__dirname, "..", "lib");

// Dynamic import to ensure we test the actual module
const {
  parseAffectedSpecifier,
  isValidFeedPayload,
  verifySignedPayload,
  defaultChecksumsUrl,
  loadLocalFeed,
  loadRemoteFeed,
} = await import(`${LIB_PATH}/feed-reader.js`);

let tempDirCleanup;

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Test: parseAffectedSpecifier - valid specifier with version
// -----------------------------------------------------------------------------
async function testParseAffectedSpecifier_WithVersion() {
  const testName = "parseAffectedSpecifier: parses package@version correctly";
  try {
    const result = parseAffectedSpecifier("test-package@1.2.3");

    if (result.name === "test-package" && result.versionSpec === "1.2.3") {
      pass(testName);
    } else {
      fail(testName, `Expected {name: 'test-package', versionSpec: '1.2.3'}, got ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parseAffectedSpecifier - package without version
// -----------------------------------------------------------------------------
async function testParseAffectedSpecifier_WithoutVersion() {
  const testName = "parseAffectedSpecifier: defaults to * when no version";
  try {
    const result = parseAffectedSpecifier("test-package");

    if (result.name === "test-package" && result.versionSpec === "*") {
      pass(testName);
    } else {
      fail(testName, `Expected {name: 'test-package', versionSpec: '*'}, got ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parseAffectedSpecifier - scoped package
// -----------------------------------------------------------------------------
async function testParseAffectedSpecifier_ScopedPackage() {
  const testName = "parseAffectedSpecifier: handles scoped packages";
  try {
    const result = parseAffectedSpecifier("@scope/package@2.0.0");

    if (result.name === "@scope/package" && result.versionSpec === "2.0.0") {
      pass(testName);
    } else {
      fail(testName, `Expected {name: '@scope/package', versionSpec: '2.0.0'}, got ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parseAffectedSpecifier - empty string
// -----------------------------------------------------------------------------
async function testParseAffectedSpecifier_EmptyString() {
  const testName = "parseAffectedSpecifier: returns null for empty string";
  try {
    const result = parseAffectedSpecifier("");

    if (result === null) {
      pass(testName);
    } else {
      fail(testName, `Expected null for empty string, got ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: parseAffectedSpecifier - version range
// -----------------------------------------------------------------------------
async function testParseAffectedSpecifier_VersionRange() {
  const testName = "parseAffectedSpecifier: handles version ranges";
  try {
    const result = parseAffectedSpecifier("package@>=1.0.0");

    if (result.name === "package" && result.versionSpec === ">=1.0.0") {
      pass(testName);
    } else {
      fail(testName, `Expected {name: 'package', versionSpec: '>=1.0.0'}, got ${JSON.stringify(result)}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: isValidFeedPayload - valid payload
// -----------------------------------------------------------------------------
async function testIsValidFeedPayload_Valid() {
  const testName = "isValidFeedPayload: accepts valid feed structure";
  try {
    const payload = {
      version: "1.0.0",
      advisories: [
        {
          id: "TEST-001",
          severity: "high",
          affected: ["package@1.0.0"],
        },
      ],
    };

    const result = isValidFeedPayload(payload);

    if (result === true) {
      pass(testName);
    } else {
      fail(testName, "Expected true for valid payload");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: isValidFeedPayload - missing version
// -----------------------------------------------------------------------------
async function testIsValidFeedPayload_MissingVersion() {
  const testName = "isValidFeedPayload: rejects payload missing version";
  try {
    const payload = {
      advisories: [],
    };

    const result = isValidFeedPayload(payload);

    if (result === false) {
      pass(testName);
    } else {
      fail(testName, "Expected false for payload missing version");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: isValidFeedPayload - invalid advisory structure
// -----------------------------------------------------------------------------
async function testIsValidFeedPayload_InvalidAdvisory() {
  const testName = "isValidFeedPayload: rejects invalid advisory structure";
  try {
    const payload = {
      version: "1.0.0",
      advisories: [
        {
          id: "TEST-001",
          // missing severity and affected
        },
      ],
    };

    const result = isValidFeedPayload(payload);

    if (result === false) {
      pass(testName);
    } else {
      fail(testName, "Expected false for invalid advisory structure");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: isValidFeedPayload - empty advisories array
// -----------------------------------------------------------------------------
async function testIsValidFeedPayload_EmptyAdvisories() {
  const testName = "isValidFeedPayload: accepts empty advisories array";
  try {
    const payload = {
      version: "1.0.0",
      advisories: [],
    };

    const result = isValidFeedPayload(payload);

    if (result === true) {
      pass(testName);
    } else {
      fail(testName, "Expected true for empty advisories array");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: isValidFeedPayload - non-object
// -----------------------------------------------------------------------------
async function testIsValidFeedPayload_NonObject() {
  const testName = "isValidFeedPayload: rejects non-object values";
  try {
    const result1 = isValidFeedPayload(null);
    const result2 = isValidFeedPayload("string");
    const result3 = isValidFeedPayload(123);

    if (result1 === false && result2 === false && result3 === false) {
      pass(testName);
    } else {
      fail(testName, "Expected false for all non-object values");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - valid signature
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_ValidSignature() {
  const testName = "verifySignedPayload: accepts valid signature";
  try {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const payload = "test payload content";
    const signature = signPayload(payload, privateKeyPem);

    const result = verifySignedPayload(payload, signature, publicKeyPem);

    if (result === true) {
      pass(testName);
    } else {
      fail(testName, "Expected true for valid signature");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - invalid signature
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_InvalidSignature() {
  const testName = "verifySignedPayload: rejects tampered payload";
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
      fail(testName, "Expected false for tampered payload");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - wrong key
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_WrongKey() {
  const testName = "verifySignedPayload: rejects wrong public key";
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
      fail(testName, "Expected false for wrong public key");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - malformed signature
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_MalformedSignature() {
  const testName = "verifySignedPayload: rejects malformed signature";
  try {
    const { publicKeyPem } = generateEd25519KeyPair();
    const payload = "test payload content";

    const result = verifySignedPayload(payload, "not-valid-base64!!!", publicKeyPem);

    if (result === false) {
      pass(testName);
    } else {
      fail(testName, "Expected false for malformed signature");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - empty signature
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_EmptySignature() {
  const testName = "verifySignedPayload: rejects empty signature";
  try {
    const { publicKeyPem } = generateEd25519KeyPair();
    const payload = "test payload content";

    const result = verifySignedPayload(payload, "", publicKeyPem);

    if (result === false) {
      pass(testName);
    } else {
      fail(testName, "Expected false for empty signature");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: verifySignedPayload - JSON-wrapped signature
// -----------------------------------------------------------------------------
async function testVerifySignedPayload_JsonWrappedSignature() {
  const testName = "verifySignedPayload: accepts JSON-wrapped signature";
  try {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const payload = "test payload content";
    const signatureBase64 = signPayload(payload, privateKeyPem);
    const jsonWrapped = JSON.stringify({ signature: signatureBase64 });

    const result = verifySignedPayload(payload, jsonWrapped, publicKeyPem);

    if (result === true) {
      pass(testName);
    } else {
      fail(testName, "Expected true for JSON-wrapped signature");
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: defaultChecksumsUrl - standard URL
// -----------------------------------------------------------------------------
async function testDefaultChecksumsUrl_StandardUrl() {
  const testName = "defaultChecksumsUrl: generates correct checksums URL";
  try {
    const feedUrl = "https://example.com/advisories/feed.json";
    const result = defaultChecksumsUrl(feedUrl);

    if (result === "https://example.com/advisories/checksums.json") {
      pass(testName);
    } else {
      fail(testName, `Expected 'https://example.com/advisories/checksums.json', got '${result}'`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: defaultChecksumsUrl - root URL
// -----------------------------------------------------------------------------
async function testDefaultChecksumsUrl_RootUrl() {
  const testName = "defaultChecksumsUrl: handles root URL";
  try {
    const feedUrl = "https://example.com/feed.json";
    const result = defaultChecksumsUrl(feedUrl);

    if (result === "https://example.com/checksums.json") {
      pass(testName);
    } else {
      fail(testName, `Expected 'https://example.com/checksums.json', got '${result}'`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - valid signed feed
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_ValidSigned() {
  const testName = "loadLocalFeed: loads valid signed feed";
  try {
    const { path: tmpDir, cleanup } = await createTempDir();
    tempDirCleanup = cleanup;

    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createValidFeed();
    const signature = signPayload(feedContent, privateKeyPem);

    const feedPath = path.join(tmpDir, "feed.json");
    const signaturePath = path.join(tmpDir, "feed.json.sig");

    await fs.writeFile(feedPath, feedContent, "utf8");
    await fs.writeFile(signaturePath, signature, "utf8");

    const result = await loadLocalFeed(feedPath, {
      publicKeyPem,
      verifyChecksumManifest: false,
    });

    if (
      result.version === "1.0.0" &&
      result.advisories.length === 1 &&
      result.advisories[0].id === "TEST-001"
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected feed payload: ${JSON.stringify(result)}`);
    }

    await cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - invalid signature
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_InvalidSignature() {
  const testName = "loadLocalFeed: rejects invalid signature";
  try {
    const { path: tmpDir, cleanup } = await createTempDir();
    tempDirCleanup = cleanup;

    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createValidFeed();
    const signature = signPayload(feedContent, privateKeyPem);

    const feedPath = path.join(tmpDir, "feed.json");
    const signaturePath = path.join(tmpDir, "feed.json.sig");

    // Tamper with feed content after signing
    const tamperedFeed = feedContent.replace("TEST-001", "TAMPERED-001");
    await fs.writeFile(feedPath, tamperedFeed, "utf8");
    await fs.writeFile(signaturePath, signature, "utf8");

    try {
      await loadLocalFeed(feedPath, {
        publicKeyPem,
        verifyChecksumManifest: false,
      });
      fail(testName, "Expected error for invalid signature");
    } catch (error) {
      if (error.message.includes("signature verification failed")) {
        pass(testName);
      } else {
        fail(testName, `Unexpected error: ${error.message}`);
      }
    }

    await cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - unsigned allowed
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_UnsignedAllowed() {
  const testName = "loadLocalFeed: allows unsigned feed when explicitly enabled";
  try {
    const { path: tmpDir, cleanup } = await createTempDir();
    tempDirCleanup = cleanup;

    const feedContent = createValidFeed();
    const feedPath = path.join(tmpDir, "feed.json");

    await fs.writeFile(feedPath, feedContent, "utf8");

    const result = await loadLocalFeed(feedPath, {
      allowUnsigned: true,
    });

    if (result.version === "1.0.0" && result.advisories.length === 1) {
      pass(testName);
    } else {
      fail(testName, `Unexpected feed payload: ${JSON.stringify(result)}`);
    }

    await cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - with checksum verification
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_WithChecksumVerification() {
  const testName = "loadLocalFeed: verifies checksums when enabled";
  try {
    const { path: tmpDir, cleanup } = await createTempDir();
    tempDirCleanup = cleanup;

    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createValidFeed();
    const signature = signPayload(feedContent, privateKeyPem);

    const checksumManifest = createChecksumManifest({
      "feed.json": feedContent,
      "feed.json.sig": signature,
    });
    const checksumSignature = signPayload(checksumManifest, privateKeyPem);

    const feedPath = path.join(tmpDir, "feed.json");
    const signaturePath = path.join(tmpDir, "feed.json.sig");
    const checksumsPath = path.join(tmpDir, "checksums.json");
    const checksumsSignaturePath = path.join(tmpDir, "checksums.json.sig");

    await fs.writeFile(feedPath, feedContent, "utf8");
    await fs.writeFile(signaturePath, signature, "utf8");
    await fs.writeFile(checksumsPath, checksumManifest, "utf8");
    await fs.writeFile(checksumsSignaturePath, checksumSignature, "utf8");

    const result = await loadLocalFeed(feedPath, {
      publicKeyPem,
      verifyChecksumManifest: true,
    });

    if (result.version === "1.0.0" && result.advisories.length === 1) {
      pass(testName);
    } else {
      fail(testName, `Unexpected feed payload: ${JSON.stringify(result)}`);
    }

    await cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - invalid feed format
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_InvalidFormat() {
  const testName = "loadLocalFeed: rejects invalid feed format";
  try {
    const { path: tmpDir, cleanup } = await createTempDir();
    tempDirCleanup = cleanup;

    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const invalidFeed = JSON.stringify({ invalid: "structure" });
    const signature = signPayload(invalidFeed, privateKeyPem);

    const feedPath = path.join(tmpDir, "feed.json");
    const signaturePath = path.join(tmpDir, "feed.json.sig");

    await fs.writeFile(feedPath, invalidFeed, "utf8");
    await fs.writeFile(signaturePath, signature, "utf8");

    try {
      await loadLocalFeed(feedPath, {
        publicKeyPem,
        verifyChecksumManifest: false,
      });
      fail(testName, "Expected error for invalid feed format");
    } catch (error) {
      if (error.message.includes("Invalid advisory feed format")) {
        pass(testName);
      } else {
        fail(testName, `Unexpected error: ${error.message}`);
      }
    }

    await cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Test: loadLocalFeed - checksum mismatch
// -----------------------------------------------------------------------------
async function testLoadLocalFeed_ChecksumMismatch() {
  const testName = "loadLocalFeed: rejects checksum mismatch";
  try {
    const { path: tmpDir, cleanup } = await createTempDir();
    tempDirCleanup = cleanup;

    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const feedContent = createValidFeed();
    const signature = signPayload(feedContent, privateKeyPem);

    // Create checksum manifest with original content
    const checksumManifest = createChecksumManifest({
      "feed.json": feedContent,
      "feed.json.sig": signature,
    });
    const checksumSignature = signPayload(checksumManifest, privateKeyPem);

    // Write tampered feed content
    const tamperedFeed = feedContent.replace("TEST-001", "TAMPERED-001");
    const tamperedSignature = signPayload(tamperedFeed, privateKeyPem);

    const feedPath = path.join(tmpDir, "feed.json");
    const signaturePath = path.join(tmpDir, "feed.json.sig");
    const checksumsPath = path.join(tmpDir, "checksums.json");
    const checksumsSignaturePath = path.join(tmpDir, "checksums.json.sig");

    await fs.writeFile(feedPath, tamperedFeed, "utf8");
    await fs.writeFile(signaturePath, tamperedSignature, "utf8");
    await fs.writeFile(checksumsPath, checksumManifest, "utf8");
    await fs.writeFile(checksumsSignaturePath, checksumSignature, "utf8");

    try {
      await loadLocalFeed(feedPath, {
        publicKeyPem,
        verifyChecksumManifest: true,
      });
      fail(testName, "Expected error for checksum mismatch");
    } catch (error) {
      if (error.message.includes("Checksum mismatch")) {
        pass(testName);
      } else {
        fail(testName, `Unexpected error: ${error.message}`);
      }
    }

    await cleanup();
    tempDirCleanup = null;
  } catch (error) {
    fail(testName, error);
    if (tempDirCleanup) await tempDirCleanup();
  }
}

// -----------------------------------------------------------------------------
// Run all tests
// -----------------------------------------------------------------------------
async function runAllTests() {
  console.log("=== Feed Reader Tests ===\n");

  // parseAffectedSpecifier tests
  await testParseAffectedSpecifier_WithVersion();
  await testParseAffectedSpecifier_WithoutVersion();
  await testParseAffectedSpecifier_ScopedPackage();
  await testParseAffectedSpecifier_EmptyString();
  await testParseAffectedSpecifier_VersionRange();

  // isValidFeedPayload tests
  await testIsValidFeedPayload_Valid();
  await testIsValidFeedPayload_MissingVersion();
  await testIsValidFeedPayload_InvalidAdvisory();
  await testIsValidFeedPayload_EmptyAdvisories();
  await testIsValidFeedPayload_NonObject();

  // verifySignedPayload tests
  await testVerifySignedPayload_ValidSignature();
  await testVerifySignedPayload_InvalidSignature();
  await testVerifySignedPayload_WrongKey();
  await testVerifySignedPayload_MalformedSignature();
  await testVerifySignedPayload_EmptySignature();
  await testVerifySignedPayload_JsonWrappedSignature();

  // defaultChecksumsUrl tests
  await testDefaultChecksumsUrl_StandardUrl();
  await testDefaultChecksumsUrl_RootUrl();

  // loadLocalFeed tests
  await testLoadLocalFeed_ValidSigned();
  await testLoadLocalFeed_InvalidSignature();
  await testLoadLocalFeed_UnsignedAllowed();
  await testLoadLocalFeed_WithChecksumVerification();
  await testLoadLocalFeed_InvalidFormat();
  await testLoadLocalFeed_ChecksumMismatch();

  report();
  exitWithResults();
}

// Run tests
runAllTests().catch((error) => {
  console.error("Test runner failed:", error);
  process.exit(1);
});
