#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  getFeedVerificationStatus,
  isValidFeedPayload,
  loadLocalFeed,
  loadRemoteFeed,
  refreshAdvisoryFeed,
  resolveFeedConfig,
} from "../lib/feed.mjs";
import { buildAttestation } from "../lib/attestation.mjs";

function createFeedPayload() {
  return {
    version: "1.0.0",
    updated: "2026-04-20T00:00:00Z",
    advisories: [
      {
        id: "TEST-ADVISORY-001",
        severity: "high",
        affected: ["sample-skill@1.0.0"],
      },
    ],
  };
}

function signPayload(payloadRaw, privateKeyPem) {
  const key = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign(null, Buffer.from(payloadRaw, "utf8"), key);
  return signature.toString("base64");
}

function createChecksumManifest(files) {
  const checksums = {};
  for (const [name, content] of Object.entries(files)) {
    checksums[name] = crypto.createHash("sha256").update(content).digest("hex");
  }
  return JSON.stringify(
    {
      schema_version: "1",
      algorithm: "sha256",
      files: checksums,
    },
    null,
    2,
  );
}

async function withTempDir(run) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "hag-feed-"));
  try {
    await run(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

async function withPatchedEnv(patch, run) {
  const previous = new Map();
  for (const [key, value] of Object.entries(patch)) {
    previous.set(key, process.env[key]);
    if (value === undefined || value === null) {
      delete process.env[key];
    } else {
      process.env[key] = String(value);
    }
  }

  try {
    await run();
  } finally {
    for (const [key, value] of previous.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

async function expectReject(label, run) {
  let failed = false;
  try {
    await run();
  } catch {
    failed = true;
  }
  assert.equal(failed, true, label);
}

async function withMockedFetch(mockFetch, run) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = mockFetch;
  try {
    await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function testValidSignedLocalFeed() {
  await withTempDir(async (tempDir) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
    const feedPath = path.join(tempDir, "feed.json");
    const signaturePath = path.join(tempDir, "feed.json.sig");

    await fs.writeFile(feedPath, feedRaw, "utf8");
    await fs.writeFile(signaturePath, `${signPayload(feedRaw, privateKeyPem)}\n`, "utf8");

    const loaded = await loadLocalFeed({
      localFeedPath: feedPath,
      localSignaturePath: signaturePath,
      localChecksumsPath: path.join(tempDir, "checksums.json"),
      localChecksumsSignaturePath: path.join(tempDir, "checksums.json.sig"),
      publicKeyPem,
      allowUnsigned: false,
      verifyChecksumManifest: false,
    });

    assert.equal(loaded.payload.version, "1.0.0");
    assert.equal(loaded.verification.unsigned_bypass, false);
  });
}

async function testUnsupportedAffectedRangesFailClosed() {
  await withTempDir(async (tempDir) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const testSpecs = ["1.2 || 1.3", ">=1.0.0 garbage <2.0.0"];
    for (const unsupportedSpec of testSpecs) {
      const payload = createFeedPayload();
      payload.advisories[0].affected = [`sample-skill@${unsupportedSpec}`];
      const feedRaw = JSON.stringify(payload, null, 2);

      const feedPath = path.join(tempDir, `feed-${unsupportedSpec.replace(/[^a-z0-9]+/gi, "-")}.json`);
      const signaturePath = `${feedPath}.sig`;

      await fs.writeFile(feedPath, feedRaw, "utf8");
      await fs.writeFile(signaturePath, `${signPayload(feedRaw, privateKeyPem)}\n`, "utf8");

      await expectReject(`unsupported affected range '${unsupportedSpec}' must fail closed`, async () => {
        await loadLocalFeed({
          localFeedPath: feedPath,
          localSignaturePath: signaturePath,
          localChecksumsPath: path.join(tempDir, "checksums.json"),
          localChecksumsSignaturePath: path.join(tempDir, "checksums.json.sig"),
          publicKeyPem,
          allowUnsigned: false,
          verifyChecksumManifest: false,
        });
      });
    }
  });
}

function testCanonicalRepositoryFeedPayloadIsAccepted() {
  const canonicalFeedUrl = new URL("../../../advisories/feed.json", import.meta.url);
  const canonicalFeed = JSON.parse(fsSync.readFileSync(canonicalFeedUrl, "utf8"));

  assert.equal(
    isValidFeedPayload(canonicalFeed),
    true,
    "Hermes must accept the canonical consolidated feed, including CPE metadata and supported comparator sets",
  );
}

function testMalformedCpeFailsClosed() {
  const payload = createFeedPayload();
  payload.advisories[0].affected = ["cpe:2.3:a:missing-components"];
  assert.equal(isValidFeedPayload(payload), false, "malformed CPE metadata must still fail closed");
}

async function testInvalidSignatureFailsClosed() {
  await withTempDir(async (tempDir) => {
    const signerKeys = crypto.generateKeyPairSync("ed25519");
    const verifierKeys = crypto.generateKeyPairSync("ed25519");

    const verifierPublicKeyPem = verifierKeys.publicKey.export({ type: "spki", format: "pem" });
    const signerPrivateKeyPem = signerKeys.privateKey.export({ type: "pkcs8", format: "pem" });

    const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
    const feedPath = path.join(tempDir, "feed.json");
    const signaturePath = path.join(tempDir, "feed.json.sig");

    await fs.writeFile(feedPath, feedRaw, "utf8");
    await fs.writeFile(signaturePath, `${signPayload(feedRaw, signerPrivateKeyPem)}\n`, "utf8");

    await expectReject("invalid signature must fail closed", async () => {
      await loadLocalFeed({
        localFeedPath: feedPath,
        localSignaturePath: signaturePath,
        localChecksumsPath: path.join(tempDir, "checksums.json"),
        localChecksumsSignaturePath: path.join(tempDir, "checksums.json.sig"),
        publicKeyPem: verifierPublicKeyPem,
        allowUnsigned: false,
        verifyChecksumManifest: false,
      });
    });
  });
}

async function testChecksumMismatchFails() {
  await withTempDir(async (tempDir) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
    const feedPath = path.join(tempDir, "feed.json");
    const signaturePath = path.join(tempDir, "feed.json.sig");
    const checksumsPath = path.join(tempDir, "checksums.json");
    const checksumsSignaturePath = path.join(tempDir, "checksums.json.sig");

    const feedSigRaw = `${signPayload(feedRaw, privateKeyPem)}\n`;
    const checksumsRaw = JSON.stringify(
      {
        schema_version: "1",
        algorithm: "sha256",
        files: {
          "feed.json": "0".repeat(64),
        },
      },
      null,
      2,
    );

    await fs.writeFile(feedPath, feedRaw, "utf8");
    await fs.writeFile(signaturePath, feedSigRaw, "utf8");
    await fs.writeFile(checksumsPath, checksumsRaw, "utf8");
    await fs.writeFile(checksumsSignaturePath, `${signPayload(checksumsRaw, privateKeyPem)}\n`, "utf8");

    await expectReject("checksum mismatch must fail", async () => {
      await loadLocalFeed({
        localFeedPath: feedPath,
        localSignaturePath: signaturePath,
        localChecksumsPath: checksumsPath,
        localChecksumsSignaturePath: checksumsSignaturePath,
        publicKeyPem,
        allowUnsigned: false,
        verifyChecksumManifest: true,
      });
    });
  });
}

async function testChecksumManifestRequiresFeedSignatureEntry() {
  await withTempDir(async (tempDir) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
    const feedPath = path.join(tempDir, "feed.json");
    const signaturePath = path.join(tempDir, "feed.json.sig");
    const checksumsPath = path.join(tempDir, "checksums.json");
    const checksumsSignaturePath = path.join(tempDir, "checksums.json.sig");

    const feedSigRaw = `${signPayload(feedRaw, privateKeyPem)}\n`;
    const checksumsRaw = createChecksumManifest({ "feed.json": feedRaw });

    await fs.writeFile(feedPath, feedRaw, "utf8");
    await fs.writeFile(signaturePath, feedSigRaw, "utf8");
    await fs.writeFile(checksumsPath, checksumsRaw, "utf8");
    await fs.writeFile(checksumsSignaturePath, `${signPayload(checksumsRaw, privateKeyPem)}\n`, "utf8");

    await expectReject("checksum manifest must include feed signature digest entry", async () => {
      await loadLocalFeed({
        localFeedPath: feedPath,
        localSignaturePath: signaturePath,
        localChecksumsPath: checksumsPath,
        localChecksumsSignaturePath: checksumsSignaturePath,
        publicKeyPem,
        allowUnsigned: false,
        verifyChecksumManifest: true,
      });
    });
  });
}

async function testChecksumManifestVerifiesFeedAndSignatureEntries() {
  await withTempDir(async (tempDir) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
    const feedPath = path.join(tempDir, "feed.json");
    const signaturePath = path.join(tempDir, "feed.json.sig");
    const checksumsPath = path.join(tempDir, "checksums.json");
    const checksumsSignaturePath = path.join(tempDir, "checksums.json.sig");

    const feedSigRaw = `${signPayload(feedRaw, privateKeyPem)}\n`;
    const checksumsRaw = createChecksumManifest({
      "feed.json": feedRaw,
      "feed.json.sig": feedSigRaw,
    });

    await fs.writeFile(feedPath, feedRaw, "utf8");
    await fs.writeFile(signaturePath, feedSigRaw, "utf8");
    await fs.writeFile(checksumsPath, checksumsRaw, "utf8");
    await fs.writeFile(checksumsSignaturePath, `${signPayload(checksumsRaw, privateKeyPem)}\n`, "utf8");

    const loaded = await loadLocalFeed({
      localFeedPath: feedPath,
      localSignaturePath: signaturePath,
      localChecksumsPath: checksumsPath,
      localChecksumsSignaturePath: checksumsSignaturePath,
      publicKeyPem,
      allowUnsigned: false,
      verifyChecksumManifest: true,
    });

    assert.equal(loaded.payload.version, "1.0.0");
    assert.equal(loaded.verification.checksums_verified, true);
  });
}

async function testLocalChecksumPartialArtifactsFailClosed() {
  await withTempDir(async (tempDir) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
    const feedPath = path.join(tempDir, "feed.json");
    const signaturePath = path.join(tempDir, "feed.json.sig");
    const checksumsPath = path.join(tempDir, "checksums.json");
    const checksumsSignaturePath = path.join(tempDir, "checksums.json.sig");

    const feedSigRaw = `${signPayload(feedRaw, privateKeyPem)}\n`;
    await fs.writeFile(feedPath, feedRaw, "utf8");
    await fs.writeFile(signaturePath, feedSigRaw, "utf8");

    const checksumsRaw = createChecksumManifest({
      "feed.json": feedRaw,
      "feed.json.sig": feedSigRaw,
    });

    await fs.writeFile(checksumsPath, checksumsRaw, "utf8");
    await expectReject("manifest-only checksum artifacts must fail closed", async () => {
      await loadLocalFeed({
        localFeedPath: feedPath,
        localSignaturePath: signaturePath,
        localChecksumsPath: checksumsPath,
        localChecksumsSignaturePath: checksumsSignaturePath,
        publicKeyPem,
        allowUnsigned: false,
        verifyChecksumManifest: true,
      });
    });

    await fs.rm(checksumsPath, { force: true });
    await fs.writeFile(checksumsSignaturePath, `${signPayload(checksumsRaw, privateKeyPem)}\n`, "utf8");
    await expectReject("signature-only checksum artifacts must fail closed", async () => {
      await loadLocalFeed({
        localFeedPath: feedPath,
        localSignaturePath: signaturePath,
        localChecksumsPath: checksumsPath,
        localChecksumsSignaturePath: checksumsSignaturePath,
        publicKeyPem,
        allowUnsigned: false,
        verifyChecksumManifest: true,
      });
    });
  });
}

async function testLocalChecksumArtifactsMissingFailClosed() {
  await withTempDir(async (tempDir) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
    const feedPath = path.join(tempDir, "feed.json");
    const signaturePath = path.join(tempDir, "feed.json.sig");

    await fs.writeFile(feedPath, feedRaw, "utf8");
    await fs.writeFile(signaturePath, `${signPayload(feedRaw, privateKeyPem)}\n`, "utf8");

    await expectReject("missing checksum manifest and signature must fail closed", async () => {
      await loadLocalFeed({
        localFeedPath: feedPath,
        localSignaturePath: signaturePath,
        localChecksumsPath: path.join(tempDir, "checksums.json"),
        localChecksumsSignaturePath: path.join(tempDir, "checksums.json.sig"),
        publicKeyPem,
        allowUnsigned: false,
        verifyChecksumManifest: true,
      });
    });
  });
}

async function testRemoteChecksumArtifactsMissingFailClosed() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

  const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
  const signatureRaw = `${signPayload(feedRaw, privateKeyPem)}\n`;

  await withMockedFetch(
    async (url) => {
      const target = String(url);
      if (target === "https://example.test/feed.json") {
        return { ok: true, status: 200, text: async () => feedRaw };
      }
      if (target === "https://example.test/feed.json.sig") {
        return { ok: true, status: 200, text: async () => signatureRaw };
      }
      if (target === "https://example.test/checksums.json") {
        return { ok: false, status: 404, text: async () => "" };
      }
      if (target === "https://example.test/checksums.json.sig") {
        return { ok: false, status: 404, text: async () => "" };
      }
      throw new Error(`unexpected fetch url: ${target}`);
    },
    async () => {
      await expectReject("remote missing checksum artifacts must fail closed", async () => {
        await loadRemoteFeed({
          feedUrl: "https://example.test/feed.json",
          signatureUrl: "https://example.test/feed.json.sig",
          checksumsUrl: "https://example.test/checksums.json",
          checksumsSignatureUrl: "https://example.test/checksums.json.sig",
          publicKeyPem,
          allowUnsigned: false,
          verifyChecksumManifest: true,
        });
      });
    },
  );
}

async function testMissingSignatureFailsClosed() {
  await withTempDir(async (tempDir) => {
    const { publicKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });

    const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
    const feedPath = path.join(tempDir, "feed.json");

    await fs.writeFile(feedPath, feedRaw, "utf8");

    await expectReject("missing signature must fail closed", async () => {
      await loadLocalFeed({
        localFeedPath: feedPath,
        localSignaturePath: path.join(tempDir, "feed.json.sig"),
        localChecksumsPath: path.join(tempDir, "checksums.json"),
        localChecksumsSignaturePath: path.join(tempDir, "checksums.json.sig"),
        publicKeyPem,
        allowUnsigned: false,
        verifyChecksumManifest: false,
      });
    });
  });
}

async function testAllowUnsignedBypass() {
  await withTempDir(async (tempDir) => {
    const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
    const feedPath = path.join(tempDir, "feed.json");

    await fs.writeFile(feedPath, feedRaw, "utf8");

    const loaded = await loadLocalFeed({
      localFeedPath: feedPath,
      localSignaturePath: path.join(tempDir, "feed.json.sig"),
      localChecksumsPath: path.join(tempDir, "checksums.json"),
      localChecksumsSignaturePath: path.join(tempDir, "checksums.json.sig"),
      publicKeyPem: "",
      allowUnsigned: true,
      verifyChecksumManifest: true,
    });

    assert.equal(loaded.payload.version, "1.0.0");
    assert.equal(loaded.verification.unsigned_bypass, true);
  });
}

async function testRefreshUpdatesStateAndAttestationReadableStatus() {
  await withTempDir(async (tempDir) => {
    const hermesHome = path.join(tempDir, ".hermes");
    const advisoryDir = path.join(tempDir, "advisories-src");
    const customStatePath = path.join(hermesHome, "security", "advisories", "custom-state.json");
    await fs.mkdir(advisoryDir, { recursive: true });

    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const feedRaw = JSON.stringify(createFeedPayload(), null, 2);
    const feedPath = path.join(advisoryDir, "feed.json");
    const signaturePath = `${feedPath}.sig`;
    const checksumsPath = path.join(advisoryDir, "checksums.json");
    const checksumsSignaturePath = `${checksumsPath}.sig`;

    const feedSigRaw = `${signPayload(feedRaw, privateKeyPem)}\n`;
    const checksumsRaw = createChecksumManifest({
      "feed.json": feedRaw,
      "feed.json.sig": feedSigRaw,
    });
    const checksumsSigRaw = `${signPayload(checksumsRaw, privateKeyPem)}\n`;

    await fs.writeFile(feedPath, feedRaw, "utf8");
    await fs.writeFile(signaturePath, feedSigRaw, "utf8");
    await fs.writeFile(checksumsPath, checksumsRaw, "utf8");
    await fs.writeFile(checksumsSignaturePath, checksumsSigRaw, "utf8");

    await withPatchedEnv(
      {
        HERMES_HOME: hermesHome,
        HERMES_ADVISORY_FEED_STATE_PATH: customStatePath,
      },
      async () => {
        const result = await refreshAdvisoryFeed({
          source: "local",
          localFeedPath: feedPath,
          localSignaturePath: signaturePath,
          localChecksumsPath: checksumsPath,
          localChecksumsSignaturePath: checksumsSignaturePath,
          publicKeyPem,
          allowUnsigned: false,
          verifyChecksumManifest: true,
        });
        assert.equal(result.status, "verified");
        assert.equal(result.statePath, customStatePath);

        const status = getFeedVerificationStatus({ statePath: customStatePath });
        assert.equal(status.status, "verified");
        assert.equal(status.available, true);

        const attestation = buildAttestation({ generatedAt: "2026-04-20T00:00:00.000Z" });
        assert.equal(attestation.posture.feed_verification.status, "verified");
        assert.equal(attestation.posture.feed_verification.configured, true);
        assert.equal(attestation.posture.feed_verification.state_path, customStatePath);
      },
    );
  });
}

async function testRefreshWritesCachedFeedAtomicallyWithTrailingNewline() {
  await withTempDir(async (tempDir) => {
    const hermesHome = path.join(tempDir, ".hermes");
    const advisoryDir = path.join(tempDir, "advisories-src");
    const cachedFeedPath = path.join(hermesHome, "security", "advisories", "feed-cache.json");
    await fs.mkdir(advisoryDir, { recursive: true });

    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const feedRaw = `${JSON.stringify(createFeedPayload(), null, 2)}\n\n`;
    const feedPath = path.join(advisoryDir, "feed.json");
    const signaturePath = `${feedPath}.sig`;

    await fs.writeFile(feedPath, feedRaw, "utf8");
    await fs.writeFile(signaturePath, `${signPayload(feedRaw, privateKeyPem)}\n`, "utf8");

    const originalWriteFileSync = fsSync.writeFileSync;
    const originalRenameSync = fsSync.renameSync;
    const writes = [];
    const renames = [];

    fsSync.writeFileSync = function patchedWriteFileSync(filePath, data, ...rest) {
      writes.push({ filePath: String(filePath), data: String(data) });
      return originalWriteFileSync.call(this, filePath, data, ...rest);
    };

    fsSync.renameSync = function patchedRenameSync(fromPath, toPath) {
      renames.push({ fromPath: String(fromPath), toPath: String(toPath) });
      return originalRenameSync.call(this, fromPath, toPath);
    };

    try {
      await withPatchedEnv(
        {
          HERMES_HOME: hermesHome,
        },
        async () => {
          const result = await refreshAdvisoryFeed({
            source: "local",
            localFeedPath: feedPath,
            localSignaturePath: signaturePath,
            localChecksumsPath: path.join(advisoryDir, "checksums.json"),
            localChecksumsSignaturePath: path.join(advisoryDir, "checksums.json.sig"),
            cachedFeedPath,
            publicKeyPem,
            allowUnsigned: false,
            verifyChecksumManifest: false,
          });
          assert.equal(result.status, "verified");
        },
      );
    } finally {
      fsSync.writeFileSync = originalWriteFileSync;
      fsSync.renameSync = originalRenameSync;
    }

    const cachedRename = renames.find((entry) => entry.toPath === cachedFeedPath);
    assert.ok(cachedRename, "cached feed must be written via rename into destination path");
    assert.equal(path.dirname(cachedRename.fromPath), path.dirname(cachedFeedPath));
    assert.ok(
      path.basename(cachedRename.fromPath).startsWith(`${path.basename(cachedFeedPath)}.tmp-`),
      "cached feed temp filename should be derived from destination basename",
    );

    const cachedWrite = writes.find((entry) => entry.filePath === cachedRename.fromPath);
    assert.ok(cachedWrite, "cached feed should be written to temp path before rename");
    assert.equal(cachedWrite.data, `${feedRaw.trimEnd()}\n`, "cached feed should keep single trailing newline semantics");

    const cachedFileRaw = await fs.readFile(cachedFeedPath, "utf8");
    assert.equal(cachedFileRaw, `${feedRaw.trimEnd()}\n`);
  });
}

async function testResolveFeedConfigRejectsOutsideHermesHomeStateAndCachePaths() {
  await withTempDir(async (tempDir) => {
    const hermesHome = path.join(tempDir, ".hermes");
    const outsideDir = path.join(tempDir, "outside");
    await fs.mkdir(hermesHome, { recursive: true });
    await fs.mkdir(outsideDir, { recursive: true });

    await withPatchedEnv(
      {
        HERMES_HOME: hermesHome,
        HERMES_ADVISORY_FEED_STATE_PATH: path.join(outsideDir, "feed-state.json"),
        HERMES_ADVISORY_CACHED_FEED: undefined,
      },
      async () => {
        assert.throws(
          () => resolveFeedConfig({}),
          /advisory state path must stay under/,
          "outside HERMES_HOME state path must be rejected",
        );
      },
    );

    await withPatchedEnv(
      {
        HERMES_HOME: hermesHome,
        HERMES_ADVISORY_CACHED_FEED: path.join(outsideDir, "feed-cache.json"),
        HERMES_ADVISORY_FEED_STATE_PATH: undefined,
      },
      async () => {
        assert.throws(
          () => resolveFeedConfig({}),
          /cached feed path must stay under/,
          "outside HERMES_HOME cached feed path must be rejected",
        );
      },
    );
  });
}

await testValidSignedLocalFeed();
testCanonicalRepositoryFeedPayloadIsAccepted();
testMalformedCpeFailsClosed();
await testUnsupportedAffectedRangesFailClosed();
await testInvalidSignatureFailsClosed();
await testChecksumMismatchFails();
await testChecksumManifestRequiresFeedSignatureEntry();
await testChecksumManifestVerifiesFeedAndSignatureEntries();
await testLocalChecksumPartialArtifactsFailClosed();
await testLocalChecksumArtifactsMissingFailClosed();
await testRemoteChecksumArtifactsMissingFailClosed();
await testMissingSignatureFailsClosed();
await testAllowUnsignedBypass();
async function testLocalChecksumArtifactsIgnoredWhenVerificationDisabled() {
  await withTempDir(async (tempDir) => {
    const hermesHome = path.join(tempDir, ".hermes");
    const advisoryDir = path.join(tempDir, "advisories-src");
    await fs.mkdir(advisoryDir, { recursive: true });

    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const feedRaw = `${JSON.stringify(createFeedPayload(), null, 2)}\n`;
    const feedPath = path.join(advisoryDir, "feed.json");
    const signaturePath = `${feedPath}.sig`;
    const checksumsPath = path.join(advisoryDir, "checksums.json");

    await fs.writeFile(feedPath, feedRaw, "utf8");
    await fs.writeFile(signaturePath, `${signPayload(feedRaw, privateKeyPem)}\n`, "utf8");
    await fs.mkdir(checksumsPath, { recursive: true });

    await withPatchedEnv(
      { HERMES_HOME: hermesHome },
      async () => {
        const result = await refreshAdvisoryFeed({
          source: "local",
          localFeedPath: feedPath,
          localSignaturePath: signaturePath,
          localChecksumsPath: checksumsPath,
          localChecksumsSignaturePath: `${checksumsPath}.sig`,
          publicKeyPem,
          allowUnsigned: false,
          verifyChecksumManifest: false,
        });
        assert.equal(result.status, "verified");
      },
    );
  });
}

await testRefreshUpdatesStateAndAttestationReadableStatus();
await testRefreshWritesCachedFeedAtomicallyWithTrailingNewline();
await testResolveFeedConfigRejectsOutsideHermesHomeStateAndCachePaths();
await testLocalChecksumArtifactsIgnoredWhenVerificationDisabled();

console.log("feed_verification.test.mjs: ok");
