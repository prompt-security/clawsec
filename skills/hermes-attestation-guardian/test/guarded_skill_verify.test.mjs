#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const skillRoot = path.resolve(__dirname, "..");
const guardedVerifyScript = path.join(skillRoot, "scripts", "guarded_skill_verify.mjs");

function runNode(args = [], env = {}) {
  return spawnSync(process.execPath, [guardedVerifyScript, ...args], {
    cwd: skillRoot,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function signPayload(payloadRaw, privateKeyPem) {
  const key = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign(null, Buffer.from(payloadRaw, "utf8"), key);
  return signature.toString("base64");
}

async function withTempDir(run) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "hag-guarded-"));
  try {
    await run(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

async function writeFeedArtifacts({ dir, advisories, keyPair, signatureKeyPair = keyPair }) {
  const feedPath = path.join(dir, "feed.json");
  const feedSigPath = `${feedPath}.sig`;
  const checksumsPath = path.join(dir, "checksums.json");
  const checksumsSigPath = `${checksumsPath}.sig`;
  const publicKeyPath = path.join(dir, "feed-public.pem");

  const feedRaw = JSON.stringify(
    {
      version: "1.0.0",
      updated: "2026-04-20T00:00:00Z",
      advisories,
    },
    null,
    2,
  );

  const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" });
  const signingPrivatePem = signatureKeyPair.privateKey.export({ type: "pkcs8", format: "pem" });

  await fs.writeFile(feedPath, feedRaw, "utf8");
  const feedSignature = `${signPayload(feedRaw, signingPrivatePem)}\n`;
  await fs.writeFile(feedSigPath, feedSignature, "utf8");

  const sha256 = (value) => crypto.createHash("sha256").update(value, "utf8").digest("hex");
  const checksumsRaw = JSON.stringify(
    {
      files: {
        [path.basename(feedPath)]: sha256(feedRaw),
        [path.basename(feedSigPath)]: sha256(feedSignature),
      },
    },
    null,
    2,
  );
  await fs.writeFile(checksumsPath, `${checksumsRaw}\n`, "utf8");
  await fs.writeFile(checksumsSigPath, `${signPayload(`${checksumsRaw}\n`, signingPrivatePem)}\n`, "utf8");

  await fs.writeFile(publicKeyPath, publicKeyPem, "utf8");

  return { feedPath, feedSigPath, checksumsPath, checksumsSigPath, publicKeyPath };
}

function hermesEnv(base) {
  return {
    HERMES_HOME: path.join(base, ".hermes"),
    HERMES_ADVISORY_FEED_SOURCE: "local",
  };
}

function localFeedEnv({ feedPath, feedSigPath, checksumsPath, checksumsSigPath, publicKeyPath }) {
  return {
    HERMES_LOCAL_ADVISORY_FEED: feedPath,
    HERMES_LOCAL_ADVISORY_FEED_SIG: feedSigPath,
    HERMES_LOCAL_ADVISORY_FEED_CHECKSUMS: checksumsPath,
    HERMES_LOCAL_ADVISORY_FEED_CHECKSUMS_SIG: checksumsSigPath,
    HERMES_ADVISORY_FEED_PUBLIC_KEY: publicKeyPath,
  };
}

await withTempDir(async (tempDir) => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const artifacts = await writeFeedArtifacts({
    dir: tempDir,
    keyPair: keys,
    advisories: [
      {
        id: "ADV-CONSERVATIVE",
        severity: "high",
        affected: ["demo-skill@>=1.2.3"],
      },
    ],
  });

  const result = runNode(["--skill", "demo-skill"], {
    ...hermesEnv(tempDir),
    ...localFeedEnv(artifacts),
  });

  assert.equal(result.status, 42, `conservative name-only match should gate with 42: ${result.stderr}`);
  assert.ok(result.stdout.includes("No --version provided; applying conservative name-based advisory gate."), result.stdout);
  assert.ok(result.stdout.includes("ADV-CONSERVATIVE"), result.stdout);
});

await withTempDir(async (tempDir) => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const artifacts = await writeFeedArtifacts({
    dir: tempDir,
    keyPair: keys,
    advisories: [
      {
        id: "ADV-VERSION-MATCH",
        severity: "critical",
        affected: ["versioned-skill@>=2.0.0"],
      },
    ],
  });

  const result = runNode(["--skill", "versioned-skill", "--version", "2.1.0"], {
    ...hermesEnv(tempDir),
    ...localFeedEnv(artifacts),
  });

  assert.equal(result.status, 42, `explicit version match should gate with 42: ${result.stderr}`);
  assert.ok(result.stdout.includes("ADV-VERSION-MATCH"), result.stdout);
});

await withTempDir(async (tempDir) => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const artifacts = await writeFeedArtifacts({
    dir: tempDir,
    keyPair: keys,
    advisories: [
      {
        id: "ADV-NONMATCH",
        severity: "medium",
        affected: ["different-skill@>=1.0.0"],
      },
    ],
  });

  const result = runNode(["--skill", "safe-skill", "--version", "1.0.0"], {
    ...hermesEnv(tempDir),
    ...localFeedEnv(artifacts),
  });

  assert.equal(result.status, 0, `non-matching skill should pass: ${result.stderr}`);
  assert.ok(result.stdout.includes("No advisory matches found for candidate."), result.stdout);
});

await withTempDir(async (tempDir) => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const artifacts = await writeFeedArtifacts({
    dir: tempDir,
    keyPair: keys,
    advisories: [
      {
        id: "ADV-MALFORMED-AFFECTED",
        severity: "high",
        affected: ["missing-at-specifier"],
      },
    ],
  });

  const result = runNode(["--skill", "missing-at-specifier", "--version", "1.0.0"], {
    ...hermesEnv(tempDir),
    ...localFeedEnv(artifacts),
  });

  assert.equal(result.status, 1, `malformed affected entry without '@' must fail closed: ${result.stderr}`);
  assert.ok(result.stderr.includes("CRITICAL: advisory feed verification failed"), result.stderr);
});

await withTempDir(async (tempDir) => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const artifacts = await writeFeedArtifacts({
    dir: tempDir,
    keyPair: keys,
    advisories: [
      {
        id: "ADV-CONFIRM",
        severity: "high",
        affected: ["confirm-me@1.0.0"],
      },
    ],
  });

  const result = runNode(["--skill", "confirm-me", "--version", "1.0.0", "--confirm-advisory"], {
    ...hermesEnv(tempDir),
    ...localFeedEnv(artifacts),
  });

  assert.equal(result.status, 0, `--confirm-advisory should allow proceed: ${result.stderr}`);
  assert.ok(result.stderr.includes("WARNING: proceeding despite 1 advisory match(es)"), result.stderr);
});

await withTempDir(async (tempDir) => {
  const verifierKeys = crypto.generateKeyPairSync("ed25519");
  const signerKeys = crypto.generateKeyPairSync("ed25519");
  const artifacts = await writeFeedArtifacts({
    dir: tempDir,
    keyPair: verifierKeys,
    signatureKeyPair: signerKeys,
    advisories: [
      {
        id: "ADV-BROKEN-SIG",
        severity: "high",
        affected: ["broken-skill@*"],
      },
    ],
  });

  const strictResult = runNode(["--skill", "safe-skill", "--version", "1.0.0"], {
    ...hermesEnv(tempDir),
    ...localFeedEnv(artifacts),
  });

  assert.equal(strictResult.status, 1, "invalid signature must fail closed without unsigned bypass");
  assert.ok(strictResult.stderr.includes("CRITICAL: advisory feed verification failed"), strictResult.stderr);

  const bypassResult = runNode(["--skill", "safe-skill", "--version", "1.0.0", "--allow-unsigned"], {
    ...hermesEnv(tempDir),
    ...localFeedEnv(artifacts),
  });

  assert.equal(bypassResult.status, 0, `unsigned bypass should allow verification path to continue: ${bypassResult.stderr}`);
  assert.ok(bypassResult.stderr.includes("WARNING: unsigned advisory bypass enabled via --allow-unsigned"), bypassResult.stderr);

  const envBypassResult = runNode(["--skill", "safe-skill", "--version", "1.0.0"], {
    ...hermesEnv(tempDir),
    ...localFeedEnv(artifacts),
    HERMES_ADVISORY_ALLOW_UNSIGNED_FEED: "1",
  });

  assert.equal(
    envBypassResult.status,
    0,
    `env-configured unsigned bypass should allow verification path to continue: ${envBypassResult.stderr}`,
  );
  assert.ok(
    envBypassResult.stderr.includes("WARNING: unsigned advisory bypass enabled via resolved env/config policy"),
    envBypassResult.stderr,
  );
});

await withTempDir(async (tempDir) => {
  const invalidArgResult = runNode(["--skill", "demo-skill", "--definitely-invalid-arg"], {
    ...hermesEnv(tempDir),
  });

  assert.equal(invalidArgResult.status, 1, "unknown CLI argument must fail");
  assert.ok(invalidArgResult.stderr.includes("Unknown argument: --definitely-invalid-arg"), invalidArgResult.stderr);
});

await withTempDir(async (tempDir) => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const semverCases = [
    { label: "caret-accept", versionSpec: "^1.2.3", candidateVersion: "1.9.0", expectedStatus: 42 },
    { label: "caret-reject-major-bump", versionSpec: "^1.2.3", candidateVersion: "2.0.0", expectedStatus: 0 },
    { label: "caret-zero-minor-accept", versionSpec: "^0.2.3", candidateVersion: "0.2.99", expectedStatus: 42 },
    { label: "caret-zero-minor-reject", versionSpec: "^0.2.3", candidateVersion: "0.3.0", expectedStatus: 0 },
    { label: "caret-zero-zero-patch-accept", versionSpec: "^0.0.3", candidateVersion: "0.0.3", expectedStatus: 42 },
    { label: "caret-zero-zero-patch-reject", versionSpec: "^0.0.3", candidateVersion: "0.0.99", expectedStatus: 0 },
    { label: "tilde-accept", versionSpec: "~1.2.3", candidateVersion: "1.2.9", expectedStatus: 42 },
    { label: "tilde-reject-minor-bump", versionSpec: "~1.2.3", candidateVersion: "1.3.0", expectedStatus: 0 },
    { label: "wildcard-accept", versionSpec: "1.2.*", candidateVersion: "1.2.99", expectedStatus: 42 },
    { label: "wildcard-reject", versionSpec: "1.2.*", candidateVersion: "1.3.0", expectedStatus: 0 },
    {
      label: "comma-comparator-set-accept",
      versionSpec: ">= 2026.5.14-beta.1, < 2026.5.27",
      candidateVersion: "2026.5.20",
      expectedStatus: 42,
    },
    {
      label: "comma-comparator-set-reject-upper-bound",
      versionSpec: ">= 2026.5.14-beta.1, < 2026.5.27",
      candidateVersion: "2026.5.27",
      expectedStatus: 0,
    },
    {
      label: "space-comparator-set-accept",
      versionSpec: ">= 2026.2.13 <= 2026.3.1",
      candidateVersion: "2026.3.1",
      expectedStatus: 42,
    },
    {
      label: "prerelease-precedence",
      versionSpec: "<1.2.3",
      candidateVersion: "1.2.3-beta.1",
      expectedStatus: 42,
    },
    {
      label: "build-metadata-ignored",
      versionSpec: "=1.2.3+build.2",
      candidateVersion: "1.2.3+build.1",
      expectedStatus: 42,
    },
    { label: "malformed-comparator-fail-closed", versionSpec: ">>1.2.3", candidateVersion: "1.9.0", expectedStatus: 1 },
    {
      label: "partially-parsed-comparator-set-fail-closed",
      versionSpec: ">=1.0.0 garbage <2.0.0",
      candidateVersion: "1.9.0",
      expectedStatus: 1,
    },
    { label: "logical-or-fail-closed", versionSpec: "1.2 || 1.3", candidateVersion: "1.2.5", expectedStatus: 1 },
  ];

  for (const semverCase of semverCases) {
    const artifacts = await writeFeedArtifacts({
      dir: tempDir,
      keyPair: keys,
      advisories: [
        {
          id: `ADV-SEMVER-${semverCase.label.toUpperCase()}`,
          severity: "high",
          affected: [`semver-skill@${semverCase.versionSpec}`],
        },
      ],
    });

    const result = runNode(["--skill", "semver-skill", "--version", semverCase.candidateVersion], {
      ...hermesEnv(tempDir),
      ...localFeedEnv(artifacts),
    });

    assert.equal(
      result.status,
      semverCase.expectedStatus,
      `${semverCase.label} expected status ${semverCase.expectedStatus}, got ${result.status}. stderr=${result.stderr}`,
    );
    if (semverCase.expectedStatus === 1) {
      assert.ok(result.stderr.includes("CRITICAL: advisory feed verification failed"), result.stderr);
    }
  }
});

console.log("guarded_skill_verify.test.mjs: ok");
