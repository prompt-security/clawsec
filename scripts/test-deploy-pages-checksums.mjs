import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ADVISORY_PUBLIC_CONTRACT,
  RELEASE_MIRROR_MAPPINGS,
  generateAdvisoryChecksums,
  publishAdvisoryAliases,
  publishReleaseCompatibilityMirror,
  retryLiveAdvisoryEndpointVerification,
  smokeTestBuiltAdvisoryEndpoints,
  verifyBuiltAdvisoryArtifacts,
  verifyLiveAdvisoryEndpoints,
} from "./ci/advisory_pages_artifacts.mjs";

const workflow = await fs.readFile(new URL("../.github/workflows/deploy-pages.yml", import.meta.url), "utf8");
const verifyWorkflow = await fs.readFile(new URL("../.github/workflows/pages-verify.yml", import.meta.url), "utf8");

function stepIndex(source, name) {
  const marker = `- name: ${name}`;
  const index = source.indexOf(marker);
  assert.notEqual(index, -1, `missing workflow step: ${name}`);
  return index;
}

function stepBody(source, name) {
  const start = stepIndex(source, name);
  const end = source.indexOf("- name:", start + 1);
  return source.slice(start, end === -1 ? undefined : end);
}

function assertProductionOrdering(source, workflowName) {
  const setupNodeIndex = stepIndex(source, "Setup Node.js");
  const signFeedIndex = stepIndex(source, "Sign advisory feed and verify");
  const signGhsaIndex = stepIndex(source, "Sign provisional GHSA feed and verify");
  const generateChecksumsIndex = stepIndex(source, "Generate advisory checksums manifest");
  const signChecksumsIndex = stepIndex(source, "Sign checksums and verify");
  const aliasesIndex = stepIndex(source, "Publish advisory compatibility aliases");
  const buildIndex = stepIndex(source, workflowName === "Deploy Pages" ? "Build" : "Build site");
  const smokeIndex = stepIndex(source, "Smoke-test built advisory endpoints");

  assert.ok(setupNodeIndex < generateChecksumsIndex, `${workflowName} must pin Node before running the artifact helper`);
  assert.ok(signFeedIndex < generateChecksumsIndex, `${workflowName} must checksum feed.json.sig`);
  assert.ok(signGhsaIndex < generateChecksumsIndex, `${workflowName} must checksum the provisional feed signature`);
  assert.ok(generateChecksumsIndex < signChecksumsIndex, `${workflowName} must sign the refreshed checksum manifest`);
  assert.ok(signChecksumsIndex < aliasesIndex, `${workflowName} must publish aliases only after signing checksums.json`);
  assert.ok(aliasesIndex < buildIndex, `${workflowName} must publish aliases before Vite copies public assets`);
  assert.ok(buildIndex < smokeIndex, `${workflowName} must smoke-test endpoints after the Vite build`);

  assert.match(
    stepBody(source, "Generate advisory checksums manifest"),
    /node scripts\/ci\/advisory_pages_artifacts\.mjs generate/,
    `${workflowName} must use the shared checksum generator`,
  );
  assert.match(
    stepBody(source, "Publish advisory compatibility aliases"),
    /node scripts\/ci\/advisory_pages_artifacts\.mjs publish-aliases/,
    `${workflowName} must use the shared alias publisher`,
  );
  assert.match(
    stepBody(source, "Smoke-test built advisory endpoints"),
    /node scripts\/ci\/advisory_pages_artifacts\.mjs smoke-http/,
    `${workflowName} must exercise the built endpoints over HTTP`,
  );
}

assertProductionOrdering(workflow, "Deploy Pages");
assertProductionOrdering(verifyWorkflow, "Pages Verify");

assert.doesNotMatch(
  workflow,
  /cp -r public\/(?:skills|advisories) dist\//,
  "Vite already copies public directories into dist",
);
assert.doesNotMatch(
  workflow,
  /cp public\/(?:checksums\.(?:json|sig)|signing-public\.pem) dist\//,
  "Vite already copies root public artifacts into dist",
);
assert.match(
  stepBody(workflow, "Verify built public artifacts"),
  /advisory_pages_artifacts\.mjs verify-built/,
  "Deploy Pages must verify Vite copied the advisory artifacts",
);
assert.match(
  stepBody(verifyWorkflow, "Sanity-check generated artifacts"),
  /advisory_pages_artifacts\.mjs verify-built/,
  "Pages Verify must validate the same built advisory artifacts as production",
);

const productionMirrorStep = stepBody(workflow, "Get latest clawsec-suite release URL");
assert.match(
  productionMirrorStep,
  /advisory_pages_artifacts\.mjs publish-release-mirror/,
  "Deploy Pages must use the tested release compatibility mirror",
);
assert.doesNotMatch(
  productionMirrorStep,
  /cp "public\/(?:advisories|checksums|signing-public)/,
  "release compatibility files must not be maintained as duplicate workflow copy lists",
);
assert.match(
  stepBody(verifyWorkflow, "Simulate release compatibility mirror"),
  /advisory_pages_artifacts\.mjs publish-release-mirror/,
  "Pages Verify must simulate the production release compatibility mirror",
);
assert.match(
  stepBody(workflow, "Verify deployed advisory endpoints"),
  /advisory_pages_artifacts\.mjs verify-url/,
  "Deploy Pages must verify the real custom-domain endpoints after deployment",
);
assert.match(
  stepBody(workflow, "Verify deployed advisory endpoints"),
  /--base-url https:\/\/clawsec\.prompt\.security/,
  "post-deploy verification must target the production custom domain",
);
assert.match(
  stepBody(workflow, "Verify deployed advisory endpoints"),
  /--retry-backoff-factor 1\.5/,
  "post-deploy verification must use exponential backoff for GitHub Pages propagation",
);
assert.match(
  stepBody(workflow, "Verify deployed advisory endpoints"),
  /--max-retry-delay-ms 60000/,
  "post-deploy verification must cap retry backoff waits",
);

async function collectContractSources(entryPath) {
  const stat = await fs.stat(entryPath);
  if (stat.isFile()) return [entryPath];
  const files = [];
  for (const entry of await fs.readdir(entryPath, { withFileTypes: true })) {
    if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
    const childPath = path.join(entryPath, entry.name);
    if (entry.isDirectory()) {
      files.push(...await collectContractSources(childPath));
    } else if (/\.(?:json|md|mjs|sh|ts)$/.test(entry.name) && !/^(?:feed|ghsa-without-cve)\.json$/.test(entry.name)) {
      files.push(childPath);
    }
  }
  return files;
}

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const contractSources = [];
for (const relativePath of ["README.md", "wiki", "skills"]) {
  contractSources.push(...await collectContractSources(path.join(repositoryRoot, relativePath)));
}
const referencedAdvisoryArtifacts = new Set();
const advisoryArtifactPattern = /advisories\/(?:feed\.json(?:\.sig)?|checksums\.json(?:\.sig)?|feed-signing-public\.pem)/g;
for (const sourcePath of contractSources) {
  const source = await fs.readFile(sourcePath, "utf8");
  for (const match of source.matchAll(advisoryArtifactPattern)) referencedAdvisoryArtifacts.add(match[0]);
}
const documentedAdvisoryContract = ADVISORY_PUBLIC_CONTRACT.filter((artifact) => artifact.startsWith("advisories/"));
for (const artifact of referencedAdvisoryArtifacts) {
  assert.ok(documentedAdvisoryContract.includes(artifact), `skill or instruction expects unpublished artifact: ${artifact}`);
}
for (const artifact of documentedAdvisoryContract) {
  assert.ok(referencedAdvisoryArtifacts.has(artifact), `published advisory artifact has no skill or instruction consumer: ${artifact}`);
}
assert.deepEqual(
  [...new Set(RELEASE_MIRROR_MAPPINGS.map(([, destination]) => destination))].sort(),
  [
    "advisories/feed.json",
    "advisories/feed.json.sig",
    "checksums.json",
    "checksums.sig",
    "feed.json",
    "feed.json.sig",
    "signing-public.pem",
  ],
  "release compatibility mirror must preserve the documented root and nested artifacts",
);

function createVerificationAttempt({ failuresBeforeSuccess, error = new Error("temporary endpoint mismatch") }) {
  let attempts = 0;
  return {
    attempts() {
      return attempts;
    },
    async verifyAttempt() {
      attempts += 1;
      if (attempts <= failuresBeforeSuccess) throw error;
    },
  };
}

async function startArtifactFixtureServer(rootDir) {
  const root = path.resolve(rootDir);
  const server = http.createServer((request, response) => {
    void (async () => {
      const pathname = decodeURIComponent(new URL(request.url || "/", "http://127.0.0.1").pathname);
      const filePath = path.resolve(root, pathname.replace(/^\/+/, ""));
      if (filePath !== root && !filePath.startsWith(`${root}${path.sep}`)) {
        response.writeHead(400).end("invalid path");
        return;
      }
      const content = await fs.readFile(filePath);
      response
        .writeHead(200, { "content-type": filePath.endsWith(".json") ? "application/json" : "text/plain" })
        .end(content);
    })().catch((error) => {
      response.writeHead(error?.code === "ENOENT" ? 404 : 500).end(error?.message || String(error));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("failed to start artifact fixture server");
  return {
    origin: `http://127.0.0.1:${address.port}`,
    async stop() {
      await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    },
  };
}

for (const [label, options, expectedMessage] of [
  ["NaN attempts", { attempts: Number.NaN }, /attempts must be a finite positive integer/],
  ["fractional attempts", { attempts: 1.5 }, /attempts must be a finite positive integer/],
  ["zero attempts", { attempts: 0 }, /attempts must be a finite positive integer/],
  ["negative retry delay", { retryDelayMs: -1 }, /retryDelayMs must be a finite non-negative number/],
  [
    "infinite retry delay",
    { retryDelayMs: Number.POSITIVE_INFINITY },
    /retryDelayMs must be a finite non-negative number/,
  ],
  [
    "shrinking retry factor",
    { retryBackoffFactor: 0.5 },
    /retryBackoffFactor must be a finite number greater than or equal to 1/,
  ],
  [
    "infinite retry factor",
    { retryBackoffFactor: Number.POSITIVE_INFINITY },
    /retryBackoffFactor must be a finite number greater than or equal to 1/,
  ],
  ["negative retry cap", { maxRetryDelayMs: -1 }, /maxRetryDelayMs must be a finite non-negative number/],
  ["NaN retry cap", { maxRetryDelayMs: Number.NaN }, /maxRetryDelayMs must be a finite non-negative number/],
]) {
  let verificationAttempts = 0;
  let sleepCalls = 0;
  await assert.rejects(
    retryLiveAdvisoryEndpointVerification({
      baseUrl: "https://example.test",
      verifyAttempt: async () => {
        verificationAttempts += 1;
      },
      sleep: async () => {
        sleepCalls += 1;
      },
      writeStderr: () => {},
      ...options,
    }),
    expectedMessage,
    `${label} must be rejected before verification starts`,
  );
  assert.equal(verificationAttempts, 0, `${label} must not run a verification attempt`);
  assert.equal(sleepCalls, 0, `${label} must not schedule a retry timer`);
}

{
  const verification = createVerificationAttempt({ failuresBeforeSuccess: 4 });
  const delays = [];
  const logs = [];
  await retryLiveAdvisoryEndpointVerification({
    baseUrl: "https://example.test",
    verifyAttempt: verification.verifyAttempt,
    attempts: 5,
    retryDelayMs: 1000,
    retryBackoffFactor: 2,
    maxRetryDelayMs: 5000,
    sleep: async (delayMs) => {
      delays.push(delayMs);
    },
    writeStderr: (message) => {
      logs.push(message);
    },
  });
  assert.equal(verification.attempts(), 5, "temporary production verification failures must be retried");
  assert.deepEqual(delays, [1000, 2000, 4000, 5000], "post-deploy retries must use capped exponential backoff");
  assert.match(logs.join(""), /waiting 1000ms before retry/, "retry logs must include the first backoff wait");
  assert.match(logs.join(""), /waiting 2000ms before retry/, "retry logs must include the second backoff wait");
  assert.match(logs.join(""), /waiting 5000ms before retry/, "retry logs must include the capped backoff wait");
}

{
  const mismatchError = new Error(
    "HTTP checksum alias mismatch: /checksums.json and /advisories/checksums.json served different content; " +
      "this usually means GitHub Pages or CDN propagation is serving mixed deploy artifacts",
  );
  const verification = createVerificationAttempt({ failuresBeforeSuccess: 3, error: mismatchError });
  const delays = [];
  await assert.rejects(
    retryLiveAdvisoryEndpointVerification({
      baseUrl: "https://example.test",
      verifyAttempt: verification.verifyAttempt,
      attempts: 3,
      retryDelayMs: 1000,
      retryBackoffFactor: 2,
      maxRetryDelayMs: 5000,
      sleep: async (delayMs) => {
        delays.push(delayMs);
      },
      writeStderr: () => {},
    }),
    (error) => {
      assert.match(error.message, /Production advisory endpoint verification failed after 3 attempts/);
      assert.match(error.message, /\/checksums\.json/);
      assert.match(error.message, /\/advisories\/checksums\.json/);
      assert.match(error.message, /GitHub Pages or CDN propagation/);
      assert.equal(error.cause, mismatchError);
      return true;
    },
    "persistent production verification failures must keep the actionable propagation message",
  );
  assert.equal(verification.attempts(), 3, "persistent production verification failures must use all attempts");
  assert.deepEqual(delays, [1000, 2000], "failed post-deploy retries must preserve exponential backoff");
}

{
  const sensitiveBaseUrl = "https://ci-user:ci-password@example.test/private/path?token=secret#fragment"; // trufflehog:ignore -- synthetic fixture; example.test is RFC 6761 reserved and cannot resolve
  await assert.rejects(
    retryLiveAdvisoryEndpointVerification({
      baseUrl: sensitiveBaseUrl,
      verifyAttempt: async () => {
        throw new Error("persistent endpoint mismatch");
      },
      attempts: 1,
      writeStderr: () => {},
    }),
    (error) => {
      assert.match(error.message, /for https:\/\/example\.test\./);
      assert.doesNotMatch(error.message, /ci-user|ci-password|private\/path|token=secret|fragment/);
      return true;
    },
    "production verification diagnostics must not expose URL credentials or request details",
  );
}

{
  const invalidBaseUrl = "not-a-url?token=secret#fragment";
  await assert.rejects(
    verifyLiveAdvisoryEndpoints({
      baseUrl: invalidBaseUrl,
      attempts: 1,
      writeStderr: () => {},
    }),
    (error) => {
      assert.match(error.message, /baseUrl must be a valid HTTP\(S\) URL/);
      assert.doesNotMatch(error.message, /token=secret|fragment/);
      return true;
    },
    "live verification must reject invalid base URLs without exposing their contents",
  );
}

{
  const pathPrefixedBaseUrl = "http://127.0.0.1:1/project-prefix?token=secret#fragment";
  await assert.rejects(
    verifyLiveAdvisoryEndpoints({
      baseUrl: pathPrefixedBaseUrl,
      attempts: 1,
      retryDelayMs: 0,
      writeStderr: () => {},
    }),
    (error) => {
      assert.match(error.message, /baseUrl must not include a path/);
      assert.doesNotMatch(error.message, /project-prefix|token=secret|fragment/);
      return true;
    },
    "live verification must reject unsupported path-prefixed base URLs without exposing their contents",
  );
}

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "clawsec-pages-checksums-"));
try {
  const publicDir = path.join(tempRoot, "public");
  const advisoryDir = path.join(publicDir, "advisories");
  const distDir = path.join(tempRoot, "dist");
  await fs.mkdir(advisoryDir, { recursive: true });

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const sign = (content) => `${crypto.sign(null, Buffer.from(content), privateKey).toString("base64")}\n`;
  const feedRaw = "{\"advisories\":[]}\n";
  const ghsaRaw = "{\"advisories\":[]}\n";
  const artifacts = {
    "feed.json": feedRaw,
    "feed.json.sig": sign(feedRaw),
    "ghsa-without-cve.json": ghsaRaw,
    "ghsa-without-cve.json.sig": sign(ghsaRaw),
  };
  await Promise.all(
    Object.entries(artifacts).map(([name, content]) => fs.writeFile(path.join(advisoryDir, name), content)),
  );
  await fs.writeFile(path.join(advisoryDir, "checksums.json"), "stale alias must not checksum itself\n");
  await fs.writeFile(path.join(advisoryDir, "checksums.json.sig"), "stale signature alias\n");

  const { manifest } = await generateAdvisoryChecksums({
    publicDir,
    repository: "prompt-security/clawsec-test",
    generatedAt: "2026-07-12T00:00:00Z",
  });
  assert.equal(manifest.repository, "prompt-security/clawsec-test");
  assert.deepEqual(Object.keys(manifest.files), [
    "advisories/feed.json",
    "advisories/feed.json.sig",
    "advisories/ghsa-without-cve.json",
    "advisories/ghsa-without-cve.json.sig",
  ]);
  for (const [name, content] of Object.entries(artifacts)) {
    const entry = manifest.files[`advisories/${name}`];
    assert.equal(entry.sha256, crypto.createHash("sha256").update(content).digest("hex"));
    assert.equal(entry.size, Buffer.byteLength(content));
  }

  const checksumsRaw = await fs.readFile(path.join(publicDir, "checksums.json"));
  await fs.writeFile(path.join(publicDir, "checksums.sig"), sign(checksumsRaw));
  await fs.writeFile(path.join(publicDir, "signing-public.pem"), publicKey.export({ type: "spki", format: "pem" }));
  await publishAdvisoryAliases({ publicDir });

  const distWithoutReleaseMirror = path.join(tempRoot, "dist-without-release-mirror");
  await fs.cp(publicDir, distWithoutReleaseMirror, { recursive: true });
  await smokeTestBuiltAdvisoryEndpoints({ distDir: distWithoutReleaseMirror });

  await publishReleaseCompatibilityMirror({ publicDir });
  await fs.cp(publicDir, distDir, { recursive: true });
  await verifyBuiltAdvisoryArtifacts({ publicDir, distDir });
  await smokeTestBuiltAdvisoryEndpoints({ distDir });

  const fixture = await startArtifactFixtureServer(distDir);
  try {
    const observedRequests = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      observedRequests.push(new URL(String(input)));
      return originalFetch(input, init);
    };
    try {
      const sensitiveBaseUrl =
        fixture.origin.replace("://", "://ci-user:ci-password@") + "/?token=secret#fragment"; // trufflehog:ignore -- synthetic fixture
      await verifyLiveAdvisoryEndpoints({
        baseUrl: sensitiveBaseUrl,
        attempts: 1,
        retryDelayMs: 0,
        includeGhsa: true,
        writeStderr: () => {},
      });
    } finally {
      globalThis.fetch = originalFetch;
    }

    const requestedPaths = observedRequests.map((requestUrl) => requestUrl.pathname);
    assert.ok(
      requestedPaths.includes("/releases/latest/download/checksums.json"),
      "full live verification must probe the normalized release-mirror path",
    );
    assert.ok(requestedPaths.includes("/checksums.json"), "full live verification must request the root manifest");
    assert.ok(
      requestedPaths.includes("/advisories/checksums.json"),
      "full live verification must request the checksum alias",
    );
    for (const requestUrl of observedRequests) {
      assert.equal(requestUrl.origin, fixture.origin, "normalization must preserve the intended HTTP origin");
      assert.equal(requestUrl.username, "", "normalized requests must not include a username");
      assert.equal(requestUrl.password, "", "normalized requests must not include a password");
      assert.equal(requestUrl.search, "", "normalized requests must not include a query string");
      assert.equal(requestUrl.hash, "", "normalized requests must not include a fragment");
    }

    let mirrorChecksumRequests = 0;
    let rootChecksumRequests = 0;
    const retryLogs = [];
    globalThis.fetch = async (input, init) => {
      const requestUrl = new URL(String(input));
      if (requestUrl.pathname === "/releases/latest/download/checksums.json") {
        mirrorChecksumRequests += 1;
        if (mirrorChecksumRequests === 2) return new globalThis.Response("missing\n", { status: 404 });
      }
      if (requestUrl.pathname === "/checksums.json") {
        rootChecksumRequests += 1;
        if (rootChecksumRequests === 1) {
          return new globalThis.Response("temporarily unavailable\n", { status: 503 });
        }
      }
      return originalFetch(input, init);
    };
    try {
      await verifyLiveAdvisoryEndpoints({
        baseUrl: fixture.origin,
        attempts: 3,
        retryDelayMs: 0,
        retryBackoffFactor: 1,
        maxRetryDelayMs: 0,
        includeGhsa: true,
        sleep: async () => {},
        writeStderr: (message) => {
          retryLogs.push(message);
        },
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
    assert.equal(mirrorChecksumRequests, 4, "mirror verification must remain required after a transient 404");
    assert.match(
      retryLogs.join(""),
      /release compatibility mirror returned HTTP 404 after it was previously available/,
      "mirror propagation failures must explain why verification is still required",
    );
  } finally {
    await fixture.stop();
  }

  await fs.writeFile(path.join(distDir, "advisories/checksums.json"), "tampered\n");
  await assert.rejects(
    verifyBuiltAdvisoryArtifacts({ publicDir, distDir }),
    /files differ/,
    "built verification must reject a changed advisory checksum alias",
  );
} finally {
  await fs.rm(tempRoot, { recursive: true, force: true });
}
