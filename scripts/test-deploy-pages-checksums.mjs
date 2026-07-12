import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  generateAdvisoryChecksums,
  publishAdvisoryAliases,
  verifyBuiltAdvisoryArtifacts,
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

  assert.ok(setupNodeIndex < generateChecksumsIndex, `${workflowName} must pin Node before running the artifact helper`);
  assert.ok(signFeedIndex < generateChecksumsIndex, `${workflowName} must checksum feed.json.sig`);
  assert.ok(signGhsaIndex < generateChecksumsIndex, `${workflowName} must checksum the provisional feed signature`);
  assert.ok(generateChecksumsIndex < signChecksumsIndex, `${workflowName} must sign the refreshed checksum manifest`);
  assert.ok(signChecksumsIndex < aliasesIndex, `${workflowName} must publish aliases only after signing checksums.json`);
  assert.ok(aliasesIndex < buildIndex, `${workflowName} must publish aliases before Vite copies public assets`);

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

const mirrorBlockIndex = workflow.indexOf(
  "# Mirror advisories feed + signatures at the path referenced by suite docs/heartbeat",
);
assert.notEqual(mirrorBlockIndex, -1, "missing advisory release mirror block");
const mirrorBlock = workflow.slice(mirrorBlockIndex, workflow.indexOf("if [ -f \"public/checksums.json\"", mirrorBlockIndex));
assert.match(
  mirrorBlock,
  /cp "public\/advisories\/ghsa-without-cve\.json" "\$MIRROR_LATEST_DIR\/ghsa-without-cve\.json"/,
  "GHSA provisional feed must remain at the release-root compatibility path",
);
assert.match(
  mirrorBlock,
  /cp "public\/advisories\/ghsa-without-cve\.json\.sig" "\$MIRROR_LATEST_DIR\/ghsa-without-cve\.json\.sig"/,
  "GHSA provisional signature must remain at the release-root compatibility path",
);

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "clawsec-pages-checksums-"));
try {
  const publicDir = path.join(tempRoot, "public");
  const advisoryDir = path.join(publicDir, "advisories");
  const distDir = path.join(tempRoot, "dist");
  await fs.mkdir(advisoryDir, { recursive: true });

  const artifacts = {
    "feed.json": "{\"advisories\":[]}\n",
    "feed.json.sig": "feed-signature\n",
    "ghsa-without-cve.json": "{\"advisories\":[]}\n",
    "ghsa-without-cve.json.sig": "ghsa-signature\n",
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

  await fs.writeFile(path.join(publicDir, "checksums.sig"), "checksums-signature\n");
  await fs.writeFile(path.join(publicDir, "signing-public.pem"), "public-key\n");
  await publishAdvisoryAliases({ publicDir });
  await fs.cp(publicDir, distDir, { recursive: true });
  await verifyBuiltAdvisoryArtifacts({ publicDir, distDir });

  await fs.writeFile(path.join(distDir, "advisories/checksums.json"), "tampered\n");
  await assert.rejects(
    verifyBuiltAdvisoryArtifacts({ publicDir, distDir }),
    /files differ/,
    "built verification must reject a changed advisory checksum alias",
  );
} finally {
  await fs.rm(tempRoot, { recursive: true, force: true });
}
