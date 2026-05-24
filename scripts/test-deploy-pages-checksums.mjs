import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const workflowPath = new URL("../.github/workflows/deploy-pages.yml", import.meta.url);
const workflow = await readFile(workflowPath, "utf8");

function stepIndex(name) {
  const marker = `- name: ${name}`;
  const index = workflow.indexOf(marker);
  assert.notEqual(index, -1, `missing workflow step: ${name}`);
  return index;
}

const signFeedIndex = stepIndex("Sign advisory feed and verify");
const signGhsaIndex = stepIndex("Sign provisional GHSA feed and verify");
const generateChecksumsIndex = stepIndex("Generate advisory checksums manifest");
const signChecksumsIndex = stepIndex("Sign checksums and verify");

assert.ok(
  signFeedIndex < generateChecksumsIndex,
  "advisory checksums manifest must be generated after feed.json.sig is created",
);
assert.ok(
  signGhsaIndex < generateChecksumsIndex,
  "advisory checksums manifest must be generated after ghsa-without-cve.json.sig is created",
);
assert.ok(
  generateChecksumsIndex < signChecksumsIndex,
  "checksums signature must be generated after checksums.json is refreshed",
);

const generateStepBody = workflow.slice(generateChecksumsIndex, signChecksumsIndex);
assert.match(
  generateStepBody,
  /public\/advisories\/\*\.json\.sig/,
  "advisory checksums manifest must include detached advisory signatures",
);

const mirrorBlockIndex = workflow.indexOf(
  "# Mirror advisories feed + signatures at the path referenced by suite docs/heartbeat",
);
assert.notEqual(mirrorBlockIndex, -1, "missing advisory release mirror block");

const mirrorBlock = workflow.slice(mirrorBlockIndex, workflow.indexOf("if [ -f \"public/checksums.json\"", mirrorBlockIndex));
assert.match(
  mirrorBlock,
  /cp "public\/advisories\/ghsa-without-cve\.json" "\$MIRROR_LATEST_DIR\/ghsa-without-cve\.json"/,
  "GHSA provisional feed must be mirrored at the release-root compatibility path",
);
assert.match(
  mirrorBlock,
  /cp "public\/advisories\/ghsa-without-cve\.json\.sig" "\$MIRROR_LATEST_DIR\/ghsa-without-cve\.json\.sig"/,
  "GHSA provisional feed signature must be mirrored at the release-root compatibility path",
);
