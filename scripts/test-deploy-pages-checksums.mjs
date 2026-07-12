import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const workflowPath = new URL("../.github/workflows/deploy-pages.yml", import.meta.url);
const workflow = await readFile(workflowPath, "utf8");
const verifyWorkflowPath = new URL("../.github/workflows/pages-verify.yml", import.meta.url);
const verifyWorkflow = await readFile(verifyWorkflowPath, "utf8");

function stepIndex(source, name) {
  const marker = `- name: ${name}`;
  const index = source.indexOf(marker);
  assert.notEqual(index, -1, `missing workflow step: ${name}`);
  return index;
}

function assertAdvisoryChecksumAliases(source, workflowName) {
  const signChecksumsIndex = stepIndex(source, "Sign checksums and verify");
  const aliasesIndex = stepIndex(source, "Publish advisory checksum aliases");
  const nextStepIndex = source.indexOf("- name:", aliasesIndex + 1);
  const aliasesStep = source.slice(aliasesIndex, nextStepIndex === -1 ? undefined : nextStepIndex);

  assert.ok(
    signChecksumsIndex < aliasesIndex,
    `${workflowName} must publish advisory checksum aliases after checksums.json is signed`,
  );
  assert.match(
    aliasesStep,
    /cp public\/checksums\.json public\/advisories\/checksums\.json/,
    `${workflowName} must publish checksums.json beside the advisory feed`,
  );
  assert.match(
    aliasesStep,
    /cp public\/checksums\.sig public\/advisories\/checksums\.json\.sig/,
    `${workflowName} must publish the checksum signature at the URL derived by advisory clients`,
  );
}

const signFeedIndex = stepIndex(workflow, "Sign advisory feed and verify");
const signGhsaIndex = stepIndex(workflow, "Sign provisional GHSA feed and verify");
const generateChecksumsIndex = stepIndex(workflow, "Generate advisory checksums manifest");
const signChecksumsIndex = stepIndex(workflow, "Sign checksums and verify");

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

assertAdvisoryChecksumAliases(workflow, "Deploy Pages");
assertAdvisoryChecksumAliases(verifyWorkflow, "Pages Verify");

const verifySanityIndex = stepIndex(verifyWorkflow, "Sanity-check generated artifacts");
const verifySanityStep = verifyWorkflow.slice(verifySanityIndex);
assert.match(
  verifySanityStep,
  /test -f dist\/advisories\/checksums\.json/,
  "Pages Verify must require the advisory checksum manifest in the built site",
);
assert.match(
  verifySanityStep,
  /test -f dist\/advisories\/checksums\.json\.sig/,
  "Pages Verify must require the advisory checksum signature in the built site",
);
assert.match(
  verifySanityStep,
  /cmp public\/checksums\.json dist\/advisories\/checksums\.json/,
  "Pages Verify must keep the advisory checksum alias byte-identical to the signed root manifest",
);
assert.match(
  verifySanityStep,
  /cmp public\/checksums\.sig dist\/advisories\/checksums\.json\.sig/,
  "Pages Verify must keep the advisory checksum signature alias byte-identical to the root signature",
);
