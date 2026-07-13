import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const canonicalFeed = await readFile(new URL("advisories/feed.json", root));
const canonicalSignature = await readFile(new URL("advisories/feed.json.sig", root));

for (const skillName of ["clawsec-feed", "clawsec-suite"]) {
  const mirrorFeed = await readFile(new URL(`skills/${skillName}/advisories/feed.json`, root));
  const mirrorSignature = await readFile(new URL(`skills/${skillName}/advisories/feed.json.sig`, root));

  assert.deepEqual(mirrorFeed, canonicalFeed, `${skillName} feed mirror must match the canonical feed byte-for-byte`);
  assert.deepEqual(
    mirrorSignature,
    canonicalSignature,
    `${skillName} feed signature must match the canonical signature byte-for-byte`,
  );
}

for (const workflowPath of [
  ".github/workflows/poll-nvd-cves.yml",
  ".github/workflows/poll-ghsa-without-cve.yml",
  ".github/workflows/community-advisory.yml",
]) {
  const workflow = await readFile(new URL(workflowPath, root), "utf8");

  assert.match(workflow, /SUITE_FEED_PATH: skills\/clawsec-suite\/advisories\/feed\.json/);
  assert.match(workflow, /SUITE_FEED_SIG_PATH: skills\/clawsec-suite\/advisories\/feed\.json\.sig/);
  assert.ok(
    workflow.includes('cp "$FEED_PATH" "$SUITE_FEED_PATH"'),
    `${workflowPath} must propagate the canonical feed to ClawSec Suite`,
  );
  assert.ok(
    workflow.includes('cp "$FEED_SIG_PATH" "$SUITE_FEED_SIG_PATH"'),
    `${workflowPath} must propagate the canonical signature to ClawSec Suite`,
  );
  assert.ok(
    workflow.split("SUITE_FEED_PATH").length >= 5,
    `${workflowPath} must verify and publish the Suite feed mirror`,
  );
  assert.ok(
    workflow.split("SUITE_FEED_SIG_PATH").length >= 4,
    `${workflowPath} must publish the Suite signature mirror`,
  );
}

const feedUtils = await readFile(new URL("scripts/feed-utils.sh", root), "utf8");
assert.ok(feedUtils.includes("skills/clawsec-suite/advisories/feed.json"));
assert.ok(feedUtils.includes('for target in "$SKILL_FEED_PATH" "$SUITE_FEED_PATH" "$PUBLIC_FEED_PATH"'));

const releaseWorkflow = await readFile(new URL(".github/workflows/skill-release.yml", root), "utf8");
const installDocValidator = await readFile(new URL("scripts/ci/validate_skill_install_docs.mjs", root), "utf8");
for (const mirrorPath of [
  "skills/clawsec-feed/advisories/feed.json",
  "skills/clawsec-feed/advisories/feed.json.sig",
  "skills/clawsec-suite/advisories/feed.json",
  "skills/clawsec-suite/advisories/feed.json.sig",
]) {
  assert.ok(
    releaseWorkflow.includes(`      - '!${mirrorPath}'`),
    `generated mirror-only changes must not trigger a skill release: ${mirrorPath}`,
  );
  assert.ok(
    releaseWorkflow.includes(`':(exclude)${mirrorPath}'`),
    `generated mirror-only changes must not require a version bump: ${mirrorPath}`,
  );
  assert.ok(
    installDocValidator.includes(`":(exclude)${mirrorPath}"`),
    `generated mirror-only changes must not trigger install-doc validation: ${mirrorPath}`,
  );
}

console.log("Advisory mirror propagation PASS");
