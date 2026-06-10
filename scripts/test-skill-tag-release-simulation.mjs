import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const tempRoot = await mkdtemp(path.join(tmpdir(), "clawsec-tag-release-sim-"));
const fakeSkillspector = path.join(tempRoot, "skillspector");

async function runSimulation({ skillDir, outputDir, expectedOriginal, expectedSimulated }) {
  const result = spawnSync(
    process.execPath,
    [
      "scripts/ci/simulate_skill_tag_release.mjs",
      skillDir,
      outputDir,
      "--repository",
      "prompt-security/clawsec",
      "--source-ref",
      "pull-request-head",
      "--skillspector-bin",
      fakeSkillspector,
    ],
    { encoding: "utf8" },
  );

  assert.equal(
    result.status,
    0,
    `tag release simulation failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );

  const skillName = path.basename(skillDir);
  const expectedTag = `${skillName}-v${expectedSimulated}`;
  const summary = JSON.parse(await readFile(path.join(outputDir, "simulation-summary.json"), "utf8"));
  assert.equal(summary.skill, skillName);
  assert.equal(summary.original_version, expectedOriginal);
  assert.equal(summary.simulated_version, expectedSimulated);
  assert.equal(summary.tag, expectedTag);

  const releaseAssetsDir = path.join(outputDir, "release-assets");
  const checksums = JSON.parse(await readFile(path.join(releaseAssetsDir, "checksums.json"), "utf8"));
  assert.equal(checksums.skill, skillName);
  assert.equal(checksums.version, expectedSimulated);
  assert.equal(checksums.tag, expectedTag);
  assert.equal(checksums.archive.filename, `${expectedTag}.zip`);

  for (const artifact of [
    "skill-card.md",
    "permissions.json",
    "install.md",
    "skillspector-report.md",
    "checksums.sig",
    "signing-public.pem",
  ]) {
    assert.ok(
      checksums.files[artifact] || artifact.endsWith(".sig") || artifact === "signing-public.pem",
      `expected ${artifact} to be represented in the release output`,
    );
    const file = await readFile(path.join(releaseAssetsDir, artifact));
    assert.ok(file.length > 0, `${artifact} should not be empty`);
  }

  const archive = await readFile(path.join(releaseAssetsDir, `${expectedTag}.zip`));
  assert.ok(archive.length > 0, "release archive should not be empty");

  const install = await readFile(path.join(releaseAssetsDir, "install.md"), "utf8");
  assert.match(
    install,
    new RegExp(`npx skills add prompt-security/clawsec#pull-request-head --skill ${skillName} --agent codex --global --yes`),
  );
  assert.match(install, new RegExp(`npx skills update ${skillName}`));
}

try {
  await writeFile(
    fakeSkillspector,
    `#!/usr/bin/env node
import { writeFileSync } from "node:fs";

const outputIndex = process.argv.indexOf("--output");
if (outputIndex === -1 || !process.argv[outputIndex + 1]) {
  console.error("missing --output");
  process.exit(2);
}

writeFileSync(process.argv[outputIndex + 1], "# Fake SkillSpector Report\\n\\nNo live scan executed in unit test.\\n");
`,
    { mode: 0o700 },
  );
  await chmod(fakeSkillspector, 0o700);

  await runSimulation({
    skillDir: "skills/clawsec-suite",
    outputDir: path.join(tempRoot, "stable"),
    expectedOriginal: "0.1.9",
    expectedSimulated: "0.1.10",
  });

  await runSimulation({
    skillDir: "skills/hermes-traffic-guardian",
    outputDir: path.join(tempRoot, "beta"),
    expectedOriginal: "0.0.1-beta2",
    expectedSimulated: "0.0.1-beta3",
  });
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}
