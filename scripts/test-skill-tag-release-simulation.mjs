import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const tempRoot = await mkdtemp(path.join(tmpdir(), "clawsec-tag-release-sim-"));
const outputDir = path.join(tempRoot, "out");
const fakeSkillspector = path.join(tempRoot, "skillspector");

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

  const result = spawnSync(
    process.execPath,
    [
      "scripts/ci/simulate_skill_tag_release.mjs",
      "skills/clawsec-suite",
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

  const summary = JSON.parse(await readFile(path.join(outputDir, "simulation-summary.json"), "utf8"));
  assert.equal(summary.skill, "clawsec-suite");
  assert.equal(summary.original_version, "0.1.9");
  assert.equal(summary.simulated_version, "0.1.10-beta.1");
  assert.equal(summary.tag, "clawsec-suite-v0.1.10-beta.1");

  const releaseAssetsDir = path.join(outputDir, "release-assets");
  const checksums = JSON.parse(await readFile(path.join(releaseAssetsDir, "checksums.json"), "utf8"));
  assert.equal(checksums.skill, "clawsec-suite");
  assert.equal(checksums.version, "0.1.10-beta.1");
  assert.equal(checksums.tag, "clawsec-suite-v0.1.10-beta.1");
  assert.equal(checksums.archive.filename, "clawsec-suite-v0.1.10-beta.1.zip");

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

  const archive = await readFile(path.join(releaseAssetsDir, "clawsec-suite-v0.1.10-beta.1.zip"));
  assert.ok(archive.length > 0, "release archive should not be empty");

  const install = await readFile(path.join(releaseAssetsDir, "install.md"), "utf8");
  assert.match(install, /npx skills add prompt-security\/clawsec#pull-request-head --skill clawsec-suite --agent codex --global --yes/);
  assert.match(install, /npx skills update clawsec-suite/);
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}
