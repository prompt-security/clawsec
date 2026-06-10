import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const outputDir = await mkdtemp(path.join(tmpdir(), "clawsec-trust-packet-"));

try {
  const result = spawnSync(
    process.execPath,
    [
      "scripts/ci/generate_skill_release_trust_packet.mjs",
      "skills/clawsec-suite",
      outputDir,
      "--repository",
      "prompt-security/clawsec",
      "--tag",
      "clawsec-suite-v0.1.9",
      "--source-ref",
      "main",
    ],
    { encoding: "utf8" },
  );

  assert.equal(
    result.status,
    0,
    `trust packet generator failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );

  const skillCard = await readFile(path.join(outputDir, "skill-card.md"), "utf8");
  const permissions = JSON.parse(await readFile(path.join(outputDir, "permissions.json"), "utf8"));
  const install = await readFile(path.join(outputDir, "install.md"), "utf8");

  assert.match(skillCard, /^# Skill Card/m);
  assert.match(skillCard, /## License\/Terms of Use/);
  assert.match(skillCard, /AGPL-3\.0-or-later/);
  assert.match(skillCard, /skillspector-report\.md/);
  assert.match(skillCard, /clawsec-suite-v0\.1\.9/);

  assert.equal(permissions.skill, "clawsec-suite");
  assert.equal(permissions.version, "0.1.9");
  assert.equal(permissions.platform, "openclaw");
  assert.deepEqual(
    permissions.required_binaries,
    ["node", "npx", "openclaw", "curl", "jq", "shasum", "openssl", "unzip"],
  );
  assert.match(permissions.network_egress, /signed advisory feed/);
  assert.match(permissions.persistence, /OpenClaw advisory hook/);
  assert.ok(Array.isArray(permissions.operator_review));
  assert.ok(permissions.operator_review.length > 0);

  assert.match(install, /npx skills add prompt-security\/clawsec --skill clawsec-suite --agent codex --global --yes/);
  assert.match(install, /npx skills update clawsec-suite/);
  assert.match(install, /npx skills add prompt-security\/clawsec --skill clawsec-suite --agent openclaw --global --yes/);
} finally {
  await rm(outputDir, { recursive: true, force: true });
}
