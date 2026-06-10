import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const outputDir = await mkdtemp(path.join(tmpdir(), "clawsec-trust-packet-"));

function runTrustPacket(skillDir, targetDir, tag) {
  return spawnSync(
    process.execPath,
    [
      "scripts/ci/generate_skill_release_trust_packet.mjs",
      skillDir,
      targetDir,
      "--repository",
      "prompt-security/clawsec",
      "--tag",
      tag,
      "--source-ref",
      "main",
    ],
    { encoding: "utf8" },
  );
}

try {
  const result = runTrustPacket("skills/clawsec-suite", outputDir, "clawsec-suite-v0.1.10");

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
  assert.match(skillCard, /clawsec-suite-v0\.1\.10/);

  assert.equal(permissions.skill, "clawsec-suite");
  assert.equal(permissions.version, "0.1.10");
  assert.equal(permissions.platform, "openclaw");
  assert.deepEqual(
    permissions.required_binaries,
    ["node", "npx", "openclaw", "curl", "jq", "shasum", "openssl", "unzip"],
  );
  assert.match(permissions.network_egress, /signed advisory feed/);
  assert.match(permissions.persistence, /OpenClaw advisory hook/);
  assert.ok(Array.isArray(permissions.operator_review));
  assert.ok(permissions.operator_review.length > 0);

  assert.match(install, /npx skills add prompt-security\/clawsec --skill clawsec-suite --agent openclaw --global --yes/);
  assert.match(install, /npx skills update clawsec-suite/);

  const hermesOutputDir = path.join(outputDir, "hermes");
  const hermesResult = runTrustPacket(
    "skills/hermes-attestation-guardian",
    hermesOutputDir,
    "hermes-attestation-guardian-v0.1.4",
  );
  assert.equal(
    hermesResult.status,
    0,
    `Hermes trust packet generator failed\nstdout:\n${hermesResult.stdout}\nstderr:\n${hermesResult.stderr}`,
  );
  const hermesInstall = await readFile(path.join(hermesOutputDir, "install.md"), "utf8");
  assert.match(
    hermesInstall,
    /npx skills add prompt-security\/clawsec --skill hermes-attestation-guardian --agent hermes-agent --global --yes/,
  );
} finally {
  await rm(outputDir, { recursive: true, force: true });
}
