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
      tag,
    ],
    { encoding: "utf8" },
  );
}

try {
  const result = runTrustPacket("skills/clawsec-suite", outputDir, "clawsec-suite-v0.1.16");

  assert.equal(
    result.status,
    0,
    `trust packet generator failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );

  const skillCard = await readFile(path.join(outputDir, "skill-card.md"), "utf8");
  const permissions = JSON.parse(await readFile(path.join(outputDir, "permissions.json"), "utf8"));
  const install = await readFile(path.join(outputDir, "install.md"), "utf8");
  const releaseVerifier = await readFile(path.join(outputDir, "verify_skill_release_bundle.py"), "utf8");

  assert.match(skillCard, /^# Skill Card/m);
  assert.match(skillCard, /## License\/Terms of Use/);
  assert.match(skillCard, /AGPL-3\.0-or-later/);
  assert.match(skillCard, /skillspector-report\.md/);
  assert.match(skillCard, /clawsec-suite-v0\.1\.16/);

  assert.equal(permissions.skill, "clawsec-suite");
  assert.equal(permissions.version, "0.1.16");
  assert.equal(permissions.platform, "openclaw");
  assert.deepEqual(
    permissions.required_binaries,
    ["node", "npx", "openclaw", "curl", "jq", "shasum", "openssl", "unzip"],
  );
  assert.match(permissions.network_egress, /signed advisory feed/);
  assert.match(permissions.persistence, /OpenClaw advisory hook/);
  assert.ok(Array.isArray(permissions.operator_review));
  assert.ok(permissions.operator_review.length > 0);
  assert.match(releaseVerifier, /safe|archive/i);

  assert.match(install, /EXPECTED_KEY_SHA256="711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8"/);
  assert.match(install, /BASE_URL="https:\/\/github\.com\/prompt-security\/clawsec\/releases\/download\/clawsec-suite-v0\.1\.16"/);
  assert.match(install, /ARCHIVE="clawsec-suite-v0\.1\.16\.zip"/);
  assert.match(install, /python3 verify_skill_release_bundle\.py[\s\S]*--release-dir "\$VERIFY_DIR"[\s\S]*--output-dir "\$VERIFY_DIR\/verified"/);
  assert.match(
    install,
    /npx skills add prompt-security\/clawsec#clawsec-suite-v0\.1\.16 --skill clawsec-suite --agent openclaw --yes/,
  );
  assert.match(install, /installed tree is not byte-bound to the signed release archive/);
  assert.doesNotMatch(install, /npx skills (?:update|list)/);
  assert.doesNotMatch(install, /#main\b/);

  const keyCheckIndex = install.indexOf('test "$EXPECTED_KEY_SHA256" = "$ACTUAL_KEY_SHA256"');
  const signatureCheckIndex = install.indexOf("openssl pkeyutl -verify");
  const verifierHashIndex = install.indexOf('test "$EXPECTED_VERIFIER_SHA" = "$ACTUAL_VERIFIER_SHA"');
  const verifierExecutionIndex = install.indexOf("python3 verify_skill_release_bundle.py");
  const resolverIndex = install.indexOf("npx skills add");
  assert.ok(keyCheckIndex > 0, "key fingerprint verification must be present");
  assert.ok(keyCheckIndex < signatureCheckIndex, "key verification must precede signature verification");
  assert.ok(signatureCheckIndex < verifierHashIndex, "signature verification must precede verifier authentication");
  assert.ok(verifierHashIndex < verifierExecutionIndex, "the verifier must be authenticated before execution");
  assert.ok(verifierExecutionIndex < resolverIndex, "bounded verification must precede compatibility resolution");
  assert.doesNotMatch(install, /\bunzip\b/, "install instructions must not use raw archive extraction");

  const hermesOutputDir = path.join(outputDir, "hermes");
  const hermesResult = runTrustPacket(
    "skills/hermes-attestation-guardian",
    hermesOutputDir,
    "hermes-attestation-guardian-v0.1.7",
  );
  assert.equal(
    hermesResult.status,
    0,
    `Hermes trust packet generator failed\nstdout:\n${hermesResult.stdout}\nstderr:\n${hermesResult.stderr}`,
  );
  const hermesInstall = await readFile(path.join(hermesOutputDir, "install.md"), "utf8");
  assert.match(
    hermesInstall,
    /npx skills add prompt-security\/clawsec#hermes-attestation-guardian-v0\.1\.7 --skill hermes-attestation-guardian --agent hermes-agent --yes/,
  );

  for (const [skillDir, tag, platform] of [
    ["skills/clawsec-nanoclaw", "clawsec-nanoclaw-v0.0.10", "nanoclaw"],
    ["skills/picoclaw-security-guardian", "picoclaw-security-guardian-v0.0.3", "picoclaw"],
  ]) {
    const skillName = path.basename(skillDir);
    const nativeOutputDir = path.join(outputDir, skillName);
    const nativeResult = runTrustPacket(skillDir, nativeOutputDir, tag);
    assert.equal(
      nativeResult.status,
      0,
      `${skillName} trust packet generator failed\nstdout:\n${nativeResult.stdout}\nstderr:\n${nativeResult.stderr}`,
    );
    const nativeInstall = await readFile(path.join(nativeOutputDir, "install.md"), "utf8");
    assert.match(nativeInstall, /## Harness-Native Integration/);
    assert.match(nativeInstall, new RegExp(`${platform} has no reviewed direct Vercel Agent Skills target`));
    assert.doesNotMatch(nativeInstall, /npx skills (?:add|update|list)/);
    assert.doesNotMatch(nativeInstall, /--agent openclaw/);
  }

  const multiOutputDir = path.join(outputDir, "clawtributor");
  const multiResult = runTrustPacket("skills/clawtributor", multiOutputDir, "clawtributor-v0.1.4");
  assert.equal(
    multiResult.status,
    0,
    `multi-platform trust packet generator failed\nstdout:\n${multiResult.stdout}\nstderr:\n${multiResult.stderr}`,
  );
  const multiInstall = await readFile(path.join(multiOutputDir, "install.md"), "utf8");
  assert.match(multiInstall, /--agent openclaw --yes/);
  assert.match(multiInstall, /--agent hermes-agent --yes/);
  assert.match(multiInstall, /nanoclaw and picoclaw have no reviewed direct Agent Skills target/);
} finally {
  await rm(outputDir, { recursive: true, force: true });
}
