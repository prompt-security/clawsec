import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const outputDir = await mkdtemp(path.join(tmpdir(), "clawsec-trust-packet-"));

async function loadSkillIdentity(skillDir) {
  const skill = JSON.parse(await readFile(path.join(skillDir, "skill.json"), "utf8"));
  return {
    ...skill,
    tag: `${skill.name}-v${skill.version}`,
  };
}

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
  const suite = await loadSkillIdentity("skills/clawsec-suite");
  const mismatchedTagDir = path.join(outputDir, "mismatched-tag");
  const mismatchedTag = runTrustPacket(
    "skills/clawsec-suite",
    mismatchedTagDir,
    "clawsec-suite-v9.9.9",
  );
  assert.equal(mismatchedTag.status, 1, "a mismatched release tag must fail closed");
  assert.match(
    mismatchedTag.stderr,
    new RegExp(`Release tag clawsec-suite-v9\\.9\\.9 does not match skill identity ${suite.tag.replaceAll(".", "\\.")}`),
  );

  const result = runTrustPacket("skills/clawsec-suite", outputDir, suite.tag);

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
  assert.ok(skillCard.includes(suite.tag));

  assert.equal(permissions.skill, "clawsec-suite");
  assert.equal(permissions.version, suite.version);
  assert.equal(permissions.platform, "openclaw");
  assert.equal(permissions.installable, true);
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
  assert.ok(install.includes(`BASE_URL="https://github.com/prompt-security/clawsec/releases/download/${suite.tag}"`));
  assert.ok(install.includes(`ARCHIVE="${suite.tag}.zip"`));
  assert.match(install, /python3 verify_skill_release_bundle\.py[\s\S]*--release-dir "\$VERIFY_DIR"[\s\S]*--output-dir "\$VERIFY_DIR\/verified"/);
  assert.match(
    install,
    new RegExp(`npx skills add prompt-security/clawsec#${suite.tag.replaceAll(".", "\\.")} --skill clawsec-suite --agent openclaw --yes`),
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
  const hermes = await loadSkillIdentity("skills/hermes-attestation-guardian");
  const hermesResult = runTrustPacket(
    "skills/hermes-attestation-guardian",
    hermesOutputDir,
    hermes.tag,
  );
  assert.equal(
    hermesResult.status,
    0,
    `Hermes trust packet generator failed\nstdout:\n${hermesResult.stdout}\nstderr:\n${hermesResult.stderr}`,
  );
  const hermesInstall = await readFile(path.join(hermesOutputDir, "install.md"), "utf8");
  assert.match(
    hermesInstall,
    new RegExp(`npx skills add prompt-security/clawsec#${hermes.tag.replaceAll(".", "\\.")} --skill hermes-attestation-guardian --agent hermes-agent --yes`),
  );

  for (const [skillDir, platform] of [["skills/picoclaw-security-guardian", "picoclaw"]]) {
    const skillName = path.basename(skillDir);
    const identity = await loadSkillIdentity(skillDir);
    const nativeOutputDir = path.join(outputDir, skillName);
    const nativeResult = runTrustPacket(skillDir, nativeOutputDir, identity.tag);
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

  const nonInstallableSource = path.join(outputDir, "non-installable-source", "clawsec-nanoclaw");
  await cp("skills/clawsec-nanoclaw", nonInstallableSource, { recursive: true });
  const nonInstallableJsonPath = path.join(nonInstallableSource, "skill.json");
  const nonInstallableSkill = JSON.parse(await readFile(nonInstallableJsonPath, "utf8"));
  nonInstallableSkill.installable = false;
  nonInstallableSkill.platform = "retired-unmapped-harness";
  delete nonInstallableSkill.nanoclaw;
  await writeFile(nonInstallableJsonPath, `${JSON.stringify(nonInstallableSkill, null, 2)}\n`);

  const nonInstallableOutput = path.join(outputDir, "non-installable-output");
  const nonInstallableTag = `${nonInstallableSkill.name}-v${nonInstallableSkill.version}`;
  const nonInstallableResult = runTrustPacket(
    nonInstallableSource,
    nonInstallableOutput,
    nonInstallableTag,
  );
  assert.equal(
    nonInstallableResult.status,
    0,
    `non-installable trust packet generation failed\nstdout:\n${nonInstallableResult.stdout}\nstderr:\n${nonInstallableResult.stderr}`,
  );
  const nonInstallableDoc = await readFile(path.join(nonInstallableOutput, "install.md"), "utf8");
  const nonInstallableCard = await readFile(path.join(nonInstallableOutput, "skill-card.md"), "utf8");
  const nonInstallablePermissions = JSON.parse(
    await readFile(path.join(nonInstallableOutput, "permissions.json"), "utf8"),
  );
  assert.match(nonInstallableDoc, /^# Installation Unavailable for clawsec-nanoclaw/m);
  assert.match(nonInstallableDoc, /declares `installable: false`/);
  assert.match(nonInstallableDoc, /no supported installation or activation path/);
  assert.doesNotMatch(nonInstallableDoc, /```|curl|python3|npx skills|--agent openclaw|\bcopy\b/i);
  assert.match(nonInstallableCard, /declares `installable: false`/);
  assert.match(nonInstallableCard, /no supported execution or activation path/);
  assert.doesNotMatch(nonInstallableCard, /provides this capability|Use this skill for/);
  assert.equal(nonInstallablePermissions.installable, false);
  assert.equal(nonInstallablePermissions.platform, "not-applicable");
  assert.deepEqual(nonInstallablePermissions.required_binaries, []);
  assert.deepEqual(nonInstallablePermissions.optional_binaries, []);
  assert.deepEqual(nonInstallablePermissions.required_env, []);
  assert.deepEqual(nonInstallablePermissions.optional_env, []);
  assert.deepEqual(nonInstallablePermissions.capabilities, []);
  assert.match(nonInstallablePermissions.network_egress, /Not applicable: package is non-installable/);
  assert.match(nonInstallablePermissions.persistence, /Not applicable: package is non-installable/);
  assert.match(String(nonInstallablePermissions.automatic_execution), /Not applicable: package is non-installable/);

  const invalidInstallableSource = path.join(outputDir, "invalid-installable-source", "clawsec-nanoclaw");
  await cp("skills/clawsec-nanoclaw", invalidInstallableSource, { recursive: true });
  const invalidInstallableJsonPath = path.join(invalidInstallableSource, "skill.json");
  const invalidInstallableSkill = JSON.parse(await readFile(invalidInstallableJsonPath, "utf8"));
  invalidInstallableSkill.installable = "false";
  await writeFile(invalidInstallableJsonPath, `${JSON.stringify(invalidInstallableSkill, null, 2)}\n`);
  const invalidInstallableResult = runTrustPacket(
    invalidInstallableSource,
    path.join(outputDir, "invalid-installable-output"),
    `${invalidInstallableSkill.name}-v${invalidInstallableSkill.version}`,
  );
  assert.equal(invalidInstallableResult.status, 1, "non-boolean installable metadata must fail closed");
  assert.match(invalidInstallableResult.stderr, /"installable" must be a boolean/);

  const multiOutputDir = path.join(outputDir, "clawtributor");
  const clawtributor = await loadSkillIdentity("skills/clawtributor");
  const multiResult = runTrustPacket("skills/clawtributor", multiOutputDir, clawtributor.tag);
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
