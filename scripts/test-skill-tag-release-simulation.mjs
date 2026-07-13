import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const tempRoot = await mkdtemp(path.join(tmpdir(), "clawsec-tag-release-sim-"));
const fakeSkillspector = path.join(tempRoot, "skillspector");

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

async function prereleaseFixture(sourceSkillDir, version, fixtureGroup) {
  const fixtureDir = path.join(tempRoot, fixtureGroup, path.basename(sourceSkillDir));
  await cp(sourceSkillDir, fixtureDir, { recursive: true });

  const skillJsonPath = path.join(fixtureDir, "skill.json");
  const skill = JSON.parse(await readFile(skillJsonPath, "utf8"));
  skill.version = version;
  await writeFile(skillJsonPath, `${JSON.stringify(skill, null, 2)}\n`);

  const skillMdPath = path.join(fixtureDir, "SKILL.md");
  const skillMd = await readFile(skillMdPath, "utf8");
  await writeFile(skillMdPath, skillMd.replace(/^version:\s*.+$/m, `version: ${version}`));

  return fixtureDir;
}

async function runSimulation({
  skillDir,
  outputDir,
  expectedOriginal,
  expectedSimulated,
  expectedAgent,
  verifyEmbeddedAdvisory = false,
}) {
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

  for (const artifact of ["skill.json", "SKILL.md", "skillspector-report.md"]) {
    const file = await readFile(path.join(releaseAssetsDir, artifact));
    assert.equal(
      checksums.files[artifact]?.sha256,
      sha256(file),
      `${artifact} must be downloadable and covered by checksums.json`,
    );
  }

  if (existsSync(path.join(releaseAssetsDir, "README.md"))) {
    const file = await readFile(path.join(releaseAssetsDir, "README.md"));
    assert.equal(
      checksums.files["README.md"]?.sha256,
      sha256(file),
      "README.md must be downloadable and covered by checksums.json when shipped",
    );
  }

  const archivePath = path.join(releaseAssetsDir, `${expectedTag}.zip`);
  const archive = await readFile(archivePath);
  assert.ok(archive.length > 0, "release archive should not be empty");

  if (verifyEmbeddedAdvisory) {
    const readArchiveEntry = (entry) => {
      const extracted = spawnSync("unzip", ["-p", archivePath, entry], {
        maxBuffer: 64 * 1024 * 1024,
      });
      assert.equal(
        extracted.status,
        0,
        `failed to read ${entry} from simulated release archive: ${extracted.stderr?.toString() || ""}`,
      );
      assert.ok(extracted.stdout.length > 0, `${entry} must not be empty in simulated release archive`);
      return extracted.stdout;
    };

    const canonicalFeed = await readFile("advisories/feed.json");
    const canonicalFeedPayload = JSON.parse(canonicalFeed.toString("utf8"));
    const packagedFeed = readArchiveEntry(`${skillName}/advisories/feed.json`);
    const packagedFeedSignature = readArchiveEntry(`${skillName}/advisories/feed.json.sig`);
    const packagedChecksumsRaw = readArchiveEntry(`${skillName}/advisories/checksums.json`);
    readArchiveEntry(`${skillName}/advisories/checksums.json.sig`);
    const packagedPublicKey = readArchiveEntry(`${skillName}/advisories/feed-signing-public.pem`);

    assert.deepEqual(packagedFeed, canonicalFeed, "simulated release must package the canonical advisory feed");
    const embeddedChecksums = JSON.parse(packagedChecksumsRaw.toString("utf8"));
    assert.equal(
      embeddedChecksums.files["advisories/feed.json"].sha256,
      sha256(packagedFeed),
      "embedded manifest must checksum the packaged feed",
    );
    assert.equal(
      embeddedChecksums.files["advisories/feed.json.sig"].sha256,
      sha256(packagedFeedSignature),
      "embedded manifest must checksum the packaged feed signature",
    );
    assert.equal(
      embeddedChecksums.files["advisories/feed-signing-public.pem"].sha256,
      sha256(packagedPublicKey),
      "embedded manifest must checksum the packaged feed signing key",
    );

    const extractedReleaseDir = path.join(outputDir, "extracted-release");
    const extracted = spawnSync("unzip", ["-q", "-o", archivePath, "-d", extractedReleaseDir]);
    assert.equal(
      extracted.status,
      0,
      `failed to extract simulated release archive: ${extracted.stderr?.toString() || ""}`,
    );

    const extractedSkillDir = path.join(extractedReleaseDir, skillName);
    const extractedAdvisoryDir = path.join(extractedSkillDir, "advisories");
    const extractedFeedPath = path.join(extractedAdvisoryDir, "feed.json");
    const extractedPublicKeyPath = path.join(extractedAdvisoryDir, "feed-signing-public.pem");
    const extractedPublicKeyPem = await readFile(extractedPublicKeyPath, "utf8");
    const feedModuleUrl = pathToFileURL(
      path.join(extractedSkillDir, "hooks", "clawsec-advisory-guardian", "lib", "feed.mjs"),
    );
    const { loadLocalFeed } = await import(feedModuleUrl.href);
    const loadedFeed = await loadLocalFeed(extractedFeedPath, {
      signaturePath: `${extractedFeedPath}.sig`,
      checksumsPath: path.join(extractedAdvisoryDir, "checksums.json"),
      checksumsSignaturePath: path.join(extractedAdvisoryDir, "checksums.json.sig"),
      publicKeyPem: extractedPublicKeyPem,
      checksumsPublicKeyPem: extractedPublicKeyPem,
      verifyChecksumManifest: true,
      checksumPublicKeyEntry: path.basename(extractedPublicKeyPath),
    });
    assert.equal(loadedFeed.version, canonicalFeedPayload.version);
    assert.equal(loadedFeed.advisories.length, canonicalFeedPayload.advisories.length);
  }

  const install = await readFile(path.join(releaseAssetsDir, "install.md"), "utf8");
  assert.match(
    install,
    new RegExp(
      `npx skills add prompt-security/clawsec#pull-request-head --skill ${skillName} --agent ${expectedAgent} --global --yes`,
    ),
  );
  assert.match(install, new RegExp(`npx skills update ${skillName}`));
}

try {
  await writeFile(
    fakeSkillspector,
    `#!/usr/bin/env node
import { readdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const scanIndex = process.argv.indexOf("scan");
if (scanIndex === -1 || !process.argv[scanIndex + 1]) {
  console.error("missing scan target");
  process.exit(2);
}

function containsTestDirectory(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) {
      continue;
    }
    const lowerName = entry.name.toLowerCase();
    if (lowerName === "test" || lowerName === "tests") {
      return true;
    }
    if (containsTestDirectory(path.join(dir, entry.name))) {
      return true;
    }
  }
  return false;
}

const scanTarget = process.argv[scanIndex + 1];
if (containsTestDirectory(scanTarget)) {
  console.error("SkillSpector test fixture must scan the staged release payload, not source test directories.");
  process.exit(42);
}

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
    expectedOriginal: "0.1.14",
    expectedSimulated: "0.1.15",
    expectedAgent: "openclaw",
    verifyEmbeddedAdvisory: true,
  });

  await runSimulation({
    skillDir: "skills/hermes-traffic-guardian",
    outputDir: path.join(tempRoot, "beta"),
    expectedOriginal: "0.0.1-beta5",
    expectedSimulated: "0.0.1-beta6",
    expectedAgent: "hermes-agent",
  });

  const alphaSkillDir = await prereleaseFixture("skills/picoclaw-self-pen-testing", "0.0.3-alpha1", "alpha-fixture");
  await runSimulation({
    skillDir: alphaSkillDir,
    outputDir: path.join(tempRoot, "alpha"),
    expectedOriginal: "0.0.3-alpha1",
    expectedSimulated: "0.0.3-alpha2",
    expectedAgent: "openclaw",
  });

  const rcSkillDir = await prereleaseFixture("skills/picoclaw-security-guardian", "0.0.4-rc1", "rc-fixture");
  await runSimulation({
    skillDir: rcSkillDir,
    outputDir: path.join(tempRoot, "rc"),
    expectedOriginal: "0.0.4-rc1",
    expectedSimulated: "0.0.4-rc2",
    expectedAgent: "openclaw",
  });

  const previewSkillDir = await prereleaseFixture("skills/openclaw-traffic-guardian", "0.0.1-preview", "preview-fixture");
  await runSimulation({
    skillDir: previewSkillDir,
    outputDir: path.join(tempRoot, "preview"),
    expectedOriginal: "0.0.1-preview",
    expectedSimulated: "0.0.1-preview1",
    expectedAgent: "openclaw",
  });
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}
