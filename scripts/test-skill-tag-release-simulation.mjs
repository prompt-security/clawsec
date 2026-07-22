import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import {
  collectClawhubPackageFiles,
  collectPackageFiles,
  prepareReleasePackage,
  verifyRegistryPackage,
  verifyPublishedPackage,
} from "./ci/clawhub_release_package.mjs";

const tempRoot = await mkdtemp(path.join(tmpdir(), "clawsec-tag-release-sim-"));
const fakeSkillspector = path.join(tempRoot, "skillspector");
const fakeClawhub = path.join(tempRoot, "clawhub");

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

async function stablePatchFixture(skillDir) {
  const skill = JSON.parse(await readFile(path.join(skillDir, "skill.json"), "utf8"));
  const version = typeof skill.version === "string" ? skill.version : "";
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(version);
  assert.ok(
    match,
    `${skill.name} tag-release fixture must start from a final SemVer`,
  );

  return {
    expectedOriginal: version,
    expectedSimulated: `${match[1]}.${match[2]}.${BigInt(match[3]) + 1n}`,
  };
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
  expectedInstallable = true,
  expectedAgents = [],
  verifyReleaseBundle = false,
  verifyEmbeddedAdvisory = false,
  expectedPreparationError = null,
  expectedExcludedPaths = [],
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
  assert.equal(summary.installable, expectedInstallable);
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
    "verify_skill_release_bundle.py",
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

  for (const artifact of [
    "skill.json",
    "SKILL.md",
    "skill-card.md",
    "permissions.json",
    "install.md",
    "verify_skill_release_bundle.py",
    "skillspector-report.md",
  ]) {
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
  const archiveListing = spawnSync("unzip", ["-Z1", archivePath], { encoding: "utf8" });
  assert.equal(archiveListing.status, 0, `failed to list simulated release archive: ${archiveListing.stderr}`);
  const archiveEntries = new Set(archiveListing.stdout.split(/\r?\n/).filter(Boolean));
  for (const excludedPath of expectedExcludedPaths) {
    assert.equal(
      archiveEntries.has(`${skillName}/${excludedPath}`),
      false,
      `simulated release archive must exclude test-only path: ${excludedPath}`,
    );
  }

  if (verifyReleaseBundle) {
    const publicKeyPath = path.join(releaseAssetsDir, "signing-public.pem");
    const publicKeyDer = spawnSync(
      "openssl",
      ["pkey", "-pubin", "-in", publicKeyPath, "-outform", "DER"],
    );
    assert.equal(
      publicKeyDer.status,
      0,
      `failed to encode simulated release key: ${publicKeyDer.stderr?.toString() || ""}`,
    );
    const verifiedOutputDir = path.join(outputDir, "verified-release");
    const verifier = spawnSync(
      "python3",
      [
        path.join(releaseAssetsDir, "verify_skill_release_bundle.py"),
        "--release-dir",
        releaseAssetsDir,
        "--output-dir",
        verifiedOutputDir,
        "--skill",
        skillName,
        "--version",
        expectedSimulated,
        "--tag",
        expectedTag,
        "--spki-sha256",
        sha256(publicKeyDer.stdout),
        "--openssl",
        "openssl",
      ],
      { encoding: "utf8" },
    );
    assert.equal(
      verifier.status,
      0,
      `shipped verifier rejected a signed simulated bundle\nstdout:\n${verifier.stdout}\nstderr:\n${verifier.stderr}`,
    );
    const verifiedSkill = JSON.parse(
      await readFile(path.join(verifiedOutputDir, skillName, "skill.json"), "utf8"),
    );
    assert.equal(verifiedSkill.name, skillName);
    assert.equal(verifiedSkill.version, expectedSimulated);
  }

  if (expectedInstallable && !verifyEmbeddedAdvisory) {
    const clawhubOutputDir = path.join(outputDir, "clawhub-package");
    const prepareOptions = {
      releaseDir: releaseAssetsDir,
      outputDir: clawhubOutputDir,
      skillName,
      version: expectedSimulated,
      canonicalKeyPath: path.join(releaseAssetsDir, "signing-public.pem"),
    };
    if (expectedPreparationError) {
      await assert.rejects(
        prepareReleasePackage(prepareOptions),
        expectedPreparationError,
      );
      assert.deepEqual(
        await readdir(clawhubOutputDir),
        [],
        "failed ClawHub staging must leave the output directory safely retryable",
      );
    } else {
      const prepared = await prepareReleasePackage(prepareOptions);
      const publishableFiles = await collectClawhubPackageFiles(prepared.packageDir);
      const inspectJsonPath = path.join(outputDir, "clawhub-inspect.json");
      await writeFile(inspectJsonPath, `${JSON.stringify({
        version: { version: expectedSimulated, files: [...publishableFiles.values()] },
      }, null, 2)}\n`);
      assert.deepEqual(
        await verifyPublishedPackage({
          packageDir: prepared.packageDir,
          inspectJsonPath,
          version: expectedSimulated,
        }),
        { version: expectedSimulated, files: publishableFiles.size },
      );

      const registryAttemptPath = path.join(outputDir, "clawhub-inspect-attempts.txt");
      const previousPath = process.env.PATH;
      process.env.PATH = `${tempRoot}:${previousPath}`;
      process.env.FAKE_CLAWHUB_INSPECT_JSON = inspectJsonPath;
      process.env.FAKE_CLAWHUB_ATTEMPT_FILE = registryAttemptPath;
      try {
        assert.deepEqual(
          await verifyRegistryPackage({
            packageDir: prepared.packageDir,
            slug: "clawsec-suite",
            version: expectedSimulated,
            attempts: 2,
            delayMs: 1,
          }),
          { version: expectedSimulated, files: publishableFiles.size },
        );
        assert.equal(await readFile(registryAttemptPath, "utf8"), "2");
      } finally {
        process.env.PATH = previousPath;
        delete process.env.FAKE_CLAWHUB_INSPECT_JSON;
        delete process.env.FAKE_CLAWHUB_ATTEMPT_FILE;
      }
    }
  }

  if (expectedInstallable && verifyEmbeddedAdvisory) {
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

    const clawhubOutputDir = path.join(outputDir, "clawhub-package");
    const prepared = await prepareReleasePackage({
      releaseDir: releaseAssetsDir,
      outputDir: clawhubOutputDir,
      skillName,
      version: expectedSimulated,
      canonicalKeyPath: path.join(releaseAssetsDir, "signing-public.pem"),
    });
    assert.equal(prepared.embeddedAdvisoryTrust.verified, true);
    assert.equal(prepared.embeddedAdvisoryTrust.files, 5);

    const preparedFiles = await collectPackageFiles(prepared.packageDir);
    const publishableFiles = await collectClawhubPackageFiles(prepared.packageDir);
    const extractedFiles = await collectPackageFiles(extractedSkillDir);
    assert.deepEqual(
      Object.fromEntries(preparedFiles),
      Object.fromEntries(extractedFiles),
      "ClawHub staging must be byte-identical to the verified GitHub release archive",
    );

    const preparedAdvisoryDir = path.join(prepared.packageDir, "advisories");
    const preparedFeedPath = path.join(preparedAdvisoryDir, "feed.json");
    const preparedPublicKeyPath = path.join(preparedAdvisoryDir, "feed-signing-public.pem");
    const preparedPublicKeyPem = await readFile(preparedPublicKeyPath, "utf8");
    const preparedFeedModuleUrl = pathToFileURL(
      path.join(prepared.packageDir, "hooks", "clawsec-advisory-guardian", "lib", "feed.mjs"),
    );
    const { loadLocalFeed: loadClawHubFeed } = await import(preparedFeedModuleUrl.href);
    const clawhubFeed = await loadClawHubFeed(preparedFeedPath, {
      signaturePath: `${preparedFeedPath}.sig`,
      checksumsPath: path.join(preparedAdvisoryDir, "checksums.json"),
      checksumsSignaturePath: path.join(preparedAdvisoryDir, "checksums.json.sig"),
      publicKeyPem: preparedPublicKeyPem,
      checksumsPublicKeyPem: preparedPublicKeyPem,
      verifyChecksumManifest: true,
      checksumPublicKeyEntry: path.basename(preparedPublicKeyPath),
    });
    assert.equal(clawhubFeed.version, canonicalFeedPayload.version);
    assert.equal(clawhubFeed.advisories.length, canonicalFeedPayload.advisories.length);

    const inspectJsonPath = path.join(outputDir, "clawhub-inspect.json");
    const inspectPayload = {
      version: {
        version: expectedSimulated,
        files: [...publishableFiles.values()],
      },
    };
    await writeFile(inspectJsonPath, `${JSON.stringify(inspectPayload, null, 2)}\n`);
    assert.deepEqual(
      await verifyPublishedPackage({
        packageDir: prepared.packageDir,
        inspectJsonPath,
        version: expectedSimulated,
      }),
      { version: expectedSimulated, files: publishableFiles.size },
    );

    const incompleteInspectPath = path.join(outputDir, "clawhub-inspect-missing-key.json");
    const incompleteInspect = cloneJson(inspectPayload);
    incompleteInspect.version.files = incompleteInspect.version.files.filter(
      (entry) => entry.path !== "advisories/feed-signing-public.pem",
    );
    await writeFile(incompleteInspectPath, `${JSON.stringify(incompleteInspect, null, 2)}\n`);
    await assert.rejects(
      verifyPublishedPackage({
        packageDir: prepared.packageDir,
        inspectJsonPath: incompleteInspectPath,
        version: expectedSimulated,
      }),
      /missing advisories\/feed-signing-public\.pem/,
    );

    const duplicateInspectPath = path.join(outputDir, "clawhub-inspect-duplicate-path.json");
    const duplicateInspect = cloneJson(inspectPayload);
    duplicateInspect.version.files.push(duplicateInspect.version.files[0]);
    await writeFile(duplicateInspectPath, `${JSON.stringify(duplicateInspect, null, 2)}\n`);
    await assert.rejects(
      verifyPublishedPackage({
        packageDir: prepared.packageDir,
        inspectJsonPath: duplicateInspectPath,
        version: expectedSimulated,
      }),
      /duplicate file paths/,
    );
  }

  const install = await readFile(path.join(releaseAssetsDir, "install.md"), "utf8");
  const permissions = JSON.parse(
    await readFile(path.join(releaseAssetsDir, "permissions.json"), "utf8"),
  );
  assert.equal(permissions.installable, expectedInstallable);

  if (!expectedInstallable) {
    const card = await readFile(path.join(releaseAssetsDir, "skill-card.md"), "utf8");
    assert.match(install, /^# Installation Unavailable for /m);
    assert.match(install, /declares `installable: false`/);
    assert.match(install, /no supported installation or activation path/);
    assert.doesNotMatch(install, /```|\bcurl\b|\bpython3\b|\bnpx\b|--agent|\bunzip\b/);
    assert.equal(permissions.platform, "not-applicable");
    assert.deepEqual(permissions.required_binaries, []);
    assert.deepEqual(permissions.optional_binaries, []);
    assert.deepEqual(permissions.required_env, []);
    assert.deepEqual(permissions.optional_env, []);
    assert.deepEqual(permissions.capabilities, []);
    assert.match(permissions.network_egress, /Not applicable: package is non-installable/);
    assert.match(card, /declares `installable: false`/);
    assert.match(card, /no supported execution or activation path/);
    assert.doesNotMatch(card, /provides this capability|Use this skill for/);
    assert.equal(
      existsSync(path.join(outputDir, "clawhub-package")),
      false,
      "non-installable simulation must not prepare a ClawHub package",
    );
    const rejectedClawhubOutputDir = path.join(outputDir, "rejected-clawhub-package");
    await assert.rejects(
      prepareReleasePackage({
        releaseDir: releaseAssetsDir,
        outputDir: rejectedClawhubOutputDir,
        skillName,
        version: expectedSimulated,
        canonicalKeyPath: path.join(releaseAssetsDir, "signing-public.pem"),
      }),
      /Publication denied .*skill\.json declares "installable": false/,
    );
    assert.deepEqual(
      await readdir(rejectedClawhubOutputDir),
      [],
      "rejected non-installable release staging must leave no publishable package",
    );
    return;
  }

  assert.match(install, /## Secure Path: Verify the Canonical Release Before Installation/);
  assert.match(install, new RegExp(`TAG="${expectedTag}"`));
  assert.match(install, new RegExp(`ARCHIVE="${expectedTag}\\.zip"`));
  assert.match(install, /EXPECTED_KEY_SHA256="711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8"/);
  assert.match(install, /installed tree is not byte-bound|## Harness-Native Integration/);
  assert.doesNotMatch(install, /npx skills (?:update|list)/);

  const keyCheckIndex = install.indexOf('test "$EXPECTED_KEY_SHA256" = "$ACTUAL_KEY_SHA256"');
  const signatureCheckIndex = install.indexOf("openssl pkeyutl -verify");
  const verifierHashIndex = install.indexOf('test "$EXPECTED_VERIFIER_SHA" = "$ACTUAL_VERIFIER_SHA"');
  const verifierExecutionIndex = install.indexOf("python3 verify_skill_release_bundle.py");
  assert.ok(keyCheckIndex > 0 && keyCheckIndex < signatureCheckIndex);
  assert.ok(signatureCheckIndex < verifierHashIndex);
  assert.ok(verifierHashIndex < verifierExecutionIndex);
  assert.doesNotMatch(install, /\bunzip\b/);

  if (expectedAgents.length === 0) {
    assert.match(install, /## Harness-Native Integration/);
    assert.match(install, /no reviewed direct Vercel Agent Skills target/);
    assert.doesNotMatch(install, /npx skills (?:add|update|list)/);
  } else {
    for (const expectedAgent of expectedAgents) {
      assert.match(
        install,
        new RegExp(
          `npx skills add prompt-security/clawsec#pull-request-head --skill ${skillName} --agent ${expectedAgent} --yes`,
        ),
      );
    }
    assert.ok(verifierExecutionIndex < install.indexOf("npx skills add"));
  }
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
  await writeFile(
    fakeClawhub,
    `#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const attemptFile = process.env.FAKE_CLAWHUB_ATTEMPT_FILE;
const inspectFile = process.env.FAKE_CLAWHUB_INSPECT_JSON;
if (process.argv[2] !== "inspect" || !attemptFile || !inspectFile) {
  process.exit(2);
}
const attempt = existsSync(attemptFile) ? Number(readFileSync(attemptFile, "utf8")) + 1 : 1;
writeFileSync(attemptFile, String(attempt));
if (attempt === 1) {
  process.stderr.write("registry result not yet visible\\n");
  process.exit(1);
}
process.stdout.write(readFileSync(inspectFile, "utf8"));
`,
    { mode: 0o700 },
  );
  await chmod(fakeClawhub, 0o700);

  const suiteVersionFixture = await stablePatchFixture("skills/clawsec-suite");
  await runSimulation({
    skillDir: "skills/clawsec-suite",
    outputDir: path.join(tempRoot, "stable"),
    ...suiteVersionFixture,
    expectedAgents: ["openclaw"],
    verifyReleaseBundle: true,
    verifyEmbeddedAdvisory: true,
  });

  await runSimulation({
    skillDir: "skills/clawsec-feed",
    outputDir: path.join(tempRoot, "feed-only"),
    expectedOriginal: "0.0.11",
    expectedSimulated: "0.0.12",
    expectedAgents: ["openclaw"],
  });

  const nonInstallableSkillDir = await prereleaseFixture(
    "skills/picoclaw-security-guardian",
    "0.0.7",
    "non-installable-fixture",
  );
  const nonInstallableSkillJsonPath = path.join(nonInstallableSkillDir, "skill.json");
  const nonInstallableSkill = JSON.parse(await readFile(nonInstallableSkillJsonPath, "utf8"));
  nonInstallableSkill.installable = false;
  await writeFile(
    nonInstallableSkillJsonPath,
    `${JSON.stringify(nonInstallableSkill, null, 2)}\n`,
  );
  await runSimulation({
    skillDir: nonInstallableSkillDir,
    outputDir: path.join(tempRoot, "non-installable"),
    expectedOriginal: "0.0.7",
    expectedSimulated: "0.0.8",
    expectedInstallable: false,
    verifyReleaseBundle: true,
  });

  await runSimulation({
    skillDir: "skills/hermes-traffic-guardian",
    outputDir: path.join(tempRoot, "beta"),
    expectedOriginal: "0.0.1-beta5",
    expectedSimulated: "0.0.1-beta6",
    expectedAgents: ["hermes-agent"],
  });

  const alphaSkillDir = await prereleaseFixture("skills/picoclaw-self-pen-testing", "0.0.3-alpha1", "alpha-fixture");
  await runSimulation({
    skillDir: alphaSkillDir,
    outputDir: path.join(tempRoot, "alpha"),
    expectedOriginal: "0.0.3-alpha1",
    expectedSimulated: "0.0.3-alpha2",
  });

  const rcSkillDir = await prereleaseFixture("skills/picoclaw-security-guardian", "0.0.4-rc1", "rc-fixture");
  await runSimulation({
    skillDir: rcSkillDir,
    outputDir: path.join(tempRoot, "rc"),
    expectedOriginal: "0.0.4-rc1",
    expectedSimulated: "0.0.4-rc2",
  });

  const previewSkillDir = await prereleaseFixture("skills/openclaw-traffic-guardian", "0.0.1-preview", "preview-fixture");
  await runSimulation({
    skillDir: previewSkillDir,
    outputDir: path.join(tempRoot, "preview"),
    expectedOriginal: "0.0.1-preview",
    expectedSimulated: "0.0.1-preview1",
    expectedAgents: ["openclaw"],
  });

  const testFilterSkillDir = await prereleaseFixture(
    "skills/picoclaw-self-pen-testing",
    "0.0.5",
    "test-filter-fixture",
  );
  const testOnlyPaths = [
    "tests/scanner-fixture.md",
    "__tests__/scanner-fixture.js",
    "test_scanner_fixture.py",
    "scanner-fixture.spec.mjs",
  ];
  await mkdir(path.join(testFilterSkillDir, "tests"));
  await mkdir(path.join(testFilterSkillDir, "__tests__"));
  for (const testOnlyPath of testOnlyPaths) {
    await writeFile(path.join(testFilterSkillDir, testOnlyPath), "test fixture\n");
  }
  const testFilterSkillJsonPath = path.join(testFilterSkillDir, "skill.json");
  const testFilterSkill = JSON.parse(await readFile(testFilterSkillJsonPath, "utf8"));
  for (const testOnlyPath of testOnlyPaths) {
    testFilterSkill.sbom.files.push({
      path: testOnlyPath,
      required: true,
      description: "Test-only release filtering fixture",
    });
  }
  await writeFile(testFilterSkillJsonPath, `${JSON.stringify(testFilterSkill, null, 2)}\n`);
  await runSimulation({
    skillDir: testFilterSkillDir,
    outputDir: path.join(tempRoot, "test-filter"),
    expectedOriginal: "0.0.5",
    expectedSimulated: "0.0.6",
    expectedExcludedPaths: testOnlyPaths,
  });

  const unsupportedSkillDir = await prereleaseFixture(
    "skills/picoclaw-self-pen-testing",
    "0.0.5",
    "unsupported-client-file-fixture",
  );
  await writeFile(path.join(unsupportedSkillDir, "runtime.bin"), "required runtime binary\n");
  const unsupportedSkillJsonPath = path.join(unsupportedSkillDir, "skill.json");
  const unsupportedSkill = JSON.parse(await readFile(unsupportedSkillJsonPath, "utf8"));
  unsupportedSkill.sbom.files.push({
    path: "runtime.bin",
    required: true,
    description: "Unsupported ClawHub runtime fixture",
  });
  await writeFile(unsupportedSkillJsonPath, `${JSON.stringify(unsupportedSkill, null, 2)}\n`);
  await runSimulation({
    skillDir: unsupportedSkillDir,
    outputDir: path.join(tempRoot, "unsupported-client-file"),
    expectedOriginal: "0.0.5",
    expectedSimulated: "0.0.6",
    expectedPreparationError: /would omit non-placeholder package file: runtime\.bin/,
  });
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}
