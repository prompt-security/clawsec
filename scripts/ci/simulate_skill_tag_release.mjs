#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const TRUST_ARTIFACTS = [
  "skill-card.md",
  "permissions.json",
  "install.md",
  "skillspector-report.md",
];

function usage() {
  return [
    "Usage: node scripts/ci/simulate_skill_tag_release.mjs <skill-dir> <output-dir> [options]",
    "",
    "Options:",
    "  --repository <owner/repo>       Source repository used in release metadata",
    "  --source-ref <ref>              Source ref used in npx skills examples",
    "  --skillspector-bin <path>       SkillSpector executable to run",
  ].join("\n");
}

function parseArgs(argv) {
  const positional = [];
  const options = {
    repository: "prompt-security/clawsec",
    sourceRef: "main",
    skillspectorBin: "skillspector",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--repository") {
      options.repository = argv[++i];
    } else if (token === "--source-ref") {
      options.sourceRef = argv[++i];
    } else if (token === "--skillspector-bin") {
      options.skillspectorBin = argv[++i];
    } else if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
    } else if (token.startsWith("--")) {
      throw new Error(`Unknown option: ${token}`);
    } else {
      positional.push(token);
    }
  }

  if (positional.length !== 2) {
    throw new Error(usage());
  }

  return {
    skillDir: positional[0],
    outputDir: positional[1],
    ...options,
  };
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...options,
  });

  if (result.status !== 0) {
    throw new Error(
      [
        `Command failed: ${command} ${args.join(" ")}`,
        result.stdout ? `stdout:\n${result.stdout}` : "",
        result.stderr ? `stderr:\n${result.stderr}` : "",
      ].filter(Boolean).join("\n"),
    );
  }

  return result.stdout;
}

function runAllowFailure(command, args, options = {}) {
  return spawnSync(command, args, {
    encoding: "utf8",
    ...options,
  });
}

function nextSimulatedReleaseVersion(version) {
  const versionMatch = version.match(/^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9]+))?$/);
  if (!versionMatch) {
    throw new Error(`Cannot derive simulated release version from unsupported version: ${version}`);
  }

  const [, major, minor, patch, prerelease] = versionMatch;
  if (!prerelease) {
    return `${major}.${minor}.${Number(patch) + 1}`;
  }

  const prereleaseMatch = prerelease.match(/^(.*?)(\d+)$/);
  if (prereleaseMatch) {
    const [, label, number] = prereleaseMatch;
    return `${major}.${minor}.${patch}-${label}${Number(number) + 1}`;
  }

  return `${major}.${minor}.${patch}-${prerelease}1`;
}

function normalizeReleasePath(rawPath) {
  let releasePath = rawPath.replaceAll("\\", "/");
  while (releasePath.startsWith("./")) {
    releasePath = releasePath.slice(2);
  }
  while (releasePath.includes("//")) {
    releasePath = releasePath.replaceAll("//", "/");
  }

  if (
    releasePath === "" ||
    releasePath.startsWith("/") ||
    /^[A-Za-z]:/.test(releasePath) ||
    releasePath === ".." ||
    releasePath.startsWith("../") ||
    releasePath.endsWith("/..") ||
    releasePath.includes("/../")
  ) {
    throw new Error(`Unsafe release path: ${rawPath}`);
  }

  return releasePath;
}

function isTestReleasePath(releasePath) {
  const lower = releasePath.toLowerCase();
  return lower === "test" ||
    lower === "tests" ||
    lower.startsWith("test/") ||
    lower.startsWith("tests/") ||
    lower.includes("/test/") ||
    lower.includes("/tests/");
}

async function sha256File(filePath) {
  const buffer = await readFile(filePath);
  return createHash("sha256").update(buffer).digest("hex");
}

async function fileSize(filePath) {
  return (await stat(filePath)).size;
}

async function checksumEntry(filePath, releasePath) {
  return {
    sha256: await sha256File(filePath),
    size: await fileSize(filePath),
    path: releasePath,
  };
}

function replaceSkillMarkdownVersion(markdown, version) {
  if (!markdown.startsWith("---\n")) {
    throw new Error("SKILL.md is missing YAML frontmatter");
  }

  const end = markdown.indexOf("\n---", 4);
  if (end === -1) {
    throw new Error("SKILL.md frontmatter is not closed");
  }

  const frontmatter = markdown.slice(0, end);
  if (!/^version:\s*.+$/m.test(frontmatter)) {
    throw new Error("SKILL.md frontmatter is missing a version field");
  }

  return markdown.replace(/^version:\s*.+$/m, `version: ${version}`);
}

async function addSimulatedChangelogEntry(skillDir, version) {
  const changelogPath = path.join(skillDir, "CHANGELOG.md");
  if (!existsSync(changelogPath)) {
    return;
  }

  const today = new Date().toISOString().slice(0, 10);
  const original = await readFile(changelogPath, "utf8");
  if (original.includes(`## [${version}] -`)) {
    return;
  }

  const entry = [
    `## [${version}] - ${today}`,
    "",
    "- Simulated prerelease build for release-pipeline validation.",
    "",
    "---",
    "",
  ].join("\n");

  await writeFile(changelogPath, `${entry}${original}`);
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

async function signFileBase64({ keyPath, inputPath, outputPath, tempRoot }) {
  const sigBin = path.join(tempRoot, `${path.basename(outputPath)}.bin`);
  run("openssl", ["pkeyutl", "-sign", "-rawin", "-inkey", keyPath, "-in", inputPath, "-out", sigBin]);
  run("openssl", ["base64", "-A", "-in", sigBin, "-out", outputPath]);
  await rm(sigBin, { force: true });
}

async function verifyFileBase64Signature({ publicKeyPath, inputPath, signaturePath, tempRoot }) {
  const sigBin = path.join(tempRoot, `${path.basename(signaturePath)}.verify.bin`);
  run("openssl", ["base64", "-d", "-A", "-in", signaturePath, "-out", sigBin]);
  run("openssl", [
    "pkeyutl",
    "-verify",
    "-rawin",
    "-pubin",
    "-inkey",
    publicKeyPath,
    "-sigfile",
    sigBin,
    "-in",
    inputPath,
  ]);
  await rm(sigBin, { force: true });
}

async function createSigningKeyPair(tempRoot) {
  const keyDir = await mkdtemp(path.join(tempRoot, "signing-"));
  const privateKeyPath = path.join(keyDir, "private.pem");
  const publicKeyPath = path.join(keyDir, "public.pem");

  run("openssl", ["genpkey", "-algorithm", "ED25519", "-out", privateKeyPath]);
  run("openssl", ["pkey", "-in", privateKeyPath, "-pubout", "-out", publicKeyPath]);

  return { privateKeyPath, publicKeyPath };
}

async function signAdvisoryArtifacts(skillDir, tempRoot) {
  const advisoryDir = path.join(skillDir, "advisories");
  const feedPath = path.join(advisoryDir, "feed.json");
  if (!existsSync(feedPath)) {
    return;
  }

  const { privateKeyPath, publicKeyPath } = await createSigningKeyPair(tempRoot);
  const feedSignaturePath = path.join(advisoryDir, "feed.json.sig");
  const checksumsPath = path.join(advisoryDir, "checksums.json");
  const checksumsSignaturePath = path.join(advisoryDir, "checksums.json.sig");
  const publicKeyOutputPath = path.join(advisoryDir, "feed-signing-public.pem");

  await signFileBase64({
    keyPath: privateKeyPath,
    inputPath: feedPath,
    outputPath: feedSignaturePath,
    tempRoot,
  });
  await verifyFileBase64Signature({
    publicKeyPath,
    inputPath: feedPath,
    signaturePath: feedSignaturePath,
    tempRoot,
  });

  await writeJson(checksumsPath, {
    schema_version: "1",
    algorithm: "sha256",
    version: "simulation",
    generated_at: new Date().toISOString(),
    files: {
      "advisories/feed.json": await checksumEntry(feedPath, "advisories/feed.json"),
      "advisories/feed.json.sig": await checksumEntry(feedSignaturePath, "advisories/feed.json.sig"),
    },
  });

  await signFileBase64({
    keyPath: privateKeyPath,
    inputPath: checksumsPath,
    outputPath: checksumsSignaturePath,
    tempRoot,
  });
  await verifyFileBase64Signature({
    publicKeyPath,
    inputPath: checksumsPath,
    signaturePath: checksumsSignaturePath,
    tempRoot,
  });

  await cp(publicKeyPath, publicKeyOutputPath);
}

async function addReleaseAssetChecksum({ releaseAssetsDir, manifest, asset }) {
  const filePath = path.join(releaseAssetsDir, asset);
  if (!existsSync(filePath) || (await fileSize(filePath)) === 0) {
    throw new Error(`Required release trust artifact is missing or empty: ${filePath}`);
  }

  manifest.files[asset] = await checksumEntry(filePath, asset);
}

async function stageSbomFiles({ skillDir, innerDir, sbomFiles }) {
  for (const entry of sbomFiles) {
    const releasePath = normalizeReleasePath(entry.path);
    if (isTestReleasePath(releasePath)) {
      continue;
    }

    const fullPath = path.join(skillDir, releasePath);
    if (!existsSync(fullPath)) {
      throw new Error(`SBOM references missing file: ${releasePath}`);
    }

    const destination = path.join(innerDir, releasePath);
    await mkdir(path.dirname(destination), { recursive: true });
    await cp(fullPath, destination);
  }
}

async function buildFilesManifest({ skillDir, skillJsonPath, sbomFiles }) {
  const files = {};
  for (const entry of sbomFiles) {
    const releasePath = normalizeReleasePath(entry.path);
    if (isTestReleasePath(releasePath)) {
      continue;
    }

    const fullPath = path.join(skillDir, releasePath);
    if (existsSync(fullPath)) {
      files[releasePath] = await checksumEntry(fullPath, releasePath);
    }
  }

  files["skill.json"] = {
    sha256: await sha256File(skillJsonPath),
    size: await fileSize(skillJsonPath),
  };

  return files;
}

async function runSkillSpector({ skillspectorBin, skillDir, reportPath }) {
  const result = runAllowFailure(skillspectorBin, [
    "scan",
    skillDir,
    "--no-llm",
    "--format",
    "markdown",
    "--output",
    reportPath,
  ]);

  if (!existsSync(reportPath) || (await fileSize(reportPath)) === 0) {
    throw new Error(
      [
        "SkillSpector did not produce a report.",
        result.stdout ? `stdout:\n${result.stdout}` : "",
        result.stderr ? `stderr:\n${result.stderr}` : "",
      ].filter(Boolean).join("\n"),
    );
  }

  if (result.status !== 0) {
    console.warn(`SkillSpector returned exit code ${result.status}; report is included for review.`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const sourceSkillDir = path.resolve(args.skillDir);
  const outputDir = path.resolve(args.outputDir);
  const releaseAssetsDir = path.join(outputDir, "release-assets");
  const tempRoot = await mkdtemp(path.join(tmpdir(), "clawsec-release-sim-"));

  try {
    const skillName = path.basename(sourceSkillDir);
    const tempSkillDir = path.join(tempRoot, skillName);
    await cp(sourceSkillDir, tempSkillDir, { recursive: true });

    const skillJsonPath = path.join(tempSkillDir, "skill.json");
    const skillMdPath = path.join(tempSkillDir, "SKILL.md");
    const skill = JSON.parse(await readFile(skillJsonPath, "utf8"));
    const originalVersion = skill.version;
    const simulatedVersion = nextSimulatedReleaseVersion(originalVersion);
    const tag = `${skillName}-v${simulatedVersion}`;
    const zipName = `${tag}.zip`;

    skill.version = simulatedVersion;
    await writeJson(skillJsonPath, skill);
    await writeFile(
      skillMdPath,
      replaceSkillMarkdownVersion(await readFile(skillMdPath, "utf8"), simulatedVersion),
    );
    await addSimulatedChangelogEntry(tempSkillDir, simulatedVersion);
    await signAdvisoryArtifacts(tempSkillDir, tempRoot);

    if (!skill.sbom || !Array.isArray(skill.sbom.files)) {
      throw new Error(`skill.json missing required release field: sbom.files`);
    }

    await mkdir(releaseAssetsDir, { recursive: true });

    const stagingDir = await mkdtemp(path.join(tempRoot, "staging-"));
    const innerDir = path.join(stagingDir, skillName);
    await mkdir(innerDir, { recursive: true });
    await stageSbomFiles({
      skillDir: tempSkillDir,
      innerDir,
      sbomFiles: skill.sbom.files,
    });
    await cp(skillJsonPath, path.join(innerDir, "skill.json"));

    run("python3", ["scripts/ci/verify_skill_release_import_closure.py", innerDir], {
      cwd: process.cwd(),
    });

    run("zip", ["-qr", path.join(releaseAssetsDir, zipName), "."], {
      cwd: stagingDir,
    });

    const zipContents = run("unzip", ["-Z1", path.join(releaseAssetsDir, zipName)]);
    if (zipContents.split("\n").some((entry) => /(^|\/)(test|tests)\//i.test(entry))) {
      throw new Error(`Simulated release archive contains test-only files: ${zipName}`);
    }

    const manifest = {
      skill: skillName,
      version: simulatedVersion,
      generated_at: new Date().toISOString(),
      repository: args.repository,
      tag,
      archive: {
        filename: zipName,
        sha256: await sha256File(path.join(releaseAssetsDir, zipName)),
        size: await fileSize(path.join(releaseAssetsDir, zipName)),
        url: `https://github.com/${args.repository}/releases/download/${tag}/${zipName}`,
      },
      files: await buildFilesManifest({
        skillDir: tempSkillDir,
        skillJsonPath,
        sbomFiles: skill.sbom.files,
      }),
    };

    await writeJson(path.join(releaseAssetsDir, "checksums.json"), manifest);

    run(process.execPath, [
      "scripts/ci/generate_skill_release_trust_packet.mjs",
      tempSkillDir,
      releaseAssetsDir,
      "--repository",
      args.repository,
      "--tag",
      tag,
      "--source-ref",
      args.sourceRef,
    ]);

    await runSkillSpector({
      skillspectorBin: args.skillspectorBin,
      skillDir: tempSkillDir,
      reportPath: path.join(releaseAssetsDir, "skillspector-report.md"),
    });

    for (const artifact of TRUST_ARTIFACTS) {
      await addReleaseAssetChecksum({ releaseAssetsDir, manifest, asset: artifact });
    }
    await writeJson(path.join(releaseAssetsDir, "checksums.json"), manifest);

    await cp(skillJsonPath, path.join(releaseAssetsDir, "skill.json"));
    await cp(skillMdPath, path.join(releaseAssetsDir, "SKILL.md"));
    if (existsSync(path.join(tempSkillDir, "README.md"))) {
      await cp(path.join(tempSkillDir, "README.md"), path.join(releaseAssetsDir, "README.md"));
    }

    const { privateKeyPath, publicKeyPath } = await createSigningKeyPair(tempRoot);
    await signFileBase64({
      keyPath: privateKeyPath,
      inputPath: path.join(releaseAssetsDir, "checksums.json"),
      outputPath: path.join(releaseAssetsDir, "checksums.sig"),
      tempRoot,
    });
    await verifyFileBase64Signature({
      publicKeyPath,
      inputPath: path.join(releaseAssetsDir, "checksums.json"),
      signaturePath: path.join(releaseAssetsDir, "checksums.sig"),
      tempRoot,
    });
    await cp(publicKeyPath, path.join(releaseAssetsDir, "signing-public.pem"));

    await writeJson(path.join(outputDir, "simulation-summary.json"), {
      skill: skillName,
      original_version: originalVersion,
      simulated_version: simulatedVersion,
      tag,
      release_assets: path.relative(outputDir, releaseAssetsDir),
      archive: `release-assets/${zipName}`,
    });

    console.log(`Simulated tag release build for ${skillName}: ${tag}`);
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
