#!/usr/bin/env node

import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
} from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const CLAWHUB_TEXT_EXTENSIONS = new Set([
  "c", "cfg", "cjs", "cpp", "cs", "css", "csv", "env", "go", "h", "hpp",
  "html", "ini", "java", "js", "json", "json5", "jsx", "kt", "md", "mdx",
  "mjs", "pem", "py", "rb", "rs", "sass", "scss", "sh", "sig", "sql", "svg",
  "swift", "toml", "ts", "tsx", "txt", "xml", "yaml", "yml",
]);
const ADVISORY_TRUST_ARTIFACTS = [
  "advisories/feed.json",
  "advisories/feed.json.sig",
  "advisories/checksums.json",
  "advisories/checksums.json.sig",
  "advisories/feed-signing-public.pem",
];

function usage() {
  return [
    "Usage:",
    "  node scripts/ci/clawhub_release_package.mjs prepare --release-dir <dir> --output-dir <dir> --skill <name> --version <semver> --canonical-key <pem>",
    "  node scripts/ci/clawhub_release_package.mjs verify-client-selection --package-dir <dir> --cli-prefix <dir>",
    "  node scripts/ci/clawhub_release_package.mjs verify-published --package-dir <dir> --inspect-json <file> --version <semver>",
    "  node scripts/ci/clawhub_release_package.mjs verify-registry --package-dir <dir> --slug <slug> --version <semver>",
  ].join("\n");
}

function parseOptions(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      throw new Error(`Unexpected argument: ${token}\n${usage()}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for ${token}\n${usage()}`);
    }
    options[token.slice(2)] = value;
    index += 1;
  }
  return options;
}

function requireOptions(options, names) {
  for (const name of names) {
    if (!options[name]) {
      throw new Error(`Missing required option --${name}\n${usage()}`);
    }
  }
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

function publicKeyFingerprint(publicKeyPem) {
  const publicKey = createPublicKey(publicKeyPem);
  return sha256(publicKey.export({ type: "spki", format: "der" }));
}

function decodeBase64Signature(rawSignature, label) {
  const normalized = String(rawSignature ?? "").trim().replace(/\s+/g, "");
  if (!normalized || !/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) {
    throw new Error(`${label} is not a valid base64 signature`);
  }
  return Buffer.from(normalized, "base64");
}

function run(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
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

function normalizeArchiveEntry(entry) {
  const normalized = String(entry ?? "").trim().replace(/\/+$/, "");
  if (
    !normalized
    || normalized.includes("\\")
    || normalized.startsWith("/")
    || /^[A-Za-z]:/.test(normalized)
    || normalized === ".."
    || normalized.startsWith("../")
    || normalized.endsWith("/..")
    || normalized.includes("/../")
  ) {
    throw new Error(`Unsafe release archive entry: ${entry}`);
  }
  return normalized;
}

export async function collectPackageFiles(rootDir) {
  const files = new Map();

  async function visit(currentDir, relativeDir = "") {
    const entries = await readdir(currentDir, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relativePath = path.posix.join(relativeDir.replaceAll("\\", "/"), entry.name);
      const metadata = await lstat(fullPath);
      if (metadata.isSymbolicLink()) {
        throw new Error(`ClawHub package must not contain symbolic links: ${relativePath}`);
      }
      if (metadata.isDirectory()) {
        await visit(fullPath, relativePath);
        continue;
      }
      if (!metadata.isFile()) {
        throw new Error(`ClawHub package contains unsupported entry type: ${relativePath}`);
      }
      const content = await readFile(fullPath);
      files.set(relativePath, {
        path: relativePath,
        sha256: sha256(content),
        size: content.length,
      });
    }
  }

  await visit(rootDir);
  return files;
}

export async function collectClawhubPackageFiles(rootDir) {
  const packageFiles = await collectPackageFiles(rootDir);
  const skill = JSON.parse(await readFile(path.join(rootDir, "skill.json"), "utf8"));
  const optionalPlaceholders = new Set(
    (skill.sbom?.files ?? [])
      .filter((entry) => entry.required === false && path.posix.basename(entry.path) === ".gitkeep")
      .map((entry) => entry.path.replaceAll("\\", "/").replace(/^\.\//, "")),
  );
  const publishedFiles = new Map();

  for (const [filePath, metadata] of packageFiles) {
    const parts = filePath.split("/");
    const extension = path.posix.extname(filePath).slice(1).toLowerCase();
    const clientWouldOmit = parts.some((part) => part.startsWith("."))
      || !extension
      || !CLAWHUB_TEXT_EXTENSIONS.has(extension);

    if (!clientWouldOmit) {
      publishedFiles.set(filePath, metadata);
      continue;
    }
    if (optionalPlaceholders.has(filePath)) {
      continue;
    }
    throw new Error(
      `ClawHub client would omit non-placeholder package file: ${filePath}`,
    );
  }

  return publishedFiles;
}

async function verifyEmbeddedAdvisoryTrust(packageDir, releaseKeyFingerprint, required) {
  const advisoryDir = path.join(packageDir, "advisories");
  const feedPath = path.join(advisoryDir, "feed.json");
  try {
    await stat(feedPath);
  } catch (error) {
    if (error?.code === "ENOENT" && !required) return { verified: false, files: 0 };
    if (error?.code === "ENOENT") {
      throw new Error("Embedded advisory trust artifact is missing: advisories/feed.json");
    }
    throw error;
  }

  if (!required) {
    return { verified: false, files: 1 };
  }

  const requiredArtifacts = ADVISORY_TRUST_ARTIFACTS.map((artifact) => artifact.slice("advisories/".length));
  for (const artifact of requiredArtifacts) {
    const artifactPath = path.join(advisoryDir, artifact);
    const metadata = await stat(artifactPath).catch(() => null);
    if (!metadata?.isFile() || metadata.size === 0) {
      throw new Error(`Embedded advisory trust artifact is missing or empty: advisories/${artifact}`);
    }
  }

  const feedRaw = await readFile(feedPath);
  const feedSignatureRaw = await readFile(path.join(advisoryDir, "feed.json.sig"), "utf8");
  const checksumsRaw = await readFile(path.join(advisoryDir, "checksums.json"));
  const checksumsSignatureRaw = await readFile(path.join(advisoryDir, "checksums.json.sig"), "utf8");
  const feedPublicKeyPem = await readFile(path.join(advisoryDir, "feed-signing-public.pem"));
  const feedPublicKey = createPublicKey(feedPublicKeyPem);

  const feedKeyFingerprint = publicKeyFingerprint(feedPublicKeyPem);
  if (feedKeyFingerprint !== releaseKeyFingerprint) {
    throw new Error(
      `Embedded feed key fingerprint ${feedKeyFingerprint} does not match release key ${releaseKeyFingerprint}`,
    );
  }

  if (!verifySignature(
    null,
    feedRaw,
    feedPublicKey,
    decodeBase64Signature(feedSignatureRaw, "advisories/feed.json.sig"),
  )) {
    throw new Error("Embedded advisory feed signature verification failed");
  }

  if (!verifySignature(
    null,
    checksumsRaw,
    feedPublicKey,
    decodeBase64Signature(checksumsSignatureRaw, "advisories/checksums.json.sig"),
  )) {
    throw new Error("Embedded advisory checksum signature verification failed");
  }

  const checksums = JSON.parse(checksumsRaw);
  const expectedFiles = new Map([
    ["advisories/feed.json", feedRaw],
    ["advisories/feed.json.sig", Buffer.from(feedSignatureRaw)],
    ["advisories/feed-signing-public.pem", feedPublicKeyPem],
  ]);
  for (const [entry, content] of expectedFiles) {
    const expected = checksums.files?.[entry];
    if (!expected) {
      throw new Error(`Embedded advisory checksum manifest is missing ${entry}`);
    }
    if (expected.sha256 !== sha256(content) || expected.size !== content.length) {
      throw new Error(`Embedded advisory checksum mismatch for ${entry}`);
    }
  }

  return { verified: true, files: requiredArtifacts.length };
}

export async function prepareReleasePackage({
  releaseDir,
  outputDir,
  skillName,
  version,
  canonicalKeyPath,
}) {
  const resolvedReleaseDir = path.resolve(releaseDir);
  const resolvedOutputDir = path.resolve(outputDir);
  const archiveName = `${skillName}-v${version}.zip`;
  const archivePath = path.join(resolvedReleaseDir, archiveName);
  const checksumsPath = path.join(resolvedReleaseDir, "checksums.json");
  const checksumsSignaturePath = path.join(resolvedReleaseDir, "checksums.sig");
  const releaseKeyPath = path.join(resolvedReleaseDir, "signing-public.pem");

  const [archive, checksumsRaw, checksumsSignatureRaw, releaseKeyPem, canonicalKeyPem] = await Promise.all([
    readFile(archivePath),
    readFile(checksumsPath),
    readFile(checksumsSignaturePath, "utf8"),
    readFile(releaseKeyPath),
    readFile(path.resolve(canonicalKeyPath)),
  ]);

  const releaseKeyFingerprint = publicKeyFingerprint(releaseKeyPem);
  const canonicalKeyFingerprint = publicKeyFingerprint(canonicalKeyPem);
  if (releaseKeyFingerprint !== canonicalKeyFingerprint) {
    throw new Error(
      `Release signing key fingerprint ${releaseKeyFingerprint} does not match canonical key ${canonicalKeyFingerprint}`,
    );
  }

  const releaseKey = createPublicKey(releaseKeyPem);
  if (!verifySignature(
    null,
    checksumsRaw,
    releaseKey,
    decodeBase64Signature(checksumsSignatureRaw, "checksums.sig"),
  )) {
    throw new Error("Release checksums signature verification failed");
  }

  const checksums = JSON.parse(checksumsRaw);
  if (checksums.skill !== skillName || checksums.version !== version) {
    throw new Error(
      `Release manifest identity mismatch: expected ${skillName}@${version}, got ${checksums.skill}@${checksums.version}`,
    );
  }
  if (checksums.archive?.filename !== archiveName) {
    throw new Error(`Release manifest archive mismatch: expected ${archiveName}`);
  }
  if (checksums.archive.sha256 !== sha256(archive) || checksums.archive.size !== archive.length) {
    throw new Error(`Release archive checksum mismatch: ${archiveName}`);
  }

  const archiveEntries = run("unzip", ["-Z1", archivePath])
    .split(/\r?\n/)
    .filter(Boolean)
    .map(normalizeArchiveEntry);
  const expectedPrefix = `${skillName}/`;
  for (const entry of archiveEntries) {
    if (entry !== skillName && !entry.startsWith(expectedPrefix)) {
      throw new Error(`Release archive entry is outside ${expectedPrefix}: ${entry}`);
    }
  }

  await mkdir(resolvedOutputDir, { recursive: true });
  const existingOutputEntries = await readdir(resolvedOutputDir);
  if (existingOutputEntries.length > 0) {
    throw new Error(`ClawHub package output directory must be empty: ${resolvedOutputDir}`);
  }
  const stagingDir = await mkdtemp(path.join(resolvedOutputDir, ".staging-"));
  try {
    run("unzip", ["-q", archivePath, "-d", stagingDir]);

    const packageDir = path.join(stagingDir, skillName);
    const packageMetadata = await stat(packageDir).catch(() => null);
    if (!packageMetadata?.isDirectory()) {
      throw new Error(`Release archive did not create expected package directory: ${packageDir}`);
    }

    const packageFiles = await collectPackageFiles(packageDir);
    for (const [filePath, actual] of packageFiles) {
      const expected = checksums.files?.[filePath];
      if (!expected) {
        throw new Error(`Signed release manifest is missing packaged file: ${filePath}`);
      }
      if (expected.sha256 !== actual.sha256 || expected.size !== actual.size) {
        throw new Error(`Signed release manifest mismatch for packaged file: ${filePath}`);
      }
    }

    const skill = JSON.parse(await readFile(path.join(packageDir, "skill.json"), "utf8"));
    if (skill.version !== version) {
      throw new Error(`Packaged skill.json version mismatch: expected ${version}, got ${skill.version}`);
    }

    const declaredPackageFiles = new Set(
      (skill.sbom?.files ?? []).map((entry) => entry.path.replaceAll("\\", "/").replace(/^\.\//, "")),
    );
    const requiresEmbeddedAdvisoryTrust = ADVISORY_TRUST_ARTIFACTS.every(
      (artifact) => declaredPackageFiles.has(artifact),
    );
    const advisoryTrust = await verifyEmbeddedAdvisoryTrust(
      packageDir,
      releaseKeyFingerprint,
      requiresEmbeddedAdvisoryTrust,
    );
    const clawhubFiles = await collectClawhubPackageFiles(packageDir);
    const finalPackageDir = path.join(resolvedOutputDir, skillName);
    await rename(packageDir, finalPackageDir);
    return {
      packageDir: finalPackageDir,
      files: packageFiles.size,
      clawhubFiles: clawhubFiles.size,
      releaseKeyFingerprint,
      embeddedAdvisoryTrust: advisoryTrust,
    };
  } finally {
    await rm(stagingDir, { recursive: true, force: true });
  }
}

export async function verifyClawhubClientSelection({ packageDir, cliPrefix }) {
  const resolvedPackageDir = path.resolve(packageDir);
  const expectedFiles = await collectClawhubPackageFiles(resolvedPackageDir);
  const skillsModulePath = path.resolve(
    cliPrefix,
    "node_modules",
    "clawhub",
    "dist",
    "skills.js",
  );
  const skillsModule = await import(`${pathToFileURL(skillsModulePath).href}?selection=${Date.now()}`);
  if (typeof skillsModule.listTextFiles !== "function") {
    throw new Error(`ClawHub client does not export listTextFiles: ${skillsModulePath}`);
  }

  const selectedFiles = await skillsModule.listTextFiles(resolvedPackageDir);
  const actualFiles = new Map(selectedFiles.map((entry) => [entry.relPath, {
    path: entry.relPath,
    sha256: sha256(Buffer.from(entry.bytes)),
    size: entry.bytes.byteLength,
  }]));
  if (actualFiles.size !== selectedFiles.length) {
    throw new Error("ClawHub client selected duplicate file paths");
  }

  for (const [filePath, expected] of expectedFiles) {
    const actual = actualFiles.get(filePath);
    if (!actual) {
      throw new Error(`ClawHub client would omit expected package file: ${filePath}`);
    }
    if (actual.sha256 !== expected.sha256 || actual.size !== expected.size) {
      throw new Error(`ClawHub client selected mismatched package file: ${filePath}`);
    }
  }
  for (const filePath of actualFiles.keys()) {
    if (!expectedFiles.has(filePath)) {
      throw new Error(`ClawHub client selected unexpected package file: ${filePath}`);
    }
  }

  return { files: expectedFiles.size };
}

async function verifyPublishedInspect({ packageDir, inspect, version }) {
  const expectedFiles = await collectClawhubPackageFiles(path.resolve(packageDir));
  const publishedVersion = inspect.version?.version;
  if (publishedVersion !== version) {
    throw new Error(`Published ClawHub version mismatch: expected ${version}, got ${publishedVersion}`);
  }

  if (!Array.isArray(inspect.version?.files)) {
    throw new Error("ClawHub inspect response is missing version.files");
  }
  const publishedFiles = new Map(inspect.version.files.map((entry) => [entry.path, entry]));
  if (publishedFiles.size !== inspect.version.files.length) {
    throw new Error("ClawHub inspect response contains duplicate file paths");
  }

  for (const [filePath, expected] of expectedFiles) {
    const published = publishedFiles.get(filePath);
    if (!published) {
      throw new Error(`Published ClawHub package is missing ${filePath}`);
    }
    if (published.sha256 !== expected.sha256 || published.size !== expected.size) {
      throw new Error(`Published ClawHub package mismatch for ${filePath}`);
    }
  }

  for (const filePath of publishedFiles.keys()) {
    if (!expectedFiles.has(filePath)) {
      throw new Error(`Published ClawHub package contains unexpected file: ${filePath}`);
    }
  }

  return { version, files: expectedFiles.size };
}

export async function verifyPublishedPackage({ packageDir, inspectJsonPath, version }) {
  const inspect = JSON.parse(await readFile(path.resolve(inspectJsonPath), "utf8"));
  return verifyPublishedInspect({ packageDir, inspect, version });
}

export async function verifyRegistryPackage({
  packageDir,
  slug,
  version,
  attempts = 6,
  delayMs = 5000,
}) {
  const site = process.env.CLAWHUB_SITE || "https://clawhub.ai";
  const registry = process.env.CLAWHUB_REGISTRY || site;
  let lastError = "";

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const result = spawnSync(
      "clawhub",
      ["inspect", slug, "--version", version, "--json"],
      {
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
        env: {
          ...process.env,
          CLAWHUB_DISABLE_TELEMETRY: "1",
          CLAWHUB_SITE: site,
          CLAWHUB_REGISTRY: registry,
        },
      },
    );
    if (result.status === 0) {
      const inspect = JSON.parse(result.stdout);
      return verifyPublishedInspect({ packageDir, inspect, version });
    }

    lastError = result.stderr || result.stdout || `clawhub inspect exited ${result.status}`;
    if (attempt < attempts) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  throw new Error(`Unable to inspect published ClawHub package after ${attempts} attempts:\n${lastError}`);
}

async function main() {
  const [command, ...argv] = process.argv.slice(2);
  const options = parseOptions(argv);

  if (command === "prepare") {
    requireOptions(options, ["release-dir", "output-dir", "skill", "version", "canonical-key"]);
    const result = await prepareReleasePackage({
      releaseDir: options["release-dir"],
      outputDir: options["output-dir"],
      skillName: options.skill,
      version: options.version,
      canonicalKeyPath: options["canonical-key"],
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  if (command === "verify-published") {
    requireOptions(options, ["package-dir", "inspect-json", "version"]);
    const result = await verifyPublishedPackage({
      packageDir: options["package-dir"],
      inspectJsonPath: options["inspect-json"],
      version: options.version,
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  if (command === "verify-client-selection") {
    requireOptions(options, ["package-dir", "cli-prefix"]);
    const result = await verifyClawhubClientSelection({
      packageDir: options["package-dir"],
      cliPrefix: options["cli-prefix"],
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  if (command === "verify-registry") {
    requireOptions(options, ["package-dir", "slug", "version"]);
    const result = await verifyRegistryPackage({
      packageDir: options["package-dir"],
      slug: options.slug,
      version: options.version,
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  throw new Error(usage());
}

const invokedUrl = process.argv[1]
  ? pathToFileURL(path.resolve(process.argv[1])).href
  : "";
if (import.meta.url === invokedUrl) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exit(1);
  });
}
