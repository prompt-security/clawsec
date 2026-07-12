#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CHECKSUM_ALIAS = "advisories/checksums.json";
const CHECKSUM_SIGNATURE_ALIAS = "advisories/checksums.json.sig";
const PUBLIC_KEY_ALIAS = "advisories/feed-signing-public.pem";

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

async function requireFile(filePath) {
  const stat = await fs.stat(filePath).catch(() => null);
  if (!stat?.isFile()) {
    throw new Error(`required file is missing: ${filePath}`);
  }
}

async function assertSameFile(firstPath, secondPath) {
  const [first, second] = await Promise.all([fs.readFile(firstPath), fs.readFile(secondPath)]);
  if (!first.equals(second)) {
    throw new Error(`files differ: ${firstPath} != ${secondPath}`);
  }
}

export async function generateAdvisoryChecksums({
  publicDir = "public",
  repository = process.env.GITHUB_REPOSITORY || "prompt-security/clawsec",
  generatedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
} = {}) {
  const advisoryDir = path.join(publicDir, "advisories");
  const entries = await fs.readdir(advisoryDir, { withFileTypes: true });
  const artifactNames = entries
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((name) => name.endsWith(".json") || name.endsWith(".json.sig"))
    .filter((name) => name !== "checksums.json" && name !== "checksums.json.sig")
    .sort((left, right) => left.localeCompare(right));

  if (artifactNames.length === 0) {
    throw new Error(`no advisory JSON artifacts found in ${advisoryDir}`);
  }

  const files = {};
  for (const name of artifactNames) {
    const absolutePath = path.join(advisoryDir, name);
    const content = await fs.readFile(absolutePath);
    const relativePath = path.posix.join("advisories", name);
    files[relativePath] = {
      sha256: sha256(content),
      size: content.byteLength,
      path: relativePath,
      url: `https://clawsec.prompt.security/${relativePath}`,
    };
  }

  const manifest = {
    schema_version: "1",
    algorithm: "sha256",
    version: "1.1.0",
    generated_at: generatedAt,
    repository,
    files,
  };
  const outputPath = path.join(publicDir, "checksums.json");
  await fs.writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return { manifest, outputPath };
}

export async function publishAdvisoryAliases({ publicDir = "public" } = {}) {
  const aliases = [
    ["checksums.json", CHECKSUM_ALIAS],
    ["checksums.sig", CHECKSUM_SIGNATURE_ALIAS],
    ["signing-public.pem", PUBLIC_KEY_ALIAS],
  ];

  await Promise.all(aliases.map(([source]) => requireFile(path.join(publicDir, source))));
  await fs.mkdir(path.join(publicDir, "advisories"), { recursive: true });

  for (const [source, destination] of aliases) {
    const sourcePath = path.join(publicDir, source);
    const destinationPath = path.join(publicDir, destination);
    await fs.copyFile(sourcePath, destinationPath);
    await assertSameFile(sourcePath, destinationPath);
  }
}

export async function verifyBuiltAdvisoryArtifacts({ publicDir = "public", distDir = "dist" } = {}) {
  const requiredArtifacts = [
    "checksums.json",
    "checksums.sig",
    "signing-public.pem",
    "advisories/feed.json",
    "advisories/feed.json.sig",
    CHECKSUM_ALIAS,
    CHECKSUM_SIGNATURE_ALIAS,
    PUBLIC_KEY_ALIAS,
  ];

  if (await fs.stat(path.join(publicDir, "advisories/ghsa-without-cve.json")).catch(() => null)) {
    requiredArtifacts.push("advisories/ghsa-without-cve.json", "advisories/ghsa-without-cve.json.sig");
  }

  for (const relativePath of requiredArtifacts) {
    const publicPath = path.join(publicDir, relativePath);
    const distPath = path.join(distDir, relativePath);
    await requireFile(publicPath);
    await requireFile(distPath);
    await assertSameFile(publicPath, distPath);
  }

  await assertSameFile(path.join(distDir, "checksums.json"), path.join(distDir, CHECKSUM_ALIAS));
  await assertSameFile(path.join(distDir, "checksums.sig"), path.join(distDir, CHECKSUM_SIGNATURE_ALIAS));
  await assertSameFile(path.join(distDir, "signing-public.pem"), path.join(distDir, PUBLIC_KEY_ALIAS));
}

function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    const value = args[index + 1];
    if (!value || !option.startsWith("--")) {
      throw new Error(`invalid option: ${option}`);
    }
    if (option === "--public-dir") options.publicDir = value;
    else if (option === "--dist-dir") options.distDir = value;
    else if (option === "--repository") options.repository = value;
    else throw new Error(`unknown option: ${option}`);
    index += 1;
  }
  return options;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  const options = parseOptions(args);
  if (command === "generate") {
    const { outputPath } = await generateAdvisoryChecksums(options);
    process.stdout.write(`Generated ${outputPath}\n`);
  } else if (command === "publish-aliases") {
    await publishAdvisoryAliases(options);
    process.stdout.write("Published advisory checksum and signing-key aliases\n");
  } else if (command === "verify-built") {
    await verifyBuiltAdvisoryArtifacts(options);
    process.stdout.write("Verified built advisory artifacts\n");
  } else {
    throw new Error("usage: advisory_pages_artifacts.mjs <generate|publish-aliases|verify-built> [options]");
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
  });
}
