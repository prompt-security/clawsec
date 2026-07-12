#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CHECKSUM_ALIAS = "advisories/checksums.json";
const CHECKSUM_SIGNATURE_ALIAS = "advisories/checksums.json.sig";
const PUBLIC_KEY_ALIAS = "advisories/feed-signing-public.pem";

export const ADVISORY_PUBLIC_CONTRACT = Object.freeze([
  "checksums.json",
  "checksums.sig",
  "signing-public.pem",
  "advisories/feed.json",
  "advisories/feed.json.sig",
  CHECKSUM_ALIAS,
  CHECKSUM_SIGNATURE_ALIAS,
  PUBLIC_KEY_ALIAS,
]);

export const RELEASE_MIRROR_MAPPINGS = Object.freeze([
  ["advisories/feed.json", "feed.json"],
  ["advisories/feed.json", "advisories/feed.json"],
  ["advisories/feed.json.sig", "feed.json.sig"],
  ["advisories/feed.json.sig", "advisories/feed.json.sig"],
  ["checksums.json", "checksums.json"],
  ["checksums.sig", "checksums.sig"],
  ["signing-public.pem", "signing-public.pem"],
]);

const OPTIONAL_GHSA_MAPPINGS = Object.freeze([
  ["advisories/ghsa-without-cve.json", "ghsa-without-cve.json"],
  ["advisories/ghsa-without-cve.json", "advisories/ghsa-without-cve.json"],
  ["advisories/ghsa-without-cve.json.sig", "ghsa-without-cve.json.sig"],
  ["advisories/ghsa-without-cve.json.sig", "advisories/ghsa-without-cve.json.sig"],
]);

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

async function fileExists(filePath) {
  const stat = await fs.stat(filePath).catch(() => null);
  return stat?.isFile() === true;
}

async function directoryExists(directoryPath) {
  const stat = await fs.stat(directoryPath).catch(() => null);
  return stat?.isDirectory() === true;
}

async function requireFile(filePath) {
  if (!(await fileExists(filePath))) {
    throw new Error(`required file is missing: ${filePath}`);
  }
}

async function assertSameFile(firstPath, secondPath) {
  const [first, second] = await Promise.all([fs.readFile(firstPath), fs.readFile(secondPath)]);
  if (!first.equals(second)) {
    throw new Error(`files differ: ${firstPath} != ${secondPath}`);
  }
}

async function advisoryMappings(publicDir) {
  const ghsaPath = path.join(publicDir, "advisories/ghsa-without-cve.json");
  if (!(await fileExists(ghsaPath))) return [...RELEASE_MIRROR_MAPPINGS];
  await requireFile(path.join(publicDir, "advisories/ghsa-without-cve.json.sig"));
  return [...RELEASE_MIRROR_MAPPINGS, ...OPTIONAL_GHSA_MAPPINGS];
}

async function copyMappings({ sourceRoot, destinationRoot, mappings }) {
  await Promise.all(mappings.map(([source]) => requireFile(path.join(sourceRoot, source))));
  for (const [source, destination] of mappings) {
    const sourcePath = path.join(sourceRoot, source);
    const destinationPath = path.join(destinationRoot, destination);
    await fs.mkdir(path.dirname(destinationPath), { recursive: true });
    await fs.copyFile(sourcePath, destinationPath);
    await assertSameFile(sourcePath, destinationPath);
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
  await copyMappings({
    sourceRoot: publicDir,
    destinationRoot: publicDir,
    mappings: [
      ["checksums.json", CHECKSUM_ALIAS],
      ["checksums.sig", CHECKSUM_SIGNATURE_ALIAS],
      ["signing-public.pem", PUBLIC_KEY_ALIAS],
    ],
  });
}

export async function publishReleaseCompatibilityMirror({
  publicDir = "public",
  mirrorDir = path.join(publicDir, "releases/latest/download"),
} = {}) {
  const mappings = await advisoryMappings(publicDir);
  await copyMappings({ sourceRoot: publicDir, destinationRoot: mirrorDir, mappings });
}

export async function verifyBuiltAdvisoryArtifacts({ publicDir = "public", distDir = "dist" } = {}) {
  const requiredArtifacts = [...ADVISORY_PUBLIC_CONTRACT];
  if (await fileExists(path.join(publicDir, "advisories/ghsa-without-cve.json"))) {
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

  const publicMirrorDir = path.join(publicDir, "releases/latest/download");
  if (await directoryExists(publicMirrorDir)) {
    const mappings = await advisoryMappings(publicDir);
    for (const [source, destination] of mappings) {
      const sourcePath = path.join(publicDir, source);
      const publicMirrorPath = path.join(publicMirrorDir, destination);
      const distMirrorPath = path.join(distDir, "releases/latest/download", destination);
      await requireFile(publicMirrorPath);
      await requireFile(distMirrorPath);
      await assertSameFile(sourcePath, publicMirrorPath);
      await assertSameFile(publicMirrorPath, distMirrorPath);
    }
  }
}

function verifySignature(payload, signatureRaw, publicKey, label) {
  const signature = Buffer.from(signatureRaw.toString("utf8").trim(), "base64");
  if (!crypto.verify(null, payload, publicKey, signature)) {
    throw new Error(`${label} signature verification failed`);
  }
}

function verifyManifestEntry(manifest, entryName, content) {
  const entry = manifest.files?.[entryName];
  const expected = typeof entry === "string" ? entry : entry?.sha256;
  if (expected !== sha256(content)) {
    throw new Error(`checksum mismatch for ${entryName}`);
  }
}

async function startStaticServer(distDir) {
  const root = path.resolve(distDir);
  const server = http.createServer((request, response) => {
    void (async () => {
      const pathname = decodeURIComponent(new URL(request.url || "/", "http://127.0.0.1").pathname);
      const relativePath = pathname.replace(/^\/+/, "");
      const filePath = path.resolve(root, relativePath);
      if (filePath !== root && !filePath.startsWith(`${root}${path.sep}`)) {
        response.writeHead(400).end("invalid path");
        return;
      }
      const content = await fs.readFile(filePath);
      const contentType = filePath.endsWith(".json")
        ? "application/json"
        : filePath.endsWith(".sig")
          ? "application/pgp-signature"
          : "text/plain";
      response.writeHead(200, { "content-type": contentType }).end(content);
    })().catch((error) => {
      response.writeHead(error?.code === "ENOENT" ? 404 : 500).end(error?.message || String(error));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("failed to start local artifact server");
  return { server, baseUrl: `http://127.0.0.1:${address.port}` };
}

async function stopServer(server) {
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
}

async function fetchArtifact(baseUrl, artifactPath) {
  const response = await globalThis.fetch(`${baseUrl}/${artifactPath}`);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} for /${artifactPath}`);
  }
  return {
    body: Buffer.from(await response.arrayBuffer()),
    contentType: response.headers.get("content-type") || "",
  };
}

export async function smokeTestBuiltAdvisoryEndpoints({ distDir = "dist" } = {}) {
  const { server, baseUrl } = await startStaticServer(distDir);
  try {
    const fetched = new Map();
    for (const artifactPath of ADVISORY_PUBLIC_CONTRACT) {
      fetched.set(artifactPath, await fetchArtifact(baseUrl, artifactPath));
    }
    const hasGhsaFeed = await fileExists(path.join(distDir, "advisories/ghsa-without-cve.json"));
    if (hasGhsaFeed) {
      for (const artifactPath of ["advisories/ghsa-without-cve.json", "advisories/ghsa-without-cve.json.sig"]) {
        fetched.set(artifactPath, await fetchArtifact(baseUrl, artifactPath));
      }
    }

    if (!fetched.get(CHECKSUM_ALIAS).contentType.startsWith("application/json")) {
      throw new Error(`unexpected content type for /${CHECKSUM_ALIAS}`);
    }

    const checksums = fetched.get("checksums.json").body;
    const checksumsSignature = fetched.get("checksums.sig").body;
    const publicKey = fetched.get("signing-public.pem").body;
    verifySignature(checksums, checksumsSignature, publicKey, "checksum manifest");
    verifySignature(
      fetched.get("advisories/feed.json").body,
      fetched.get("advisories/feed.json.sig").body,
      publicKey,
      "advisory feed",
    );

    const manifest = JSON.parse(checksums.toString("utf8"));
    verifyManifestEntry(manifest, "advisories/feed.json", fetched.get("advisories/feed.json").body);
    verifyManifestEntry(manifest, "advisories/feed.json.sig", fetched.get("advisories/feed.json.sig").body);
    if (hasGhsaFeed) {
      verifySignature(
        fetched.get("advisories/ghsa-without-cve.json").body,
        fetched.get("advisories/ghsa-without-cve.json.sig").body,
        publicKey,
        "provisional GHSA feed",
      );
      verifyManifestEntry(
        manifest,
        "advisories/ghsa-without-cve.json",
        fetched.get("advisories/ghsa-without-cve.json").body,
      );
      verifyManifestEntry(
        manifest,
        "advisories/ghsa-without-cve.json.sig",
        fetched.get("advisories/ghsa-without-cve.json.sig").body,
      );
    }

    if (!checksums.equals(fetched.get(CHECKSUM_ALIAS).body)) throw new Error("HTTP checksum alias differs from root");
    if (!checksumsSignature.equals(fetched.get(CHECKSUM_SIGNATURE_ALIAS).body)) {
      throw new Error("HTTP checksum signature alias differs from root");
    }
    if (!publicKey.equals(fetched.get(PUBLIC_KEY_ALIAS).body)) throw new Error("HTTP signing-key alias differs from root");

    const mirrorDir = path.join(distDir, "releases/latest/download");
    if (await directoryExists(mirrorDir)) {
      for (const [source, destination] of await advisoryMappings(distDir)) {
        const [sourceArtifact, mirroredArtifact] = await Promise.all([
          fetchArtifact(baseUrl, source),
          fetchArtifact(baseUrl, `releases/latest/download/${destination}`),
        ]);
        if (!sourceArtifact.body.equals(mirroredArtifact.body)) {
          throw new Error(`HTTP release mirror differs: ${destination}`);
        }
      }
    }
  } finally {
    await stopServer(server);
  }
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
    else if (option === "--mirror-dir") options.mirrorDir = value;
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
  } else if (command === "publish-release-mirror") {
    await publishReleaseCompatibilityMirror(options);
    process.stdout.write("Published release compatibility mirror\n");
  } else if (command === "verify-built") {
    await verifyBuiltAdvisoryArtifacts(options);
    process.stdout.write("Verified built advisory artifacts\n");
  } else if (command === "smoke-http") {
    await smokeTestBuiltAdvisoryEndpoints(options);
    process.stdout.write("Smoke-tested built advisory endpoints over HTTP\n");
  } else {
    throw new Error(
      "usage: advisory_pages_artifacts.mjs <generate|publish-aliases|publish-release-mirror|verify-built|smoke-http> [options]",
    );
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
  });
}
