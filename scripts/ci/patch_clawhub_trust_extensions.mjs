#!/usr/bin/env node

import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REQUIRED_TRUST_EXTENSIONS = ["pem", "sig"];

function resolveTextFilesPath(cliPrefix) {
  return path.join(
    path.resolve(cliPrefix),
    "node_modules",
    "clawhub",
    "dist",
    "schema",
    "textFiles.js",
  );
}

function extensionPattern(extension) {
  return new RegExp(`["']${extension}["']\\s*,`);
}

export async function patchClawhubTrustExtensions(cliPrefix) {
  const textFilesPath = resolveTextFilesPath(cliPrefix);
  if (!existsSync(textFilesPath)) {
    throw new Error(`ClawHub text-file schema not found: ${textFilesPath}`);
  }

  const original = await readFile(textFilesPath, "utf8");
  const listPattern = /(const RAW_TEXT_FILE_EXTENSIONS\s*=\s*\[)([\s\S]*?)(\n\s*\];)/;
  const match = original.match(listPattern);
  if (!match) {
    throw new Error(`Could not find ClawHub text extension allowlist in ${textFilesPath}`);
  }

  const entries = match[2];
  const missingExtensions = REQUIRED_TRUST_EXTENSIONS.filter(
    (extension) => !extensionPattern(extension).test(entries),
  );
  if (missingExtensions.length === 0) {
    return { patched: false, path: textFilesPath, extensions: REQUIRED_TRUST_EXTENSIONS };
  }

  const indentation = entries.match(/\n([ \t]+)["']/)?.[1] ?? "    ";
  const quote = entries.match(/["']/)?.[0] ?? "'";
  const additions = missingExtensions
    .map((extension) => `${indentation}${quote}${extension}${quote},`)
    .join("\n");
  const patchedEntries = `${entries.replace(/\s*$/, "")}\n${additions}`;
  const patched = original.replace(listPattern, `$1${patchedEntries}$3`);

  const verifiedEntries = patched.match(listPattern)?.[2] ?? "";
  for (const extension of REQUIRED_TRUST_EXTENSIONS) {
    if (!extensionPattern(extension).test(verifiedEntries)) {
      throw new Error(`Failed to add .${extension} to ClawHub text extension allowlist`);
    }
  }

  await writeFile(textFilesPath, patched, "utf8");
  return { patched: true, path: textFilesPath, extensions: REQUIRED_TRUST_EXTENSIONS };
}

async function main() {
  const prefixIndex = process.argv.indexOf("--cli-prefix");
  if (prefixIndex !== -1 && !process.argv[prefixIndex + 1]) {
    throw new Error("--cli-prefix requires a directory");
  }
  const cliPrefix = prefixIndex === -1
    ? (process.env.CLAWHUB_CLI_PREFIX || ".github/clawhub-cli")
    : process.argv[prefixIndex + 1];
  const result = await patchClawhubTrustExtensions(cliPrefix);
  const action = result.patched ? "Patched" : "Already patched";
  process.stdout.write(`[patch-clawhub-trust] ${action}: ${result.path}\n`);
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
