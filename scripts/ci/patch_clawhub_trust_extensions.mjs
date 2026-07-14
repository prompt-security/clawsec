#!/usr/bin/env node

import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REQUIRED_TRUST_EXTENSIONS = ["pem", "sig"];
const REQUIRED_TRUST_CONTENT_TYPE = "text/plain";

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

function resolveSkillsPath(cliPrefix) {
  return path.join(
    path.resolve(cliPrefix),
    "node_modules",
    "clawhub",
    "dist",
    "skills.js",
  );
}

function extensionPattern(extension) {
  return new RegExp(`["']${extension}["']\\s*,`);
}

function patchTextFileExtensions(original, textFilesPath) {
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
    return { source: original, patched: false };
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

  return { source: patched, patched: true };
}

function patchTrustMimeTypes(original, skillsPath) {
  const originalAssignment = /const contentType = mime\.getType\(relPath\) \?\? (["'])text\/plain\1;/;
  const extensions = JSON.stringify(REQUIRED_TRUST_EXTENSIONS);
  // ClawHub validates upload MIME types separately from its extension allowlist.
  // The mime package classifies .sig/.pem as non-text even though these files are ASCII here.
  const patchedAssignment = `const contentType = ${extensions}.includes(ext) ? "${REQUIRED_TRUST_CONTENT_TYPE}" : (mime.getType(relPath) ?? "text/plain");`;

  if (original.includes(patchedAssignment)) {
    return { source: original, patched: false };
  }
  if (!originalAssignment.test(original)) {
    throw new Error(`Could not find ClawHub MIME assignment in ${skillsPath}`);
  }

  const patched = original.replace(originalAssignment, patchedAssignment);
  if (!patched.includes(patchedAssignment)) {
    throw new Error(`Failed to force trust artifacts to ${REQUIRED_TRUST_CONTENT_TYPE}`);
  }
  return { source: patched, patched: true };
}

export async function patchClawhubTrustExtensions(cliPrefix) {
  const textFilesPath = resolveTextFilesPath(cliPrefix);
  const skillsPath = resolveSkillsPath(cliPrefix);
  if (!existsSync(textFilesPath)) {
    throw new Error(`ClawHub text-file schema not found: ${textFilesPath}`);
  }
  if (!existsSync(skillsPath)) {
    throw new Error(`ClawHub skill collector not found: ${skillsPath}`);
  }

  const textFilesPatch = patchTextFileExtensions(
    await readFile(textFilesPath, "utf8"),
    textFilesPath,
  );
  const skillsPatch = patchTrustMimeTypes(
    await readFile(skillsPath, "utf8"),
    skillsPath,
  );
  if (textFilesPatch.patched) {
    await writeFile(textFilesPath, textFilesPatch.source, "utf8");
  }
  if (skillsPatch.patched) {
    await writeFile(skillsPath, skillsPatch.source, "utf8");
  }

  return {
    patched: textFilesPatch.patched || skillsPatch.patched,
    path: textFilesPath,
    paths: { textFiles: textFilesPath, skills: skillsPath },
    extensions: REQUIRED_TRUST_EXTENSIONS,
    contentType: REQUIRED_TRUST_CONTENT_TYPE,
  };
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
  process.stdout.write(
    `[patch-clawhub-trust] ${action}: ${result.paths.textFiles}, ${result.paths.skills}\n`,
  );
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
