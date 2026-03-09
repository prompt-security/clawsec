#!/usr/bin/env node

import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

function resolvePublishScriptPath() {
  const override = process.argv[2];
  if (override) return path.resolve(override);

  const npmRoot = execSync("npm root -g", { encoding: "utf8" }).trim();
  return path.join(npmRoot, "clawhub", "dist", "cli", "commands", "publish.js");
}

function main() {
  const publishScriptPath = resolvePublishScriptPath();

  if (!fs.existsSync(publishScriptPath)) {
    throw new Error(`clawhub publish script not found: ${publishScriptPath}`);
  }

  const original = fs.readFileSync(publishScriptPath, "utf8");

  if (original.includes("acceptLicenseTerms: true")) {
    console.log(`[patch-clawhub] Already patched: ${publishScriptPath}`);
    return;
  }

  const payloadPattern = /changelog,\r?\n(\s*)tags,/;
  if (!payloadPattern.test(original)) {
    throw new Error(
      `[patch-clawhub] Could not find expected publish payload pattern in ${publishScriptPath}`
    );
  }

  const patched = original.replace(
    payloadPattern,
    (_, indent) => `changelog,\n${indent}acceptLicenseTerms: true,\n${indent}tags,`
  );

  if (!patched.includes("acceptLicenseTerms: true")) {
    throw new Error(`[patch-clawhub] Patch verification failed for ${publishScriptPath}`);
  }

  fs.writeFileSync(publishScriptPath, patched, "utf8");
  console.log(`[patch-clawhub] Patched: ${publishScriptPath}`);
}

main();
