import fs from "node:fs";
import path from "node:path";

const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
const npmRoot = path.join(workspace, ".github", "clawhub-cli", "node_modules");
const publishScriptPath = path.join(
  npmRoot,
  "clawhub",
  "dist",
  "cli",
  "commands",
  "publish.js",
);

if (!fs.existsSync(publishScriptPath)) {
  throw new Error(`clawhub publish script not found: ${publishScriptPath}`);
}

const original = fs.readFileSync(publishScriptPath, "utf8");
if (original.includes("acceptLicenseTerms: true")) {
  console.log(`[patch-clawhub] Already patched: ${publishScriptPath}`);
  process.exit(0);
}

const payloadPattern = /changelog,\r?\n(\s*)tags,/;
if (!payloadPattern.test(original)) {
  throw new Error(`[patch-clawhub] Could not find expected publish payload pattern in ${publishScriptPath}`);
}

const patched = original.replace(
  payloadPattern,
  (_, indent) => `changelog,\n${indent}acceptLicenseTerms: true,\n${indent}tags,`,
);
fs.writeFileSync(publishScriptPath, patched, "utf8");
console.log(`[patch-clawhub] Patched: ${publishScriptPath}`);
