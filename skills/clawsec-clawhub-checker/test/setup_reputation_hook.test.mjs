#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createTempDir, pass, fail, report, exitWithResults } from "../../clawsec-suite/test/lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NODE_BIN = process.execPath;
const SCRIPT_PATH = path.resolve(__dirname, "..", "scripts", "setup_reputation_hook.mjs");
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

async function runScript(env) {
  return await new Promise((resolve) => {
    const proc = spawn(NODE_BIN, [SCRIPT_PATH], {
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

async function stageInstalledSkill(tempHome, skillName) {
  const sourceDir = path.join(REPO_ROOT, "skills", skillName);
  const destDir = path.join(tempHome, ".openclaw", "skills", skillName);
  await fs.mkdir(path.dirname(destDir), { recursive: true });
  await fs.cp(sourceDir, destDir, { recursive: true });
  return destDir;
}

async function testPreflightSummaryNoMutation() {
  const testName = "setup_reputation_hook: prints preflight review without mutating installed suite files";
  const tmp = await createTempDir();
  const homeDir = path.join(tmp.path, "home");

  try {
    await stageInstalledSkill(homeDir, "clawsec-suite");
    await stageInstalledSkill(homeDir, "clawsec-clawhub-checker");

    const result = await runScript({
      ...process.env,
      HOME: homeDir,
    });

    if (result.code !== 0) {
      fail(testName, `script failed: ${result.stderr}`);
      return;
    }

    const wrapperPath = path.join(
      homeDir,
      ".openclaw",
      "skills",
      "clawsec-suite",
      "scripts",
      "guarded_skill_install_wrapper.mjs",
    );
    const reputationModulePath = path.join(
      homeDir,
      ".openclaw",
      "skills",
      "clawsec-suite",
      "hooks",
      "clawsec-advisory-guardian",
      "lib",
      "reputation.mjs",
    );
    const wrapperExists = await fs
      .access(wrapperPath)
      .then(() => true)
      .catch(() => false);
    const reputationModuleExists = await fs
      .access(reputationModulePath)
      .then(() => true)
      .catch(() => false);

    if (
      result.stdout.includes("Preflight review:") &&
      result.stdout.includes("does not rewrite files in other skills") &&
      result.stdout.includes("Recommended command:") &&
      result.stdout.includes("alias clawsec-guarded-install") &&
      wrapperExists === false &&
      reputationModuleExists === false
    ) {
      pass(testName);
    } else {
      fail(testName, `missing preflight detail: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    await tmp.cleanup();
  }
}

async function runAllTests() {
  await testPreflightSummaryNoMutation();
  report();
  exitWithResults();
}

runAllTests().catch((err) => {
  console.error("Test runner failed:", err);
  process.exit(1);
});
