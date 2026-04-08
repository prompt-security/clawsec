#!/usr/bin/env node

/**
 * Regression tests for clawsec-suite HEARTBEAT Step 1 version checks.
 *
 * Run: node skills/clawsec-suite/test/heartbeat_version_check.test.mjs
 */

import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createTempDir, pass, fail, report, exitWithResults } from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HEARTBEAT_PATH = path.resolve(__dirname, "..", "HEARTBEAT.md");

function extractStepOneScript(markdown) {
  const match = markdown.match(/## Step 1[^\n]*\n\n```bash\n([\s\S]*?)\n```/);
  return match ? match[1] : "";
}

function runShellScript(script, env = {}) {
  return new Promise((resolve) => {
    const proc = spawn("bash", ["-lc", `set -euo pipefail\n${script}`], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

function withServer(handler) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("Failed to bind test server"));
        return;
      }

      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise((done) => {
            server.close(() => done());
          }),
      });
    });

    server.on("error", reject);
  });
}

async function testHeartbeatVersionCheckUsesSuiteVersion() {
  const testName = "heartbeat step 1: does not treat advisory feed version as suite update";
  let fixture = null;
  let tempDir = null;

  try {
    const markdown = await fs.readFile(HEARTBEAT_PATH, "utf8");
    const stepScript = extractStepOneScript(markdown);
    if (!stepScript) {
      fail(testName, "Failed to extract Step 1 shell block from HEARTBEAT.md");
      return;
    }

    tempDir = await createTempDir();
    const installRoot = path.join(tempDir.path, "skills");
    const suiteDir = path.join(installRoot, "clawsec-suite");
    await fs.mkdir(suiteDir, { recursive: true });
    await fs.writeFile(
      path.join(suiteDir, "skill.json"),
      JSON.stringify({ name: "clawsec-suite", version: "0.1.4" }, null, 2),
      "utf8",
    );

    fixture = await withServer((req, res) => {
      if (req.url === "/api/releases") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify([
            { tag_name: "clawsec-scanner-v0.0.2" },
            { tag_name: "clawsec-suite-v0.1.4" },
          ]),
        );
        return;
      }

      if (req.url === "/releases/download/clawsec-suite-v0.1.4/skill.json") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ version: "0.1.4" }));
        return;
      }

      if (req.url === "/checksums.json") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ version: "1.1.0" }));
        return;
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
    });

    const result = await runShellScript(stepScript, {
      INSTALL_ROOT: installRoot,
      SUITE_DIR: suiteDir,
      CHECKSUMS_URL: `${fixture.url}/checksums.json`,
      GITHUB_RELEASES_API: `${fixture.url}/api/releases`,
      RELEASE_DOWNLOAD_BASE_URL: `${fixture.url}/releases/download`,
    });

    if (result.code !== 0) {
      fail(testName, `Expected exit 0, got ${result.code}: ${result.stderr}`);
      return;
    }

    if (result.stdout.includes("UPDATE AVAILABLE")) {
      fail(testName, `Unexpected update reported:\n${result.stdout}`);
      return;
    }

    if (!result.stdout.includes("Suite appears up to date.")) {
      fail(testName, `Expected up-to-date message. Output:\n${result.stdout}`);
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.close();
    }
    if (tempDir) {
      await tempDir.cleanup();
    }
  }
}

async function testHeartbeatVersionCheckFallbackDoesNotFalseAlert() {
  const testName = "heartbeat step 1: release metadata failure warns without false update alert";
  let fixture = null;
  let tempDir = null;

  try {
    const markdown = await fs.readFile(HEARTBEAT_PATH, "utf8");
    const stepScript = extractStepOneScript(markdown);
    if (!stepScript) {
      fail(testName, "Failed to extract Step 1 shell block from HEARTBEAT.md");
      return;
    }

    tempDir = await createTempDir();
    const installRoot = path.join(tempDir.path, "skills");
    const suiteDir = path.join(installRoot, "clawsec-suite");
    await fs.mkdir(suiteDir, { recursive: true });
    await fs.writeFile(
      path.join(suiteDir, "skill.json"),
      JSON.stringify({ name: "clawsec-suite", version: "0.1.4" }, null, 2),
      "utf8",
    );

    fixture = await withServer((req, res) => {
      if (req.url === "/api/releases") {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "API rate limit exceeded" }));
        return;
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
    });

    const result = await runShellScript(stepScript, {
      INSTALL_ROOT: installRoot,
      SUITE_DIR: suiteDir,
      GITHUB_RELEASES_API: `${fixture.url}/api/releases`,
      RELEASE_DOWNLOAD_BASE_URL: `${fixture.url}/releases/download`,
    });

    if (result.code !== 0) {
      fail(testName, `Expected exit 0, got ${result.code}: ${result.stderr}`);
      return;
    }

    if (result.stdout.includes("UPDATE AVAILABLE")) {
      fail(testName, `Unexpected update reported:\n${result.stdout}`);
      return;
    }

    if (!result.stdout.includes("WARNING: Could not determine latest suite version from release metadata.")) {
      fail(testName, `Expected warning about release metadata fallback. Output:\n${result.stdout}`);
      return;
    }

    pass(testName);
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.close();
    }
    if (tempDir) {
      await tempDir.cleanup();
    }
  }
}

async function runTests() {
  await testHeartbeatVersionCheckUsesSuiteVersion();
  await testHeartbeatVersionCheckFallbackDoesNotFalseAlert();
  report();
  exitWithResults();
}

runTests();
