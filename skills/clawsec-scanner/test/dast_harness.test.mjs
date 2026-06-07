#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  pass,
  fail,
  report,
  exitWithResults,
  createTempDir,
} from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SKILL_ROOT = path.resolve(__dirname, "..");
const DAST_SCRIPT = path.join(SKILL_ROOT, "scripts", "dast_runner.mjs");

/**
 * @param {string} targetPath
 * @param {number} timeoutMs
 * @param {Record<string, string>} envOverrides
 * @returns {Promise<{code: number, stdout: string, stderr: string, report: any}>}
 */
async function runDast(targetPath, timeoutMs = 3000, envOverrides = {}) {
  return new Promise((resolve, reject) => {
    const proc = spawn(
      "node",
      [DAST_SCRIPT, "--target", targetPath, "--format", "json", "--timeout", String(timeoutMs)],
      {
        cwd: SKILL_ROOT,
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          ...envOverrides,
        },
      },
    );

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });

    proc.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });

    proc.on("error", reject);

    proc.on("close", (code) => {
      try {
        const parsed = JSON.parse(stdout.trim());
        resolve({
          code: code ?? 1,
          stdout,
          stderr,
          report: parsed,
        });
      } catch (error) {
        reject(new Error(`Failed to parse DAST JSON output: ${String(error)}\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`));
      }
    });
  });
}

/**
 * @param {string} hookDir
 * @param {string} eventsLiteral
 * @param {string} handlerSource
 * @param {string} [handlerFile]
 * @returns {Promise<void>}
 */
async function writeHookFixture(hookDir, eventsLiteral, handlerSource, handlerFile = "handler.js") {
  await fs.mkdir(hookDir, { recursive: true });

  const hookMd = `---
name: ${path.basename(hookDir)}
description: fixture hook
metadata: { "openclaw": { "events": [${eventsLiteral}] } }
---

# Fixture Hook
`;

  await fs.writeFile(path.join(hookDir, "HOOK.md"), hookMd, "utf8");
  await fs.writeFile(path.join(hookDir, handlerFile), handlerSource, "utf8");
}

async function writeExecutable(filePath, content) {
  await fs.writeFile(filePath, content, "utf8");
  await fs.chmod(filePath, 0o755);
}

async function testSafeHookIsInspectedWithoutExecution() {
  const testName = "DAST harness: inspects hooks without executing target code";
  const tmp = await createTempDir();

  try {
    const targetPath = path.join(tmp.path, "skill");
    const hookDir = path.join(targetPath, "hooks", "safe-hook");
    const markerFile = path.join(hookDir, "executed.marker");

    await writeHookFixture(
      hookDir,
      '"command:new"',
      `import fs from "node:fs/promises";
import path from "node:path";

const handler = async (event, context) => {
  const marker = path.join(path.dirname(new URL(import.meta.url).pathname), "executed.marker");
  await fs.writeFile(marker, String(context?.event || "unknown"), "utf8");

  if (!Array.isArray(event.messages)) {
    event.messages = [];
  }

  event.messages.push("hook executed");
};

export default handler;
`,
    );

    const result = await runDast(targetPath, 2500);
    const markerExists = await fs
      .access(markerFile)
      .then(() => true)
      .catch(() => false);

    const noHighSummary =
      result.report?.summary?.critical === 0
      && result.report?.summary?.high === 0
      && result.report?.summary?.medium === 0
      && result.report?.summary?.low === 0;
    const hasStaticCoverageInfo = Array.isArray(result.report?.vulnerabilities)
      && result.report.vulnerabilities.some((v) => String(v.id || "").includes("DAST-STATIC-COVERAGE"));

    if (result.code === 0 && !markerExists && noHighSummary && hasStaticCoverageInfo) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected exit=0, markerExists=false, static coverage info, and no high findings. Got exit=${result.code}, markerExists=${markerExists}, summary=${JSON.stringify(result.report?.summary)} findings=${JSON.stringify(result.report?.vulnerabilities || [])} stderr=${result.stderr}`,
      );
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    await tmp.cleanup();
  }
}

async function testMaliciousHandlerIsNotExecutedForPayloadChecks() {
  const testName = "DAST harness: malicious payload checks do not execute hook code";
  const tmp = await createTempDir();

  try {
    const targetPath = path.join(tmp.path, "skill");
    const hookDir = path.join(targetPath, "hooks", "crashy-hook");
    const markerFile = path.join(hookDir, "executed.marker");

    await writeHookFixture(
      hookDir,
      '"message:preprocessed"',
      `import fs from "node:fs";
import path from "node:path";

fs.writeFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), "executed.marker"), "top-level");

const handler = async (event) => {
  const payload = String(event?.context?.content || "");
  if (payload.includes("<script>")) {
    throw new Error("Unhandled payload path");
  }
};

export default handler;
`,
    );

    const result = await runDast(targetPath, 2500);
    const markerExists = await fs
      .access(markerFile)
      .then(() => true)
      .catch(() => false);
    const noHigh = Number(result.report?.summary?.high || 0) === 0
      && Number(result.report?.summary?.critical || 0) === 0;
    const hasStaticCoverageInfo = Array.isArray(result.report?.vulnerabilities)
      && result.report.vulnerabilities.some((v) => String(v.id || "").includes("DAST-STATIC-COVERAGE"));

    if (result.code === 0 && !markerExists && noHigh && hasStaticCoverageInfo) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected static inspection without marker/high findings. Got exit=${result.code}, markerExists=${markerExists}, summary=${JSON.stringify(result.report?.summary)}, findings=${JSON.stringify(result.report?.vulnerabilities || [])}`,
      );
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    await tmp.cleanup();
  }
}

async function testTypeScriptHookIsStaticallyInspectedWithoutCompiler() {
  const testName = "DAST harness: TypeScript hooks are statically inspected without compiler execution";
  const tmp = await createTempDir();

  try {
    const targetPath = path.join(tmp.path, "skill");
    const hookDir = path.join(targetPath, "hooks", "ts-hook");

    await writeHookFixture(
      hookDir,
      '"command:new"',
      `type Ctx = { dastMode?: boolean };

const handler = async (_event: unknown, _context: Ctx): Promise<void> => {
  return;
};

export default handler;
`,
      "handler.ts",
    );

    const result = await runDast(
      targetPath,
      2500,
      { CLAWSEC_DAST_DISABLE_TYPESCRIPT: "1" },
    );

    const noHigh = Number(result.report?.summary?.high || 0) === 0
      && Number(result.report?.summary?.critical || 0) === 0;
    const hasCoverageInfo = Array.isArray(result.report?.vulnerabilities)
      && result.report.vulnerabilities.some((v) => String(v.id || "").includes("DAST-STATIC-COVERAGE"));
    const hasInfoCount = Number(result.report?.summary?.info || 0) > 0;

    if (result.code === 0 && noHigh && hasCoverageInfo && hasInfoCount) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected coverage info only (no high/critical). Got exit=${result.code}, summary=${JSON.stringify(result.report?.summary)}, findings=${JSON.stringify(result.report?.vulnerabilities || [])}`,
      );
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    await tmp.cleanup();
  }
}

async function testStaticInspectionRunsOncePerHook() {
  const testName = "DAST harness: static inspection runs once per hook across events";
  const tmp = await createTempDir();

  try {
    const targetPath = path.join(tmp.path, "skill");
    const hookDir = path.join(targetPath, "hooks", "multi-event-hook");
    const binDir = path.join(tmp.path, "bin");
    const nodeLogPath = path.join(tmp.path, "node-invocations.log");

    await writeHookFixture(
      hookDir,
      '"agent:bootstrap", "command:new", "message:preprocessed"',
      `export default async function handler() {
  return;
}
`,
    );

    await fs.mkdir(binDir, { recursive: true });
    await writeExecutable(
      path.join(binDir, "node"),
      `#!${process.execPath}
import fs from "node:fs";
import { spawnSync } from "node:child_process";

fs.appendFileSync(${JSON.stringify(nodeLogPath)}, JSON.stringify(process.argv.slice(2)) + "\\n");
const result = spawnSync(${JSON.stringify(process.execPath)}, process.argv.slice(2), {
  env: process.env,
  stdio: ["ignore", "inherit", "inherit"],
});
process.exit(result.status ?? 1);
`,
    );

    const result = await runDast(targetPath, 2500, {
      PATH: `${binDir}:${process.env.PATH}`,
    });

    const log = await fs.readFile(nodeLogPath, "utf8");
    const invocations = log
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    const executorCount = invocations.filter((args) => String(args[0] || "").endsWith("dast_hook_executor.mjs")).length;
    const staticCoverageCount = Array.isArray(result.report?.vulnerabilities)
      ? result.report.vulnerabilities.filter((v) => String(v.id || "").includes("DAST-STATIC-COVERAGE")).length
      : 0;

    if (result.code === 0 && executorCount === 1 && staticCoverageCount === 3) {
      pass(testName);
    } else {
      fail(
        testName,
        `Expected one executor spawn and three per-event findings. Got exit=${result.code}, executorCount=${executorCount}, staticCoverageCount=${staticCoverageCount}, invocations=${JSON.stringify(invocations)}`,
      );
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    await tmp.cleanup();
  }
}

async function main() {
  await testSafeHookIsInspectedWithoutExecution();
  await testMaliciousHandlerIsNotExecutedForPayloadChecks();
  await testTypeScriptHookIsStaticallyInspectedWithoutCompiler();
  await testStaticInspectionRunsOncePerHook();

  report();
  exitWithResults();
}

await main();
