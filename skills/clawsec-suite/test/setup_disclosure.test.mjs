#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createTempDir, pass, fail, report, exitWithResults } from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NODE_BIN = process.execPath;
const SETUP_CRON_SCRIPT = path.resolve(__dirname, "..", "scripts", "setup_advisory_cron.mjs");
const SETUP_HOOK_SCRIPT = path.resolve(__dirname, "..", "scripts", "setup_advisory_hook.mjs");

async function writeExecutable(filePath, content) {
  await fs.writeFile(filePath, content, { encoding: "utf8", mode: 0o755 });
}

async function createOpenClawFixture() {
  const tmp = await createTempDir();
  const binDir = path.join(tmp.path, "bin");
  const capturePath = path.join(tmp.path, "openclaw-calls.json");

  await fs.mkdir(binDir, { recursive: true });
  await writeExecutable(
    path.join(binDir, "openclaw"),
    `#!/usr/bin/env node
import fs from "node:fs";

const capturePath = process.env.OPENCLAW_CAPTURE_PATH;
const args = process.argv.slice(2);
let entries = [];
if (capturePath && fs.existsSync(capturePath)) {
  entries = JSON.parse(fs.readFileSync(capturePath, "utf8"));
}
entries.push(args);
if (capturePath) {
  fs.writeFileSync(capturePath, JSON.stringify(entries), "utf8");
}

if (args[0] === "--version") {
  process.stdout.write("openclaw test\\n");
  process.exit(0);
}
if (args[0] === "cron" && args[1] === "list") {
  process.stdout.write(JSON.stringify({ jobs: [] }) + "\\n");
  process.exit(0);
}
if (args[0] === "cron" && args[1] === "add") {
  process.stdout.write(JSON.stringify({ id: "cron-123" }) + "\\n");
  process.exit(0);
}
if (args[0] === "cron" && args[1] === "edit") {
  process.stdout.write("{}\\n");
  process.exit(0);
}
if (args[0] === "hooks" && args[1] === "enable") {
  process.stdout.write("enabled\\n");
  process.exit(0);
}

process.stderr.write("unexpected args: " + JSON.stringify(args) + "\\n");
process.exit(1);
`,
  );

  return { tmp, binDir, capturePath };
}

async function runNodeScript(scriptPath, env) {
  return await new Promise((resolve) => {
    const proc = spawn(NODE_BIN, [scriptPath], {
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

    proc.on("close", async (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

async function testAdvisoryCronPreflight() {
  const testName = "setup_advisory_cron: prints preflight review before creating unattended cron";
  const fixture = await createOpenClawFixture();

  try {
    const result = await runNodeScript(SETUP_CRON_SCRIPT, {
      ...process.env,
      PATH: `${fixture.binDir}:${process.env.PATH || ""}`,
      OPENCLAW_CAPTURE_PATH: fixture.capturePath,
      CLAWSEC_ADVISORY_CRON_EVERY: "6h",
    });

    if (result.code !== 0) {
      fail(testName, `script failed: ${result.stderr}`);
      return;
    }

    const captures = JSON.parse(await fs.readFile(fixture.capturePath, "utf8"));
    const sawAdd = captures.some((args) => args[0] === "cron" && args[1] === "add");

    if (
      sawAdd &&
      result.stdout.includes("Preflight review:") &&
      result.stdout.includes("unattended openclaw cron job") &&
      result.stdout.includes("Schedule: every 6h") &&
      result.stdout.includes("request explicit approval before any removal")
    ) {
      pass(testName);
    } else {
      fail(testName, `missing preflight details: ${result.stdout}`);
    }
  } finally {
    await fixture.tmp.cleanup();
  }
}

async function testAdvisoryHookPreflight() {
  const testName = "setup_advisory_hook: prints preflight review before installing persistent hook";
  const fixture = await createOpenClawFixture();
  const homeDir = path.join(fixture.tmp.path, "home");

  try {
    await fs.mkdir(homeDir, { recursive: true });

    const result = await runNodeScript(SETUP_HOOK_SCRIPT, {
      ...process.env,
      HOME: homeDir,
      PATH: `${fixture.binDir}:${process.env.PATH || ""}`,
      OPENCLAW_CAPTURE_PATH: fixture.capturePath,
    });

    if (result.code !== 0) {
      fail(testName, `script failed: ${result.stderr}`);
      return;
    }

    const installedHook = path.join(homeDir, ".openclaw", "hooks", "clawsec-advisory-guardian", "HOOK.md");
    const captures = JSON.parse(await fs.readFile(fixture.capturePath, "utf8"));
    const sawEnable = captures.some((args) => args[0] === "hooks" && args[1] === "enable");

    await fs.access(installedHook);

    if (
      sawEnable &&
      result.stdout.includes("Preflight review:") &&
      result.stdout.includes("persistent OpenClaw hook") &&
      result.stdout.includes("fetches signed advisory feed data") &&
      result.stdout.includes("Restart your OpenClaw gateway process")
    ) {
      pass(testName);
    } else {
      fail(testName, `missing hook preflight details: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    await fixture.tmp.cleanup();
  }
}

async function runAllTests() {
  await testAdvisoryCronPreflight();
  await testAdvisoryHookPreflight();
  report();
  exitWithResults();
}

runAllTests().catch((err) => {
  console.error("Test runner failed:", err);
  process.exit(1);
});
