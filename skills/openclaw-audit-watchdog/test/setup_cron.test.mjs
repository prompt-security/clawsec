#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createTempDir, pass, fail, report, exitWithResults } from "../../clawsec-suite/test/lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.resolve(__dirname, "..", "scripts", "setup_cron.mjs");
const NODE_BIN = process.execPath;

async function writeExecutable(filePath, content) {
  await fs.writeFile(filePath, content, { encoding: "utf8", mode: 0o755 });
}

async function createFixture() {
  const tmp = await createTempDir();
  const binDir = path.join(tmp.path, "bin");
  const installDir = path.join(tmp.path, "install");
  const scriptsDir = path.join(installDir, "scripts");
  const capturePath = path.join(tmp.path, "openclaw-args.json");

  await fs.mkdir(binDir, { recursive: true });
  await fs.mkdir(scriptsDir, { recursive: true });
  await writeExecutable(path.join(scriptsDir, "runner.sh"), "#!/usr/bin/env bash\nexit 0\n");

  await writeExecutable(
    path.join(binDir, "openclaw"),
    `#!/usr/bin/env node
import fs from "node:fs";

const args = process.argv.slice(2);
const capturePath = process.env.OPENCLAW_CAPTURE_PATH;
if (capturePath) {
  fs.writeFileSync(capturePath, JSON.stringify(args), "utf8");
}

if (args[0] === "cron" && args[1] === "list") {
  process.stdout.write(JSON.stringify({ jobs: [] }) + "\\n");
  process.exit(0);
}

if (args[0] === "cron" && args[1] === "add") {
  process.stdout.write(JSON.stringify({ id: "job-123" }) + "\\n");
  process.exit(0);
}

if (args[0] === "cron" && args[1] === "edit") {
  process.stdout.write("{}\\n");
  process.exit(0);
}

process.stderr.write("unexpected args: " + JSON.stringify(args) + "\\n");
process.exit(1);
`,
  );

  return {
    tmp,
    binDir,
    installDir,
    capturePath,
  };
}

async function runSetupCron(extraEnv = {}) {
  const fixture = await createFixture();

  const env = {
    ...process.env,
    ...extraEnv,
    PATH: `${fixture.binDir}:${process.env.PATH || ""}`,
    OPENCLAW_CAPTURE_PATH: fixture.capturePath,
    PROMPTSEC_TZ: "UTC",
    PROMPTSEC_DM_CHANNEL: "telegram",
    PROMPTSEC_DM_TO: "@security-team",
    PROMPTSEC_INSTALL_DIR: fixture.installDir,
  };

  const result = await new Promise((resolve) => {
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

    proc.on("close", async (code) => {
      let capturedArgs = null;
      try {
        capturedArgs = JSON.parse(await fs.readFile(fixture.capturePath, "utf8"));
      } catch {}
      resolve({ code, stdout, stderr, capturedArgs, fixture });
    });
  });

  return result;
}

async function testPreflightSummaryIncludesDependenciesAndRecipients() {
  const testName = "setup_cron: preflight summary includes recipients and runtime review details";
  const result = await runSetupCron({
    PROMPTSEC_EMAIL_TO: "security@example.com",
  });

  try {
    if (result.code !== 0) {
      fail(testName, `setup_cron failed: ${result.stderr}`);
      return;
    }

    const hasSummary = result.stdout.includes("Preflight review:");
    const hasDmTarget = result.stdout.includes("DM target: telegram:@security-team");
    const hasEmailTarget = result.stdout.includes("Email target: security@example.com");
    const hasDependencies = result.stdout.includes("Required runtime: openclaw CLI, node");

    if (hasSummary && hasDmTarget && hasEmailTarget && hasDependencies) {
      pass(testName);
    } else {
      fail(testName, `Missing preflight detail in stdout: ${result.stdout}`);
    }
  } finally {
    await result.fixture.tmp.cleanup();
  }
}

async function testCronMessageDoesNotPromiseEmailWhenUnset() {
  const testName = "setup_cron: cron payload only promises email when email target is configured";
  const result = await runSetupCron();

  try {
    if (result.code !== 0) {
      fail(testName, `setup_cron failed: ${result.stderr}`);
      return;
    }

    const messageIndex = Array.isArray(result.capturedArgs) ? result.capturedArgs.indexOf("--message") : -1;
    const message = messageIndex >= 0 ? result.capturedArgs[messageIndex + 1] : "";

    if (
      message.includes("Delivery DM: telegram:@security-team") &&
      message.includes("Email: disabled unless PROMPTSEC_EMAIL_TO is set") &&
      !message.includes("target@example.com")
    ) {
      pass(testName);
    } else {
      fail(testName, `Cron payload should keep email disabled by default: ${message}`);
    }
  } finally {
    await result.fixture.tmp.cleanup();
  }
}

async function runAllTests() {
  await testPreflightSummaryIncludesDependenciesAndRecipients();
  await testCronMessageDoesNotPromiseEmailWhenUnset();
  report();
  exitWithResults();
}

runAllTests().catch((err) => {
  console.error("Test runner failed:", err);
  process.exit(1);
});
