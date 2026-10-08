#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const skillRoot = path.resolve(__dirname, "..");
const setupScript = path.join(skillRoot, "scripts", "setup_advisory_check_cron.mjs");

function runSetup(args = [], env = {}) {
  return spawnSync(process.execPath, [setupScript, ...args], {
    cwd: skillRoot,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

const dateBuildPreview = runSetup([
  "--print-only",
  "--skill",
  "hermes-agent",
  "--version",
  "2026.5.29.2",
]);
assert.equal(dateBuildPreview.status, 0, dateBuildPreview.stderr);
assert.ok(dateBuildPreview.stdout.includes("--version '2026.5.29.2'"), dateBuildPreview.stdout);

const leapDayBuildPreview = runSetup([
  "--print-only",
  "--skill",
  "hermes-agent",
  "--version",
  "0096.2.29.1",
]);
assert.equal(leapDayBuildPreview.status, 0, leapDayBuildPreview.stderr);
assert.ok(leapDayBuildPreview.stdout.includes("--version '0096.2.29.1'"), leapDayBuildPreview.stdout);

const impossibleDateBuild = runSetup([
  "--print-only",
  "--skill",
  "hermes-agent",
  "--version",
  "2026.2.30.1",
]);
assert.equal(impossibleDateBuild.status, 1, impossibleDateBuild.stderr);
assert.ok(impossibleDateBuild.stderr.includes("Invalid --version value"), impossibleDateBuild.stderr);

async function withTempDir(run) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "hag-advisory-cron-"));
  try {
    await run(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

function toBase64(value) {
  return Buffer.from(String(value), "utf8").toString("base64");
}

async function installFakeCrontab(tempDir, { listStdout = "", listStatus = 0, listStderr = "" } = {}) {
  const fakeBinDir = path.join(tempDir, "bin");
  const logPath = path.join(tempDir, "crontab.log");
  const writePath = path.join(tempDir, "crontab.write");
  await fs.mkdir(fakeBinDir, { recursive: true });

  const fakeCrontab = `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
const logPath = process.env.CRONTAB_LOG_PATH;
const writePath = process.env.CRONTAB_WRITE_PATH;
const listStatus = Number(process.env.CRONTAB_LIST_STATUS || '0');
const listStdout = Buffer.from(process.env.CRONTAB_LIST_STDOUT_B64 || '', 'base64').toString('utf8');
const listStderr = process.env.CRONTAB_LIST_STDERR || '';
const writeStatus = Number(process.env.CRONTAB_WRITE_STATUS || '0');
const writeStderr = process.env.CRONTAB_WRITE_STDERR || '';

if (args[0] === '-l') {
  fs.appendFileSync(logPath, 'list\\n', 'utf8');
  if (listStatus !== 0) {
    if (listStderr) process.stderr.write(listStderr);
    process.exit(listStatus);
  }
  process.stdout.write(listStdout);
  process.exit(0);
}

if (args[0] === '-') {
  fs.appendFileSync(logPath, 'write\\n', 'utf8');
  fs.writeFileSync(writePath, fs.readFileSync(0, 'utf8'), 'utf8');
  if (writeStatus !== 0) {
    if (writeStderr) process.stderr.write(writeStderr);
    process.exit(writeStatus);
  }
  process.exit(0);
}

process.stderr.write('unexpected crontab args: ' + args.join(' ') + '\\n');
process.exit(2);
`;

  const fakeCrontabPath = path.join(fakeBinDir, "crontab");
  await fs.writeFile(fakeCrontabPath, fakeCrontab, { encoding: "utf8", mode: 0o755 });

  return {
    fakeBinDir,
    logPath,
    writePath,
    env: {
      CRONTAB_LOG_PATH: logPath,
      CRONTAB_WRITE_PATH: writePath,
      CRONTAB_LIST_STATUS: String(listStatus),
      CRONTAB_LIST_STDOUT_B64: toBase64(listStdout),
      CRONTAB_LIST_STDERR: listStderr,
      CRONTAB_WRITE_STATUS: "0",
      CRONTAB_WRITE_STDERR: "",
    },
  };
}

async function installSelfDeletingCrontab(tempDir) {
  const fakeBinDir = path.join(tempDir, "bin-self-delete");
  const logPath = path.join(tempDir, "crontab.self-delete.log");
  await fs.mkdir(fakeBinDir, { recursive: true });

  const fakeCrontabPath = path.join(fakeBinDir, "crontab");
  const fakeCrontab = `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
const logPath = process.env.CRONTAB_SELF_DELETE_LOG_PATH;

if (args[0] === '-l') {
  fs.appendFileSync(logPath, 'list\\n', 'utf8');
  fs.unlinkSync(process.argv[1]);
  process.stdout.write('# existing line\\n');
  process.exit(0);
}

if (args[0] === '-') {
  fs.appendFileSync(logPath, 'write-ran\\n', 'utf8');
  process.exit(99);
}

process.exit(2);
`;

  await fs.writeFile(fakeCrontabPath, fakeCrontab, { encoding: "utf8", mode: 0o755 });

  return {
    fakeBinDir,
    logPath,
    env: {
      CRONTAB_SELF_DELETE_LOG_PATH: logPath,
    },
  };
}

await withTempDir(async (tempDir) => {
  const hermesHome = path.join(tempDir, ".hermes");
  const fake = await installFakeCrontab(tempDir, {
    listStdout: "# should never be read in print-only mode\n",
  });

  const result = runSetup(["--every", "6h", "--skill", "clawsec-feed", "--print-only"], {
    HERMES_HOME: hermesHome,
    PATH: `${fake.fakeBinDir}:${process.env.PATH}`,
    ...fake.env,
  });

  assert.equal(result.status, 0, `setup script failed: ${result.stderr}`);
  assert.ok(result.stdout.includes("Preflight review:"), result.stdout);
  assert.ok(result.stdout.includes("guarded_skill_verify.mjs"), result.stdout);
  assert.ok(result.stdout.includes("Target skill: clawsec-feed"), result.stdout);
  assert.ok(result.stdout.includes("# >>> hermes-attestation-guardian-advisory-check >>>"), result.stdout);

  const cronLine = result.stdout
    .split(/\r?\n/)
    .find((line) => line.includes("guarded_skill_verify.mjs") && line.includes("--skill"));
  assert.ok(cronLine, "managed cron line using guarded flow should be present");
  assert.ok(cronLine.includes(process.execPath), "cron command must use absolute process.execPath node runtime");
  assert.equal(
    /node\s+[^\n]*guarded_skill_verify\.mjs/.test(cronLine),
    false,
    "must not schedule a generic 'node' invocation when process.execPath is available",
  );
  assert.equal(
    /node\s+[^\n]*check_advisories\.mjs/.test(cronLine),
    false,
    "must not schedule raw advisory check entrypoint",
  );

  const logExists = await fs
    .access(fake.logPath)
    .then(() => true)
    .catch(() => false);
  assert.equal(logExists, false, "print-only mode must never invoke crontab");
});

await withTempDir(async (tempDir) => {
  const hermesHome = path.join(tempDir, ".hermes");
  const fake = await installFakeCrontab(tempDir, {
    listStdout:
      "# existing line\n" +
      "# >>> hermes-attestation-guardian-advisory-check >>>\n" +
      "0 */6 * * * HERMES_HOME=\"/old\" /usr/bin/node /old/guarded_skill_verify.mjs --skill old-skill\n" +
      "# <<< hermes-attestation-guardian-advisory-check <<<\n",
  });

  const result = runSetup(["--apply", "--every", "12h", "--skill", "clawsec-feed", "--version", "1.2.3"], {
    HERMES_HOME: hermesHome,
    PATH: `${fake.fakeBinDir}:${process.env.PATH}`,
    ...fake.env,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.includes("Updated user schedule table"), result.stdout);

  const log = await fs.readFile(fake.logPath, "utf8");
  assert.ok(log.includes("list"), "script should read schedule table");
  assert.ok(log.includes("write"), "script should write updated schedule table");

  const written = await fs.readFile(fake.writePath, "utf8");
  assert.ok(written.includes("# existing line"), "existing non-managed entries must be preserved");

  const startCount = (written.match(/# >>> hermes-attestation-guardian-advisory-check >>>/g) || []).length;
  const endCount = (written.match(/# <<< hermes-attestation-guardian-advisory-check <<</g) || []).length;
  assert.equal(startCount, 1, `expected exactly one managed start marker, got ${startCount}`);
  assert.equal(endCount, 1, `expected exactly one managed end marker, got ${endCount}`);

  assert.ok(written.includes("guarded_skill_verify.mjs"), written);
  assert.ok(written.includes(process.execPath), written);
  assert.ok(written.includes("--skill 'clawsec-feed'"), written);
  assert.ok(written.includes("--version '1.2.3'"), written);
  assert.equal(written.includes("old-skill"), false, "old managed block content must be replaced");
});

await withTempDir(async (tempDir) => {
  const hermesHome = path.join(tempDir, ".hermes");
  const fake = await installFakeCrontab(tempDir, {
    listStatus: 1,
    listStderr: "no crontab for davida\n",
  });

  const result = runSetup(["--apply", "--every", "6h", "--skill", "clawsec-feed"], {
    HERMES_HOME: hermesHome,
    PATH: `${fake.fakeBinDir}:${process.env.PATH}`,
    ...fake.env,
  });

  assert.equal(result.status, 0, result.stderr);

  const log = await fs.readFile(fake.logPath, "utf8");
  assert.ok(log.includes("list"), "script should attempt schedule table read");
  assert.ok(log.includes("write"), "script should write new schedule table when none exists");

  const written = await fs.readFile(fake.writePath, "utf8");
  assert.ok(written.includes("# >>> hermes-attestation-guardian-advisory-check >>>"), written);
  assert.ok(written.includes("--skill 'clawsec-feed'"), written);
});

for (const markerCase of [
  {
    name: "unmatched start marker",
    listStdout:
      "# >>> hermes-attestation-guardian-advisory-check >>>\n" +
      "0 */6 * * * HERMES_HOME=\"/old\" /usr/bin/node /old/guarded_skill_verify.mjs --skill old-skill\n",
    expectedError: "has no end marker",
  },
  {
    name: "unmatched end marker",
    listStdout: "# <<< hermes-attestation-guardian-advisory-check <<<\n# existing line\n",
    expectedError: "unmatched managed block end",
  },
  {
    name: "nested start marker",
    listStdout:
      "# >>> hermes-attestation-guardian-advisory-check >>>\n" +
      "# >>> hermes-attestation-guardian-advisory-check >>>\n" +
      "# <<< hermes-attestation-guardian-advisory-check <<<\n",
    expectedError: "nested managed block start",
  },
]) {
  await withTempDir(async (tempDir) => {
    const hermesHome = path.join(tempDir, ".hermes");
    const fake = await installFakeCrontab(tempDir, {
      listStdout: markerCase.listStdout,
    });

    const result = runSetup(["--apply", "--every", "6h", "--skill", "clawsec-feed"], {
      HERMES_HOME: hermesHome,
      PATH: `${fake.fakeBinDir}:${process.env.PATH}`,
      ...fake.env,
    });

    assert.notEqual(result.status, 0, `${markerCase.name}: expected non-zero exit status`);
    assert.ok(result.stderr.includes("Malformed schedule markers"), `${markerCase.name}: ${result.stderr}`);
    assert.ok(result.stderr.includes(markerCase.expectedError), `${markerCase.name}: ${result.stderr}`);

    const log = await fs.readFile(fake.logPath, "utf8");
    assert.ok(log.includes("list"), `${markerCase.name}: schedule table read should happen`);
    assert.equal(log.includes("write"), false, `${markerCase.name}: write must not occur`);

    const writeExists = await fs
      .access(fake.writePath)
      .then(() => true)
      .catch(() => false);
    assert.equal(writeExists, false, `${markerCase.name}: no written schedule table expected`);
  });
}

await withTempDir(async (tempDir) => {
  const hermesHome = path.join(tempDir, ".hermes");
  const result = runSetup(["--apply", "--every", "6h", "--skill", "clawsec-feed"], {
    HERMES_HOME: hermesHome,
    PATH: path.join(tempDir, "missing-bin"),
  });

  assert.notEqual(result.status, 0, "spawnSync ENOENT while reading crontab should fail");
  assert.ok(result.stderr.includes("Failed reading schedule table"), result.stderr);
  assert.ok(result.stderr.includes("code=ENOENT"), result.stderr);
  assert.ok(result.stderr.includes("message="), result.stderr);
  assert.ok(result.stderr.includes("stack="), result.stderr);
});

await withTempDir(async (tempDir) => {
  const hermesHome = path.join(tempDir, ".hermes");
  const fake = await installSelfDeletingCrontab(tempDir);

  const result = runSetup(["--apply", "--every", "6h", "--skill", "clawsec-feed"], {
    HERMES_HOME: hermesHome,
    PATH: fake.fakeBinDir,
    ...fake.env,
  });

  assert.notEqual(result.status, 0, "spawnSync ENOENT while writing crontab should fail");
  assert.ok(result.stderr.includes("Failed writing schedule table"), result.stderr);
  assert.ok(result.stderr.includes("code=ENOENT"), result.stderr);
  assert.ok(result.stderr.includes("message="), result.stderr);
  assert.ok(result.stderr.includes("stack="), result.stderr);

  const log = await fs.readFile(fake.logPath, "utf8");
  assert.ok(log.includes("list"), "self-deleting fake crontab should run for list before write failure");
  assert.equal(log.includes("write-ran"), false, "write command should fail before executing fake crontab");
});

console.log("setup_advisory_check_cron.test.mjs: ok");
