#!/usr/bin/env node
/**
 * Setup: create/update a daily 23:00 cron job that
 * - runs openclaw security audits
 * - DMs a chosen recipient (channel+id)
 * - emails target@example.com via local sendmail
 *
 * Uses the `openclaw cron` CLI so it can run on a host without direct Gateway RPC access.
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const JOB_NAME = "Daily security audit (Prompt Security)";
const COMPANY_EMAIL = "target@example.com";
const DEFAULT_TZ = "UTC";
const DEFAULT_EXPR = "0 23 * * *"; // 23:00 daily

const SCRIPT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function sh(cmd, args, { input } = {}) {
  const res = spawnSync(cmd, args, {
    encoding: "utf8",
    input: input ?? undefined,
    stdio: [input ? "pipe" : "ignore", "pipe", "pipe"],
  });
  if (res.error) throw res.error;
  if (res.status !== 0) {
    const msg = (res.stderr || res.stdout || "").trim();
    throw new Error(`${cmd} ${args.join(" ")} failed (code ${res.status})${msg ? `: ${msg}` : ""}`);
  }
  return res.stdout;
}

async function prompt(question, { defaultValue = "" } = {}) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const q = defaultValue ? `${question} [${defaultValue}]: ` : `${question}: `;
  const answer = await new Promise((resolve) => rl.question(q, resolve));
  rl.close();
  const trimmed = String(answer ?? "").trim();
  return trimmed || defaultValue;
}

function envOrEmpty(name) {
  const v = process.env[name];
  return typeof v === "string" ? v.trim() : "";
}

function oneline(v) {
  return String(v ?? "")
    .replace(/[\r\n]+/g, " ")
    .replace(/"/g, "\\\"")

    .trim();
}

function defaultInstallDir() {
  const env = envOrEmpty("PROMPTSEC_INSTALL_DIR");
  if (env) return env;
  const home = envOrEmpty("HOME");
  if (home) return path.join(home, ".config", "security-checkup");
  return SCRIPT_ROOT;
}

function buildAgentMessage({ dmChannel, dmTo, hostLabel, installDir }) {
  const safeDir = oneline(installDir || "");
  return [
    "Run daily openclaw security audits and deliver report (DM + email).",
    "",
    `Delivery DM: ${oneline(dmChannel)}:${oneline(dmTo)}`,
    `Email: ${COMPANY_EMAIL} (local sendmail)`,
    "",
    "Execute:",
    `- Run via exec: cd "${safeDir}" && PROMPTSEC_HOST_LABEL="${oneline(hostLabel)}" ./scripts/runner.sh`,
    "",
    "Output requirements:",
    "- Print the report to stdout (cron deliver will DM it).",
    `- Also email the same report to ${COMPANY_EMAIL}; if email fails, append a NOTE line to stdout.`,
    "- Do not apply fixes automatically.",
  ].join("\n");
}

function findExistingJobId(listJson) {
  const jobs = Array.isArray(listJson?.jobs) ? listJson.jobs : [];
  const match = jobs.find((j) => j?.name === JOB_NAME);
  return match?.id ?? null;
}

async function run() {
  // Non-interactive first (MDM-friendly)
  const tzEnv = envOrEmpty("PROMPTSEC_TZ");
  const dmChannelEnv = envOrEmpty("PROMPTSEC_DM_CHANNEL");
  const dmToEnv = envOrEmpty("PROMPTSEC_DM_TO");
  const hostLabelEnv = envOrEmpty("PROMPTSEC_HOST_LABEL");

  const interactive = !(tzEnv && dmChannelEnv && dmToEnv);

  const tz = interactive
    ? await prompt("Timezone for daily 11pm run (IANA)", { defaultValue: tzEnv || DEFAULT_TZ })
    : tzEnv || DEFAULT_TZ;

  const dmChannel = interactive
    ? await prompt("DM channel (e.g. telegram, slack, discord)", { defaultValue: dmChannelEnv })
    : dmChannelEnv;

  const dmTo = interactive
    ? await prompt("DM recipient id (Telegram numeric chatId/userId preferred)", { defaultValue: dmToEnv })
    : dmToEnv;

  const hostLabel = interactive
    ? await prompt("Optional host label to include in report", { defaultValue: hostLabelEnv })
    : hostLabelEnv;

  const installDirDefault = defaultInstallDir();
  const installDir = interactive
    ? await prompt("Install dir containing scripts/runner.sh", { defaultValue: installDirDefault })
    : installDirDefault;

  if (!dmChannel || !dmTo) {
    throw new Error("Missing DM target. Set PROMPTSEC_DM_CHANNEL and PROMPTSEC_DM_TO (or run interactively). ");
  }

  const runnerPath = path.join(installDir, "scripts", "runner.sh");
  if (!fs.existsSync(runnerPath)) {
    throw new Error(`runner.sh not found at ${runnerPath}; set PROMPTSEC_INSTALL_DIR to the deployed path`);
  }

  const listOut = sh("openclaw", ["cron", "list", "--json"]);
  const listJson = JSON.parse(listOut);
  const existingId = findExistingJobId(listJson);

  const agentMessage = buildAgentMessage({ dmChannel, dmTo, hostLabel, installDir });
  const description = `Runs openclaw security audit daily and delivers to ${dmChannel}:${dmTo} + ${COMPANY_EMAIL}.`;

  if (!existingId) {
    const args = [
      "cron",
      "add",
      "--name",
      JOB_NAME,
      "--description",
      description,
      "--session",
      "isolated",
      "--wake",
      "now",
      "--cron",
      DEFAULT_EXPR,
      "--tz",
      tz,
      "--message",
      agentMessage,
      "--deliver",
      "--channel",
      dmChannel,
      "--to",
      dmTo,
      "--best-effort-deliver",
      "--post-prefix",
      "[daily security audit]",
      "--post-mode",
      "summary",
      "--json",
    ];
    const out = sh("openclaw", args);
    const job = JSON.parse(out);
    process.stdout.write(`Created cron job ${job.id}: ${JOB_NAME}\n`);
  } else {
    const args = [
      "cron",
      "edit",
      existingId,
      "--name",
      JOB_NAME,
      "--description",
      description,
      "--enable",
      "--session",
      "isolated",
      "--wake",
      "now",
      "--cron",
      DEFAULT_EXPR,
      "--tz",
      tz,
      "--message",
      agentMessage,
      "--deliver",
      "--channel",
      dmChannel,
      "--to",
      dmTo,
      "--best-effort-deliver",
      "--post-prefix",
      "[daily security audit]",
    ];
    sh("openclaw", args);
    process.stdout.write(`Updated cron job ${existingId}: ${JOB_NAME}\n`);
  }
}

run().catch((err) => {
  process.stderr.write(String(err?.stack || err) + "\n");
  process.exit(1);
});
