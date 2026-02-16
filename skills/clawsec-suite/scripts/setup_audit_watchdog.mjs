#!/usr/bin/env node
/**
 * Setup: create/update a daily security-audit watchdog cron from clawsec-suite.
 *
 * Requirements:
 * - DM target is required (channel + id)
 * - Email recipient is required; if known from OpenClaw config/runtime, auto-populate
 *   otherwise prompt interactively. In non-interactive mode, fail with actionable error.
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const JOB_NAME = "Daily security audit (Prompt Security)";
const DEFAULT_TZ = "UTC";
const DEFAULT_EXPR = "0 23 * * *";

const SCRIPT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WATCHDOG_DIR = path.join(SCRIPT_ROOT, "scripts", "audit-watchdog");

const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;

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
    .replace(/"/g, '\\"')
    .trim();
}

function escapeForShellEnvVar(v) {
  return String(v ?? "")
    .replace(/[\r\n]+/g, " ")
    .replace(/\\/g, "\\\\")
    .replace(/\$/g, "\\$")
    .replace(/`/g, "\\`")
    .replace(/"/g, '\\"')
    .trim();
}

function looksLikeEmail(value) {
  return EMAIL_RE.test(String(value ?? "").trim());
}

function collectEmailsFromObject(obj, found = new Set()) {
  if (!obj) return found;
  if (typeof obj === "string") {
    const match = obj.match(EMAIL_RE);
    if (match) found.add(match[0]);
    return found;
  }
  if (Array.isArray(obj)) {
    for (const item of obj) collectEmailsFromObject(item, found);
    return found;
  }
  if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === "string") {
        const key = String(k).toLowerCase();
        if (key.includes("email") && looksLikeEmail(v)) found.add(v.trim());
        const match = v.match(EMAIL_RE);
        if (match) found.add(match[0]);
      } else {
        collectEmailsFromObject(v, found);
      }
    }
  }
  return found;
}

function discoverKnownEmail() {
  const candidates = [
    envOrEmpty("PROMPTSEC_EMAIL_TO"),
    envOrEmpty("OPENCLAW_USER_EMAIL"),
    envOrEmpty("USER_EMAIL"),
  ].filter(Boolean);

  try {
    const gitEmail = sh("git", ["config", "--get", "user.email"]).trim();
    if (gitEmail) candidates.push(gitEmail);
  } catch {}

  // Scan OpenClaw config/state for known email addresses.
  const cfgPaths = [
    path.join(os.homedir(), ".openclaw", "openclaw.json"),
    path.join(os.homedir(), ".openclaw", "config.json"),
  ];

  for (const p of cfgPaths) {
    try {
      if (!fs.existsSync(p)) continue;
      const raw = fs.readFileSync(p, "utf8");
      const parsed = JSON.parse(raw);
      for (const e of collectEmailsFromObject(parsed)) candidates.push(e);
    } catch {}
  }

  return candidates.find(looksLikeEmail) || "";
}

function buildAgentMessage({ dmChannel, dmTo, hostLabel, installDir, emailTo }) {
  const safeDir = escapeForShellEnvVar(installDir || "");
  const escapedHostLabel = escapeForShellEnvVar(hostLabel);
  const escapedEmail = escapeForShellEnvVar(emailTo);

  return [
    "Run daily openclaw security audits and deliver report (DM + email).",
    "",
    `Delivery DM: ${oneline(dmChannel)}:${oneline(dmTo)}`,
    `Email: ${oneline(emailTo)} (sendmail/SMTP fallback)`,
    "",
    "Execute:",
    `- Run via exec: cd "${safeDir}" && PROMPTSEC_HOST_LABEL="${escapedHostLabel}" PROMPTSEC_EMAIL_TO="${escapedEmail}" ./scripts/audit-watchdog/runner.sh`,
    "",
    "Output requirements:",
    "- Print the report to stdout (cron deliver will DM it).",
    `- Also email the same report to ${oneline(emailTo)}; if email fails, append a NOTE line to stdout.`,
    "- Do not apply fixes automatically.",
    "- Keep findings aligned with openclaw security audit / healthcheck workflows.",
  ].join("\n");
}

function findExistingJobId(listJson) {
  const jobs = Array.isArray(listJson?.jobs) ? listJson.jobs : [];
  const match = jobs.find((j) => j?.name === JOB_NAME);
  return match?.id ?? null;
}

async function run() {
  const tzEnv = envOrEmpty("PROMPTSEC_TZ");
  const dmChannelEnv = envOrEmpty("PROMPTSEC_DM_CHANNEL");
  const dmToEnv = envOrEmpty("PROMPTSEC_DM_TO");
  const hostLabelEnv = envOrEmpty("PROMPTSEC_HOST_LABEL");
  const emailEnv = envOrEmpty("PROMPTSEC_EMAIL_TO");
  const knownEmail = discoverKnownEmail();

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

  const installDir = SCRIPT_ROOT;

  let emailTo = emailEnv || knownEmail;
  if (interactive) {
    emailTo = await prompt("Email recipient for audit reports", { defaultValue: emailTo });
  }

  if (!dmChannel || !dmTo) {
    throw new Error("Missing DM target. Set PROMPTSEC_DM_CHANNEL and PROMPTSEC_DM_TO (or run interactively).");
  }

  if (!looksLikeEmail(emailTo)) {
    throw new Error(
      "Missing/invalid email recipient. Provide PROMPTSEC_EMAIL_TO or run interactively and enter an email. " +
      "Cron job was not created."
    );
  }

  const runnerPath = path.join(WATCHDOG_DIR, "runner.sh");
  if (!fs.existsSync(runnerPath)) {
    throw new Error(`runner.sh not found at ${runnerPath}; reinstall clawsec-suite`);
  }

  const listOut = sh("openclaw", ["cron", "list", "--json"]);
  const listJson = JSON.parse(listOut);
  const existingId = findExistingJobId(listJson);

  const agentMessage = buildAgentMessage({ dmChannel, dmTo, hostLabel, installDir, emailTo });
  const description = `Runs openclaw security audit daily and delivers to ${dmChannel}:${dmTo} + ${emailTo}.`;

  if (!existingId) {
    const args = [
      "cron", "add",
      "--name", JOB_NAME,
      "--description", description,
      "--session", "isolated",
      "--wake", "now",
      "--cron", DEFAULT_EXPR,
      "--tz", tz,
      "--message", agentMessage,
      "--deliver",
      "--channel", dmChannel,
      "--to", dmTo,
      "--best-effort-deliver",
      "--post-prefix", "[daily security audit]",
      "--post-mode", "summary",
      "--json",
    ];
    const out = sh("openclaw", args);
    const job = JSON.parse(out);
    process.stdout.write(`Created cron job ${job.id}: ${JOB_NAME}\n`);
    process.stdout.write(`Email recipient: ${emailTo}\n`);
  } else {
    const args = [
      "cron", "edit", existingId,
      "--name", JOB_NAME,
      "--description", description,
      "--enable",
      "--session", "isolated",
      "--wake", "now",
      "--cron", DEFAULT_EXPR,
      "--tz", tz,
      "--message", agentMessage,
      "--deliver",
      "--channel", dmChannel,
      "--to", dmTo,
      "--best-effort-deliver",
      "--post-prefix", "[daily security audit]",
    ];
    sh("openclaw", args);
    process.stdout.write(`Updated cron job ${existingId}: ${JOB_NAME}\n`);
    process.stdout.write(`Email recipient: ${emailTo}\n`);
  }
}

run().catch((err) => {
  process.stderr.write(String(err?.stack || err) + "\n");
  process.exit(1);
});
