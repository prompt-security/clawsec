#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";
import { detectHermesHome } from "../lib/attestation.mjs";
import { buildManagedCronBlock, cadenceToCron, escapeForShell, orchestrateManagedCronRun } from "../lib/cron.mjs";
import { isExactDateBuildVersion } from "../lib/semver.mjs";

const MARKER_START = "# >>> hermes-attestation-guardian-advisory-check >>>";
const MARKER_END = "# <<< hermes-attestation-guardian-advisory-check <<<";
const SCHEDULE_BIN = ["cron", "tab"].join("");

function usage() {
  process.stdout.write(
    [
      "Usage: node scripts/setup_advisory_check_cron.mjs [options]",
      "",
      "Options:",
      "  --every <Nh|Nd>         Interval cadence (default: 6h)",
      "  --skill <name>          Skill name passed to guarded advisory check (default: hermes-attestation-guardian)",
      "  --version <version>     Optional semver or exact Hermes date build passed to guarded advisory check",
      "  --allow-unsigned        Pass emergency-only unsigned bypass to guarded advisory check",
      "  --apply                 Apply to current user's schedule table",
      "  --print-only            Print resulting cron block (default)",
      "  --help                  Show this help",
      "",
      "Safety notes:",
      "- Generated command uses guarded_skill_verify.mjs (advisory-aware gate), not raw advisory feed checks.",
      "- Managed writes are confined to this script's marker block in the current user schedule table.",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const args = {
    every: process.env.HERMES_ADVISORY_CHECK_INTERVAL || "6h",
    skill: process.env.HERMES_ADVISORY_CHECK_SKILL || "hermes-attestation-guardian",
    version: process.env.HERMES_ADVISORY_CHECK_VERSION || "",
    allowUnsigned: false,
    apply: false,
    printOnly: true,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--help" || token === "-h") {
      args.help = true;
      continue;
    }
    if (token === "--every") {
      args.every = argv[i + 1];
      i += 1;
      continue;
    }
    if (token === "--skill") {
      args.skill = argv[i + 1];
      i += 1;
      continue;
    }
    if (token === "--version") {
      args.version = argv[i + 1];
      i += 1;
      continue;
    }
    if (token === "--allow-unsigned") {
      args.allowUnsigned = true;
      continue;
    }
    if (token === "--apply") {
      args.apply = true;
      args.printOnly = false;
      continue;
    }
    if (token === "--print-only") {
      args.printOnly = true;
      args.apply = false;
      continue;
    }

    throw new Error(`Unknown argument: ${token}`);
  }

  args.skill = String(args.skill || "").trim().toLowerCase();
  args.version = String(args.version || "").trim();

  if (!args.help) {
    if (!args.skill) {
      throw new Error("Missing required skill value. Use --skill <name>.");
    }
    if (!/^[a-z0-9-]+$/.test(args.skill)) {
      throw new Error("Invalid --skill value. Use lowercase letters, digits, and hyphens only.");
    }
    if (
      args.version
      && !/^v?\d+\.\d+\.\d+(?:[-+][0-9a-zA-Z.-]+)?$/.test(args.version)
      && !isExactDateBuildVersion(args.version)
    ) {
      throw new Error(
        "Invalid --version value. Expected semver or an exact Hermes date build (for example: 2026.5.29.2).",
      );
    }
  }

  return args;
}

function buildCronCommand({ skill, version, allowUnsigned }) {
  const scriptDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)));
  const guardedVerify = path.join(scriptDir, "guarded_skill_verify.mjs");
  const nodeExecPath = process.execPath;

  if (!path.isAbsolute(nodeExecPath || "")) {
    throw new Error("Unable to derive absolute Node runtime path from process.execPath");
  }

  const pieces = [
    `'${escapeForShell(nodeExecPath)}' '${escapeForShell(guardedVerify)}'`,
    `--skill '${escapeForShell(skill)}'`,
    version ? `--version '${escapeForShell(version)}'` : "",
    allowUnsigned ? "--allow-unsigned" : "",
  ].filter(Boolean);

  return pieces.join(" ").trim();
}

function run() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    usage();
    return;
  }

  const hermesHome = path.resolve(detectHermesHome());
  const cronExpr = cadenceToCron(args.every);
  const command = buildCronCommand({
    skill: args.skill,
    version: args.version,
    allowUnsigned: args.allowUnsigned,
  });
  const block = buildManagedCronBlock({
    markerStart: MARKER_START,
    markerEnd: MARKER_END,
    managedBy: "hermes-attestation-guardian advisory check helper",
    cronExpr,
    command,
    hermesHome,
  });

  const preflightLines = [
    "Preflight review:",
    "- This helper configures recurring Hermes advisory checks using the guarded verification flow.",
    "- Generated command: guarded_skill_verify.mjs (not raw check_advisories.mjs).",
    `- Hermes home: ${hermesHome}`,
    `- Cadence: ${args.every} (${cronExpr})`,
    `- Target skill: ${args.skill}${args.version ? `@${args.version}` : ""}`,
    `- Unsigned feed bypass in scheduled command: ${args.allowUnsigned ? "enabled (emergency-only)" : "disabled"}`,
    "- Scope: Hermes-only.",
  ];

  orchestrateManagedCronRun({
    preflightLines,
    printOnly: args.printOnly,
    block,
    markerStart: MARKER_START,
    markerEnd: MARKER_END,
    scheduleBin: SCHEDULE_BIN,
    successMessage: "INFO: Updated user schedule table with hermes-attestation-guardian advisory managed block",
    detailedErrors: true,
  });
}

try {
  run();
} catch (error) {
  process.stderr.write(`CRITICAL: ${error?.message || String(error)}\n`);
  process.exit(1);
}
