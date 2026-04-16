#!/usr/bin/env node

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

function printUsage() {
  console.log([
    "Usage:",
    "  node scripts/setup_reputation_hook.mjs",
    "",
    "This helper no longer mutates installed clawsec-suite files.",
    "It validates local prerequisites and prints the standalone checker command.",
    "",
  ].join("\n"));
}

function printSummary({ suiteDir, checkerDir, enhancedInstaller }) {
  const lines = [
    "Preflight review:",
    "- This setup does not rewrite files in other skills.",
    `- It validates expected install paths: ${suiteDir} and ${checkerDir}.`,
    "- Required runtime for reputation checks: node + clawhub.",
    "- Advisory-hook reputation annotations are manual only in this release.",
    "- If you want hook alert annotations, wire checker lib/reputation.mjs into suite handler.ts yourself.",
    "- Reputation scoring is heuristic and must remain confirmation-gated.",
    "",
    "Recommended command:",
    `  node ${enhancedInstaller} --skill <slug> [--version <semver>]`,
    "",
    "Optional shell alias (manual, not applied automatically):",
    `  alias clawsec-guarded-install='node ${enhancedInstaller}'`,
  ];

  console.log(lines.join("\n"));
}

async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    printUsage();
    return;
  }

  const suiteDir = path.join(os.homedir(), ".openclaw", "skills", "clawsec-suite");
  const checkerDir = path.join(os.homedir(), ".openclaw", "skills", "clawsec-clawhub-checker");
  const enhancedInstaller = path.join(checkerDir, "scripts", "enhanced_guarded_install.mjs");
  const suiteGuardedInstaller = path.join(suiteDir, "scripts", "guarded_skill_install.mjs");

  await fs.access(checkerDir);
  await fs.access(enhancedInstaller);
  await fs.access(suiteDir);
  await fs.access(suiteGuardedInstaller);

  printSummary({ suiteDir, checkerDir, enhancedInstaller });
}

main().catch((error) => {
  console.error(`Setup failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
