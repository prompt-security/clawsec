#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { checkClawhubReputation } from "./check_clawhub_reputation.mjs";

const EXIT_ADVISORY_CONFIRM_REQUIRED = 42;
const EXIT_REPUTATION_CONFIRM_REQUIRED = 43;

function printUsage() {
  process.stderr.write(
    [
      "Usage:",
      "  node scripts/enhanced_guarded_install.mjs --skill <skill-name> [--version <version>] [--confirm-advisory] [--confirm-reputation] [--dry-run] [--reputation-threshold <score>]",
      "",
      "Examples:",
      "  node scripts/enhanced_guarded_install.mjs --skill helper-plus --version 1.0.1",
      "  node scripts/enhanced_guarded_install.mjs --skill helper-plus --version 1.0.1 --confirm-advisory --confirm-reputation",
      "  node scripts/enhanced_guarded_install.mjs --skill suspicious-skill --reputation-threshold 80",
      "",
      "Exit codes:",
      "  0  success / no advisory or reputation block",
      "  42 advisory matched and second confirmation is required",
      "  43 reputation warning and second confirmation is required",
      "  1  error",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  // Parse and validate CLAWHUB_REPUTATION_THRESHOLD environment variable
  let defaultThreshold = 70;
  const envThreshold = process.env.CLAWHUB_REPUTATION_THRESHOLD;

  if (envThreshold !== undefined && envThreshold !== "") {
    const parsedEnv = parseInt(envThreshold, 10);
    if (Number.isNaN(parsedEnv) || parsedEnv < 0 || parsedEnv > 100) {
      throw new Error(
        `Invalid CLAWHUB_REPUTATION_THRESHOLD environment variable: "${envThreshold}". Must be between 0 and 100.`
      );
    }
    defaultThreshold = parsedEnv;
  }

  const parsed = {
    skill: "",
    version: "",
    confirmAdvisory: false,
    confirmReputation: false,
    dryRun: false,
    reputationThreshold: defaultThreshold,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];

    if (token === "--skill") {
      parsed.skill = String(argv[i + 1] ?? "").trim();
      i += 1;
      continue;
    }
    if (token === "--version") {
      parsed.version = String(argv[i + 1] ?? "").trim();
      i += 1;
      continue;
    }
    if (token === "--confirm-advisory") {
      parsed.confirmAdvisory = true;
      continue;
    }
    if (token === "--confirm-reputation") {
      parsed.confirmReputation = true;
      continue;
    }
    if (token === "--dry-run") {
      parsed.dryRun = true;
      continue;
    }
    if (token === "--reputation-threshold") {
      parsed.reputationThreshold = parseInt(String(argv[i + 1] ?? "70"), 10);
      i += 1;
      continue;
    }
    if (token === "--help" || token === "-h") {
      printUsage();
      process.exit(0);
    }

    throw new Error(`Unknown argument: ${token}`);
  }

  if (!parsed.skill) {
    throw new Error("Missing required argument: --skill");
  }
  // Must start with alphanumeric, then can contain hyphens (matches check_clawhub_reputation.mjs validation)
  if (!/^[a-z0-9][a-z0-9-]*$/.test(parsed.skill)) {
    throw new Error("Invalid --skill value. Must start with a letter or digit, followed by lowercase letters, digits, and hyphens.");
  }
  if (parsed.version && !/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?(?:\+[a-zA-Z0-9.-]+)?$/.test(parsed.version)) {
    throw new Error(
      "Invalid --version value. Must be semantic version format (e.g., 1.2.3, 1.2.3-beta.1, 1.2.3+build.45)."
    );
  }
  if (parsed.reputationThreshold < 0 || parsed.reputationThreshold > 100 || Number.isNaN(parsed.reputationThreshold)) {
    throw new Error("Invalid --reputation-threshold value. Must be between 0 and 100.");
  }

  return parsed;
}

function buildOriginalArgs(argv) {
  // Filter out reputation-specific arguments that the original script doesn't understand
  const originalArgs = [];

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];

    if (token === "--confirm-reputation" || token === "--reputation-threshold") {
      // Skip reputation-specific flags
      if (token === "--reputation-threshold" && i + 1 < argv.length) {
        // Also skip the value associated with --reputation-threshold
        i += 1;
      }
      continue;
    }

    originalArgs.push(token);
  }

  return originalArgs;
}

async function runOriginalGuardedInstall(args) {
  // Find the original guarded_skill_install.mjs from clawsec-suite
  const suiteDir = path.join(os.homedir(), ".openclaw", "skills", "clawsec-suite");
  const originalScript = path.join(suiteDir, "scripts", "guarded_skill_install.mjs");
  
  try {
    await fs.access(originalScript);
  } catch {
    throw new Error(`Original guarded_skill_install.mjs not found at ${originalScript}. Is clawsec-suite installed?`);
  }

  // Pass through environment without modification
  // The original guarded_skill_install.mjs handles --confirm-advisory properly
  const child = spawnSync(
    "node",
    [originalScript, ...args.originalArgs],
    {
      stdio: "inherit",
      env: process.env,
      cwd: suiteDir,
    },
  );

  return {
    exitCode: child.status ?? 1,
    signal: child.signal,
  };
}

async function main() {
  try {
    const cliArgs = process.argv.slice(2);
    const args = parseArgs(cliArgs);

    // Build args for original script (excluding reputation-specific args)
    args.originalArgs = buildOriginalArgs(cliArgs);

    // Step 1: Check reputation (unless already confirmed)
    if (!args.confirmReputation) {
      console.log(`Checking ClawHub reputation for ${args.skill}${args.version ? `@${args.version}` : ""}...`);
      
      const reputationResult = await checkClawhubReputation(args.skill, args.version, args.reputationThreshold);
      
      if (!reputationResult.safe) {
        console.error("\n" + "=".repeat(80));
        console.error("REPUTATION WARNING");
        console.error("=".repeat(80));
        console.error(`Skill "${args.skill}" has low reputation score: ${reputationResult.score}/100`);
        console.error(`Threshold: ${args.reputationThreshold}/100`);
        console.error("");
        
        if (reputationResult.warnings.length > 0) {
          console.error("Warnings:");
          reputationResult.warnings.forEach(w => console.error(`  • ${w}`));
          console.error("");
        }
        
        if (reputationResult.virustotal) {
          console.error("VirusTotal Code Insight flags:");
          reputationResult.virustotal.forEach(v => console.error(`  • ${v}`));
          console.error("");
        }
        
        console.error("To install despite reputation warning, run with --confirm-reputation flag:");
        console.error(`  node ${process.argv[1]} --skill ${args.skill}${args.version ? ` --version ${args.version}` : ""} --confirm-reputation`);
        console.error("");
        console.error("=".repeat(80));
        
        process.exit(EXIT_REPUTATION_CONFIRM_REQUIRED);
      }
      
      console.log(`✓ Reputation check passed: ${reputationResult.score}/100`);
    } else {
      console.log(`⚠️  Reputation confirmation override enabled for ${args.skill}`);
    }

    // Step 2: Run original guarded installer (handles advisory checks)
    console.log("\nRunning advisory checks...");
    const result = await runOriginalGuardedInstall(args);
    
    if (result.exitCode !== 0 && result.exitCode !== EXIT_ADVISORY_CONFIRM_REQUIRED) {
      process.exit(result.exitCode);
    }
    
    // If we get here, either success (0) or advisory confirmation required (42)
    process.exit(result.exitCode);

  } catch (error) {
    console.error("Error:", error.message);
    process.exit(1);
  }
}

main();
