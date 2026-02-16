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
  const parsed = {
    skill: "",
    version: "",
    confirmAdvisory: false,
    confirmReputation: false,
    dryRun: false,
    reputationThreshold: process.env.CLAWHUB_REPUTATION_THRESHOLD
      ? parseInt(process.env.CLAWHUB_REPUTATION_THRESHOLD, 10)
      : 70,
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
  if (!/^[a-z0-9-]+$/.test(parsed.skill)) {
    throw new Error("Invalid --skill value. Use lowercase letters, digits, and hyphens only.");
  }
  if (parsed.reputationThreshold < 0 || parsed.reputationThreshold > 100 || Number.isNaN(parsed.reputationThreshold)) {
    throw new Error("Invalid --reputation-threshold value. Must be between 0 and 100.");
  }

  return parsed;
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

  const env = { ...process.env };
  if (args.confirmAdvisory) {
    env.CLAWSEC_ALLOW_UNSIGNED_FEED = "1"; // Pass through to original script
  }

  const child = spawnSync(
    "node",
    [originalScript, ...args.originalArgs],
    {
      stdio: "inherit",
      env,
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
    const args = parseArgs(process.argv.slice(2));
    
    // Build args for original script (excluding reputation-specific args)
    const originalArgs = [];
    for (let i = 0; i < process.argv.slice(2).length; i++) {
      const token = process.argv.slice(2)[i];
      if (token === "--confirm-reputation" || token === "--reputation-threshold") {
        i += token === "--reputation-threshold" ? 1 : 0;
        continue;
      }
      originalArgs.push(token);
    }

    args.originalArgs = originalArgs;

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