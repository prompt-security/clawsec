#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

async function main() {
  console.log("Setting up ClawHub reputation checker integration...");
  
  // Paths
  const suiteDir = path.join(os.homedir(), ".openclaw", "skills", "clawsec-suite");
  const checkerDir = path.join(os.homedir(), ".openclaw", "skills", "clawsec-clawhub-checker");
  const hookLibDir = path.join(suiteDir, "hooks", "clawsec-advisory-guardian", "lib");
  const suiteScriptsDir = path.join(suiteDir, "scripts");
  
  try {
    // Check if clawsec-suite is installed
    await fs.access(suiteDir);
    console.log(`✓ Found clawsec-suite at ${suiteDir}`);
    
    // Check if hook lib directory exists
    await fs.access(hookLibDir);
    console.log(`✓ Found advisory guardian hook at ${hookLibDir}`);
    
    // Copy reputation module to hook lib
    const reputationModuleSrc = path.join(checkerDir, "hooks", "clawsec-advisory-guardian", "lib", "reputation.mjs");
    const reputationModuleDst = path.join(hookLibDir, "reputation.mjs");
    
    await fs.copyFile(reputationModuleSrc, reputationModuleDst);
    console.log(`✓ Copied reputation module to ${reputationModuleDst}`);
    
    // Update hook handler to import reputation module
    const hookHandlerPath = path.join(suiteDir, "hooks", "clawsec-advisory-guardian", "handler.ts");
    let handlerContent = await fs.readFile(hookHandlerPath, "utf8");

    // WARNING: This setup script uses string manipulation to modify handler.ts
    // This is fragile and may break if the handler structure changes
    // Consider using AST-based transformation or manual integration for production use
    let handlerChanged = false;
    const importLine = "import { checkReputation } from \"./lib/reputation.mjs\";";
    const reputationMarker = "// ClawHub reputation check for matched skills";

    if (!handlerContent.includes(importLine)) {
      // Add import after other imports
      const importIndex = handlerContent.lastIndexOf("import");
      if (importIndex === -1) {
        throw new Error("Could not find import statements in handler.ts. Manual integration required.");
      }

      const lineEndIndex = handlerContent.indexOf("\n", importIndex);
      handlerContent = handlerContent.slice(0, lineEndIndex + 1) + `${importLine}\n` + handlerContent.slice(lineEndIndex + 1);
      handlerChanged = true;
    } else {
      console.log("✓ Hook handler already imports reputation module");
    }

    if (!handlerContent.includes(reputationMarker)) {
      const findMatchesAnchors = [
        { line: "const allMatches = findMatches(feed, installedSkills);", variable: "allMatches" },
        { line: "const matches = findMatches(feed, installedSkills);", variable: "matches" },
      ];
      const matchedAnchor = findMatchesAnchors.find((entry) => handlerContent.includes(entry.line));

      if (!matchedAnchor) {
        throw new Error(
          "Could not find findMatches assignment in handler.ts. Refusing partial setup. Manual integration required."
        );
      }

      const anchorIndex = handlerContent.indexOf(matchedAnchor.line);
      const insertIndex = handlerContent.indexOf("\n", anchorIndex) + 1;
      const reputationCheckCode = `
  ${reputationMarker}
  for (const match of ${matchedAnchor.variable}) {
    const repResult = await checkReputation(match.skill.name, match.skill.version);
    if (!repResult.safe) {
      match.reputationWarning = true;
      match.reputationScore = repResult.score;
      match.reputationWarnings = repResult.warnings;
    }
  }
`;
      handlerContent = handlerContent.slice(0, insertIndex) + reputationCheckCode + handlerContent.slice(insertIndex);
      handlerChanged = true;
    } else {
      console.log("✓ Hook handler already has reputation scan block");
    }

    if (handlerChanged) {
      await fs.writeFile(hookHandlerPath, handlerContent);
      console.log("✓ Updated hook handler with reputation checks");
    } else {
      console.log("✓ Hook handler already has required reputation integration");
    }
    
    // Copy enhanced installer and reputation checker scripts
    const enhancedInstallerSrc = path.join(checkerDir, "scripts", "enhanced_guarded_install.mjs");
    const enhancedInstallerDst = path.join(suiteDir, "scripts", "enhanced_guarded_install.mjs");
    const reputationCheckSrc = path.join(checkerDir, "scripts", "check_clawhub_reputation.mjs");
    const reputationCheckDst = path.join(suiteScriptsDir, "check_clawhub_reputation.mjs");
    
    await fs.copyFile(enhancedInstallerSrc, enhancedInstallerDst);
    console.log(`✓ Installed enhanced guarded installer at ${enhancedInstallerDst}`);

    await fs.copyFile(reputationCheckSrc, reputationCheckDst);
    console.log(`✓ Installed reputation check script at ${reputationCheckDst}`);
    
    // Create wrapper script that uses enhanced installer by default
    const wrapperScript = `#!/usr/bin/env node

// Wrapper that uses enhanced guarded installer with reputation checks
// This replaces the original guarded_skill_install.mjs in usage

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const enhancedScript = path.join(__dirname, "enhanced_guarded_install.mjs");

const result = spawnSync("node", [enhancedScript, ...process.argv.slice(2)], {
  stdio: "inherit",
});

process.exit(result.status ?? 1);
`;
    
    const wrapperPath = path.join(suiteDir, "scripts", "guarded_skill_install_wrapper.mjs");
    await fs.writeFile(wrapperPath, wrapperScript);
    await fs.chmod(wrapperPath, 0o755);
    console.log(`✓ Created wrapper script at ${wrapperPath}`);
    
    console.log("\n" + "=".repeat(80));
    console.log("SETUP COMPLETE");
    console.log("=".repeat(80));
    console.log("\nThe ClawHub reputation checker has been integrated with clawsec-suite.");
    console.log("\nWhat changed:");
    console.log("1. Enhanced guarded installer with reputation checks installed");
    console.log("2. Reputation check helper script installed");
    console.log("3. Advisory guardian hook updated to include reputation warnings");
    console.log("4. Wrapper script created for backward compatibility");
    console.log("\nUsage:");
    console.log("  node scripts/enhanced_guarded_install.mjs --skill <name> [--version <ver>]");
    console.log("  node scripts/guarded_skill_install_wrapper.mjs --skill <name> [--version <ver>]");
    console.log("\nNew exit code: 43 = Reputation warning (requires --confirm-reputation)");
    console.log("\nRestart OpenClaw gateway for hook changes to take effect.");
    console.log("=".repeat(80));
    
  } catch (error) {
    console.error("Setup failed:", error.message);
    console.error("\nMake sure:");
    console.error("1. clawsec-suite is installed (npx clawhub install clawsec-suite)");
    console.error("2. You have write permissions to the suite directory");
    process.exit(1);
  }
}

main().catch(console.error);
