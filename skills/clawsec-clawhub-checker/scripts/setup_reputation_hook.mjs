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
    
    // Check if already imported
    if (!handlerContent.includes("from \"./lib/reputation.mjs\"")) {
      // Add import after other imports
      const importIndex = handlerContent.lastIndexOf("import");
      const lineEndIndex = handlerContent.indexOf("\n", importIndex);
      
      const newImport = `import { checkReputation } from "./lib/reputation.mjs";\n`;
      handlerContent = handlerContent.slice(0, lineEndIndex + 1) + newImport + handlerContent.slice(lineEndIndex + 1);
      
      // Find where matches are processed and add reputation check
      const findMatchesLine = handlerContent.indexOf("const matches = findMatches(feed, installedSkills);");
      if (findMatchesLine !== -1) {
        const insertIndex = handlerContent.indexOf("\n", findMatchesLine) + 1;
        
        const reputationCheckCode = `
        // ClawHub reputation check for matched skills
        for (const match of matches) {
          const repResult = await checkReputation(match.skill.name, match.skill.version);
          if (!repResult.safe) {
            match.reputationWarning = true;
            match.reputationScore = repResult.score;
            match.reputationWarnings = repResult.warnings;
          }
        }
        `;
        
        handlerContent = handlerContent.slice(0, insertIndex) + reputationCheckCode + handlerContent.slice(insertIndex);
      }
      
      // Update alert message building to include reputation warnings
      const buildAlertLine = handlerContent.indexOf("const alertMessage = buildAlertMessage(match);");
      if (buildAlertLine !== -1) {
        const lineStart = handlerContent.lastIndexOf("\n", buildAlertLine) + 1;
        const lineEnd = handlerContent.indexOf("\n", buildAlertLine);
        const oldLine = handlerContent.slice(lineStart, lineEnd);
        
        const newLine = `const alertMessage = buildAlertMessage(match, match.reputationWarning ? { score: match.reputationScore, warnings: match.reputationWarnings } : undefined);`;
        handlerContent = handlerContent.slice(0, lineStart) + newLine + handlerContent.slice(lineEnd);
      }
      
      await fs.writeFile(hookHandlerPath, handlerContent);
      console.log(`✓ Updated hook handler with reputation checks`);
    } else {
      console.log(`✓ Hook handler already has reputation checks`);
    }
    
    // Create symlink or copy enhanced installer
    const enhancedInstallerSrc = path.join(checkerDir, "scripts", "enhanced_guarded_install.mjs");
    const enhancedInstallerDst = path.join(suiteDir, "scripts", "enhanced_guarded_install.mjs");
    
    await fs.copyFile(enhancedInstallerSrc, enhancedInstallerDst);
    console.log(`✓ Installed enhanced guarded installer at ${enhancedInstallerDst}`);
    
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
    console.log("2. Advisory guardian hook updated to include reputation warnings");
    console.log("3. Wrapper script created for backward compatibility");
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