#!/usr/bin/env node

import { spawnSync } from "node:child_process";

/**
 * Check ClawHub reputation for a skill
 * @param {string} skillSlug - Skill slug to check
 * @param {string} version - Optional version
 * @param {number} threshold - Minimum reputation score (0-100)
 * @returns {Promise<{safe: boolean, score: number, warnings: string[], virustotal: string[]}>}
 */
export async function checkClawhubReputation(skillSlug, version, threshold = 70) {
  const result = {
    safe: true,
    score: 100, // Default score if no checks fail
    warnings: [],
    virustotal: [],
  };

  try {
    // Check 1: Try to inspect the skill via clawhub
    const inspectResult = spawnSync(
      "clawhub",
      ["inspect", skillSlug, "--json"],
      { encoding: "utf-8" }
    );

    if (inspectResult.status !== 0) {
      // Skill doesn't exist or can't be inspected
      result.warnings.push(`Skill "${skillSlug}" not found or cannot be inspected`);
      result.score = Math.min(result.score, 50);
    } else {
      try {
        const skillInfo = JSON.parse(inspectResult.stdout);
        
        // Check 2: Skill age (new skills are riskier)
        if (skillInfo.skill?.createdAt) {
          const createdMs = skillInfo.skill.createdAt;
          const ageDays = (Date.now() - createdMs) / (1000 * 60 * 60 * 24);
          
          if (ageDays < 7) {
            result.warnings.push(`Skill is less than 7 days old (${ageDays.toFixed(1)} days)`);
            result.score -= 15;
          } else if (ageDays < 30) {
            result.warnings.push(`Skill is less than 30 days old (${ageDays.toFixed(1)} days)`);
            result.score -= 5;
          }
        }
        
        // Check 3: Update frequency (stale skills are riskier)
        if (skillInfo.skill?.updatedAt && skillInfo.skill?.createdAt) {
          const updatedMs = skillInfo.skill.updatedAt;
          const createdMs = skillInfo.skill.createdAt;
          const updateAgeDays = (Date.now() - updatedMs) / (1000 * 60 * 60 * 24);
          const totalAgeDays = (Date.now() - createdMs) / (1000 * 60 * 60 * 24);
          
          if (updateAgeDays > 90 && totalAgeDays > 90) {
            result.warnings.push(`Skill hasn't been updated in ${updateAgeDays.toFixed(0)} days`);
            result.score -= 10;
          }
        }
        
        // Check 4: Author reputation
        if (skillInfo.owner?.handle) {
          const authorResult = spawnSync(
            "clawhub",
            ["search", skillInfo.owner.handle],
            { encoding: "utf-8" }
          );
          
          if (authorResult.status === 0) {
            const lines = authorResult.stdout.trim().split('\n').filter(l => l);
            const skillCount = lines.length - 1; // First line is header
            
            if (skillCount === 1) {
              result.warnings.push(`Author "${skillInfo.owner.handle}" has only 1 published skill`);
              result.score -= 10;
            } else if (skillCount < 3) {
              result.warnings.push(`Author "${skillInfo.owner.handle}" has only ${skillCount} published skills`);
              result.score -= 5;
            }
          }
        }
        
        // Check 5: Download statistics
        if (skillInfo.skill?.stats?.downloads !== undefined) {
          const downloads = skillInfo.skill.stats.downloads;
          if (downloads < 10) {
            result.warnings.push(`Low download count: ${downloads}`);
            result.score -= 10;
          } else if (downloads < 100) {
            result.warnings.push(`Moderate download count: ${downloads}`);
            result.score -= 5;
          }
        }
        
      } catch (parseError) {
        result.warnings.push(`Failed to parse skill information: ${parseError.message}`);
        result.score = Math.min(result.score, 60);
      }
    }

    // Check 6: Try installation to see if clawhub flags it as suspicious
    // Use --force to bypass interactive prompt in non-interactive mode
    const installCheck = spawnSync(
      "bash",
      ["-c", `echo "n" | clawhub install ${skillSlug}${version ? ` --version ${version}` : ''} 2>&1`],
      { encoding: "utf-8" }
    );

    const output = installCheck.stdout || installCheck.stderr || "";
    if (output.includes("suspicious") || output.includes("VirusTotal") || output.includes("flagged")) {
      result.virustotal.push("Flagged by ClawHub's VirusTotal Code Insight");
      result.score -= 40; // More severe penalty for VirusTotal flag
      
      // Extract specific warnings
      const lines = output.split('\n');
      for (const line of lines) {
        if (line.includes("Warning:") || line.includes("risky patterns") || 
            line.includes("crypto keys") || line.includes("external APIs") || 
            line.includes("eval") || line.includes("VirusTotal Code Insight")) {
          const cleanLine = line.trim().replace(/^⚠️\s*/, '').replace(/^\s*Warning:\s*/, '');
          if (cleanLine && !result.virustotal.includes(cleanLine)) {
            result.virustotal.push(cleanLine);
          }
        }
      }
    }

    // Check 7: If version specified, check if it exists
    if (version) {
      const versionCheck = spawnSync(
        "clawhub",
        ["inspect", skillSlug, "--version", version, "--json"],
        { encoding: "utf-8" }
      );
      
      if (versionCheck.status !== 0) {
        result.warnings.push(`Version ${version} not found for skill ${skillSlug}`);
        result.score -= 20;
      }
    }

    // Ensure score is within bounds
    result.score = Math.max(0, Math.min(100, result.score));
    result.safe = result.score >= threshold;

    // Add summary warning if below threshold
    if (!result.safe) {
      result.warnings.unshift(`Reputation score ${result.score}/100 below threshold ${threshold}/100`);
    }

  } catch (error) {
    result.warnings.push(`Reputation check error: ${error.message}`);
    result.score = 50;
    result.safe = result.score >= threshold;
  }

  return result;
}

// CLI interface for direct usage
if (import.meta.url === `file://${process.argv[1]}`) {
  async function main() {
    const args = process.argv.slice(2);
    if (args.length < 1) {
      console.error("Usage: node check_clawhub_reputation.mjs <skill-slug> [version] [threshold]");
      process.exit(1);
    }
    
    const skillSlug = args[0];
    const version = args[1] || "";
    const threshold = args[2] ? parseInt(args[2], 10) : 70;
    
    const result = await checkClawhubReputation(skillSlug, version, threshold);
    
    console.log(JSON.stringify(result, null, 2));
    
    if (!result.safe) {
      process.exit(43);
    }
  }
  
  main().catch(console.error);
}