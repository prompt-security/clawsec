import { spawnSync as runProcessSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

/**
 * Check reputation for a skill
 * @param {string} skillName - Skill name
 * @param {string} version - Skill version
 * @returns {Promise<{safe: boolean, score: number, warnings: string[]}>}
 */
export async function checkReputation(skillName, version) {
  const result = {
    safe: true,
    score: 100,
    warnings: [],
  };

  try {
    // Try to get skill slug from directory name or skill.json
    // For now, use skillName as slug (simplified)
    const skillSlug = skillName.toLowerCase().replace(/[^a-z0-9-]/g, '-');

    // Run the reputation check script
    // Current file is at: .../hooks/clawsec-advisory-guardian/lib/reputation.mjs
    // We need to go up 3 levels to get to the skill root directory
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const checkerDir = path.resolve(__dirname, '../../..');
    
    const reputationCheck = runProcessSync(
      "node",
      [
        `${checkerDir}/scripts/check_clawhub_reputation.mjs`,
        skillSlug,
        version || "",
        "70" // Default threshold
      ],
      { encoding: "utf-8", cwd: checkerDir }
    );

    if (reputationCheck.error) {
      result.safe = false;
      result.score = 0;
      result.warnings.push(`Reputation check execution error: ${reputationCheck.error.message}`);
      return result;
    }

    if (typeof reputationCheck.status !== "number") {
      result.safe = false;
      result.score = 0;
      result.warnings.push("Reputation check did not return a process exit status");
      return result;
    }

    if (reputationCheck.status === 0) {
      try {
        const repResult = JSON.parse(reputationCheck.stdout);
        result.safe = repResult.safe;
        result.score = repResult.score;
        result.warnings = repResult.warnings;
      } catch (parseError) {
        result.warnings.push(`Failed to parse reputation result: ${parseError.message}`);
        result.score = 60;
        result.safe = result.score >= 70;
      }
    } else if (reputationCheck.status === 43) {
      // Reputation warning exit code
      try {
        const repResult = JSON.parse(reputationCheck.stdout);
        result.safe = false;
        result.score = repResult.score;
        result.warnings = repResult.warnings;
      } catch {
        result.safe = false;
        result.score = 50;
        result.warnings.push("Skill flagged by reputation check");
      }
    } else {
      const stderr = (reputationCheck.stderr || "").trim();
      const stdout = (reputationCheck.stdout || "").trim();
      const output = [stderr, stdout].filter((entry) => entry).join(" | ");
      result.warnings.push(
        `Reputation check failed with exit code ${reputationCheck.status}${
          output ? `: ${output}` : ""
        }`,
      );
      result.score = 0;
      result.safe = false;
    }
  } catch (error) {
    result.warnings.push(`Reputation check error: ${error.message}`);
    result.score = 50;
    result.safe = result.score >= 70;
  }

  return result;
}

/**
 * Format reputation warning for alert messages
 * @param {{score: number, warnings: string[]}} reputationInfo
 * @returns {string}
 */
export function formatReputationWarning(reputationInfo) {
  if (!reputationInfo || reputationInfo.score >= 70) return "";
  
  const lines = [
    `\n⚠️  **REPUTATION WARNING** (Score: ${reputationInfo.score}/100)`,
  ];
  
  if (reputationInfo.warnings.length > 0) {
    lines.push("");
    reputationInfo.warnings.forEach(w => lines.push(`• ${w}`));
  }
  
  lines.push("");
  lines.push("This skill has low reputation score. Review carefully before installation.");
  
  return lines.join("\n");
}
