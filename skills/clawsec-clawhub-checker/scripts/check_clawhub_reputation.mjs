#!/usr/bin/env node

import { spawnSync as runProcessSync } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";

function runClawhub(args) {
  return runProcessSync("clawhub", args, { encoding: "utf-8" });
}

function toPublicResult(result) {
  return {
    safe: result.safe,
    score: result.score,
    warnings: result.warnings,
    virustotal: result.virustotal,
  };
}

function finalizeResult(result, threshold) {
  result.score = Math.max(0, Math.min(100, result.score));
  result.safe = !result.blocked && result.score >= threshold;
  if (!result.safe) {
    const thresholdWarning = `Reputation score ${result.score}/100 below threshold ${threshold}/100`;
    if (!result.warnings.includes(thresholdWarning)) {
      result.warnings.unshift(thresholdWarning);
    }
  }
  return toPublicResult(result);
}

function blockOnMissingScannerData(result, warning) {
  result.warnings.push(warning);
  result.score = Math.min(result.score, 60);
  result.blocked = true;
}

function parseJson(raw, label, warnings) {
  try {
    return JSON.parse(raw);
  } catch (error) {
    warnings.push(
      `Failed to parse ${label}: ${error instanceof Error ? error.message : String(error)}`,
    );
    return null;
  }
}

function maybeApplyVersionSecuritySignals(result, versionDetails) {
  if (!versionDetails || typeof versionDetails !== "object") {
    blockOnMissingScannerData(result, "ClawHub version security details are unavailable");
    return;
  }

  const security = versionDetails.security;
  if (!security || typeof security !== "object") {
    blockOnMissingScannerData(result, "ClawHub version record does not include security scanner output");
    return;
  }

  if (typeof security.status === "string" && security.status.toLowerCase() === "suspicious") {
    result.warnings.push("ClawHub static moderation marked the version as suspicious");
    result.score -= 30;
  }

  const scanners = security.scanners;
  if (!scanners || typeof scanners !== "object") {
    blockOnMissingScannerData(result, "ClawHub scanner breakdown is missing from version metadata");
    return;
  }

  const vt = scanners.vt;
  if (!vt || typeof vt !== "object") {
    blockOnMissingScannerData(result, "VirusTotal scanner data was not returned by ClawHub");
    return;
  }

  const vtStatus =
    (typeof vt.normalizedStatus === "string" && vt.normalizedStatus) ||
    (typeof vt.status === "string" && vt.status) ||
    (typeof vt.verdict === "string" && vt.verdict) ||
    "";
  const normalizedStatus = vtStatus.toLowerCase();

  if (normalizedStatus === "suspicious") {
    result.virustotal.push("ClawHub VirusTotal scan returned suspicious");
    result.score -= 40;

    const vtSummary = typeof vt.analysis === "string" ? vt.analysis.trim() : "";
    if (vtSummary) {
      result.virustotal.push(vtSummary.split("\n")[0]);
    }
  } else if (normalizedStatus === "clean" || normalizedStatus === "benign") {
    result.virustotal.push("ClawHub VirusTotal scan returned clean");
  } else if (normalizedStatus) {
    result.warnings.push(`VirusTotal scanner status reported as: ${normalizedStatus}`);
    result.score -= 10;
  } else {
    result.warnings.push("VirusTotal scanner status was unavailable");
    result.score -= 10;
  }
}

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
    score: 100,
    warnings: [],
    virustotal: [],
    blocked: false,
  };

  if (!/^[a-z0-9][a-z0-9-]*$/.test(skillSlug)) {
    result.warnings.push(`Invalid skill slug: ${skillSlug}`);
    result.score = 0;
    result.safe = false;
    result.blocked = true;
    return toPublicResult(result);
  }

  if (version && !/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?(?:\+[a-zA-Z0-9.-]+)?$/.test(version)) {
    result.warnings.push(`Invalid version format: ${version}`);
    result.score = 0;
    result.safe = false;
    result.blocked = true;
    return toPublicResult(result);
  }

  try {
    const inspectArgs = ["inspect", skillSlug, "--json"];
    if (version) inspectArgs.push("--version", version);
    const inspectResult = runClawhub(inspectArgs);

    if (inspectResult.status !== 0) {
      result.warnings.push(`Skill "${skillSlug}" not found or cannot be inspected`);
      result.score = Math.min(result.score, 40);
      result.blocked = true;
      return finalizeResult(result, threshold);
    }

    const skillInfo = parseJson(inspectResult.stdout, "skill inspection payload", result.warnings);
    if (!skillInfo) {
      result.score = Math.min(result.score, 40);
      result.blocked = true;
      return finalizeResult(result, threshold);
    }

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

    if (skillInfo.owner?.handle) {
      const authorResult = runClawhub(["search", skillInfo.owner.handle]);
      if (authorResult.status === 0) {
        const lines = authorResult.stdout
          .trim()
          .split("\n")
          .filter((line) => line);
        const skillCount = Math.max(0, lines.length - 1);

        if (skillCount === 1) {
          result.warnings.push(`Author "${skillInfo.owner.handle}" has only 1 published skill`);
          result.score -= 10;
        } else if (skillCount > 1 && skillCount < 3) {
          result.warnings.push(
            `Author "${skillInfo.owner.handle}" has only ${skillCount} published skills`,
          );
          result.score -= 5;
        }
      }
    }

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

    let versionDetails = skillInfo.version ?? null;
    if (!versionDetails && !version && skillInfo.latestVersion?.version) {
      const latestVersionCheck = runClawhub([
        "inspect",
        skillSlug,
        "--version",
        String(skillInfo.latestVersion.version),
        "--json",
      ]);
      if (latestVersionCheck.status === 0) {
        const latestInfo = parseJson(
          latestVersionCheck.stdout,
          "latest-version inspection payload",
          result.warnings,
        );
        versionDetails = latestInfo?.version ?? null;
      }
    }

    maybeApplyVersionSecuritySignals(result, versionDetails);
    return finalizeResult(result, threshold);
  } catch (error) {
    result.warnings.push(`Reputation check error: ${error instanceof Error ? error.message : String(error)}`);
    result.score = 50;
    result.blocked = true;
    return finalizeResult(result, threshold);
  }
}

const isCliEntrypoint =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isCliEntrypoint) {
  async function main() {
    const args = process.argv.slice(2);
    if (args.length < 1) {
      console.error("Usage: node check_clawhub_reputation.mjs <skill-slug> [version] [threshold]");
      process.exit(1);
    }

    const skillSlug = args[0];
    const version = args[1] || "";
    let threshold = 70;

    if (args[2] !== undefined) {
      const parsedThreshold = parseInt(args[2], 10);
      if (!Number.isInteger(parsedThreshold) || parsedThreshold < 0 || parsedThreshold > 100) {
        console.error(
          `Invalid threshold: "${args[2]}". Threshold must be an integer between 0 and 100.`,
        );
        process.exit(1);
      }
      threshold = parsedThreshold;
    }

    const result = await checkClawhubReputation(skillSlug, version, threshold);

    console.log(JSON.stringify(result, null, 2));

    if (!result.safe) {
      process.exit(43);
    }
  }

  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
