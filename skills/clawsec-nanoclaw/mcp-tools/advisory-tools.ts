/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * ClawSec Advisory Feed MCP Tools for NanoClaw
 *
 * Add these tools to /workspace/project/container/agent-runner/src/ipc-mcp-stdio.ts
 *
 * These tools run in the container context and read from the host-managed
 * advisory cache at /workspace/project/data/clawsec-advisory-cache.json
 */

import fs from 'fs';
import path from 'path';
import { z } from 'zod';
import { evaluateAdvisoryRisk, normalizeExploitabilityScore } from '../lib/risk.js';
import { matchesAffectedSpecifier } from '../lib/advisories.js';

// These variables are provided by the host environment (ipc-mcp-stdio.ts)
// when this code is integrated into the NanoClaw container agent.
declare const server: { tool: (...args: any[]) => void };
declare function writeIpcFile(dir: string, data: any): void;
declare const TASKS_DIR: string;
declare const groupFolder: string;
const CACHE_FILE = '/workspace/project/data/clawsec-advisory-cache.json';

const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const exploitabilityOrder: Record<string, number> = { high: 0, medium: 1, low: 2, unknown: 3 };

/**
 * Discover installed skills in a directory
 */
async function discoverInstalledSkills(installRoot: string): Promise<Array<{
  name: string;
  version: string | null;
  dirName: string;
}>> {
  const skills: Array<{ name: string; version: string | null; dirName: string }> = [];

  try {
    const entries = fs.readdirSync(installRoot, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const skillJsonPath = path.join(installRoot, entry.name, 'skill.json');
      try {
        const raw = fs.readFileSync(skillJsonPath, 'utf8');
        const parsed = JSON.parse(raw);
        skills.push({
          name: parsed.name || entry.name,
          version: parsed.version || null,
          dirName: entry.name,
        });
      } catch {
        // Skill without skill.json, use directory name
        skills.push({
          name: entry.name,
          version: null,
          dirName: entry.name,
        });
      }
    }
  } catch {
    // Return empty if directory doesn't exist
  }

  return skills;
}

/**
 * Find advisory matches for installed skills
 */
function findAdvisoryMatches(
  advisories: any[],
  skills: Array<{ name: string; version: string | null; dirName: string }>
): Array<{
  advisory: any;
  skill: { name: string; version: string | null; dirName: string };
  matchedAffected: string[];
}> {
  const matches: Array<{
    advisory: any;
    skill: { name: string; version: string | null; dirName: string };
    matchedAffected: string[];
  }> = [];

  for (const advisory of advisories) {
    for (const skill of skills) {
      const matchedAffected: string[] = [];

      for (const affected of advisory.affected || []) {
        if (matchesAffectedSpecifier(affected, skill.name, skill.version, skill.dirName)) {
          matchedAffected.push(affected);
        }
      }

      if (matchedAffected.length > 0) {
        matches.push({ advisory, skill, matchedAffected });
      }
    }
  }

  return matches;
}

// Add these tools to the server:

server.tool(
  'clawsec_check_advisories',
  'Check ClawSec advisory feed for security issues affecting installed skills. Returns list of matching advisories with details. Use this to scan for known vulnerabilities, malicious skills, or deprecated packages.',
  {
    installRoot: z.string().optional().describe('Skills installation directory (default: ~/.claude/skills)'),
    forceRefresh: z.boolean().optional().describe('Force cache refresh before checking (causes 1-2 second delay)'),
  },
  async (args) => {
    // Request cache refresh if needed
    if (args.forceRefresh) {
      writeIpcFile(TASKS_DIR, {
        type: 'refresh_advisory_cache',
        groupFolder,
        timestamp: new Date().toISOString(),
      });
      // Wait for refresh (async, best-effort)
      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    // Read cache from shared mount
    try {
      const cacheData = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
      const installRoot = args.installRoot || path.join(process.env.HOME || '~', '.claude', 'skills');

      // Discover installed skills
      const skills = await discoverInstalledSkills(installRoot);

      // Find matches
      const matches = findAdvisoryMatches(cacheData.feed.advisories, skills);

      // Calculate cache age
      const cacheAge = Date.now() - Date.parse(cacheData.fetchedAt);
      const cacheAgeMinutes = Math.floor(cacheAge / 60000);

      const result = {
        success: true,
        feedUpdated: cacheData.feed.updated || null,
        totalAdvisories: cacheData.feed.advisories.length,
        installedSkills: skills.length,
        matches: matches.map(m => ({
          advisory: {
            id: m.advisory.id,
            severity: m.advisory.severity,
            type: m.advisory.type,
            title: m.advisory.title,
            description: m.advisory.description,
            action: m.advisory.action,
            published: m.advisory.published,
            exploitability_score: normalizeExploitabilityScore(m.advisory.exploitability_score),
            exploitability_rationale: m.advisory.exploitability_rationale || null,
          },
          skill: m.skill,
          matchedAffected: m.matchedAffected,
        })),
        cacheAge: `${cacheAgeMinutes} minutes`,
        cacheTimestamp: cacheData.fetchedAt,
      };

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: `Failed to check advisories: ${error instanceof Error ? error.message : String(error)}`
          }, null, 2)
        }],
        isError: true,
      };
    }
  }
);

server.tool(
  'clawsec_check_skill_safety',
  'Check if a specific skill is safe to install based on ClawSec advisory feed. Returns safety recommendation (install/block/review) with reasons. Use this as a pre-install gate before installing any skill.',
  {
    skillName: z.string().describe('Name of skill to check'),
    skillVersion: z.string().optional().describe('Version of skill (optional, for version-specific checks)'),
  },
  async (args) => {
    try {
      const cacheData = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));

      // Find matching advisories for this skill
      const matchingAdvisories = cacheData.feed.advisories.filter((advisory: any) =>
        advisory.affected.some((affected: string) => {
          return matchesAffectedSpecifier(affected, args.skillName, args.skillVersion || null);
        })
      );

      if (matchingAdvisories.length === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              safe: true,
              advisories: [],
              recommendation: 'install',
              reason: 'No known advisories for this skill',
            }, null, 2),
          }],
        };
      }

      const risk = evaluateAdvisoryRisk(matchingAdvisories);

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            safe: risk.safe,
            advisories: matchingAdvisories.map((a: any) => ({
              id: a.id,
              severity: a.severity,
              type: a.type,
              title: a.title,
              description: a.description,
              action: a.action,
              published: a.published,
              affected: a.affected,
              exploitability_score: normalizeExploitabilityScore(a.exploitability_score),
              exploitability_rationale: a.exploitability_rationale || null,
            })),
            recommendation: risk.recommendation,
            reason: risk.reason,
            skillName: args.skillName,
            skillVersion: args.skillVersion || null,
            advisoryCount: matchingAdvisories.length,
          }, null, 2),
        }],
      };
    } catch (error) {
      // Conservative: block on error
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            safe: false,
            advisories: [],
            recommendation: 'review',
            reason: `Failed to verify safety: ${error instanceof Error ? error.message : String(error)}`,
            error: true,
          }, null, 2),
        }],
      };
    }
  }
);

server.tool(
  'clawsec_list_advisories',
  'List ClawSec advisories with optional filtering. Use this to browse security advisories, filter by severity/type/exploitability, or search for specific affected skills.',
  {
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Filter by severity level'),
    type: z.string().optional().describe('Filter by advisory type (for example: vulnerable_skill, malicious_skill, prompt_injection)'),
    exploitabilityScore: z.enum(['high', 'medium', 'low', 'unknown']).optional()
      .describe('Filter by exploitability score'),
    affectedSkill: z.string().optional().describe('Filter by affected skill name (partial match supported)'),
    limit: z.number().optional().describe('Maximum number of results (default: unlimited)'),
  },
  async (args) => {
    try {
      const cacheData = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
      let advisories = [...cacheData.feed.advisories];

      // Apply filters
      if (args.severity) {
        advisories = advisories.filter((a: any) => a.severity === args.severity);
      }
      if (args.type) {
        const typeFilter = String(args.type).toLowerCase().trim();
        advisories = advisories.filter((a: any) => String(a.type || '').toLowerCase().trim() === typeFilter);
      }
      if (args.exploitabilityScore) {
        advisories = advisories.filter(
          (a: any) => normalizeExploitabilityScore(a.exploitability_score) === args.exploitabilityScore
        );
      }
      if (args.affectedSkill) {
        advisories = advisories.filter((a: any) =>
          a.affected.some((spec: string) => spec.includes(args.affectedSkill!))
        );
      }

      // Sort by exploitability first, then severity, then publish date (newest first).
      advisories.sort((a: any, b: any) => {
        const exploitabilityDiff =
          (exploitabilityOrder[normalizeExploitabilityScore(a.exploitability_score)] ?? 999) -
          (exploitabilityOrder[normalizeExploitabilityScore(b.exploitability_score)] ?? 999);
        if (exploitabilityDiff !== 0) return exploitabilityDiff;

        const severityDiff = (severityOrder[a.severity] || 999) - (severityOrder[b.severity] || 999);
        if (severityDiff !== 0) return severityDiff;
        return (b.published || '').localeCompare(a.published || '');
      });

      // Apply limit
      const originalCount = advisories.length;
      if (args.limit && args.limit > 0) {
        advisories = advisories.slice(0, args.limit);
      }

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: true,
            feedUpdated: cacheData.feed.updated || null,
            advisories: advisories.map((a: any) => ({
              id: a.id,
              severity: a.severity,
              type: a.type,
              title: a.title,
              description: a.description,
              action: a.action,
              published: a.published,
              affected: a.affected,
              exploitability_score: normalizeExploitabilityScore(a.exploitability_score),
              exploitability_rationale: a.exploitability_rationale || null,
            })),
            total: cacheData.feed.advisories.length,
            filtered: originalCount,
            returned: advisories.length,
            filters: {
              severity: args.severity || null,
              type: args.type || null,
              exploitabilityScore: args.exploitabilityScore || null,
              affectedSkill: args.affectedSkill || null,
              limit: args.limit || null,
            },
          }, null, 2),
        }],
      };
    } catch (error) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: `Failed to list advisories: ${error instanceof Error ? error.message : String(error)}`,
          }, null, 2),
        }],
        isError: true,
      };
    }
  }
);

server.tool(
  'clawsec_refresh_cache',
  'Request immediate refresh of the advisory cache from ClawSec feed. This fetches the latest advisories and verifies signatures. Use when you need up-to-date advisory information.',
  {},
  async () => {
    writeIpcFile(TASKS_DIR, {
      type: 'refresh_advisory_cache',
      groupFolder,
      timestamp: new Date().toISOString(),
    });

    return {
      content: [{
        type: 'text' as const,
        text: 'Advisory cache refresh requested. This may take a few seconds. Check status with clawsec_check_advisories.',
      }],
    };
  }
);
