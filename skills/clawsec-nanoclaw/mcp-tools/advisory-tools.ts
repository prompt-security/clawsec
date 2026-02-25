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

// These variables are provided by the host environment (ipc-mcp-stdio.ts)
// when this code is integrated into the NanoClaw container agent.
declare const server: { tool: (...args: any[]) => void };
declare function writeIpcFile(dir: string, data: any): void;
declare const TASKS_DIR: string;
declare const groupFolder: string;

// Add these helper functions to the file:

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
        const atIndex = affected.lastIndexOf('@');
        const affectedName = atIndex > 0 ? affected.slice(0, atIndex) : affected;

        if (affectedName === skill.name || affectedName === skill.dirName) {
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
    const cacheFile = '/workspace/project/data/clawsec-advisory-cache.json';

    try {
      const cacheData = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
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
    const cacheFile = '/workspace/project/data/clawsec-advisory-cache.json';

    try {
      const cacheData = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));

      // Find matching advisories for this skill
      const matchingAdvisories = cacheData.feed.advisories.filter((advisory: any) =>
        advisory.affected.some((affected: string) => {
          const atIndex = affected.lastIndexOf('@');
          const affectedName = atIndex > 0 ? affected.slice(0, atIndex) : affected;
          return affectedName === args.skillName;
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

      // Evaluate severity
      const hasMalicious = matchingAdvisories.some((a: any) => a.type === 'malicious');
      const hasRemoveAction = matchingAdvisories.some((a: any) => a.action === 'remove');
      const hasCritical = matchingAdvisories.some((a: any) => a.severity === 'critical');
      const hasHigh = matchingAdvisories.some((a: any) => a.severity === 'high');

      let recommendation: 'install' | 'block' | 'review';
      let reason: string;

      if (hasMalicious || hasRemoveAction) {
        recommendation = 'block';
        reason = 'Malicious skill or removal recommended by ClawSec';
      } else if (hasCritical) {
        recommendation = 'block';
        reason = 'Critical security advisory - do not install';
      } else if (hasHigh) {
        recommendation = 'review';
        reason = 'High severity advisory - user review strongly recommended';
      } else {
        recommendation = 'review';
        reason = 'Advisory found - review details before installing';
      }

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            safe: false, // Always false when advisories exist
            advisories: matchingAdvisories.map((a: any) => ({
              id: a.id,
              severity: a.severity,
              type: a.type,
              title: a.title,
              description: a.description,
              action: a.action,
              published: a.published,
              affected: a.affected,
            })),
            recommendation,
            reason,
            skillName: args.skillName,
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
  'List ClawSec advisories with optional filtering. Use this to browse security advisories, filter by severity/type, or search for specific affected skills.',
  {
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Filter by severity level'),
    type: z.enum(['vulnerability', 'malicious', 'deprecated']).optional().describe('Filter by advisory type'),
    affectedSkill: z.string().optional().describe('Filter by affected skill name (partial match supported)'),
    limit: z.number().optional().describe('Maximum number of results (default: unlimited)'),
  },
  async (args) => {
    const cacheFile = '/workspace/project/data/clawsec-advisory-cache.json';

    try {
      const cacheData = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
      let advisories = [...cacheData.feed.advisories];

      // Apply filters
      if (args.severity) {
        advisories = advisories.filter((a: any) => a.severity === args.severity);
      }
      if (args.type) {
        advisories = advisories.filter((a: any) => a.type === args.type);
      }
      if (args.affectedSkill) {
        advisories = advisories.filter((a: any) =>
          a.affected.some((spec: string) => spec.includes(args.affectedSkill!))
        );
      }

      // Sort by severity (critical first) and published date (newest first)
      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      advisories.sort((a: any, b: any) => {
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
            })),
            total: cacheData.feed.advisories.length,
            filtered: originalCount,
            returned: advisories.length,
            filters: {
              severity: args.severity || null,
              type: args.type || null,
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
