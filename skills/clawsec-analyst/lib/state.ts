import * as fs from "node:fs/promises";
import * as path from "node:path";
import type {
  AnalystState,
  StructuredPolicy,
  AnalysisHistoryEntry,
  CachedAnalysis,
} from "./types.js";

/**
 * State persistence module for clawsec-analyst
 * Stores analysis history, cached results, and policies in ~/.openclaw/clawsec-analyst-state.json
 */

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export const DEFAULT_STATE: AnalystState = {
  schema_version: "1.0",
  last_feed_check: null,
  last_feed_updated: null,
  cached_analyses: {},
  policies: [],
  analysis_history: [],
};

/**
 * Validates and normalizes state object
 * Ensures all fields conform to AnalystState schema
 */
export function normalizeState(raw: unknown): AnalystState {
  if (!isObject(raw)) {
    return { ...DEFAULT_STATE };
  }

  // Normalize cached_analyses
  const cachedAnalyses: Record<string, CachedAnalysis> = {};
  if (isObject(raw.cached_analyses)) {
    for (const [key, value] of Object.entries(raw.cached_analyses)) {
      if (isObject(value) && typeof value.advisoryId === "string" && value.timestamp) {
        cachedAnalyses[key] = value as CachedAnalysis;
      }
    }
  }

  // Normalize policies
  const policies: StructuredPolicy[] = [];
  if (Array.isArray(raw.policies)) {
    for (const policy of raw.policies) {
      if (
        isObject(policy) &&
        typeof policy.id === "string" &&
        typeof policy.type === "string" &&
        policy.condition &&
        policy.action
      ) {
        policies.push(policy as StructuredPolicy);
      }
    }
  }

  // Normalize analysis_history
  const analysisHistory: AnalysisHistoryEntry[] = [];
  if (Array.isArray(raw.analysis_history)) {
    for (const entry of raw.analysis_history) {
      if (
        isObject(entry) &&
        typeof entry.timestamp === "string" &&
        typeof entry.type === "string" &&
        typeof entry.targetId === "string" &&
        typeof entry.result === "string"
      ) {
        analysisHistory.push(entry as AnalysisHistoryEntry);
      }
    }
  }

  return {
    schema_version: "1.0",
    last_feed_check: typeof raw.last_feed_check === "string" ? raw.last_feed_check : null,
    last_feed_updated: typeof raw.last_feed_updated === "string" ? raw.last_feed_updated : null,
    cached_analyses: cachedAnalyses,
    policies,
    analysis_history: analysisHistory,
  };
}

/**
 * Loads state from file, returns default state if file doesn't exist
 * @param stateFile - Path to state JSON file
 */
export async function loadState(stateFile: string): Promise<AnalystState> {
  try {
    const raw = await fs.readFile(stateFile, "utf8");
    return normalizeState(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_STATE };
  }
}

/**
 * Persists state to file atomically with secure permissions (0600)
 * Uses temp file + rename for atomic write
 * @param stateFile - Path to state JSON file
 * @param state - State object to persist
 */
export async function persistState(stateFile: string, state: AnalystState): Promise<void> {
  const normalized = normalizeState(state);
  await fs.mkdir(path.dirname(stateFile), { recursive: true });
  const tmpFile = `${stateFile}.tmp-${process.pid}-${Date.now()}`;
  await fs.writeFile(tmpFile, `${JSON.stringify(normalized, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await fs.rename(tmpFile, stateFile);
  try {
    await fs.chmod(stateFile, 0o600);
  } catch (err: unknown) {
    const code = err instanceof Error && "code" in err ? (err as { code: string }).code : undefined;
    if (code === "ENOTSUP" || code === "EPERM") {
      console.warn(
        `Warning: chmod 0600 failed for ${stateFile} (${code}). ` +
          "File permissions may not be enforced on this platform/filesystem.",
      );
    } else {
      throw err;
    }
  }
}
