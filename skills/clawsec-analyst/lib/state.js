import * as fs from "node:fs/promises";
import * as path from "node:path";
/**
 * State persistence module for clawsec-analyst
 * Stores analysis history, cached results, and policies in ~/.openclaw/clawsec-analyst-state.json
 */
function isObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
export const DEFAULT_STATE = {
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
export function normalizeState(raw) {
    if (!isObject(raw)) {
        return { ...DEFAULT_STATE };
    }
    // Normalize cached_analyses
    const cachedAnalyses = {};
    if (isObject(raw.cached_analyses)) {
        for (const [key, value] of Object.entries(raw.cached_analyses)) {
            if (isObject(value) && typeof value.advisoryId === "string" && value.timestamp) {
                cachedAnalyses[key] = value;
            }
        }
    }
    // Normalize policies
    const policies = [];
    if (Array.isArray(raw.policies)) {
        for (const policy of raw.policies) {
            if (isObject(policy) &&
                typeof policy.id === "string" &&
                typeof policy.type === "string" &&
                policy.condition &&
                policy.action) {
                policies.push(policy);
            }
        }
    }
    // Normalize analysis_history
    const analysisHistory = [];
    if (Array.isArray(raw.analysis_history)) {
        for (const entry of raw.analysis_history) {
            if (isObject(entry) &&
                typeof entry.timestamp === "string" &&
                typeof entry.type === "string" &&
                typeof entry.targetId === "string" &&
                typeof entry.result === "string") {
                analysisHistory.push(entry);
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
export async function loadState(stateFile) {
    try {
        const raw = await fs.readFile(stateFile, "utf8");
        return normalizeState(JSON.parse(raw));
    }
    catch {
        return { ...DEFAULT_STATE };
    }
}
/**
 * Persists state to file atomically with secure permissions (0600)
 * Uses temp file + rename for atomic write
 * @param stateFile - Path to state JSON file
 * @param state - State object to persist
 */
export async function persistState(stateFile, state) {
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
    }
    catch (err) {
        const code = err instanceof Error && "code" in err ? err.code : undefined;
        if (code === "ENOTSUP" || code === "EPERM") {
            console.warn(`Warning: chmod 0600 failed for ${stateFile} (${code}). ` +
                "File permissions may not be enforced on this platform/filesystem.");
        }
        else {
            throw err;
        }
    }
}
