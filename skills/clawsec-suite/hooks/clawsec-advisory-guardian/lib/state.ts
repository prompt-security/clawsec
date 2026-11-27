import fs from "node:fs/promises";
import path from "node:path";
import { isObject, uniqueStrings } from "./utils.mjs";
import type { AdvisoryState } from "./types.ts";

export const DEFAULT_STATE: AdvisoryState = {
  schema_version: "1.1",
  known_advisories: [],
  last_feed_check: null,
  last_feed_updated: null,
  last_hook_scan: null,
  notified_matches: {},
};

export function normalizeState(raw: unknown): AdvisoryState {
  if (!isObject(raw)) {
    return { ...DEFAULT_STATE };
  }

  const knownAdvisories = Array.isArray(raw.known_advisories)
    ? uniqueStrings(raw.known_advisories.filter((value): value is string => typeof value === "string" && value.trim() !== ""))
    : [];

  const notifiedMatches: Record<string, string> = {};
  if (isObject(raw.notified_matches)) {
    for (const [key, value] of Object.entries(raw.notified_matches)) {
      if (typeof value === "string" && value.trim()) {
        notifiedMatches[key] = value;
      }
    }
  }

  return {
    schema_version: "1.1",
    known_advisories: knownAdvisories,
    last_feed_check: typeof raw.last_feed_check === "string" ? raw.last_feed_check : null,
    last_feed_updated: typeof raw.last_feed_updated === "string" ? raw.last_feed_updated : null,
    last_hook_scan: typeof raw.last_hook_scan === "string" ? raw.last_hook_scan : null,
    notified_matches: notifiedMatches,
  };
}

export async function loadState(stateFile: string): Promise<AdvisoryState> {
  try {
    const raw = await fs.readFile(stateFile, "utf8");
    return normalizeState(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_STATE };
  }
}

export async function persistState(stateFile: string, state: AdvisoryState): Promise<void> {
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

// In-process commit queue per state file. Each entry resolves (never rejects),
// so a failed commit cannot block later scans.
const commitQueues = new Map<string, Promise<void>>();

async function withStateCommitLock<T>(stateFile: string, fn: () => Promise<T>): Promise<T> {
  const previous = commitQueues.get(stateFile) ?? Promise.resolve();
  let releaseLock!: () => void;
  const current = new Promise<void>((resolve) => {
    releaseLock = resolve;
  });
  const tail = previous.then(() => current);
  commitQueues.set(stateFile, tail);
  await previous;
  try {
    return await fn();
  } finally {
    releaseLock();
    if (commitQueues.get(stateFile) === tail) {
      commitQueues.delete(stateFile);
    }
  }
}

/**
 * Persist a scan's state without discarding notification records that another
 * scan in this process committed after this scan loaded its snapshot.
 * Under a per-file in-process lock, re-reads the file and keeps every
 * notified_matches key and known_advisories id already on disk (existing
 * timestamps win); other fields come from `state`. Does not coordinate
 * across processes.
 */
export async function persistStateMerged(stateFile: string, state: AdvisoryState): Promise<void> {
  await withStateCommitLock(stateFile, async () => {
    const onDisk = await loadState(stateFile);
    const merged = normalizeState(state);
    merged.known_advisories = uniqueStrings([...onDisk.known_advisories, ...merged.known_advisories]);
    merged.notified_matches = { ...merged.notified_matches, ...onDisk.notified_matches };
    await persistState(stateFile, merged);
  });
}
