import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { uniqueStrings } from "./lib/utils.mjs";
import { isValidFeedPayload, loadRemoteFeed } from "./lib/feed.mjs";
import type { HookEvent, FeedPayload, AdvisoryMatch } from "./lib/types.ts";
import { loadState, persistState } from "./lib/state.ts";
import { discoverInstalledSkills, findMatches, matchKey, buildAlertMessage } from "./lib/matching.ts";

const DEFAULT_FEED_URL =
  "https://raw.githubusercontent.com/prompt-security/clawsec/main/advisories/feed.json";
const DEFAULT_SCAN_INTERVAL_SECONDS = 300;

function expandHome(inputPath: string): string {
  if (!inputPath) return inputPath;
  if (inputPath === "~") return os.homedir();
  if (inputPath.startsWith("~/")) return path.join(os.homedir(), inputPath.slice(2));
  return inputPath;
}

function parsePositiveInteger(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function toEventName(event: HookEvent): string {
  const eventType = String(event.type ?? "").trim();
  const action = String(event.action ?? "").trim();
  if (!eventType || !action) return "";
  return `${eventType}:${action}`;
}

function shouldHandleEvent(event: HookEvent): boolean {
  const eventName = toEventName(event);
  return eventName === "agent:bootstrap" || eventName === "command:new";
}

function epochMs(isoTimestamp: string | null): number {
  if (!isoTimestamp) return 0;
  const parsed = Date.parse(isoTimestamp);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function scannedRecently(lastScan: string | null, minIntervalSeconds: number): boolean {
  const sinceMs = Date.now() - epochMs(lastScan);
  return sinceMs >= 0 && sinceMs < minIntervalSeconds * 1000;
}

async function loadFeed(feedUrl: string, localFeedPath: string): Promise<FeedPayload> {
  const remoteFeed = await loadRemoteFeed(feedUrl);
  if (remoteFeed) return remoteFeed;

  const fallbackRaw = await fs.readFile(localFeedPath, "utf8");
  const fallbackPayload = JSON.parse(fallbackRaw);
  if (!isValidFeedPayload(fallbackPayload)) {
    throw new Error(`Invalid advisory feed format in fallback file: ${localFeedPath}`);
  }
  return fallbackPayload;
}

const handler = async (event: HookEvent): Promise<void> => {
  if (!shouldHandleEvent(event)) return;

  const installRoot = expandHome(
    process.env.CLAWSEC_INSTALL_ROOT || process.env.INSTALL_ROOT || path.join(os.homedir(), ".openclaw", "skills"),
  );
  const suiteDir = expandHome(process.env.CLAWSEC_SUITE_DIR || path.join(installRoot, "clawsec-suite"));
  const localFeedPath = expandHome(process.env.CLAWSEC_LOCAL_FEED || path.join(suiteDir, "advisories", "feed.json"));
  const stateFile = expandHome(
    process.env.CLAWSEC_SUITE_STATE_FILE || path.join(os.homedir(), ".openclaw", "clawsec-suite-feed-state.json"),
  );
  const feedUrl = process.env.CLAWSEC_FEED_URL || DEFAULT_FEED_URL;
  const scanIntervalSeconds = parsePositiveInteger(
    process.env.CLAWSEC_HOOK_INTERVAL_SECONDS,
    DEFAULT_SCAN_INTERVAL_SECONDS,
  );

  const forceScan = toEventName(event) === "command:new";
  const state = await loadState(stateFile);
  if (!forceScan && scannedRecently(state.last_hook_scan, scanIntervalSeconds)) {
    return;
  }

  let feed: FeedPayload;
  try {
    feed = await loadFeed(feedUrl, localFeedPath);
  } catch (error) {
    console.warn(`[clawsec-advisory-guardian] failed to load advisory feed: ${String(error)}`);
    return;
  }

  const nowIso = new Date().toISOString();
  state.last_hook_scan = nowIso;
  state.last_feed_check = nowIso;

  if (typeof feed.updated === "string" && feed.updated.trim()) {
    state.last_feed_updated = feed.updated;
  }

  const advisoryIds = feed.advisories
    .map((advisory) => advisory.id)
    .filter((id): id is string => typeof id === "string" && id.trim() !== "");
  state.known_advisories = uniqueStrings([...state.known_advisories, ...advisoryIds]);

  const installedSkills = await discoverInstalledSkills(installRoot);
  const matches = findMatches(feed, installedSkills);

  if (matches.length === 0) {
    await persistState(stateFile, state);
    return;
  }

  const unseenMatches: AdvisoryMatch[] = [];
  for (const match of matches) {
    const key = matchKey(match);
    if (state.notified_matches[key]) {
      continue;
    }
    unseenMatches.push(match);
    state.notified_matches[key] = nowIso;
  }

  if (unseenMatches.length > 0 && Array.isArray(event.messages)) {
    event.messages.push(buildAlertMessage(unseenMatches, installRoot));
  }

  await persistState(stateFile, state);
};

export default handler;
