import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Dirent } from "node:fs";

const DEFAULT_FEED_URL =
  "https://raw.githubusercontent.com/prompt-security/clawsec/main/advisories/feed.json";
const DEFAULT_SCAN_INTERVAL_SECONDS = 300;

type HookEvent = {
  type?: string;
  action?: string;
  messages?: string[];
};

type Advisory = {
  id?: string;
  severity?: string;
  type?: string;
  title?: string;
  description?: string;
  action?: string;
  updated?: string;
  affected?: string[];
};

type FeedPayload = {
  updated?: string;
  advisories: Advisory[];
};

type InstalledSkill = {
  name: string;
  dirName: string;
  version: string | null;
};

type AdvisoryMatch = {
  advisory: Advisory;
  skill: InstalledSkill;
  matchedAffected: string[];
};

type AdvisoryState = {
  schema_version: string;
  known_advisories: string[];
  last_feed_check: string | null;
  last_feed_updated: string | null;
  last_hook_scan: string | null;
  notified_matches: Record<string, string>;
};

const DEFAULT_STATE: AdvisoryState = {
  schema_version: "1.1",
  known_advisories: [],
  last_feed_check: null,
  last_feed_updated: null,
  last_hook_scan: null,
  notified_matches: {},
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

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

function normalizeSkillName(value: string): string {
  return value.trim().toLowerCase();
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values));
}

function parseSemver(version: string): [number, number, number] | null {
  const cleaned = version.trim().replace(/^v/i, "").split("-")[0];
  const parts = cleaned.split(".");
  if (parts.length === 0) return null;

  const normalized = parts.slice(0, 3).map((part) => Number.parseInt(part, 10));
  while (normalized.length < 3) {
    normalized.push(0);
  }

  if (normalized.some((part) => Number.isNaN(part))) {
    return null;
  }
  return [normalized[0], normalized[1], normalized[2]];
}

function compareSemver(left: string, right: string): number | null {
  const a = parseSemver(left);
  const b = parseSemver(right);
  if (!a || !b) return null;

  for (let index = 0; index < 3; index += 1) {
    if (a[index] > b[index]) return 1;
    if (a[index] < b[index]) return -1;
  }
  return 0;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function versionMatches(version: string | null, rawSpec: string): boolean {
  const spec = rawSpec.trim();
  if (!spec || spec === "*" || spec.toLowerCase() === "any") return true;
  if (!version) return false;

  const normalizedVersion = version.trim();

  if (spec.includes("*")) {
    const regex = new RegExp(`^${escapeRegex(spec).replace(/\\\*/g, ".*")}$`);
    return regex.test(normalizedVersion);
  }

  const comparatorMatch = spec.match(/^(>=|<=|>|<|=)\s*(.+)$/);
  if (comparatorMatch) {
    const operator = comparatorMatch[1];
    const targetVersion = comparatorMatch[2].trim();
    const compared = compareSemver(normalizedVersion, targetVersion);
    if (compared === null) return false;
    if (operator === ">=") return compared >= 0;
    if (operator === "<=") return compared <= 0;
    if (operator === ">") return compared > 0;
    if (operator === "<") return compared < 0;
    return compared === 0;
  }

  if (spec.startsWith("^")) {
    const target = parseSemver(spec.slice(1));
    const current = parseSemver(normalizedVersion);
    if (!target || !current) return false;
    return current[0] === target[0] && compareSemver(normalizedVersion, spec.slice(1)) !== -1;
  }

  if (spec.startsWith("~")) {
    const target = parseSemver(spec.slice(1));
    const current = parseSemver(normalizedVersion);
    if (!target || !current) return false;
    return (
      current[0] === target[0] &&
      current[1] === target[1] &&
      compareSemver(normalizedVersion, spec.slice(1)) !== -1
    );
  }

  return normalizedVersion === spec || normalizedVersion === spec.replace(/^v/i, "");
}

function parseAffectedSpecifier(rawSpecifier: string): { name: string; versionSpec: string } | null {
  const specifier = rawSpecifier.trim();
  if (!specifier) return null;

  const atIndex = specifier.lastIndexOf("@");
  if (atIndex <= 0) {
    return { name: specifier, versionSpec: "*" };
  }

  return {
    name: specifier.slice(0, atIndex),
    versionSpec: specifier.slice(atIndex + 1),
  };
}

function affectedSpecifierMatchesSkill(rawSpecifier: string, skill: InstalledSkill): boolean {
  const parsed = parseAffectedSpecifier(rawSpecifier);
  if (!parsed) return false;

  const specName = normalizeSkillName(parsed.name);
  const skillName = normalizeSkillName(skill.name);
  if (specName !== skillName) return false;

  return versionMatches(skill.version, parsed.versionSpec);
}

function advisoryMatchesSkill(advisory: Advisory, skill: InstalledSkill): string[] {
  const affected = Array.isArray(advisory.affected) ? advisory.affected : [];
  const matches = affected.filter((specifier) => affectedSpecifierMatchesSkill(specifier, skill));
  return uniqueStrings(matches);
}

function looksRemovalRecommended(advisory: Advisory): boolean {
  const combined = `${advisory.action ?? ""} ${advisory.title ?? ""} ${advisory.description ?? ""}`.toLowerCase();
  return /\b(remove|uninstall|delete|disable|do not use|quarantine)\b/.test(combined);
}

function looksMalicious(advisory: Advisory): boolean {
  const type = String(advisory.type ?? "").toLowerCase();
  const combined = `${advisory.title ?? ""} ${advisory.description ?? ""} ${advisory.action ?? ""}`.toLowerCase();

  if (type === "malicious_skill" || type === "malicious_plugin") return true;
  if (/\b(malicious|exfiltrat|backdoor|trojan|credential theft|stealer)\b/.test(combined)) return true;
  return false;
}

function matchKey(match: AdvisoryMatch): string {
  return `${match.advisory.id ?? "unknown-advisory"}::${normalizeSkillName(match.skill.name)}@${
    match.skill.version ?? "unknown"
  }`;
}

function buildAlertMessage(matches: AdvisoryMatch[], installRoot: string): string {
  const lines: string[] = [];
  lines.push("CLAWSEC ALERT: advisory feed matches installed skill(s).");
  lines.push("Affected skill advisories:");

  const MAX_LISTED = 8;
  for (const match of matches.slice(0, MAX_LISTED)) {
    const severity = String(match.advisory.severity ?? "unknown").toUpperCase();
    const advisoryId = match.advisory.id ?? "unknown-id";
    const version = match.skill.version ?? "unknown";
    const matched = match.matchedAffected.join(", ");
    lines.push(
      `- [${severity}] ${advisoryId} -> ${match.skill.name}@${version}` +
        (matched ? ` (matched: ${matched})` : ""),
    );
    if (match.advisory.action) {
      lines.push(`  Action: ${match.advisory.action}`);
    }
  }

  if (matches.length > MAX_LISTED) {
    lines.push(`- ... ${matches.length - MAX_LISTED} additional match(es) not shown`);
  }

  const removalMatches = matches.filter((entry) => looksMalicious(entry.advisory) || looksRemovalRecommended(entry.advisory));
  if (removalMatches.length > 0) {
    const impactedSkills = uniqueStrings(removalMatches.map((entry) => entry.skill.name));
    const impactedDirs = uniqueStrings(removalMatches.map((entry) => entry.skill.dirName));
    lines.push("");
    lines.push("Recommendation: one or more matches indicate potentially malicious or unsafe skills.");
    lines.push("Best practice: remove or disable affected skills only after explicit user approval.");
    lines.push(
      "Double-confirmation policy: treat the install request as first intent and require an additional explicit confirmation with this advisory context.",
    );
    lines.push(`Approval needed: ask the user to approve removal of: ${impactedSkills.join(", ")}.`);
    lines.push("Candidate removal paths:");
    for (const dir of impactedDirs) {
      lines.push(`- ${path.join(installRoot, dir)}`);
    }
  } else {
    lines.push("");
    lines.push("Recommendation: review advisories and update/remove affected skills as directed.");
  }

  return lines.join("\n");
}

function normalizeState(raw: unknown): AdvisoryState {
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

async function loadState(stateFile: string): Promise<AdvisoryState> {
  try {
    const raw = await fs.readFile(stateFile, "utf8");
    return normalizeState(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_STATE };
  }
}

async function persistState(stateFile: string, state: AdvisoryState): Promise<void> {
  const normalized = normalizeState(state);
  await fs.mkdir(path.dirname(stateFile), { recursive: true });
  const tmpFile = `${stateFile}.tmp-${process.pid}-${Date.now()}`;
  await fs.writeFile(tmpFile, `${JSON.stringify(normalized, null, 2)}\n`, "utf8");
  await fs.rename(tmpFile, stateFile);
  try {
    await fs.chmod(stateFile, 0o600);
  } catch {
    // ignore chmod errors on platforms/filesystems that do not support POSIX permissions
  }
}

function isValidFeedPayload(raw: unknown): raw is FeedPayload {
  if (!isObject(raw)) return false;
  if (!Array.isArray(raw.advisories)) return false;
  return true;
}

async function loadRemoteFeed(feedUrl: string): Promise<FeedPayload | null> {
  const fetchFn = (globalThis as { fetch?: unknown }).fetch;
  if (typeof fetchFn !== "function") return null;

  const controller = new globalThis.AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetchFn(feedUrl, {
      method: "GET",
      signal: controller.signal,
      headers: { accept: "application/json" },
    });

    if (!response.ok) return null;
    const payload = await response.json();
    if (!isValidFeedPayload(payload)) return null;
    return payload;
  } catch {
    return null;
  } finally {
    globalThis.clearTimeout(timeout);
  }
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

async function discoverInstalledSkills(installRoot: string): Promise<InstalledSkill[]> {
  let entries: Dirent[];
  try {
    entries = await fs.readdir(installRoot, { withFileTypes: true });
  } catch {
    return [];
  }

  const skills: InstalledSkill[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;

    const fallbackName = entry.name;
    const skillDir = path.join(installRoot, entry.name);
    const skillJsonPath = path.join(skillDir, "skill.json");

    let skillName = fallbackName;
    let version: string | null = null;

    try {
      const rawSkillJson = await fs.readFile(skillJsonPath, "utf8");
      const parsedSkillJson = JSON.parse(rawSkillJson);
      if (isObject(parsedSkillJson) && typeof parsedSkillJson.name === "string" && parsedSkillJson.name.trim()) {
        skillName = parsedSkillJson.name.trim();
      }
      if (
        isObject(parsedSkillJson) &&
        typeof parsedSkillJson.version === "string" &&
        parsedSkillJson.version.trim()
      ) {
        version = parsedSkillJson.version.trim();
      }
    } catch {
      // best-effort scan: keep fallback directory name when skill.json is missing or invalid
    }

    skills.push({ name: skillName, dirName: entry.name, version });
  }

  return skills;
}

function findMatches(feed: FeedPayload, installedSkills: InstalledSkill[]): AdvisoryMatch[] {
  const matches: AdvisoryMatch[] = [];

  for (const advisory of feed.advisories) {
    const affected = Array.isArray(advisory.affected) ? advisory.affected : [];
    if (affected.length === 0) continue;

    for (const skill of installedSkills) {
      const matchedAffected = advisoryMatchesSkill(advisory, skill);
      if (matchedAffected.length === 0) continue;
      matches.push({ advisory, skill, matchedAffected });
    }
  }

  return matches;
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

  const nowIso = new Date().toISOString();
  state.last_hook_scan = nowIso;
  state.last_feed_check = nowIso;

  let feed: FeedPayload;
  try {
    feed = await loadFeed(feedUrl, localFeedPath);
  } catch (error) {
    console.warn(`[clawsec-advisory-guardian] failed to load advisory feed: ${String(error)}`);
    await persistState(stateFile, state);
    return;
  }

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
