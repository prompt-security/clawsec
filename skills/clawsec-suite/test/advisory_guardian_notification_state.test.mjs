#!/usr/bin/env node

/**
 * Notification-dedup tests for the clawsec-advisory-guardian hook handler.
 *
 * OpenClaw never routes event.messages for agent:bootstrap; among the events
 * this hook handles it only attempts to route them for command:new (chat /new).
 * These tests check that bootstrap scans do not consume notification dedup
 * keys, and that concurrent scans in one process do not drop a key another scan
 * already persisted. They do not (and cannot) verify host delivery.
 *
 * Every fixture starts from a valid, pre-written state file so these tests do
 * not depend on the missing-file DEFAULT_STATE fallback.
 *
 * Run: node skills/clawsec-suite/test/advisory_guardian_notification_state.test.mjs
 */

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { pass, fail, report, exitWithResults, createTempDir } from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HANDLER_PATH = path.resolve(__dirname, "..", "hooks", "clawsec-advisory-guardian", "handler.ts");

// Isolate HOME before importing modules that resolve default paths at load time.
const homeDir = await createTempDir();
process.env.HOME = homeDir.path;
process.env.USERPROFILE = homeDir.path;

// Interception points for deterministic interleaving (see concurrency tests).
const realRename = fs.rename;
const realReaddir = fs.readdir;
let renameHook = null;
let readdirHook = null;
fs.rename = async (from, to) => {
  if (renameHook) await renameHook(from, to);
  return realRename(from, to);
};
fs.readdir = async (dir, ...rest) => {
  if (readdirHook) await readdirHook(dir);
  return realReaddir(dir, ...rest);
};

const { default: handler } = await import(pathToFileURL(HANDLER_PATH).href);

const SKILL = { name: "helper-plus", version: "1.0.0" };
const ADVISORY = {
  id: "TEST-GUARDIAN-0001",
  severity: "high",
  type: "malicious_skill",
  title: "Synthetic advisory for notification-state tests",
  action: "Remove the affected skill",
  affected: ["helper-plus@1.0.0"],
};
const MATCH_KEY = `${ADVISORY.id}::helper-plus@1.0.0`;

const EMPTY_STATE = {
  schema_version: "1.1",
  known_advisories: [],
  last_feed_check: null,
  last_feed_updated: null,
  last_hook_scan: null,
  notified_matches: {},
};

async function setupFixture({ advisories = [ADVISORY], state = EMPTY_STATE, suppressions } = {}) {
  const tmp = await createTempDir();
  const installRoot = path.join(tmp.path, "skills");
  const skillDir = path.join(installRoot, SKILL.name);
  await fs.mkdir(skillDir, { recursive: true });
  await fs.writeFile(path.join(skillDir, "skill.json"), JSON.stringify(SKILL));

  const feedPath = path.join(tmp.path, "feed.json");
  await fs.writeFile(feedPath, JSON.stringify({ version: "1", updated: "2026-11-27T00:00:00Z", advisories }));

  const stateFile = path.join(tmp.path, "state.json");
  await fs.writeFile(stateFile, JSON.stringify(state));

  const auditConfig = path.join(tmp.path, "security-audit.json");
  const fixture = { tmp, installRoot, skillDir, stateFile, auditConfig };
  await setSuppressions(fixture, suppressions);

  Object.assign(process.env, {
    CLAWSEC_INSTALL_ROOT: installRoot,
    CLAWSEC_SUITE_STATE_FILE: stateFile,
    CLAWSEC_LOCAL_FEED: feedPath,
    CLAWSEC_FEED_URL: "https://127.0.0.1.invalid/feed.json",
    CLAWSEC_ALLOW_UNSIGNED_FEED: "1",
    CLAWSEC_HOOK_INTERVAL_SECONDS: "300",
    OPENCLAW_AUDIT_CONFIG: auditConfig,
  });
  return fixture;
}

async function setSuppressions(fixture, suppressions) {
  if (!suppressions) {
    await fs.rm(fixture.auditConfig, { force: true });
    return;
  }
  await fs.writeFile(fixture.auditConfig, JSON.stringify({ enabledFor: ["advisory"], suppressions }));
}

function makeEvent(type, action, { messages = [] } = {}) {
  const event = { type, action, sessionKey: "test", context: {}, timestamp: new Date() };
  if (messages !== null) event.messages = messages;
  if (type === "agent") event.context = { workspaceDir: "/nonexistent", bootstrapFiles: [] };
  return event;
}

async function bootstrap() {
  const event = makeEvent("agent", "bootstrap");
  await handler(event);
  return event.messages;
}

async function commandNew(opts) {
  const event = makeEvent("command", "new", opts);
  await handler(event);
  return event.messages;
}

async function readState(stateFile) {
  return JSON.parse(await fs.readFile(stateFile, "utf8"));
}

async function expireScanInterval(stateFile) {
  const state = await readState(stateFile);
  state.last_hook_scan = "2000-01-01T00:00:00.000Z";
  await fs.writeFile(stateFile, JSON.stringify(state));
}

const alerts = (messages) => (messages ?? []).filter((m) => m.startsWith("CLAWSEC ALERT"));
const keyCount = async (stateFile) => Object.keys((await readState(stateFile)).notified_matches).length;
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function runTest(name, fn) {
  let fixture;
  try {
    await fn(async (opts) => (fixture = await setupFixture(opts)));
    pass(name);
  } catch (error) {
    fail(name, error);
  } finally {
    renameHook = null;
    readdirHook = null;
    await fixture?.tmp?.cleanup();
  }
}

// Silence expected unsigned-mode / feed fallback warnings.
const originalWarn = console.warn;
console.warn = () => {};

await runTest("bootstrap appends the alert without recording a dedup key", async (setup) => {
  const f = await setup();
  assert(alerts(await bootstrap()).length === 1, "bootstrap should still append the alert");
  const state = await readState(f.stateFile);
  assert(Object.keys(state.notified_matches).length === 0, "bootstrap must not record notified_matches");
  assert(state.last_hook_scan, "bootstrap scan time should still be persisted");
});

await runTest("alert left pending by bootstrap is appended on the next command:new", async (setup) => {
  const f = await setup();
  await bootstrap();
  const messages = await commandNew();
  assert(alerts(messages).length === 1, "command:new after bootstrap must append the alert");
  assert(messages.join("\n").includes(ADVISORY.id), "alert should name the advisory");
  assert((await readState(f.stateFile)).notified_matches[MATCH_KEY], "command:new should record the key");
});

await runTest("after command:new records a key, later scans stay deduplicated", async (setup) => {
  const f = await setup();
  assert(alerts(await commandNew()).length === 1, "first command:new should append the alert");
  assert(alerts(await commandNew()).length === 0, "second command:new must not repeat the alert");
  await expireScanInterval(f.stateFile);
  assert(alerts(await bootstrap()).length === 0, "bootstrap after a recorded key must not alert");
});

await runTest("repeated bootstraps never record; alert stays pending", async (setup) => {
  const f = await setup();
  for (let i = 0; i < 3; i++) {
    await expireScanInterval(f.stateFile);
    assert(alerts(await bootstrap()).length === 1, `bootstrap #${i + 1} should append the alert`);
  }
  assert((await keyCount(f.stateFile)) === 0, "no keys after bootstraps");
  assert(alerts(await commandNew()).length === 1, "command:new should still append the alert");
});

await runTest("command:new without a messages array does not record the key", async (setup) => {
  const f = await setup();
  await commandNew({ messages: null });
  assert((await keyCount(f.stateFile)) === 0, "must not record without a messages array");
  assert(alerts(await commandNew()).length === 1, "later command:new with messages should alert");
});

await runTest("suppressed advisory is not alerted or recorded; alerts after un-suppression", async (setup) => {
  const f = await setup({
    suppressions: [{ checkId: ADVISORY.id, skill: SKILL.name, reason: "test", suppressedAt: "2026-11-27T00:00:00Z" }],
  });
  const messages = await commandNew();
  assert(alerts(messages).length === 0, "suppressed match must not alert");
  assert(messages.some((m) => m.includes("suppressed by allowlist config")), "suppressed notice expected");
  assert((await keyCount(f.stateFile)) === 0, "suppressed match not recorded");

  await setSuppressions(f, undefined);
  assert(alerts(await commandNew()).length === 1, "un-suppressed match should alert on command:new");
  assert((await keyCount(f.stateFile)) === 1, "un-suppressed match recorded");
});

await runTest("no advisory match: no messages, state persisted", async (setup) => {
  const f = await setup({ advisories: [{ ...ADVISORY, affected: ["other-skill@1.0.0"] }] });
  assert((await commandNew()).length === 0, "no messages expected without matches");
  const state = await readState(f.stateFile);
  assert(state.known_advisories.includes(ADVISORY.id), "known_advisories should be updated");
  assert(Object.keys(state.notified_matches).length === 0, "nothing recorded");
});

await runTest("existing notified_matches are honored and keep their timestamp", async (setup) => {
  const f = await setup({
    state: { ...EMPTY_STATE, known_advisories: [ADVISORY.id], notified_matches: { [MATCH_KEY]: "2026-01-01T00:00:00.000Z" } },
  });
  assert(alerts(await commandNew()).length === 0, "previously recorded key must not re-alert");
  assert((await readState(f.stateFile)).notified_matches[MATCH_KEY] === "2026-01-01T00:00:00.000Z", "timestamp kept");
});

await runTest("legacy heartbeat state file (schema 1.0) still works", async (setup) => {
  const f = await setup({
    state: { schema_version: "1.0", known_advisories: [], last_feed_check: null, last_feed_updated: null },
  });
  await bootstrap();
  assert(alerts(await commandNew()).length === 1, "command:new should alert with legacy state");
  const state = await readState(f.stateFile);
  assert(state.schema_version === "1.1", "state normalized to 1.1");
  assert(state.notified_matches[MATCH_KEY], "key recorded after command:new");
});

await runTest("removal advisory preserves fixture skill.json and directory, and requests approval", async (setup) => {
  const f = await setup();
  const before = await fs.readFile(path.join(f.skillDir, "skill.json"), "utf8");
  await bootstrap();
  const messages = await commandNew();
  assert(before === (await fs.readFile(path.join(f.skillDir, "skill.json"), "utf8")), "skill.json unchanged");
  assert((await fs.readdir(f.installRoot)).includes(SKILL.name), "skill directory must remain");
  assert(messages.join("\n").includes("Approval needed"), "removal advisory must request approval");
});

/**
 * Concurrency: bootstrap holds a stale snapshot while command:new persists a key.
 * `pausePoint` selects where bootstrap is paused:
 *   - "rename": after writing its temp file, before renaming it over the state file
 *   - "scan":   after loading state, while discovering installed skills (before commit)
 * command:new is given up to 2s to finish while bootstrap is paused; with in-process
 * commit serialization it may instead wait for bootstrap, which is also accepted.
 */
async function staleBootstrapInterleaving(f, pausePoint) {
  let onPaused;
  let release;
  const paused = new Promise((resolve) => (onPaused = resolve));
  const gate = new Promise((resolve) => (release = resolve));
  let armed = true;
  const pause = async () => {
    armed = false;
    onPaused();
    await gate;
  };
  if (pausePoint === "rename") {
    renameHook = async (_from, to) => {
      if (armed && to === f.stateFile) await pause();
    };
  } else {
    readdirHook = async (dir) => {
      if (armed && dir === f.installRoot) await pause();
    };
  }

  const bootEvent = makeEvent("agent", "bootstrap");
  const bootDone = handler(bootEvent);
  await paused;

  const newEvent = makeEvent("command", "new");
  const newDone = handler(newEvent);
  await Promise.race([newDone, delay(2000)]);
  release();
  await bootDone;
  await newDone;

  assert(alerts(newEvent.messages).length === 1, "command:new should append the alert");
  assert((await readState(f.stateFile)).notified_matches[MATCH_KEY], "persisted key lost after stale bootstrap commit");
  assert(alerts(await commandNew()).length === 0, "next command:new must not repeat the alert");
}

await runTest("concurrency: stale bootstrap paused before rename does not drop a persisted key", async (setup) => {
  await staleBootstrapInterleaving(await setup(), "rename");
});

await runTest("concurrency: stale bootstrap paused before commit does not drop a persisted key", async (setup) => {
  await staleBootstrapInterleaving(await setup(), "scan");
});

await runTest("concurrency: a failed commit does not block later scans", async (setup) => {
  const f = await setup();
  let failOnce = true;
  renameHook = async (_from, to) => {
    if (failOnce && to === f.stateFile) {
      failOnce = false;
      throw Object.assign(new Error("simulated rename failure"), { code: "EIO" });
    }
  };
  let threw = false;
  try {
    await commandNew();
  } catch {
    threw = true;
  }
  assert(threw, "first commit should surface the simulated failure");
  const second = await Promise.race([commandNew().then((m) => m), delay(2000).then(() => "timeout")]);
  assert(second !== "timeout", "later scan blocked after a failed commit");
  assert(alerts(second).length === 1, "key was not persisted by the failed commit, so alert repeats");
  assert((await keyCount(f.stateFile)) === 1, "second commit should persist the key");
});

console.warn = originalWarn;
fs.rename = realRename;
fs.readdir = realReaddir;
await homeDir.cleanup();
report();
exitWithResults();
