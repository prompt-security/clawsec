#!/usr/bin/env node

/**
 * Fallback-state isolation tests for clawsec-advisory-guardian lib/state.ts.
 *
 * loadState()/normalizeState() fall back to a default state for a missing file,
 * malformed JSON, or non-object JSON. Each fallback must own its mutable
 * containers; otherwise writes to one fallback (e.g. notified_matches) leak into
 * DEFAULT_STATE and into every later fallback in the same process.
 *
 * Run: node skills/clawsec-suite/test/advisory_guardian_state_defaults.test.mjs
 */

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { pass, fail, report, exitWithResults, createTempDir } from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STATE_PATH = path.resolve(__dirname, "..", "hooks", "clawsec-advisory-guardian", "lib", "state.ts");
const { DEFAULT_STATE, normalizeState, loadState, persistState } = await import(
  pathToFileURL(STATE_PATH).href
);

const DEFAULT_SNAPSHOT = JSON.stringify(DEFAULT_STATE);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertDefaultUntouched() {
  assert(JSON.stringify(DEFAULT_STATE) === DEFAULT_SNAPSHOT, `DEFAULT_STATE was mutated: ${JSON.stringify(DEFAULT_STATE)}`);
}

function assertIndependentFallbacks(first, second, label) {
  first.notified_matches["ADV-1::skill@1.0.0"] = "2026-01-01T00:00:00.000Z";
  first.known_advisories.push("ADV-1");
  assert(Object.keys(second.notified_matches).length === 0, `${label}: notified_matches shared between fallbacks`);
  assert(second.known_advisories.length === 0, `${label}: known_advisories shared between fallbacks`);
  assert(first.notified_matches !== DEFAULT_STATE.notified_matches, `${label}: aliases DEFAULT_STATE.notified_matches`);
  assert(first.known_advisories !== DEFAULT_STATE.known_advisories, `${label}: aliases DEFAULT_STATE.known_advisories`);
  assertDefaultUntouched();
}

const tmp = await createTempDir();
const write = async (name, content) => {
  const file = path.join(tmp.path, name);
  await fs.writeFile(file, content);
  return file;
};

async function test(name, fn) {
  try {
    await fn();
    pass(name);
  } catch (error) {
    fail(name, error);
  }
}

await test("loadState: missing file fallbacks are independent", async () => {
  const missing = path.join(tmp.path, "does-not-exist.json");
  assertIndependentFallbacks(await loadState(missing), await loadState(missing), "missing file");
});

await test("loadState: malformed JSON fallbacks are independent", async () => {
  const bad = await write("malformed.json", "{ not json");
  assertIndependentFallbacks(await loadState(bad), await loadState(bad), "malformed JSON");
});

await test("loadState: non-object JSON fallbacks are independent", async () => {
  for (const [name, body] of [["null.json", "null"], ["array.json", "[]"], ["number.json", "42"], ["string.json", '"x"']]) {
    const file = await write(name, body);
    assertIndependentFallbacks(await loadState(file), await loadState(file), name);
  }
});

await test("normalizeState: non-object inputs return independent defaults", async () => {
  for (const raw of [undefined, null, 42, "x", []]) {
    assertIndependentFallbacks(normalizeState(raw), normalizeState(raw), `normalizeState(${JSON.stringify(raw)})`);
  }
});

await test("fallback after a different file was mutated stays empty", async () => {
  const a = await loadState(path.join(tmp.path, "missing-a.json"));
  a.notified_matches["ADV-2::skill@1.0.0"] = "2026-01-01T00:00:00.000Z";
  const b = await loadState(path.join(tmp.path, "missing-b.json"));
  assert(Object.keys(b.notified_matches).length === 0, "later fallback inherited a key from an earlier fallback");
  assertDefaultUntouched();
});

await test("fallback values keep the existing default schema", async () => {
  const state = await loadState(path.join(tmp.path, "missing-schema.json"));
  assert(JSON.stringify(state) === DEFAULT_SNAPSHOT, `fallback differs from DEFAULT_STATE: ${JSON.stringify(state)}`);
});

await test("valid state file loads unchanged", async () => {
  const valid = {
    schema_version: "1.1",
    known_advisories: ["ADV-1", "ADV-2"],
    last_feed_check: "2026-11-01T00:00:00.000Z",
    last_feed_updated: "2026-11-01T00:00:00Z",
    last_hook_scan: "2026-11-01T00:00:00.000Z",
    notified_matches: { "ADV-1::skill@1.0.0": "2026-11-01T00:00:00.000Z" },
  };
  const file = await write("valid.json", JSON.stringify(valid));
  const loaded = await loadState(file);
  assert(JSON.stringify(loaded) === JSON.stringify(valid), `valid state changed on load: ${JSON.stringify(loaded)}`);
});

await test("legacy 1.0 state file is normalized as before", async () => {
  const file = await write(
    "legacy.json",
    JSON.stringify({ schema_version: "1.0", known_advisories: ["ADV-1"], last_feed_check: null, last_feed_updated: null }),
  );
  const loaded = await loadState(file);
  assert(loaded.schema_version === "1.1", "schema should normalize to 1.1");
  assert(loaded.known_advisories.length === 1 && loaded.known_advisories[0] === "ADV-1", "known_advisories preserved");
  assert(Object.keys(loaded.notified_matches).length === 0, "notified_matches defaults to empty");
});

await test("persistState output format is unchanged and round-trips", async () => {
  const file = path.join(tmp.path, "persist", "state.json");
  const state = await loadState(path.join(tmp.path, "missing-persist.json"));
  state.notified_matches["ADV-3::skill@1.0.0"] = "2026-11-02T00:00:00.000Z";
  await persistState(file, state);
  const text = await fs.readFile(file, "utf8");
  const expected = `${JSON.stringify(
    {
      schema_version: "1.1",
      known_advisories: [],
      last_feed_check: null,
      last_feed_updated: null,
      last_hook_scan: null,
      notified_matches: { "ADV-3::skill@1.0.0": "2026-11-02T00:00:00.000Z" },
    },
    null,
    2,
  )}\n`;
  assert(text === expected, `unexpected persisted format:\n${text}`);
  const reloaded = await loadState(file);
  assert(reloaded.notified_matches["ADV-3::skill@1.0.0"] === "2026-11-02T00:00:00.000Z", "round-trip lost key");
  assertDefaultUntouched();
});

await tmp.cleanup();
report();
exitWithResults();
