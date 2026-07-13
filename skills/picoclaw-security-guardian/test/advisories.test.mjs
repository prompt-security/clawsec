import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  checkPicoclawAdvisories,
  isPicoclawAdvisory,
} from "../lib/advisories.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const FEED_PATH = path.resolve(TEST_DIR, "..", "..", "..", "advisories", "feed.json");

test("tracked consolidated feed passes verified Picoclaw filtering", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "picoclaw-advisories-"));
  const statePath = path.join(tempDir, "feed-verification-state.json");

  try {
    await fs.writeFile(statePath, JSON.stringify({ status: "verified" }));
    const result = checkPicoclawAdvisories({ feedPath: FEED_PATH, statePath });

    assert.equal(result.status, "ok");
    assert.equal(result.verified_state, "verified");
    assert.ok(result.count > 0, "tracked feed must exercise Picoclaw advisory filtering");
    assert.equal(result.advisories.every(isPicoclawAdvisory), true);
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true });
  }
});

test("Picoclaw advisory check remains fail-closed without verified state", () => {
  assert.throws(
    () => checkPicoclawAdvisories({ feedPath: FEED_PATH }),
    /advisory feed state is not verified/,
  );
});

test("Picoclaw filtering accepts package and CPE selectors", () => {
  assert.equal(
    isPicoclawAdvisory({ platforms: [], affected: ["picoclaw@<1.2.3"] }),
    true,
  );
  assert.equal(
    isPicoclawAdvisory({ platforms: [], affected: ["cpe:2.3:a:picoclaw:picoclaw:1.2.3:*:*:*:*:*:*:*"] }),
    true,
  );
});
