#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(scriptsDir, "..");
const verifier = resolve(projectRoot, "skills", "clawsec-feed", "scripts", "fetch_verified_feed.sh");
const feedPath = resolve(projectRoot, "advisories", "feed.json");
const wrongSignaturePath = resolve(projectRoot, "advisories", "ghsa-without-cve.json.sig");

const verifiedFeed = JSON.parse(execFileSync(verifier, {
  encoding: "utf8",
  maxBuffer: 20 * 1024 * 1024,
  env: {
    ...process.env,
    CLAWSEC_FEED_URL: `file://${feedPath}`,
  },
}));
assert.ok(Array.isArray(verifiedFeed.advisories) && verifiedFeed.advisories.length > 0);

const rejected = spawnSync(verifier, {
  encoding: "utf8",
  env: {
    ...process.env,
    CLAWSEC_FEED_URL: `file://${feedPath}`,
    CLAWSEC_FEED_SIG_URL: `file://${wrongSignaturePath}`,
  },
});
assert.notEqual(rejected.status, 0, "A feed paired with the wrong signature must fail closed");
assert.match(rejected.stderr, /signature verification failed/i);

console.log("ClawSec feed verifier tests passed");
