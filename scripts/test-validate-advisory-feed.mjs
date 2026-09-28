import assert from "node:assert/strict";
import test from "node:test";

import { validateAdvisoryFeed } from "./ci/validate_advisory_feed.mjs";

function advisory(overrides = {}) {
  return {
    id: "CVE-2026-1000",
    severity: "high",
    title: "Scoped advisory",
    description: "A protected component is affected.",
    action: "Upgrade the affected component.",
    published: "2026-09-01T00:00:00Z",
    affected: ["openclaw@<2026.9.1"],
    platforms: ["openclaw"],
    ...overrides,
  };
}

function feed(advisories) {
  return {
    version: "1.0.0",
    updated: "2026-09-28T00:00:00Z",
    advisories,
  };
}

test("accepts scoped package selectors and canonical aliases", () => {
  const value = feed([
      advisory({
        ghsa_id: "GHSA-test-1111-2222",
        cve_id: "CVE-2026-1000",
        aliases: ["CVE-2026-1000", "GHSA-test-1111-2222"],
        affected: ["@openclaw/plugin@>=1.0.0 <1.2.0"],
        platforms: ["openclaw", "openshell"],
      }),
    ]);

  assert.equal(validateAdvisoryFeed(value), value);
});

test("rejects empty, duplicate, and unscoped feeds", () => {
  assert.throws(() => validateAdvisoryFeed(feed([])), /at least one advisory/);
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory(), advisory()])),
    /Duplicate advisory id/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ affected: [] })])),
    /explicit product and version scope/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ affected: ["openclaw"] })])),
    /invalid affected selector/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ affected: ["openclaw@banana"] })])),
    /unsupported affected version scope/,
  );
});

test("rejects unknown infrastructure, ClawHub, and alias collisions", () => {
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ platforms: ["unknown-agent"] })])),
    /unsupported protected component/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ affected: ["clawhub@<2.0.0"] })])),
    /distribution channel/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
        advisory({ id: "CVE-2026-1000", aliases: ["GHSA-dupe-1111-2222"] }),
        advisory({ id: "CVE-2026-2000", aliases: ["GHSA-dupe-1111-2222"] }),
      ])),
    /belongs to both|cve_id must also appear/,
  );
});

test("rejects structurally incomplete advisories before signing", () => {
  assert.throws(() => validateAdvisoryFeed({ advisories: [advisory()] }), /version/);
  assert.throws(() => validateAdvisoryFeed(feed([advisory({ severity: "unknown" })])), /severity/);
  assert.throws(() => validateAdvisoryFeed(feed([advisory({ title: "" })])), /title/);
  assert.throws(() => validateAdvisoryFeed(feed([advisory({ published: "not-a-date" })])), /valid date/);
});

test("rejects inferred wildcards and unprotected or unversioned CPEs", () => {
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ affected: ["openclaw@*"] })])),
    /wildcard affected scope is only valid.*GHSA/,
  );
  assert.equal(
    validateAdvisoryFeed(feed([
      advisory({
        id: "GHSA-wild-1111-2222",
        aliases: ["GHSA-wild-1111-2222"],
        affected: ["openclaw@*"],
      }),
    ])).advisories.length,
    1,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({ affected: ["cpe:2.3:a:openclaw:clawhub:1.0.0:*:*:*:*:*:*:*"] }),
    ])),
    /allowlisted protected application/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({ affected: ["cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:*:*:*"] }),
    ])),
    /explicit version/,
  );
});

test("rejects canonical and alias identity collisions", () => {
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({
        id: "CVE-2026-1000",
        cve_id: "CVE-2026-1000",
        ghsa_id: "GHSA-dupe-1111-2222",
        aliases: ["CVE-2026-1000", "GHSA-dupe-1111-2222"],
      }),
      advisory({
        id: "GHSA-dupe-1111-2222",
        aliases: ["GHSA-dupe-1111-2222"],
      }),
    ])),
    /Stable identifier GHSA-dupe-1111-2222 belongs to both/,
  );
});
