import assert from "node:assert/strict";
import test from "node:test";

import {
  SKILLS_INDEX_PATH,
  getSkillLifecycleView,
  loadSkillDetailData,
  loadSkillsIndex,
  parseSkillsIndex,
} from "../utils/skillCatalogInstallability.mjs";

const RESULT_FIELDS = [
  "state",
  "reason",
  "record",
  "skillData",
  "checksums",
  "doc",
  "view",
];

const INSTALLABLE_VIEW = {
  canInstall: true,
  showCopyControls: true,
  showPlatforms: true,
  showTriggers: true,
  showDocumentation: true,
  historicalEvidence: false,
};

const HISTORICAL_VIEW = {
  canInstall: false,
  showCopyControls: false,
  showPlatforms: false,
  showTriggers: false,
  showDocumentation: false,
  historicalEvidence: true,
};

const BLOCKED_VIEW = {
  canInstall: false,
  showCopyControls: false,
  showPlatforms: false,
  showTriggers: false,
  showDocumentation: false,
  historicalEvidence: false,
};

function catalogRecord(name, overrides = {}) {
  const version = overrides.version ?? "1.2.3";
  return {
    id: name,
    name,
    version,
    description: `${name} description`,
    emoji: "🛡️",
    category: "security",
    platforms: ["openclaw"],
    tag: `${name}-v${version}`,
    ...overrides,
  };
}

function skillMetadata(name, overrides = {}) {
  return {
    name,
    version: "1.2.3",
    description: `${name} description`,
    author: "ClawSec",
    license: "AGPL-3.0-or-later",
    homepage: "https://github.com/prompt-security/clawsec",
    keywords: ["security"],
    sbom: { files: [] },
    ...overrides,
  };
}

function indexJson(skills) {
  return JSON.stringify({
    version: "1.0.0",
    updated: "2026-07-23T00:00:00Z",
    skills,
  });
}

function response(body, { status = 200, contentType = "application/json" } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        return name.toLowerCase() === "content-type" ? contentType : null;
      },
    },
    async text() {
      return body;
    },
  };
}

function createFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url, options });
    if (!routes.has(url)) {
      throw new Error(`Unexpected fetch: ${url}`);
    }

    const route = routes.get(url);
    const value = typeof route === "function" ? await route({ url, options }) : route;
    if (value instanceof Error) throw value;
    return value;
  };
  return { fetchImpl, calls };
}

function abortError(message = "aborted") {
  const error = new Error(message);
  error.name = "AbortError";
  return error;
}

function assertExactResultShape(result) {
  assert.deepEqual(Object.keys(result), RESULT_FIELDS);
}

function assertBlocked(result) {
  assertExactResultShape(result);
  assert.equal(result.state, "blocked");
  assert.deepEqual(result.view, BLOCKED_VIEW);
  assert.equal(result.view.canInstall, false);
  assert.equal(result.view.showCopyControls, false);
  assert.equal(result.view.showPlatforms, false);
  assert.equal(result.view.showTriggers, false);
  assert.equal(result.view.showDocumentation, false);
}

test("lifecycle views expose actions only for installable records", () => {
  assert.deepEqual(getSkillLifecycleView("installable"), INSTALLABLE_VIEW);
  assert.deepEqual(getSkillLifecycleView("historical"), HISTORICAL_VIEW);
  assert.deepEqual(getSkillLifecycleView("blocked"), BLOCKED_VIEW);
  assert.throws(() => getSkillLifecycleView("unknown"), /Unknown skill lifecycle state/);
});

test("parseSkillsIndex accepts explicit booleans and preserves legacy absence", () => {
  const parsed = parseSkillsIndex(indexJson([
    catalogRecord("enabled", { installable: true }),
    catalogRecord("historical", { installable: false }),
    catalogRecord("legacy"),
  ]));

  assert.equal(parsed.skills[0].installable, true);
  assert.equal(parsed.skills[1].installable, false);
  assert.equal(Object.hasOwn(parsed.skills[2], "installable"), false);
  assert.deepEqual(parsed.skills[2].platforms, ["openclaw"]);
});

test("parseSkillsIndex rejects malformed roots and arrays", () => {
  assert.throws(() => parseSkillsIndex(42), /must be JSON text/);
  assert.throws(() => parseSkillsIndex("{"), /invalid JSON/);
  assert.throws(() => parseSkillsIndex("null"), /root must be an object/);
  assert.throws(() => parseSkillsIndex("[]"), /root must be an object/);
  assert.throws(() => parseSkillsIndex("{}"), /"skills" must be an array/);
  assert.throws(() => parseSkillsIndex('{"skills":{}}'), /"skills" must be an array/);
});

test("parseSkillsIndex validates every render-required string field", () => {
  const fields = ["id", "name", "version", "description", "emoji", "category", "tag"];
  for (const field of fields) {
    const blank = catalogRecord("fixture");
    blank[field] = "   ";
    assert.throws(
      () => parseSkillsIndex(indexJson([blank])),
      new RegExp(`field \\"${field}\\" must be a non-empty string`),
    );

    const wrongType = catalogRecord("fixture");
    wrongType[field] = 1;
    assert.throws(
      () => parseSkillsIndex(indexJson([wrongType])),
      new RegExp(`field \\"${field}\\" must be a non-empty string`),
    );
  }
  assert.throws(
    () => parseSkillsIndex(indexJson([catalogRecord("fixture", { id: "other" })])),
    /"id" must exactly match "name"/,
  );
  assert.throws(
    () => parseSkillsIndex(indexJson([catalogRecord("fixture", { tag: "wrong-v1.2.3" })])),
    /"tag" must be "fixture-v1\.2\.3"/,
  );
});

test("parseSkillsIndex rejects invalid platforms and lifecycle values", () => {
  for (const platforms of ["openclaw", {}, ["openclaw", 1]]) {
    assert.throws(
      () => parseSkillsIndex(indexJson([catalogRecord("fixture", { platforms })])),
      /"platforms" must be an array of strings/,
    );
  }

  for (const installable of [null, "false", 0, {}, []]) {
    assert.throws(
      () => parseSkillsIndex(indexJson([catalogRecord("fixture", { installable })])),
      /"installable" must be a boolean when present/,
    );
  }
});

test("parseSkillsIndex rejects duplicate catalog identities", () => {
  const duplicate = catalogRecord("duplicate");
  assert.throws(
    () => parseSkillsIndex(indexJson([duplicate, { ...duplicate }])),
    /duplicate id "duplicate"/,
  );
});

test("loadSkillsIndex returns a strict index and forwards the abort signal", async () => {
  const controller = new globalThis.AbortController();
  const { fetchImpl, calls } = createFetch(new Map([
    [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("enabled")]))],
  ]));

  const index = await loadSkillsIndex(fetchImpl, { signal: controller.signal });
  assert.equal(index.skills[0].name, "enabled");
  assert.deepEqual(calls.map(({ url }) => url), [SKILLS_INDEX_PATH]);
  assert.equal(calls[0].options.headers.Accept, "application/json");
  assert.equal(calls[0].options.signal, controller.signal);
});

test("loadSkillsIndex throws for unavailable, empty, HTML, and malformed responses", async (t) => {
  const cases = [
    ["network failure", new Error("offline"), /offline/],
    ["HTTP failure", response("missing", { status: 404, contentType: "text/plain" }), /HTTP 404/],
    ["empty body", response(""), /response is empty/],
    ["HTML content type", response("fallback", { contentType: "text/html" }), /HTML, not JSON/],
    ["HTML body", response("<!doctype html><title>fallback</title>", { contentType: "text/plain" }), /HTML, not JSON/],
    ["invalid JSON", response("not json"), /invalid JSON/],
    ["non-array skills", response('{"skills":{}}'), /"skills" must be an array/],
  ];

  for (const [name, route, pattern] of cases) {
    await t.test(name, async () => {
      const { fetchImpl, calls } = createFetch(new Map([[SKILLS_INDEX_PATH, route]]));
      await assert.rejects(loadSkillsIndex(fetchImpl), pattern);
      assert.deepEqual(calls.map(({ url }) => url), [SKILLS_INDEX_PATH]);
    });
  }
});

test("direct detail blocks index failures without any per-skill request", async (t) => {
  const duplicate = catalogRecord("duplicate");
  const cases = [
    ["network", new Error("offline")],
    ["404", response("missing", { status: 404, contentType: "text/plain" })],
    ["empty", response("")],
    ["HTML", response("<html>fallback</html>", { contentType: "text/html" })],
    ["invalid JSON", response("not json")],
    ["non-array", response('{"skills":{}}')],
    ["non-boolean lifecycle", response(indexJson([catalogRecord("enabled", { installable: "false" })]))],
    ["duplicate record", response(indexJson([duplicate, { ...duplicate }]))],
  ];

  for (const [name, indexRoute] of cases) {
    await t.test(name, async () => {
      const { fetchImpl, calls } = createFetch(new Map([[SKILLS_INDEX_PATH, indexRoute]]));
      const result = await loadSkillDetailData(fetchImpl, "enabled");
      assertBlocked(result);
      assert.equal(result.record, null);
      assert.equal(result.skillData, null);
      assert.equal(result.checksums, null);
      assert.equal(result.doc, null);
      assert.deepEqual(calls.map(({ url }) => url), [SKILLS_INDEX_PATH]);
    });
  }
});

test("a missing index record blocks the direct route without per-skill requests", async () => {
  const { fetchImpl, calls } = createFetch(new Map([
    [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("other")]))],
  ]));

  const result = await loadSkillDetailData(fetchImpl, "missing");
  assertBlocked(result);
  assert.match(result.reason, /not present/);
  assert.deepEqual(calls.map(({ url }) => url), [SKILLS_INDEX_PATH]);
});

test("an explicit index denial is historical and makes only the index request", async () => {
  const deniedRecord = catalogRecord("historical", { installable: false });
  const { fetchImpl, calls } = createFetch(new Map([
    [SKILLS_INDEX_PATH, response(indexJson([deniedRecord]))],
  ]));

  const result = await loadSkillDetailData(fetchImpl, "historical");
  assertExactResultShape(result);
  assert.equal(result.state, "historical");
  assert.equal(result.record.name, "historical");
  assert.equal(result.skillData, null);
  assert.equal(result.checksums, null);
  assert.equal(result.doc, null);
  assert.deepEqual(result.view, HISTORICAL_VIEW);
  assert.deepEqual(calls.map(({ url }) => url), [SKILLS_INDEX_PATH]);
});

test("legacy-absent lifecycle preserves the complete installable experience", async () => {
  const checksums = {
    skill: "legacy",
    version: "1.2.3",
    tag: "legacy-v1.2.3",
    files: { "SKILL.md": { sha256: "abc", size: 12 } },
  };
  const { fetchImpl, calls } = createFetch(new Map([
    [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("legacy")]))],
    ["/skills/legacy/skill.json", response(JSON.stringify(skillMetadata("legacy")))],
    ["/skills/legacy/checksums.json", response(JSON.stringify(checksums))],
    ["/skills/legacy/README.md", response("# Legacy documentation", { contentType: "text/plain" })],
  ]));

  const result = await loadSkillDetailData(fetchImpl, "legacy");
  assertExactResultShape(result);
  assert.equal(result.state, "installable");
  assert.equal(result.record.installable, undefined);
  assert.equal(result.skillData.installable, undefined);
  assert.deepEqual(result.checksums, checksums);
  assert.deepEqual(result.doc, { filename: "README.md", content: "# Legacy documentation" });
  assert.deepEqual(result.view, INSTALLABLE_VIEW);
  assert.deepEqual(calls.map(({ url }) => url), [
    SKILLS_INDEX_PATH,
    "/skills/legacy/skill.json",
    "/skills/legacy/checksums.json",
    "/skills/legacy/README.md",
  ]);
  assert.equal(calls[1].options.headers.Accept, "application/json");
  assert.equal(calls[3].options.headers.Accept, "text/plain");
});

test("explicit true at both layers remains installable", async () => {
  const { fetchImpl, calls } = createFetch(new Map([
    [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("enabled", { installable: true })]))],
    ["/skills/enabled/skill.json", response(JSON.stringify(skillMetadata("enabled", { installable: true })))],
    ["/skills/enabled/checksums.json", response("{}")],
    ["/skills/enabled/README.md", response("documentation", { contentType: "text/plain" })],
  ]));

  const result = await loadSkillDetailData(fetchImpl, "enabled");
  assert.equal(result.state, "installable");
  assert.deepEqual(result.view, INSTALLABLE_VIEW);
  assert.deepEqual(calls.map(({ url }) => url), [
    SKILLS_INDEX_PATH,
    "/skills/enabled/skill.json",
    "/skills/enabled/checksums.json",
    "/skills/enabled/README.md",
  ]);
});

test("detail metadata false adds a denial and suppresses checksums and docs", async () => {
  const { fetchImpl, calls } = createFetch(new Map([
    [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("withdrawn", { installable: true })]))],
    ["/skills/withdrawn/skill.json", response(JSON.stringify(skillMetadata("withdrawn", { installable: false })))],
  ]));

  const result = await loadSkillDetailData(fetchImpl, "withdrawn");
  assert.equal(result.state, "historical");
  assert.equal(result.skillData.installable, false);
  assert.equal(result.checksums, null);
  assert.equal(result.doc, null);
  assert.deepEqual(result.view, HISTORICAL_VIEW);
  assert.deepEqual(calls.map(({ url }) => url), [
    SKILLS_INDEX_PATH,
    "/skills/withdrawn/skill.json",
  ]);
});

test("invalid detail lifecycle values block before checksums and docs", async (t) => {
  for (const installable of [null, "false", 0, {}, []]) {
    await t.test(JSON.stringify(installable), async () => {
      const { fetchImpl, calls } = createFetch(new Map([
        [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("invalid")]))],
        ["/skills/invalid/skill.json", response(JSON.stringify(skillMetadata("invalid", { installable })))],
      ]));

      const result = await loadSkillDetailData(fetchImpl, "invalid");
      assertBlocked(result);
      assert.match(result.reason, /"installable" must be a boolean/);
      assert.deepEqual(calls.map(({ url }) => url), [
        SKILLS_INDEX_PATH,
        "/skills/invalid/skill.json",
      ]);
    });
  }
});

test("detail identity, version, and tag mismatches fail closed", async (t) => {
  const cases = [
    ["name", skillMetadata("different"), /name does not match/],
    ["version", skillMetadata("bound", { version: "9.9.9" }), /version does not match/],
    ["tag", skillMetadata("bound", { tag: "bound-v9.9.9" }), /tag does not match/],
  ];

  for (const [name, detail, pattern] of cases) {
    await t.test(name, async () => {
      const { fetchImpl, calls } = createFetch(new Map([
        [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("bound")]))],
        ["/skills/bound/skill.json", response(JSON.stringify(detail))],
      ]));

      const result = await loadSkillDetailData(fetchImpl, "bound");
      assertBlocked(result);
      assert.match(result.reason, pattern);
      assert.deepEqual(calls.map(({ url }) => url), [
        SKILLS_INDEX_PATH,
        "/skills/bound/skill.json",
      ]);
    });
  }
});

test("unavailable, empty, HTML, and malformed detail metadata block all later requests", async (t) => {
  const cases = [
    ["network", new Error("offline")],
    ["HTTP", response("missing", { status: 404, contentType: "text/plain" })],
    ["empty", response("")],
    ["HTML content type", response("fallback", { contentType: "text/html" })],
    ["HTML body", response("<!doctype html><title>fallback</title>", { contentType: "text/plain" })],
    ["invalid JSON", response("not json")],
    ["array root", response("[]")],
  ];

  for (const [name, skillRoute] of cases) {
    await t.test(name, async () => {
      const { fetchImpl, calls } = createFetch(new Map([
        [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("fixture")]))],
        ["/skills/fixture/skill.json", skillRoute],
      ]));

      const result = await loadSkillDetailData(fetchImpl, "fixture");
      assertBlocked(result);
      assert.deepEqual(calls.map(({ url }) => url), [
        SKILLS_INDEX_PATH,
        "/skills/fixture/skill.json",
      ]);
    });
  }
});

test("special skill identities are matched exactly and URL-encoded as one path segment", async () => {
  const specialId = "odd skill/β?#";
  const encoded = "odd%20skill%2F%CE%B2%3F%23";
  const { fetchImpl, calls } = createFetch(new Map([
    [SKILLS_INDEX_PATH, response(indexJson([catalogRecord(specialId)]))],
    [`/skills/${encoded}/skill.json`, response(JSON.stringify(skillMetadata(specialId)))],
    [`/skills/${encoded}/checksums.json`, response("{}")],
    [`/skills/${encoded}/README.md`, response("special documentation", { contentType: "text/plain" })],
  ]));

  const result = await loadSkillDetailData(fetchImpl, specialId);
  assert.equal(result.state, "installable");
  assert.deepEqual(calls.map(({ url }) => url), [
    SKILLS_INDEX_PATH,
    `/skills/${encoded}/skill.json`,
    `/skills/${encoded}/checksums.json`,
    `/skills/${encoded}/README.md`,
  ]);
});

test("malformed optional checksums are ignored and HTML README falls back to SKILL.md", async (t) => {
  for (const [name, malformedChecksums] of [
    ["invalid JSON", "not json"],
    ["missing files map", "{}"],
    ["missing release identity", JSON.stringify({ files: {} })],
    ["wrong skill identity", JSON.stringify({ skill: "other", version: "1.2.3", tag: "fallback-v1.2.3", files: {} })],
    ["wrong version identity", JSON.stringify({ skill: "fallback", version: "9.9.9", tag: "fallback-v1.2.3", files: {} })],
    ["wrong tag identity", JSON.stringify({ skill: "fallback", version: "1.2.3", tag: "fallback-v9.9.9", files: {} })],
    ["invalid file entry", JSON.stringify({
      skill: "fallback",
      version: "1.2.3",
      tag: "fallback-v1.2.3",
      files: { "SKILL.md": null },
    })],
    ["invalid file size", JSON.stringify({
      skill: "fallback",
      version: "1.2.3",
      tag: "fallback-v1.2.3",
      files: { "SKILL.md": { sha256: "abc", size: "1" } },
    })],
  ]) {
    await t.test(name, async () => {
      const { fetchImpl, calls } = createFetch(new Map([
        [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("fallback")]))],
        ["/skills/fallback/skill.json", response(JSON.stringify(skillMetadata("fallback")))],
        ["/skills/fallback/checksums.json", response(malformedChecksums)],
        ["/skills/fallback/README.md", response("<html>SPA fallback</html>", { contentType: "text/html" })],
        ["/skills/fallback/SKILL.md", response("---\nname: fallback\n---\nInstructions", { contentType: "text/plain" })],
      ]));

      const result = await loadSkillDetailData(fetchImpl, "fallback");
      assert.equal(result.state, "installable");
      assert.equal(result.checksums, null);
      assert.deepEqual(result.doc, {
        filename: "SKILL.md",
        content: "---\nname: fallback\n---\nInstructions",
      });
      assert.deepEqual(calls.map(({ url }) => url), [
        SKILLS_INDEX_PATH,
        "/skills/fallback/skill.json",
        "/skills/fallback/checksums.json",
        "/skills/fallback/README.md",
        "/skills/fallback/SKILL.md",
      ]);
    });
  }
});

test("valid optional checksums remain available to the installable view", async () => {
  const checksums = {
    skill: "fallback",
    version: "1.2.3",
    tag: "fallback-v1.2.3",
    files: {
      "SKILL.md": {
        sha256: "abc",
        size: 12,
        path: "SKILL.md",
        url: "https://example.test/SKILL.md",
      },
    },
  };
  const { fetchImpl, calls } = createFetch(new Map([
    [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("fallback")]))],
    ["/skills/fallback/skill.json", response(JSON.stringify(skillMetadata("fallback")))],
    ["/skills/fallback/checksums.json", response(JSON.stringify(checksums))],
    ["/skills/fallback/README.md", response("<html>SPA fallback</html>", { contentType: "text/html" })],
    ["/skills/fallback/SKILL.md", response("---\nname: fallback\n---\nInstructions", { contentType: "text/plain" })],
  ]));

  const result = await loadSkillDetailData(fetchImpl, "fallback");
  assert.equal(result.state, "installable");
  assert.deepEqual(result.checksums, checksums);
  assert.deepEqual(result.doc, {
    filename: "SKILL.md",
    content: "---\nname: fallback\n---\nInstructions",
  });
  assert.deepEqual(calls.map(({ url }) => url), [
    SKILLS_INDEX_PATH,
    "/skills/fallback/skill.json",
    "/skills/fallback/checksums.json",
    "/skills/fallback/README.md",
    "/skills/fallback/SKILL.md",
  ]);
});

test("optional endpoint failures remain non-authorizing display omissions", async () => {
  const { fetchImpl, calls } = createFetch(new Map([
    [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("optional")]))],
    ["/skills/optional/skill.json", response(JSON.stringify(skillMetadata("optional")))],
    ["/skills/optional/checksums.json", new Error("checksums offline")],
    ["/skills/optional/README.md", new Error("README offline")],
    ["/skills/optional/SKILL.md", response("", { contentType: "text/plain" })],
  ]));

  const result = await loadSkillDetailData(fetchImpl, "optional");
  assert.equal(result.state, "installable");
  assert.equal(result.checksums, null);
  assert.equal(result.doc, null);
  assert.deepEqual(calls.map(({ url }) => url), [
    SKILLS_INDEX_PATH,
    "/skills/optional/skill.json",
    "/skills/optional/checksums.json",
    "/skills/optional/README.md",
    "/skills/optional/SKILL.md",
  ]);
});

test("AbortError is the only error class rethrown by the detail loader", async (t) => {
  await t.test("index abort", async () => {
    const expected = abortError("index aborted");
    const { fetchImpl, calls } = createFetch(new Map([[SKILLS_INDEX_PATH, expected]]));
    await assert.rejects(loadSkillDetailData(fetchImpl, "fixture"), (error) => error === expected);
    assert.deepEqual(calls.map(({ url }) => url), [SKILLS_INDEX_PATH]);
  });

  await t.test("detail abort", async () => {
    const expected = abortError("detail aborted");
    const { fetchImpl, calls } = createFetch(new Map([
      [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("fixture")]))],
      ["/skills/fixture/skill.json", expected],
    ]));
    await assert.rejects(loadSkillDetailData(fetchImpl, "fixture"), (error) => error === expected);
    assert.deepEqual(calls.map(({ url }) => url), [
      SKILLS_INDEX_PATH,
      "/skills/fixture/skill.json",
    ]);
  });

  await t.test("optional abort", async () => {
    const expected = abortError("checksums aborted");
    const { fetchImpl, calls } = createFetch(new Map([
      [SKILLS_INDEX_PATH, response(indexJson([catalogRecord("fixture")]))],
      ["/skills/fixture/skill.json", response(JSON.stringify(skillMetadata("fixture")))],
      ["/skills/fixture/checksums.json", expected],
    ]));
    await assert.rejects(loadSkillDetailData(fetchImpl, "fixture"), (error) => error === expected);
    assert.deepEqual(calls.map(({ url }) => url), [
      SKILLS_INDEX_PATH,
      "/skills/fixture/skill.json",
      "/skills/fixture/checksums.json",
    ]);
  });

  await t.test("generic errors block or omit instead of escaping", async () => {
    const { fetchImpl } = createFetch(new Map([[SKILLS_INDEX_PATH, new Error("offline")]]));
    const result = await loadSkillDetailData(fetchImpl, "fixture");
    assertBlocked(result);
  });
});
