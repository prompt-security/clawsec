#!/usr/bin/env node

/**
 * Fail-closed catalog lifecycle tests for clawsec-suite.
 *
 * Run only in an isolated test environment:
 *   node skills/clawsec-suite/test/skill_catalog_discovery.test.mjs
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cp, mkdtemp, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pass, fail, report, exitWithResults } from "./lib/test_harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SUITE_DIR = path.resolve(__dirname, "..");
const SCRIPT_PATH = path.join(SUITE_DIR, "scripts", "discover_skill_catalog.mjs");
const SCRIPTS_DIR = path.join(SUITE_DIR, "scripts");
const INSTALL_COMMAND = "npx clawhub@latest install";

function catalogRecord(name, overrides = {}) {
  const version = overrides.version ?? "1.2.3";
  return {
    id: name,
    name,
    version,
    description: `${name} catalog fixture`,
    emoji: "🛡️",
    category: "security",
    platforms: ["openclaw"],
    tag: `${name}-v${version}`,
    ...overrides,
  };
}

function catalogPayload(skills) {
  return {
    version: "1.0.0",
    updated: "2026-07-23T00:00:00Z",
    skills,
  };
}

function countOccurrences(text, needle) {
  return text.split(needle).length - 1;
}

function combinedOutput(result) {
  return `${result.stdout}\n${result.stderr}`;
}

function assertNoInstallCommand(result) {
  assert.equal(
    result.stdout.includes(INSTALL_COMMAND),
    false,
    `stdout unexpectedly exposed an install command:\n${result.stdout}`,
  );
  assert.equal(
    result.stderr.includes(INSTALL_COMMAND),
    false,
    `stderr unexpectedly exposed an install command:\n${result.stderr}`,
  );
}

function parseJsonStdout(result) {
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(
      `Expected machine-readable JSON output, got exit ${result.code}:\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}\n${error}`,
    );
  }
}

function assertUnavailableList(result) {
  const payload = parseJsonStdout(result);
  assert.equal(payload.source, "unavailable", `Unexpected unavailable payload: ${result.stdout}`);
  assert.deepEqual(payload.skills, [], `Unavailable catalog must have no installable skills: ${result.stdout}`);
  assert.ok(
    typeof payload.warning === "string" && payload.warning.length > 0,
    `Unavailable catalog must explain why it is unavailable: ${result.stdout}`,
  );
  assertNoInstallCommand(result);
  return payload;
}

function assertDeniedRequest(result) {
  assert.notEqual(result.code, 0, `Denied request must exit non-zero: ${result.stdout}`);
  assertNoInstallCommand(result);
}

function runCatalogScript(args, env = {}, scriptPath = SCRIPT_PATH) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [scriptPath, ...args], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    proc.on("error", reject);
    proc.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

function withServer(handler) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Failed to bind catalog fixture server"));
        return;
      }

      resolve({
        url: `http://127.0.0.1:${address.port}`,
        close: () =>
          new Promise((done) => {
            server.closeAllConnections?.();
            server.close(() => done());
          }),
      });
    });
    server.on("error", reject);
  });
}

async function withCatalogResponse(
  { status = 200, body = "", contentType = "application/json", hang = false },
  callback,
) {
  const fixture = await withServer((_request, response) => {
    if (hang) return;
    response.writeHead(status, { "Content-Type": contentType });
    response.end(typeof body === "string" ? body : JSON.stringify(body));
  });

  try {
    return await callback(`${fixture.url}/index.json`);
  } finally {
    await fixture.close();
  }
}

function catalogEnvironment(indexUrl, overrides = {}) {
  return {
    CLAWSEC_SKILLS_INDEX_URL: indexUrl,
    CLAWSEC_SKILLS_INDEX_TIMEOUT_MS: "1000",
    ...overrides,
  };
}

async function runCase(name, callback) {
  try {
    await callback();
    pass(name);
  } catch (error) {
    fail(name, error);
  }
}

async function testValidListLifecycleScreening() {
  const withdrawnCommand = `${INSTALL_COMMAND} withdrawn-skill`;
  const payload = catalogPayload([
    catalogRecord("explicit-true", { installable: true }),
    catalogRecord("legacy-absent"),
    catalogRecord("withdrawn-skill", {
      installable: false,
      description: `Untrusted historical text: ${withdrawnCommand}`,
      version: `1.2.3 ${withdrawnCommand}`,
    }),
  ]);

  await withCatalogResponse({ body: payload }, async (indexUrl) => {
    const env = catalogEnvironment(indexUrl);

    const jsonResult = await runCatalogScript(["--json"], env);
    assert.equal(jsonResult.code, 0, jsonResult.stderr);
    const json = parseJsonStdout(jsonResult);
    assert.equal(json.source, "remote");
    assert.equal(json.catalog_role, "denial_overlay");
    assert.equal(json.stable_authorization, "not_evaluated");
    assert.deepEqual(
      json.skills.map((skill) => skill.id).sort(),
      ["explicit-true", "legacy-absent"],
      `Only explicit true and legacy-absent records may pass lifecycle screening: ${jsonResult.stdout}`,
    );
    assert.equal(json.skills.some((skill) => skill.id === "withdrawn-skill"), false);
    assert.ok(Array.isArray(json.historical), `Missing historical records: ${jsonResult.stdout}`);
    const historical = json.historical.find((skill) => skill.id === "withdrawn-skill");
    assert.ok(historical, `Explicit false must remain visible as historical: ${jsonResult.stdout}`);
    assert.equal(historical.id, "withdrawn-skill");
    assert.equal(historical.installable, false);
    assert.equal(historical.lifecycle_status, "historical");
    assert.equal(Object.hasOwn(historical, "install_command"), false);
    assert.equal(Object.hasOwn(historical, "command"), false);
    assert.equal(JSON.stringify(historical).includes(INSTALL_COMMAND), false);
    assert.equal(jsonResult.stdout.includes(withdrawnCommand), false, jsonResult.stdout);
    assert.equal(jsonResult.stderr.includes(withdrawnCommand), false, jsonResult.stderr);

    const humanResult = await runCatalogScript([], env);
    assert.equal(humanResult.code, 0, humanResult.stderr);
    assert.equal(
      countOccurrences(humanResult.stdout, `${INSTALL_COMMAND} explicit-true`),
      1,
      humanResult.stdout,
    );
    assert.equal(
      countOccurrences(humanResult.stdout, `${INSTALL_COMMAND} legacy-absent`),
      1,
      humanResult.stdout,
    );
    assert.equal(
      humanResult.stdout.includes(withdrawnCommand),
      false,
      humanResult.stdout,
    );
    assert.equal(humanResult.stderr.includes(withdrawnCommand), false, humanResult.stderr);
    assert.equal(countOccurrences(combinedOutput(humanResult), INSTALL_COMMAND), 2);
  });
}

async function testExactRequestedEligibility() {
  const payload = catalogPayload([
    catalogRecord("explicit-true", { installable: true }),
    catalogRecord("legacy-absent"),
    catalogRecord("historical-false", { installable: false }),
  ]);

  await withCatalogResponse({ body: payload }, async (indexUrl) => {
    const env = catalogEnvironment(indexUrl);

    for (const skillId of ["explicit-true", "legacy-absent"]) {
      const result = await runCatalogScript(["--skill", skillId], env);
      assert.equal(result.code, 0, `${skillId}: ${result.stderr}`);
      assert.equal(
        countOccurrences(combinedOutput(result), INSTALL_COMMAND),
        1,
        `Requested mode must emit exactly one command: ${combinedOutput(result)}`,
      );
      assert.equal(
        result.stdout.includes(`${INSTALL_COMMAND} ${skillId}`),
        true,
        `Requested mode emitted the wrong command: ${result.stdout}`,
      );

      const jsonResult = await runCatalogScript(["--json", "--skill", skillId], env);
      assert.equal(jsonResult.code, 0, `${skillId}: ${jsonResult.stderr}`);
      const json = parseJsonStdout(jsonResult);
      assert.equal(json.catalog_role, "denial_overlay");
      assert.equal(json.stable_authorization, "not_evaluated");
      const screenedRecord = json.skills.find((skill) => skill.id === skillId);
      assert.ok(screenedRecord, `Requested record missing from screened candidates: ${jsonResult.stdout}`);
      assert.equal(screenedRecord.id, skillId);
      assert.equal(screenedRecord.name, skillId);
      assert.equal(screenedRecord.version, "1.2.3");
      assert.equal(screenedRecord.tag, `${skillId}-v1.2.3`);
      assert.equal(json.recommendation?.status, "eligible_candidate");
      assert.equal(json.recommendation?.requested_skill, skillId);
      assert.equal(json.recommendation?.version, "1.2.3");
      assert.equal(json.recommendation?.tag, `${skillId}-v1.2.3`);
      assert.equal(json.recommendation?.install_command, `${INSTALL_COMMAND} ${skillId}`);
      assert.equal(json.recommendation?.stable_authorization, "not_evaluated");
      assert.equal(countOccurrences(JSON.stringify(json.recommendation), INSTALL_COMMAND), 1);
    }

    const historical = await runCatalogScript(["--skill", "historical-false"], env);
    assertDeniedRequest(historical);

    // This ID exists in suite-local metadata and is marked default_install=true.
    // A missing remote record must not resurrect it.
    const missingLocalDefault = await runCatalogScript(
      ["--skill", "openclaw-audit-watchdog"],
      env,
    );
    assertDeniedRequest(missingLocalDefault);
  });
}

async function testDeniedRequestedOutputDoesNotEchoUnrelatedMetadata() {
  const unrelatedCommand = `${INSTALL_COMMAND} unrelated-eligible`;
  const payload = catalogPayload([
    catalogRecord("unrelated-eligible", {
      installable: true,
      description: `Untrusted unrelated text: ${unrelatedCommand}`,
      version: `1.2.3 ${unrelatedCommand}`,
    }),
    catalogRecord("withdrawn-target", { installable: false }),
  ]);

  const cases = [
    {
      label: "missing remote record with matching suite-local context",
      requestedSkill: "openclaw-audit-watchdog",
      expectedReason: "missing_remote_record",
      expectedHistoricalIds: [],
      expectedContextIds: ["openclaw-audit-watchdog"],
    },
    {
      label: "explicit remote false",
      requestedSkill: "withdrawn-target",
      expectedReason: "non_installable",
      expectedHistoricalIds: ["withdrawn-target"],
      expectedContextIds: [],
    },
  ];

  await withCatalogResponse({ body: payload }, async (indexUrl) => {
    const env = catalogEnvironment(indexUrl);

    for (const testCase of cases) {
      const result = await runCatalogScript(
        ["--json", "--skill", testCase.requestedSkill],
        env,
      );
      assertDeniedRequest(result);
      const json = parseJsonStdout(result);

      assert.equal(json.source, "remote", `${testCase.label}: ${result.stdout}`);
      assert.equal(json.catalog_role, "denial_overlay");
      assert.equal(json.stable_authorization, "not_evaluated");
      assert.deepEqual(json.skills, [], `${testCase.label}: ${result.stdout}`);
      assert.equal(json.version, null, `${testCase.label}: ${result.stdout}`);
      assert.equal(json.updated, null, `${testCase.label}: ${result.stdout}`);
      assert.equal(json.recommendation?.status, "denied");
      assert.equal(json.recommendation?.requested_skill, testCase.requestedSkill);
      assert.equal(json.recommendation?.reason, testCase.expectedReason);
      assert.equal(Object.hasOwn(json.recommendation ?? {}, "install_command"), false);

      assert.deepEqual(
        (json.historical ?? []).map((record) => record.id),
        testCase.expectedHistoricalIds,
        `${testCase.label}: historical output was not request-scoped: ${result.stdout}`,
      );
      for (const historical of json.historical ?? []) {
        assert.equal(historical.id, testCase.requestedSkill);
        assert.equal(historical.installable, false);
        assert.equal(historical.lifecycle_status, "historical");
        assert.equal(Object.hasOwn(historical, "install_command"), false);
        assert.equal(Object.hasOwn(historical, "command"), false);
      }

      assert.deepEqual(
        (json.context ?? []).map((record) => record.id),
        testCase.expectedContextIds,
        `${testCase.label}: local context was not request-scoped: ${result.stdout}`,
      );
      for (const context of json.context ?? []) {
        assert.equal(context.id, testCase.requestedSkill);
        assert.equal(context.installable, false);
        assert.equal(context.lifecycle_status, "local_context_only");
        assert.equal(Object.hasOwn(context, "install_command"), false);
        assert.equal(Object.hasOwn(context, "command"), false);
      }

      assert.equal(result.stdout.includes(unrelatedCommand), false, result.stdout);
      assert.equal(result.stderr.includes(unrelatedCommand), false, result.stderr);
      assert.equal(result.stdout.includes("unrelated-eligible"), false, result.stdout);
    }
  });
}

async function testMalformedRootMetadataDoesNotLeakIntoWarning() {
  const injectedCommand = `${INSTALL_COMMAND} root-metadata`;
  const validSkill = catalogRecord("otherwise-valid", { installable: true });
  const cases = [
    {
      label: "malformed root version",
      payload: {
        ...catalogPayload([validSkill]),
        version: `1.0.0 ${injectedCommand}`,
      },
    },
    {
      label: "malformed root updated timestamp",
      payload: {
        ...catalogPayload([validSkill]),
        updated: `2026-07-23T00:00:00Z ${injectedCommand}`,
      },
    },
  ];

  for (const testCase of cases) {
    await runCase(`catalog diagnostics: ${testCase.label} is not reflected`, async () => {
      await withCatalogResponse({ body: testCase.payload }, async (indexUrl) => {
        const result = await runCatalogScript(["--json"], catalogEnvironment(indexUrl));
        const json = assertUnavailableList(result);
        assert.equal(json.version, null);
        assert.equal(json.updated, null);
        assert.match(json.warning, /catalog.*(?:unavailable|invalid)/i);
        assert.equal(json.warning.includes(injectedCommand), false, json.warning);
        assert.equal(result.stdout.includes(injectedCommand), false, result.stdout);
        assert.equal(result.stderr.includes(injectedCommand), false, result.stderr);
      });
    });
  }
}

async function testInvalidLifecycleRejectsWholeIndex() {
  const invalidValues = [
    ["null", null],
    ["string", "false"],
    ["number", 0],
    ["object", { value: false }],
    ["array", []],
  ];

  for (const [label, invalidValue] of invalidValues) {
    await runCase(`catalog lifecycle: ${label} rejects the whole index`, async () => {
      const payload = catalogPayload([
        catalogRecord("otherwise-valid", { installable: true }),
        catalogRecord("invalid-lifecycle", { installable: invalidValue }),
      ]);

      await withCatalogResponse({ body: payload }, async (indexUrl) => {
        const env = catalogEnvironment(indexUrl);
        const listResult = await runCatalogScript(["--json"], env);
        assertUnavailableList(listResult);
        assert.equal(listResult.stdout.includes("otherwise-valid"), false);

        const requestedResult = await runCatalogScript(["--skill", "otherwise-valid"], env);
        assertDeniedRequest(requestedResult);
      });
    });
  }
}

async function testMalformedCatalogRejectsWholeIndex() {
  const duplicate = catalogRecord("duplicate");
  const canonicalCollision = catalogRecord("case-collision");
  const caseVariant = catalogRecord("Case-Collision");
  const otherwiseValid = catalogRecord("otherwise-valid", { installable: true });
  const malformedCases = [
    ["invalid JSON", "{not-json", "application/json"],
    ["null root", "null", "application/json"],
    ["array root", "[]", "application/json"],
    ["missing skills", JSON.stringify({ version: "1.0.0" }), "application/json"],
    ["non-array skills", JSON.stringify({ skills: {} }), "application/json"],
    [
      "non-object record",
      JSON.stringify(catalogPayload([otherwiseValid, "invalid-record"])),
      "application/json",
    ],
    [
      "blank id",
      JSON.stringify(catalogPayload([otherwiseValid, catalogRecord("blank-id", { id: " " })])),
      "application/json",
    ],
    [
      "missing name",
      JSON.stringify(catalogPayload([
        otherwiseValid,
        (() => {
          const record = catalogRecord("missing-name");
          delete record.name;
          return record;
        })(),
      ])),
      "application/json",
    ],
    [
      "id-name mismatch",
      JSON.stringify(catalogPayload([
        otherwiseValid,
        catalogRecord("identity", { name: "different-identity" }),
      ])),
      "application/json",
    ],
    [
      "blank version",
      JSON.stringify(catalogPayload([otherwiseValid, catalogRecord("blank-version", { version: " " })])),
      "application/json",
    ],
    [
      "missing tag",
      JSON.stringify(catalogPayload([
        otherwiseValid,
        (() => {
          const record = catalogRecord("missing-tag");
          delete record.tag;
          return record;
        })(),
      ])),
      "application/json",
    ],
    [
      "tag-version mismatch",
      JSON.stringify(catalogPayload([
        otherwiseValid,
        catalogRecord("wrong-tag", { tag: "wrong-tag-v9.9.9" }),
      ])),
      "application/json",
    ],
    [
      "duplicate identity",
      JSON.stringify(catalogPayload([otherwiseValid, duplicate, { ...duplicate }])),
      "application/json",
    ],
    [
      "canonical case collision",
      JSON.stringify(catalogPayload([otherwiseValid, canonicalCollision, caseVariant])),
      "application/json",
    ],
  ];

  for (const [label, body, contentType] of malformedCases) {
    await runCase(`catalog structure: ${label} rejects the whole index`, async () => {
      await withCatalogResponse({ body, contentType }, async (indexUrl) => {
        const env = catalogEnvironment(indexUrl);
        const listResult = await runCatalogScript(["--json"], env);
        assertUnavailableList(listResult);
        assert.equal(listResult.stdout.includes("otherwise-valid"), false);

        const requestedResult = await runCatalogScript(["--skill", "otherwise-valid"], env);
        assertDeniedRequest(requestedResult);
      });
    });
  }
}

async function testUnsafeAndMalformedCliArguments() {
  const env = catalogEnvironment("http://127.0.0.1:9/index.json", {
    CLAWSEC_SKILLS_INDEX_TIMEOUT_MS: "50",
  });
  const unsafeRequestedIds = [
    "UPPER",
    "../escape",
    "skill/name",
    "double--dash",
    " leading",
    "trailing ",
    "skill;command",
    "ｃlawsec-suite",
  ];

  for (const skillId of unsafeRequestedIds) {
    await runCase(`catalog CLI: unsafe requested id ${JSON.stringify(skillId)} fails closed`, async () => {
      const result = await runCatalogScript(["--skill", skillId], env);
      assertDeniedRequest(result);
    });
  }

  const malformedArgumentCases = [
    ["missing --skill value", ["--skill"]],
    ["option used as --skill value", ["--skill", "--json"]],
    ["duplicate --skill", ["--skill", "safe-id", "--skill", "other-id"]],
    ["duplicate --json", ["--json", "--json"]],
    ["unknown option", ["--unknown"]],
    ["unexpected positional argument", ["safe-id"]],
  ];

  for (const [label, args] of malformedArgumentCases) {
    await runCase(`catalog CLI: ${label} fails without a command`, async () => {
      const result = await runCatalogScript(args, env);
      assertDeniedRequest(result);
    });
  }
}

async function testRemoteFailureNeverAuthorizesFallback() {
  const httpCases = [
    ["HTTP 404", { status: 404, body: { error: "not found" } }],
    ["HTTP 500", { status: 500, body: { error: "server error" } }],
    ["HTML fallback", { body: "<!doctype html><title>fallback</title>", contentType: "text/html" }],
  ];

  for (const [label, fixtureOptions] of httpCases) {
    await runCase(`catalog availability: ${label} yields no authorization`, async () => {
      await withCatalogResponse(fixtureOptions, async (indexUrl) => {
        const env = catalogEnvironment(indexUrl);
        const listResult = await runCatalogScript(["--json"], env);
        assertUnavailableList(listResult);

        const requestedResult = await runCatalogScript(
          ["--skill", "openclaw-audit-watchdog"],
          env,
        );
        assertDeniedRequest(requestedResult);
      });
    });
  }

  await runCase("catalog availability: unreachable remote yields no authorization", async () => {
    const env = catalogEnvironment("http://127.0.0.1:9/index.json", {
      CLAWSEC_SKILLS_INDEX_TIMEOUT_MS: "100",
    });
    const listResult = await runCatalogScript(["--json"], env);
    assertUnavailableList(listResult);

    const requestedResult = await runCatalogScript(
      ["--skill", "openclaw-audit-watchdog"],
      env,
    );
    assertDeniedRequest(requestedResult);
  });

  await runCase("catalog availability: timeout yields no authorization", async () => {
    await withCatalogResponse({ hang: true }, async (indexUrl) => {
      const env = catalogEnvironment(indexUrl, {
        CLAWSEC_SKILLS_INDEX_TIMEOUT_MS: "50",
      });
      const listResult = await runCatalogScript(["--json"], env);
      assertUnavailableList(listResult);

      const requestedResult = await runCatalogScript(
        ["--skill", "openclaw-audit-watchdog"],
        env,
      );
      assertDeniedRequest(requestedResult);
    });
  });
}

async function testLocalFlagsCannotOverrideRemoteLifecycle() {
  const fixtureRoot = await mkdtemp(path.join(tmpdir(), "clawsec-suite-catalog-test-"));
  const fixtureScripts = path.join(fixtureRoot, "scripts");
  const fixtureScript = path.join(fixtureScripts, "discover_skill_catalog.mjs");

  try {
    await cp(SCRIPTS_DIR, fixtureScripts, { recursive: true });
    await writeFile(
      path.join(fixtureRoot, "skill.json"),
      `${JSON.stringify({
        name: "clawsec-suite",
        version: "0.0.0-test",
        catalog: {
          skills: {
            "local-override": {
              description: "Must remain non-authorizing local context",
              default_install: true,
              installable: true,
            },
          },
        },
      }, null, 2)}\n`,
    );

    const remotePayload = catalogPayload([
      catalogRecord("remote-eligible", { installable: true }),
    ]);
    await withCatalogResponse({ body: remotePayload }, async (indexUrl) => {
      const env = catalogEnvironment(indexUrl);

      const listResult = await runCatalogScript(["--json"], env, fixtureScript);
      assert.equal(listResult.code, 0, listResult.stderr);
      const listPayload = parseJsonStdout(listResult);
      assert.deepEqual(
        listPayload.skills.map((skill) => skill.id),
        ["remote-eligible"],
        `Local default_install/installable flags must not join remote installable output: ${listResult.stdout}`,
      );

      const requestedResult = await runCatalogScript(
        ["--skill", "local-override"],
        env,
        fixtureScript,
      );
      assertDeniedRequest(requestedResult);
    });

    const remoteDenialPayload = catalogPayload([
      catalogRecord("local-override", { installable: false }),
    ]);
    await withCatalogResponse({ body: remoteDenialPayload }, async (indexUrl) => {
      const env = catalogEnvironment(indexUrl);

      const listResult = await runCatalogScript(["--json"], env, fixtureScript);
      assert.equal(listResult.code, 0, listResult.stderr);
      const listPayload = parseJsonStdout(listResult);
      assert.deepEqual(listPayload.skills, []);
      const historical = listPayload.historical?.find((skill) => skill.id === "local-override");
      assert.ok(historical, `Remote false must remain historical: ${listResult.stdout}`);
      assert.equal(historical.installable, false);
      assert.equal(historical.default_install, true);
      assert.equal(JSON.stringify(historical).includes(INSTALL_COMMAND), false);
      assertNoInstallCommand(listResult);

      const requestedResult = await runCatalogScript(
        ["--skill", "local-override"],
        env,
        fixtureScript,
      );
      assertDeniedRequest(requestedResult);
    });

    const unavailableEnv = catalogEnvironment("http://127.0.0.1:9/index.json", {
      CLAWSEC_SKILLS_INDEX_TIMEOUT_MS: "100",
    });
    const unavailableList = await runCatalogScript(["--json"], unavailableEnv, fixtureScript);
    assertUnavailableList(unavailableList);

    const unavailableRequested = await runCatalogScript(
      ["--skill", "local-override"],
      unavailableEnv,
      fixtureScript,
    );
    assertDeniedRequest(unavailableRequested);
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function runTests() {
  console.log("=== ClawSec Skill Catalog Lifecycle Tests ===\n");

  await runCase(
    "catalog lifecycle: list screens true and legacy absent as eligible and records false as historical",
    testValidListLifecycleScreening,
  );
  await runCase(
    "catalog lifecycle: requested mode emits lifecycle-screened eligible candidates only",
    testExactRequestedEligibility,
  );
  await runCase(
    "catalog lifecycle: denied requested JSON cannot echo unrelated eligible metadata",
    testDeniedRequestedOutputDoesNotEchoUnrelatedMetadata,
  );
  await testMalformedRootMetadataDoesNotLeakIntoWarning();
  await testInvalidLifecycleRejectsWholeIndex();
  await testMalformedCatalogRejectsWholeIndex();
  await testUnsafeAndMalformedCliArguments();
  await testRemoteFailureNeverAuthorizesFallback();
  await runCase(
    "catalog fallback: local default_install/installable flags cannot override remote lifecycle",
    testLocalFlagsCannotOverrideRemoteLifecycle,
  );

  report();
  exitWithResults();
}

runTests().catch((error) => {
  console.error("Test runner failed:", error);
  process.exit(1);
});
