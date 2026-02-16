#!/usr/bin/env node

/**
 * Dynamic skill catalog discovery tests for clawsec-suite.
 *
 * Tests cover:
 * - Remote index fetch and normalization
 * - Enrichment with suite-local metadata (non-breaking compatibility)
 * - Fallback behavior when remote index is invalid/unavailable
 *
 * Run: node skills/clawsec-suite/test/skill_catalog_discovery.test.mjs
 */

import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.resolve(__dirname, "..", "scripts", "discover_skill_catalog.mjs");

let passCount = 0;
let failCount = 0;

function pass(name) {
  passCount += 1;
  console.log(`✓ ${name}`);
}

function fail(name, error) {
  failCount += 1;
  console.error(`✗ ${name}`);
  console.error(`  ${String(error)}`);
}

function runCatalogScript(args, env = {}) {
  return new Promise((resolve) => {
    const proc = spawn("node", [SCRIPT_PATH, ...args], {
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

    proc.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

function withServer(handler) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("Failed to bind test server"));
        return;
      }

      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise((done) => {
            server.close(() => done());
          }),
      });
    });

    server.on("error", reject);
  });
}

// -----------------------------------------------------------------------------
// Test: remote index is used when valid
// -----------------------------------------------------------------------------
async function testRemoteCatalogSuccess() {
  const testName = "discover_skill_catalog: uses remote index when valid";
  let fixture = null;

  try {
    fixture = await withServer((req, res) => {
      if (req.url !== "/index.json") {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "not found" }));
        return;
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          version: "1.0.0",
          updated: "2026-02-16T08:20:00Z",
          skills: [
            {
              id: "soul-guardian",
              name: "soul-guardian",
              version: "9.9.9",
              description: "Remote skill metadata",
              emoji: "👻",
              category: "security",
              tag: "soul-guardian-v9.9.9",
            },
            {
              id: "clawtributor",
              name: "clawtributor",
              version: "1.2.3",
              description: "Remote clawtributor metadata",
              emoji: "🤝",
              category: "security",
              tag: "clawtributor-v1.2.3",
            },
          ],
        }),
      );
    });

    const result = await runCatalogScript(["--json"], {
      CLAWSEC_SKILLS_INDEX_URL: `${fixture.url}/index.json`,
      CLAWSEC_SKILLS_INDEX_TIMEOUT_MS: "2000",
    });

    if (result.code !== 0) {
      fail(testName, `Expected exit 0, got ${result.code}: ${result.stderr}`);
      return;
    }

    const payload = JSON.parse(result.stdout);
    const clawtributor = payload.skills.find((entry) => entry.id === "clawtributor");
    const soulGuardian = payload.skills.find((entry) => entry.id === "soul-guardian");

    if (
      payload.source === "remote" &&
      payload.updated === "2026-02-16T08:20:00Z" &&
      soulGuardian?.version === "9.9.9" &&
      clawtributor?.requires_explicit_consent === true
    ) {
      pass(testName);
    } else {
      fail(testName, `Unexpected payload: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.close();
    }
  }
}

// -----------------------------------------------------------------------------
// Test: invalid remote payload falls back to suite-local catalog
// -----------------------------------------------------------------------------
async function testInvalidRemotePayloadFallsBack() {
  const testName = "discover_skill_catalog: invalid remote payload falls back";
  let fixture = null;

  try {
    fixture = await withServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ version: "1.0.0", note: "missing skills" }));
    });

    const result = await runCatalogScript(["--json"], {
      CLAWSEC_SKILLS_INDEX_URL: `${fixture.url}/index.json`,
      CLAWSEC_SKILLS_INDEX_TIMEOUT_MS: "2000",
    });

    if (result.code !== 0) {
      fail(testName, `Expected exit 0, got ${result.code}: ${result.stderr}`);
      return;
    }

    const payload = JSON.parse(result.stdout);
    const hasSoulGuardian = Array.isArray(payload.skills)
      ? payload.skills.some((entry) => entry.id === "soul-guardian")
      : false;

    if (payload.source === "fallback" && hasSoulGuardian && String(payload.warning).includes("skills array")) {
      pass(testName);
    } else {
      fail(testName, `Unexpected payload: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  } finally {
    if (fixture) {
      await fixture.close();
    }
  }
}

// -----------------------------------------------------------------------------
// Test: unreachable remote index falls back to suite-local catalog
// -----------------------------------------------------------------------------
async function testUnreachableRemoteFallsBack() {
  const testName = "discover_skill_catalog: unreachable remote index falls back";

  try {
    const result = await runCatalogScript(["--json"], {
      CLAWSEC_SKILLS_INDEX_URL: "http://127.0.0.1:9/index.json",
      CLAWSEC_SKILLS_INDEX_TIMEOUT_MS: "250",
    });

    if (result.code !== 0) {
      fail(testName, `Expected exit 0, got ${result.code}: ${result.stderr}`);
      return;
    }

    const payload = JSON.parse(result.stdout);
    if (payload.source === "fallback" && Array.isArray(payload.skills) && payload.skills.length > 0) {
      pass(testName);
    } else {
      fail(testName, `Unexpected payload: ${result.stdout}`);
    }
  } catch (error) {
    fail(testName, error);
  }
}

// -----------------------------------------------------------------------------
// Main test runner
// -----------------------------------------------------------------------------
async function runTests() {
  console.log("=== ClawSec Skill Catalog Discovery Tests ===\n");

  await testRemoteCatalogSuccess();
  await testInvalidRemotePayloadFallsBack();
  await testUnreachableRemoteFallsBack();

  console.log(`\n=== Results: ${passCount} passed, ${failCount} failed ===`);

  if (failCount > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error("Test runner failed:", error);
  process.exit(1);
});
