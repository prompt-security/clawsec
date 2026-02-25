#!/usr/bin/env node

/**
 * Property-based fuzz tests for openclaw suppression config gating behavior.
 *
 * Run: node skills/openclaw-audit-watchdog/test/suppression_config_fuzz.test.mjs
 */

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import fc from "fast-check";
import { loadSuppressionConfig } from "../scripts/load_suppression_config.mjs";

const pipelineArb = fc.constantFrom("audit", "advisory", "watchdog");

function makeValidConfig({ pipeline, includePipeline }) {
  const enabledFor = includePipeline ? [pipeline.toUpperCase(), "other"] : ["other"];
  return JSON.stringify({
    enabledFor,
    suppressions: [
      {
        checkId: "SCAN-001",
        skill: "soul-guardian",
        reason: "fuzz test",
        suppressedAt: "2026-02-25",
      },
    ],
  });
}

async function withTempConfig(content, fn) {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "watchdog-fuzz-"));
  const configPath = path.join(tmpDir, "suppression.json");
  await fs.writeFile(configPath, content, "utf8");
  try {
    await fn(configPath);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
}

async function withSilencedStderr(fn) {
  const originalWrite = process.stderr.write;
  process.stderr.write = () => true;
  try {
    return await fn();
  } finally {
    process.stderr.write = originalWrite;
  }
}

async function runProperties() {
  await fc.assert(
    fc.asyncProperty(fc.string(), pipelineArb, async (rawPath, pipeline) => {
      const result = await loadSuppressionConfig(rawPath, { enabled: false, pipeline });
      assert.equal(result.source, "none");
      assert.deepEqual(result.suppressions, []);
    }),
    { numRuns: 120 },
  );

  await fc.assert(
    fc.asyncProperty(pipelineArb, fc.boolean(), async (pipeline, includePipeline) => {
      const content = makeValidConfig({ pipeline, includePipeline });
      await withTempConfig(content, async (configPath) => {
        const result = await withSilencedStderr(() =>
          loadSuppressionConfig(configPath, { enabled: true, pipeline }),
        );
        if (includePipeline) {
          assert.equal(result.source, configPath);
          assert.equal(result.suppressions.length, 1);
          assert.equal(result.suppressions[0].checkId, "SCAN-001");
        } else {
          assert.equal(result.source, "none");
          assert.deepEqual(result.suppressions, []);
        }
      });
    }),
    { numRuns: 80 },
  );
}

try {
  console.log("=== OpenClaw Suppression Config Fuzz Properties ===\n");
  await runProperties();
  console.log("=== Results: all fuzz properties passed ===");
} catch (error) {
  console.error("Fuzz property test failed:");
  console.error(error);
  process.exit(1);
}
