import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import {
  isValidFeedPayload as isValidHermesFeed,
} from "../skills/hermes-attestation-guardian/lib/feed.mjs";
import {
  isCpeAffectedSpecifier,
  parseAffectedSpecifier,
  parseVersionSpec,
  versionMatches as hermesVersionMatches,
} from "../skills/hermes-attestation-guardian/lib/semver.mjs";
import { isPicoclawAdvisory } from "../skills/picoclaw-security-guardian/lib/advisories.mjs";
import {
  isValidFeedPayload as isValidSuiteFeed,
} from "../skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs";
import {
  versionMatches as suiteVersionMatches,
} from "../skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/version.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FEED_PATH = path.join(ROOT, "advisories", "feed.json");
const CORPUS_PATH = path.join(ROOT, "scripts", "fixtures", "advisory-consumer-semver.json");
const NANOCLAW_ADVISORIES_PATH = path.join(ROOT, "skills", "clawsec-nanoclaw", "lib", "advisories.ts");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function extractFunctionSource(source, functionName) {
  const marker = `export function ${functionName}`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing NanoClaw ${functionName} export`);

  const bodyStart = source.indexOf("{", start);
  assert.notEqual(bodyStart, -1, `missing NanoClaw ${functionName} body`);

  let depth = 0;
  for (let index = bodyStart; index < source.length; index += 1) {
    const char = source[index];
    if (char === "{") depth += 1;
    if (char === "}") depth -= 1;
    if (depth === 0) {
      return source.slice(start, index + 1).replace("export ", "");
    }
  }

  throw new Error(`unterminated NanoClaw ${functionName} body`);
}

function loadNanoClawConsumer() {
  const source = fs.readFileSync(NANOCLAW_ADVISORIES_PATH, "utf8");
  const functions = ["isValidFeedPayload", "versionMatches"]
    .map((name) => extractFunctionSource(source, name))
    .join("\n");
  const transpiled = ts.transpileModule(
    `${functions}\nglobalThis.consumer = { isValidFeedPayload, versionMatches };`,
    {
      compilerOptions: {
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ES2022,
      },
    },
  ).outputText;

  const context = { globalThis: {} };
  vm.runInNewContext(transpiled, context);
  return context.globalThis.consumer;
}

function versionProbes(spec) {
  const probes = new Set(["0.0.0", "9999.0.0"]);
  const versionPattern = /\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?/g;

  for (const match of spec.matchAll(versionPattern)) {
    const value = match[0];
    probes.add(value);

    const core = value.split("-")[0].split(".").map(Number);
    while (core.length < 3) core.push(0);
    probes.add(core.join("."));
    if (core[2] > 0) probes.add([core[0], core[1], core[2] - 1].join("."));
    probes.add([core[0], core[1], core[2] + 1].join("."));

    if (value.includes("-")) {
      probes.add(`${core.join(".")}-0`);
      probes.add(`${core.join(".")}-999`);
    }
  }

  return probes;
}

const feed = readJson(FEED_PATH);
const corpus = readJson(CORPUS_PATH);
const nanoclaw = loadNanoClawConsumer();

assert.equal(isValidHermesFeed(feed), true, "Hermes must accept the complete tracked feed");
assert.equal(isValidSuiteFeed(feed), true, "ClawSec Suite must accept the complete tracked feed");
assert.equal(nanoclaw.isValidFeedPayload(feed), true, "NanoClaw must accept the complete tracked feed");

for (const testCase of corpus.cases) {
  assert.equal(
    hermesVersionMatches(testCase.version, testCase.range),
    testCase.matches,
    `Hermes conformance failure: ${testCase.id}`,
  );
  assert.equal(
    suiteVersionMatches(testCase.version, testCase.range),
    testCase.matches,
    `ClawSec Suite conformance failure: ${testCase.id}`,
  );
  assert.equal(
    nanoclaw.versionMatches(testCase.version, testCase.range),
    testCase.matches,
    `NanoClaw conformance failure: ${testCase.id}`,
  );
}

let cpeCount = 0;
let packageSelectorCount = 0;
let semanticProbeCount = 0;

for (const advisory of feed.advisories) {
  for (const affected of advisory.affected) {
    if (affected.toLowerCase().startsWith("cpe:2.3:")) {
      assert.equal(
        isCpeAffectedSpecifier(affected),
        true,
        `Malformed CPE in tracked feed: ${advisory.id} ${affected}`,
      );
      cpeCount += 1;
      continue;
    }

    const parsed = parseAffectedSpecifier(affected);
    assert.ok(parsed, `Invalid package selector in tracked feed: ${advisory.id} ${affected}`);
    assert.equal(
      parseVersionSpec(parsed.versionSpec).supported,
      true,
      `Unsupported package selector in tracked feed: ${advisory.id} ${affected}`,
    );
    packageSelectorCount += 1;

    for (const version of versionProbes(parsed.versionSpec)) {
      const expected = hermesVersionMatches(version, parsed.versionSpec);
      assert.equal(
        suiteVersionMatches(version, parsed.versionSpec),
        expected,
        `ClawSec Suite mismatch: ${advisory.id} ${affected} at ${version}`,
      );
      assert.equal(
        nanoclaw.versionMatches(version, parsed.versionSpec),
        expected,
        `NanoClaw mismatch: ${advisory.id} ${affected} at ${version}`,
      );
      semanticProbeCount += 1;
    }
  }
}

const picoclawAdvisories = feed.advisories.filter(isPicoclawAdvisory);
const explicitlyPicoclaw = feed.advisories.filter((advisory) => {
  const platforms = Array.isArray(advisory.platforms)
    ? advisory.platforms.map((entry) => String(entry).toLowerCase())
    : [];
  const affected = Array.isArray(advisory.affected)
    ? advisory.affected.map((entry) => String(entry).toLowerCase())
    : [];
  return platforms.includes("picoclaw") || affected.some((entry) => entry.includes("picoclaw"));
});

assert.ok(explicitlyPicoclaw.length > 0, "tracked feed must exercise Picoclaw filtering");
for (const advisory of explicitlyPicoclaw) {
  assert.ok(picoclawAdvisories.includes(advisory), `Picoclaw filter missed ${advisory.id}`);
}

console.log("Advisory consumer compatibility PASS");
console.log(`advisories=${feed.advisories.length}`);
console.log(`cpe_entries=${cpeCount}`);
console.log(`package_selectors=${packageSelectorCount}`);
console.log(`semantic_probes=${semanticProbeCount}`);
console.log(`picoclaw_advisories=${picoclawAdvisories.length}`);
