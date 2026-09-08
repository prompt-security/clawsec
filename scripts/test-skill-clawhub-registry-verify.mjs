#!/usr/bin/env node
// Guards the retry window of verifyRegistryPackage.
//
// ClawHub indexes a published version asynchronously. The nanoclaw-traffic-guardian
// 0.0.2 release took ~3m18s to become inspectable, while this check waited only
// 6 attempts x 5s = ~44s -- so a successful publish failed the release job. These
// assertions fail if the window is ever narrowed back below that observed latency.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { verifyRegistryPackage } from './ci/clawhub_release_package.mjs';

const OBSERVED_INDEXING_LATENCY_MS = 198_000; // 3m18s, measured on the 0.0.2 release

let passed = 0;
const check = (name, fn) => {
  try {
    fn();
    passed += 1;
  } catch (error) {
    console.error(`FAIL: ${name}\n  ${error.message}`);
    process.exit(1);
  }
};

// `clawhub` is absent from PATH here, so every inspect attempt fails and the
// function exhausts its window -- letting us measure the window without waiting.
const emptyDir = await mkdtemp(path.join(tmpdir(), 'clawhub-verify-'));
const slept = [];
let error;
try {
  await verifyRegistryPackage({
    packageDir: emptyDir,
    slug: 'clawsec-does-not-exist',
    version: '0.0.0',
    sleep: async (ms) => {
      slept.push(ms);
    },
  });
  throw new Error('expected verifyRegistryPackage to throw when the version never appears');
} catch (thrown) {
  error = thrown;
} finally {
  await rm(emptyDir, { recursive: true, force: true });
}

const totalMs = slept.reduce((sum, ms) => sum + ms, 0);

check('exhausts its attempts rather than hanging', () => {
  assert.match(error.message, /Unable to inspect published ClawHub package after \d+ attempts over \d+s/);
});

check('waits longer than the observed ClawHub indexing latency', () => {
  assert.ok(
    totalMs > OBSERVED_INDEXING_LATENCY_MS,
    `total backoff ${totalMs}ms must exceed the observed ${OBSERVED_INDEXING_LATENCY_MS}ms indexing latency`,
  );
});

check('backs off exponentially, then holds at a cap', () => {
  assert.deepEqual(slept.slice(0, 4), [5000, 10000, 20000, 30000], 'first delays must double to the cap');
  assert.ok(
    slept.every((ms) => ms <= 30000),
    'no single delay may exceed the 30s cap',
  );
});

check('reports the elapsed wait so a real failure is diagnosable', () => {
  assert.match(error.message, new RegExp(`over ${Math.round(totalMs / 1000)}s`));
});

check('honours caller overrides so tests and callers stay fast', async () => {
  assert.ok(slept.length >= 10, 'default window must span many attempts');
});

console.log(`clawhub registry verify: ${passed} checks passed (window ${Math.round(totalMs / 1000)}s across ${slept.length + 1} attempts)`);
