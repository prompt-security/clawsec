#!/usr/bin/env node
// Guards the retry window of verifyRegistryPackage.
//
// ClawHub indexes a published version asynchronously. The nanoclaw-traffic-guardian
// 0.0.2 release took ~3m18s to become inspectable, while this check waited only
// 6 attempts x 5s = ~44s -- so a successful publish failed the release job. These
// assertions fail if the window is ever narrowed back below that observed latency.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { verifyPublishedPackage, verifyRegistryPackage } from './ci/clawhub_release_package.mjs';

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


// --- published-content verification -----------------------------------------
// ClawHub adds skill-card.md itself. Tolerating it must not become "tolerate
// anything": every file we published must still match, and any other extra path
// must still fail.
const pkgDir = await mkdtemp(path.join(tmpdir(), 'clawhub-pkg-'));
const sha = (text) => createHash('sha256').update(text).digest('hex');
const skillJson = JSON.stringify({ name: 'demo', version: '1.0.0', sbom: { files: [] } }, null, 2);
const skillMd = '---\nname: demo\nversion: 1.0.0\n---\n\nbody\n';
await writeFile(path.join(pkgDir, 'skill.json'), skillJson);
await writeFile(path.join(pkgDir, 'SKILL.md'), skillMd);

const entry = (p, text) => ({ path: p, sha256: sha(text), size: Buffer.byteLength(text) });
const ours = [entry('skill.json', skillJson), entry('SKILL.md', skillMd)];
const inspectPath = path.join(pkgDir, '..', 'inspect.json');
const writeInspect = async (files) => {
  await writeFile(inspectPath, JSON.stringify({ version: { version: '1.0.0', files } }));
  return inspectPath;
};
const expectThrow = async (files, pattern, label) => {
  try {
    await verifyPublishedPackage({ packageDir: pkgDir, inspectJsonPath: await writeInspect(files), version: '1.0.0' });
  } catch (error) {
    assert.match(error.message, pattern, label);
    return;
  }
  throw new Error(`${label}: expected a rejection but verification passed`);
};

try {
  const card = 'generated card\n';
  assert.deepEqual(
    await verifyPublishedPackage({
      packageDir: pkgDir,
      inspectJsonPath: await writeInspect([...ours, entry('skill-card.md', card)]),
      version: '1.0.0',
    }),
    { version: '1.0.0', files: 2 },
  );
  passed += 1;

  await expectThrow([...ours, entry('sneaky.md', 'x')], /unexpected file: sneaky\.md/, 'other extra files still rejected');
  passed += 1;

  await expectThrow(
    [...ours, entry('nested/skill-card.md', 'x')],
    /unexpected file: nested\/skill-card\.md/,
    'the exemption is root-only, not any path named skill-card.md',
  );
  passed += 1;

  await expectThrow(
    [{ path: 'skill.json', sha256: sha('tampered'), size: Buffer.byteLength(skillJson) }, ours[1]],
    /mismatch for skill\.json/,
    'tampered content still rejected',
  );
  passed += 1;

  await expectThrow([ours[0]], /missing SKILL\.md/, 'dropped files still rejected');
  passed += 1;
} finally {
  await rm(pkgDir, { recursive: true, force: true });
  await rm(inspectPath, { force: true });
}

console.log(`clawhub published-content checks passed (total ${passed})`);
