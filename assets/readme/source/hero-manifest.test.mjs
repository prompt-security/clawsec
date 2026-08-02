import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { localeCoverageFailures, validateHeroManifest } from './hero-manifest.mjs';
import { inspectWebp } from './verify-localized-heroes.mjs';

const sourceDir = path.dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(await readFile(path.join(sourceDir, 'hero-copy.json'), 'utf8'));

const failuresAfter = (mutate) => {
  const candidate = JSON.parse(JSON.stringify(manifest));
  mutate(candidate);
  let failures;
  assert.doesNotThrow(() => {
    failures = validateHeroManifest(candidate);
  });
  return failures;
};

test('accepts the committed hero manifest', () => {
  assert.deepEqual(validateHeroManifest(manifest), []);
});

const invalidCases = [
  {
    name: 'non-string SVG title',
    mutate: (candidate) => { candidate.locales.de.accessibility.title = 42; },
    expected: '$.locales.de.accessibility.title must be a non-empty string'
  },
  {
    name: 'non-string README alt text',
    mutate: (candidate) => { candidate.locales.de.accessibility.alt = 7; },
    expected: '$.locales.de.accessibility.alt must be a non-empty string'
  },
  {
    name: 'non-array copy',
    mutate: (candidate) => { candidate.locales.de.copy.tagline = 'not-an-array'; },
    expected: '$.locales.de.copy.tagline must be a non-empty array of strings'
  },
  {
    name: 'multiple eyebrow lines',
    mutate: (candidate) => { candidate.locales.de.copy.eyebrow.push('SECOND LINE'); },
    expected: '$.locales.de.copy.eyebrow must contain exactly 1 item'
  },
  {
    name: 'multiple project-title lines',
    mutate: (candidate) => { candidate.locales.de.copy.title.push('SECOND TITLE'); },
    expected: '$.locales.de.copy.title must contain exactly 1 item'
  },
  {
    name: 'copy and coordinate count mismatch',
    mutate: (candidate) => { candidate.locales.fr.layout.tagline_y.pop(); },
    expected: '$.locales.fr.layout.tagline_y must contain 2 coordinates'
  },
  {
    name: 'non-finite coordinate',
    mutate: (candidate) => { candidate.locales.de.layout.supporting_y[0] = Number.NaN; },
    expected: '$.locales.de.layout.supporting_y[0] must be a finite number'
  },
  {
    name: 'missing translation assurance',
    mutate: (candidate) => { candidate.translation_assurance = null; },
    expected: '$.translation_assurance must be an object'
  },
  {
    name: 'false native-certification claim',
    mutate: (candidate) => { candidate.translation_assurance.human_native_certified = true; },
    expected: '$.translation_assurance.human_native_certified must be false'
  },
  {
    name: 'source banner path traversal',
    mutate: (candidate) => { candidate.source_banner.webp = '../hero.webp'; },
    expected: '$.source_banner.webp must be a repository-relative path without parent traversal'
  },
  {
    name: 'localized output redirected to another repository file',
    mutate: (candidate) => { candidate.locales.de.svg = 'package.json'; },
    expected: '$.locales.de.svg must be assets/readme/source/hero-layout-de.svg'
  },
  {
    name: 'unsupported schema version',
    mutate: (candidate) => { candidate.schema_version = 999; },
    expected: '$.schema_version must be 2'
  },
  {
    name: 'unsafe locale identifier',
    mutate: (candidate) => {
      candidate.locales['de" onload="alert(1)'] = candidate.locales.de;
      delete candidate.locales.de;
    },
    expected: '$.locales.de" onload="alert(1) uses an invalid locale identifier'
  },
  {
    name: 'changed project name',
    mutate: (candidate) => { candidate.locales.de.copy.title[0] = 'NotClawSec'; },
    expected: '$.locales.de.copy.title[0] must preserve the ClawSec project name'
  },
  {
    name: 'negative font size',
    mutate: (candidate) => { candidate.locales.de.layout.tagline_font_size = -1; },
    expected: '$.locales.de.layout.tagline_font_size must be between 1 and 120'
  },
  {
    name: 'off-canvas text',
    mutate: (candidate) => { candidate.locales.de.layout.supporting_y[1] = 400; },
    expected: '$.locales.de.layout places text or decoration outside the 460px canvas'
  }
];

for (const { name, mutate, expected } of invalidCases) {
  test(`reports ${name} with a manifest path`, () => {
    assert.ok(failuresAfter(mutate).includes(expected));
  });
}

test('requires one manifest entry for every translated README', () => {
  assert.deepEqual(
    localeCoverageFailures(['de', 'es', 'fr', 'ja'], ['de', 'es', 'fr', 'ja', 'ko']),
    ['README.ko.md has no hero manifest entry']
  );
});

test('rejects a WebP container with dimensions and alpha but no image payload', () => {
  const fake = Buffer.alloc(40);
  fake.write('RIFF', 0, 'ascii');
  fake.writeUInt32LE(32, 4);
  fake.write('WEBP', 8, 'ascii');
  fake.write('VP8X', 12, 'ascii');
  fake.writeUInt32LE(10, 16);
  fake[20] = 0x10;
  fake.writeUIntLE(1199, 24, 3);
  fake.writeUIntLE(459, 27, 3);
  fake.write('ALPH', 30, 'ascii');
  fake.writeUInt32LE(2, 34);
  fake[38] = 0;
  fake[39] = 0;

  assert.throws(() => inspectWebp(fake), /no static VP8 or VP8L image payload found/);
});
