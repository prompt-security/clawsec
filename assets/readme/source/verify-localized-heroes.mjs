#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sourceDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(sourceDir, '../../..');
const manifest = JSON.parse(await readFile(path.join(sourceDir, 'hero-copy.json'), 'utf8'));
const failures = [];
const hashes = new Map();

const fail = (message) => failures.push(message);
const normalizeForHtml = (value) => value.replaceAll('&', '&amp;').replaceAll('"', '&quot;');

const webpDimensions = (buffer) => {
  if (buffer.toString('ascii', 0, 4) !== 'RIFF' || buffer.toString('ascii', 8, 12) !== 'WEBP') {
    throw new Error('not a WebP RIFF file');
  }

  let offset = 12;
  while (offset + 8 <= buffer.length) {
    const type = buffer.toString('ascii', offset, offset + 4);
    const length = buffer.readUInt32LE(offset + 4);
    const data = offset + 8;

    if (type === 'VP8X' && length >= 10) {
      return {
        width: buffer.readUIntLE(data + 4, 3) + 1,
        height: buffer.readUIntLE(data + 7, 3) + 1,
        hasAlpha: (buffer[data] & 0x10) !== 0
      };
    }
    if (type === 'VP8 ' && length >= 10 && buffer[data + 3] === 0x9d && buffer[data + 4] === 0x01 && buffer[data + 5] === 0x2a) {
      return { width: buffer.readUInt16LE(data + 6) & 0x3fff, height: buffer.readUInt16LE(data + 8) & 0x3fff, hasAlpha: false };
    }
    if (type === 'VP8L' && length >= 5 && buffer[data] === 0x2f) {
      const width = 1 + buffer[data + 1] + ((buffer[data + 2] & 0x3f) << 8);
      const height = 1 + ((buffer[data + 2] >> 6) | (buffer[data + 3] << 2) | ((buffer[data + 4] & 0x0f) << 10));
      return { width, height, hasAlpha: (buffer[data + 4] & 0x10) !== 0 };
    }

    offset = data + length + (length % 2);
  }

  throw new Error('no supported WebP image chunk found');
};

for (const [locale, entry] of Object.entries(manifest.locales)) {
  const readme = await readFile(path.join(repoRoot, entry.readme), 'utf8').catch(() => null);
  const svg = await readFile(path.join(repoRoot, entry.svg), 'utf8').catch(() => null);
  const webp = await readFile(path.join(repoRoot, entry.webp)).catch(() => null);

  if (!readme) {
    fail(`${locale}: missing ${entry.readme}`);
  } else {
    const expectedHero = `<img src="./${entry.webp}" width="100%" alt="${normalizeForHtml(entry.accessibility.alt)}">`;
    if (!readme.includes(expectedHero)) fail(`${locale}: README hero or alt text does not match hero-copy.json`);
    const tagline = entry.copy.tagline.join(' ');
    if (!readme.includes(tagline)) fail(`${locale}: README prose does not contain the exact localized hero tagline`);
  }

  if (!svg) {
    fail(`${locale}: missing ${entry.svg}`);
  } else {
    for (const [field, lines] of Object.entries(entry.copy)) {
      for (const line of lines) {
        const escaped = line
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&apos;');
        if (!svg.includes(`data-copy="${field}"`) || !svg.includes(`>${escaped}</text>`)) {
          fail(`${locale}: ${entry.svg} is missing exact ${field} copy: ${line}`);
        }
      }
    }
    if (!svg.includes(`<title id="title">${entry.accessibility.title}</title>`)) fail(`${locale}: SVG title is stale`);
  }

  if (!webp) {
    fail(`${locale}: missing ${entry.webp}`);
  } else {
    try {
      const { width, height, hasAlpha } = webpDimensions(webp);
      if (width !== 1200 || height !== 460) fail(`${locale}: ${entry.webp} is ${width}x${height}, expected 1200x460`);
      if (!hasAlpha) fail(`${locale}: ${entry.webp} must preserve transparent rounded corners`);
    } catch (error) {
      fail(`${locale}: ${entry.webp}: ${error.message}`);
    }
    if (webp.length > 300_000) fail(`${locale}: ${entry.webp} exceeds the 300 KB budget`);
    hashes.set(locale, createHash('sha256').update(webp).digest('hex'));
  }
}

if (new Set(hashes.values()).size !== hashes.size) fail('Two or more localized WebPs are byte-identical');

if (manifest.translation_assurance.human_native_certified !== false) {
  fail('Translation assurance must not imply professional native-speaker certification');
}

if (failures.length > 0) {
  console.error(`Localized hero verification failed:\n${failures.map((message) => `- ${message}`).join('\n')}`);
  process.exitCode = 1;
} else {
  console.log(`PASS: ${hashes.size} localized heroes map to exact reviewed copy, README alt text, and distinct 1200x460 WebPs`);
  console.log('NOTE: copy is independently model-reviewed, not professionally certified by native translators');
}
