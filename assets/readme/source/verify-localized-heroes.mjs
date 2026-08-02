#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { COPY_FIELDS, loadHeroManifest, localeCoverageFailures } from './hero-manifest.mjs';

const sourceDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(sourceDir, '../../..');
const manifestPath = path.join(sourceDir, 'hero-copy.json');

const normalizeForHtml = (value) => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;');
const escapeXml = (value) => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&apos;');
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const copyNodes = (svg, field) => {
  const pattern = new RegExp(
    `<text\\b([^>]*)\\bdata-copy="${escapeRegExp(field)}"([^>]*)>([\\s\\S]*?)</text>`,
    'g'
  );
  return [...svg.matchAll(pattern)].map((match) => ({
    attributes: `${match[1]} ${match[2]}`,
    content: match[3]
  }));
};

export const inspectWebp = (buffer) => {
  if (buffer.length < 12 || buffer.toString('ascii', 0, 4) !== 'RIFF' || buffer.toString('ascii', 8, 12) !== 'WEBP') {
    throw new Error('not a WebP RIFF file');
  }
  if (buffer.readUInt32LE(4) + 8 !== buffer.length) throw new Error('RIFF size does not match file length');

  let canvasDimensions = null;
  let payloadDimensions = null;
  let payloadType = null;
  let hasAlphaChunk = false;
  let losslessUsesAlpha = false;
  let extendedAlphaDeclared = false;
  let hasExtendedHeader = false;
  let offset = 12;
  while (offset + 8 <= buffer.length) {
    const type = buffer.toString('ascii', offset, offset + 4);
    const length = buffer.readUInt32LE(offset + 4);
    const data = offset + 8;
    const paddedEnd = data + length + (length % 2);
    if (paddedEnd > buffer.length) throw new Error(`truncated ${type} chunk`);

    if (type === 'VP8X') {
      if (hasExtendedHeader) throw new Error('multiple VP8X headers');
      if (length !== 10) throw new Error('invalid VP8X header');
      hasExtendedHeader = true;
      canvasDimensions = {
        width: buffer.readUIntLE(data + 4, 3) + 1,
        height: buffer.readUIntLE(data + 7, 3) + 1
      };
      extendedAlphaDeclared = (buffer[data] & 0x10) !== 0;
    }
    if (type === 'VP8 ') {
      if (payloadType) throw new Error('multiple static image payloads');
      if (length < 10 || buffer[data + 3] !== 0x9d || buffer[data + 4] !== 0x01 || buffer[data + 5] !== 0x2a) {
        throw new Error('invalid VP8 image payload');
      }
      payloadType = type;
      payloadDimensions = {
        width: buffer.readUInt16LE(data + 6) & 0x3fff,
        height: buffer.readUInt16LE(data + 8) & 0x3fff
      };
    }
    if (type === 'VP8L') {
      if (payloadType) throw new Error('multiple static image payloads');
      if (length < 5 || buffer[data] !== 0x2f) throw new Error('invalid VP8L image payload');
      const width = 1 + buffer[data + 1] + ((buffer[data + 2] & 0x3f) << 8);
      const height = 1 + ((buffer[data + 2] >> 6) | (buffer[data + 3] << 2) | ((buffer[data + 4] & 0x0f) << 10));
      payloadType = type;
      payloadDimensions = { width, height };
      losslessUsesAlpha = (buffer[data + 4] & 0x10) !== 0;
    }
    if (type === 'ALPH') {
      if (length <= 1) throw new Error('invalid ALPH chunk');
      hasAlphaChunk = true;
    }

    offset = paddedEnd;
  }

  if (offset !== buffer.length) throw new Error('trailing incomplete WebP chunk');
  if (!payloadDimensions) throw new Error('no static VP8 or VP8L image payload found');
  if (
    canvasDimensions
    && (canvasDimensions.width !== payloadDimensions.width || canvasDimensions.height !== payloadDimensions.height)
  ) {
    throw new Error('VP8X canvas dimensions do not match image payload');
  }
  if (hasAlphaChunk && !canvasDimensions) throw new Error('ALPH chunk requires a VP8X canvas');
  if (hasAlphaChunk && !extendedAlphaDeclared) throw new Error('VP8X header does not declare its ALPH chunk');

  return {
    ...(canvasDimensions ?? payloadDimensions),
    hasAlphaData: hasAlphaChunk || losslessUsesAlpha
  };
};

const verifyBanner = async ({ locale, entry, copy }, failures, hashes) => {
  const fail = (message) => failures.push(message);
  const readme = await readFile(path.join(repoRoot, entry.readme), 'utf8').catch(() => null);
  const svg = await readFile(path.join(repoRoot, entry.svg), 'utf8').catch(() => null);
  const webp = await readFile(path.join(repoRoot, entry.webp)).catch(() => null);

  if (!readme) {
    fail(`${locale}: missing ${entry.readme}`);
  } else {
    const expectedHero = `<img src="./${entry.webp}" width="100%" alt="${normalizeForHtml(entry.accessibility.alt)}">`;
    if (!readme.includes(expectedHero)) fail(`${locale}: README hero or alt text does not match hero-copy.json`);
    const tagline = copy.tagline.join(' ');
    if (!readme.includes(tagline)) fail(`${locale}: README prose does not contain the exact hero tagline`);
  }

  if (!svg) {
    fail(`${locale}: missing ${entry.svg}`);
  } else {
    for (const field of COPY_FIELDS) {
      const nodes = copyNodes(svg, field);
      if (nodes.length !== copy[field].length) {
        fail(`${locale}: ${entry.svg} has ${nodes.length} ${field} nodes, expected ${copy[field].length}`);
      }
      for (const [index, line] of copy[field].entries()) {
        const node = nodes[index];
        if (!node || node.content !== escapeXml(line)) {
          fail(`${locale}: ${entry.svg} is missing exact ${field} copy at line ${index + 1}: ${line}`);
          continue;
        }
        const yMatch = node.attributes.match(/\by="([^"]+)"/);
        if (!yMatch || yMatch[1].trim() === '' || !Number.isFinite(Number(yMatch[1]))) {
          fail(`${locale}: ${entry.svg} ${field} line ${index + 1} must have a numeric y coordinate`);
        } else if (Number(yMatch[1]) < -50 || Number(yMatch[1]) > 460) {
          fail(`${locale}: ${entry.svg} ${field} line ${index + 1} has an out-of-canvas y coordinate`);
        }
      }
    }
    if (!new RegExp(`<svg\\b[^>]*\\blang="${escapeRegExp(locale)}"`).test(svg)) {
      fail(`${locale}: SVG language metadata is stale`);
    }
    if (!svg.includes(`<title id="title">${escapeXml(entry.accessibility.title)}</title>`)) {
      fail(`${locale}: SVG title is stale`);
    }
    if (!svg.includes(`<desc id="desc">${escapeXml(entry.accessibility.description)}</desc>`)) {
      fail(`${locale}: SVG description is stale`);
    }
  }

  if (!webp) {
    fail(`${locale}: missing ${entry.webp}`);
    return;
  }

  try {
    const { width, height, hasAlphaData } = inspectWebp(webp);
    if (width !== 1200 || height !== 460) fail(`${locale}: ${entry.webp} is ${width}x${height}, expected 1200x460`);
    if (!hasAlphaData) fail(`${locale}: ${entry.webp} must contain alpha data for the approved transparent treatment`);
  } catch (error) {
    fail(`${locale}: ${entry.webp}: ${error.message}`);
  }
  if (webp.length > 300_000) fail(`${locale}: ${entry.webp} exceeds the 300 KB budget`);
  hashes.set(locale, createHash('sha256').update(webp).digest('hex'));
};

export const runVerifier = async () => {
  const manifest = await loadHeroManifest(manifestPath);
  const failures = [];
  const hashes = new Map();
  const translatedReadmeLocales = (await readdir(repoRoot, { withFileTypes: true }))
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name.match(/^README\.([^.]+)\.md$/)?.[1])
    .filter(Boolean);
  failures.push(...localeCoverageFailures(Object.keys(manifest.locales), translatedReadmeLocales));
  const sourceCopy = Object.fromEntries(
    COPY_FIELDS.map((field) => [field, [manifest.source_copy[field]]])
  );
  const banners = [
    { locale: manifest.source_locale, entry: manifest.source_banner, copy: sourceCopy },
    ...Object.entries(manifest.locales).map(([locale, entry]) => ({ locale, entry, copy: entry.copy }))
  ];

  for (const banner of banners) await verifyBanner(banner, failures, hashes);

  if (new Set(hashes.values()).size !== hashes.size) {
    failures.push('Two or more hero WebPs are byte-identical');
  }
  if (manifest.translation_assurance?.human_native_certified !== false) {
    failures.push('Translation assurance must not imply professional native-speaker certification');
  }

  if (failures.length > 0) {
    throw new Error(`Hero verification failed:\n${failures.map((message) => `- ${message}`).join('\n')}`);
  }

  console.log(`PASS: ${hashes.size} manifest entries have exact SVG copy, matching README alt text, and distinct 1200x460 WebPs with alpha data`);
  console.log('NOTE: copy is independently model-reviewed, not professionally certified by native translators');
  console.log('NOTE: transparent corner pixels and SVG-to-WebP render fidelity remain visual QA');
};

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  await runVerifier().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
