#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sourceDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(sourceDir, '../../..');
const manifest = JSON.parse(await readFile(path.join(sourceDir, 'hero-copy.json'), 'utf8'));
const checkOnly = process.argv.includes('--check');

const escapeXml = (value) => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&apos;');

const renderLines = (lines, yPositions, attributes) => lines.map((line, index) => (
  `    <text x="2" y="${yPositions[index]}" ${attributes}>${escapeXml(line)}</text>`
)).join('\n');

const renderSvg = (locale, entry) => {
  const { accessibility, copy, layout } = entry;
  const isCjk = locale === 'ja' || locale === 'ko';
  const generalFont = locale === 'ja'
    ? '-apple-system, BlinkMacSystemFont, Hiragino Sans, Yu Gothic, Noto Sans JP, sans-serif'
    : locale === 'ko'
      ? '-apple-system, BlinkMacSystemFont, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, sans-serif'
      : '-apple-system, BlinkMacSystemFont, Segoe UI, Arial, sans-serif';
  const eyebrowFont = isCjk
    ? generalFont
    : 'ui-monospace, SFMono-Regular, Menlo, monospace';

  return `<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="1200" height="460" viewBox="0 0 1200 460"
     lang="${locale}" role="img" aria-labelledby="title desc">
  <title id="title">${escapeXml(accessibility.title)}</title>
  <desc id="desc">${escapeXml(accessibility.description)}</desc>

  <defs>
    <linearGradient id="background" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#160c31"/>
      <stop offset="0.58" stop-color="#26115d"/>
      <stop offset="1" stop-color="#523899"/>
    </linearGradient>
    <linearGradient id="signal" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#f9b347"/>
      <stop offset="1" stop-color="#ffa23f"/>
    </linearGradient>
    <pattern id="grid" width="48" height="48" patternUnits="userSpaceOnUse">
      <path d="M 48 0 L 0 0 0 48" fill="none" stroke="#c7b6ff" stroke-width="1" opacity="0.08"/>
    </pattern>
    <clipPath id="board-clip">
      <rect width="1200" height="460" rx="30"/>
    </clipPath>
  </defs>

  <g clip-path="url(#board-clip)">
    <rect width="1200" height="460" fill="url(#background)"/>
    <rect width="1200" height="460" fill="url(#grid)"/>
    <circle cx="1040" cy="228" r="300" fill="#8c6ae7" opacity="0.11"/>
    <circle cx="1040" cy="228" r="225" fill="none" stroke="#c7b6ff" stroke-width="2" opacity="0.18"/>
    <circle cx="1040" cy="228" r="175" fill="none" stroke="#f9b347" stroke-width="2" stroke-dasharray="7 14" opacity="0.34"/>
    <path d="M755 -8 L996 410 L517 410 Z" fill="none" stroke="#e4c7fd" stroke-width="5" opacity="0.07"/>
    <path d="M746 48 L941 386 L551 386 Z" fill="none" stroke="#e4c7fd" stroke-width="2" opacity="0.11"/>
  </g>

  <g id="brand-lockup" transform="translate(58 42)">
    <rect width="298" height="90" rx="18" fill="#f8f6fb"/>
    <rect x="1" y="1" width="296" height="88" rx="17" fill="none" stroke="#e4c7fd" stroke-width="2"/>
    <image href="../../../img/Black+Color.png" xlink:href="../../../img/Black+Color.png"
           x="17" y="8" width="264" height="83" preserveAspectRatio="xMidYMid meet"/>
  </g>

  <g id="title-block" transform="translate(60 ${layout.title_block_y})">
${renderLines(copy.eyebrow, [layout.eyebrow_y ?? 0], `data-copy="eyebrow" fill="#c7b6ff" font-family="${eyebrowFont}" font-size="${layout.eyebrow_font_size}" font-weight="700" letter-spacing="${layout.eyebrow_letter_spacing}"`)}
    <text x="0" y="${layout.project_title_y}" data-copy="title" fill="#f4f0ff" font-family="${generalFont}"
          font-size="${layout.project_title_font_size}" font-weight="800" letter-spacing="-4">${escapeXml(copy.title[0])}</text>
${renderLines(copy.tagline, layout.tagline_y, `data-copy="tagline" fill="#ffffff" font-family="${generalFont}" font-size="${layout.tagline_font_size}" font-weight="650"`)}
    <rect x="2" y="${layout.underline_y}" width="92" height="6" rx="3" fill="url(#signal)"/>
${renderLines(copy.supporting, layout.supporting_y, `data-copy="supporting" fill="#dcd4f4" font-family="${generalFont}" font-size="${layout.supporting_font_size}" font-weight="500"`)}
  </g>

  <g id="platforms" transform="translate(60 410)" font-family="ui-monospace, SFMono-Regular, Menlo, monospace"
     font-size="18" font-weight="700" fill="#f4f0ff" letter-spacing="0.8">
    <rect x="0" y="0" width="132" height="36" rx="18" fill="#ffffff" opacity="0.10"/>
    <text x="66" y="24" text-anchor="middle">OPENCLAW</text>
    <rect x="144" y="0" width="142" height="36" rx="18" fill="#ffffff" opacity="0.10"/>
    <text x="215" y="24" text-anchor="middle">NANOCLAW</text>
    <rect x="298" y="0" width="110" height="36" rx="18" fill="#ffffff" opacity="0.10"/>
    <text x="353" y="24" text-anchor="middle">HERMES</text>
    <rect x="420" y="0" width="122" height="36" rx="18" fill="#ffffff" opacity="0.10"/>
    <text x="481" y="24" text-anchor="middle">PICOCLAW</text>
  </g>

  <g id="mascot">
    <image href="../../../public/img/mascot.png" xlink:href="../../../public/img/mascot.png"
           x="765" y="30" width="410" height="410" preserveAspectRatio="xMidYMid meet"/>
  </g>

  <rect x="0.5" y="0.5" width="1199" height="459" rx="29.5" fill="none" stroke="#8c6ae7" stroke-width="1" opacity="0.72"/>
</svg>
`;
};

const failures = [];

for (const [locale, entry] of Object.entries(manifest.locales)) {
  const outputPath = path.join(repoRoot, entry.svg);
  const expected = renderSvg(locale, entry);

  if (checkOnly) {
    const actual = await readFile(outputPath, 'utf8').catch(() => null);
    if (actual !== expected) failures.push(entry.svg);
  } else {
    await writeFile(outputPath, expected);
    console.log(`generated ${entry.svg}`);
  }
}

if (failures.length > 0) {
  console.error(`Localized hero SVGs are stale or missing:\n${failures.map((file) => `- ${file}`).join('\n')}`);
  process.exitCode = 1;
} else if (checkOnly) {
  console.log(`PASS: ${Object.keys(manifest.locales).length} localized hero SVGs match hero-copy.json`);
}
