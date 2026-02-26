#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  extractTitleFromMarkdown,
  stripFrontmatter,
} from '../utils/markdownHelpers.mjs';
import {
  isWikiIndexSlug,
  toWikiLlmsPath,
  toWikiRoute,
} from '../utils/wikiPathHelpers.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const WIKI_ROOT = path.join(REPO_ROOT, 'wiki');
const PUBLIC_WIKI_ROOT = path.join(REPO_ROOT, 'public', 'wiki');
const LLM_INDEX_FILE = path.join(PUBLIC_WIKI_ROOT, 'llms.txt');

const WEBSITE_BASE = 'https://clawsec.prompt.security';
const REPO_BASE = 'https://github.com/prompt-security/clawsec';
const RAW_BASE = 'https://raw.githubusercontent.com/prompt-security/clawsec/main';

const toPosix = (inputPath) => inputPath.split(path.sep).join('/');
const toLlmsPageUrl = (slug) => `${WEBSITE_BASE}${toWikiLlmsPath(slug)}`;

const walkMarkdownFiles = async (dir) => {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const nested = await walkMarkdownFiles(fullPath);
      files.push(...nested);
      continue;
    }
    if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) {
      files.push(fullPath);
    }
  }

  return files;
};

const sortDocs = (a, b) => {
  if (a.slug === 'index' && b.slug !== 'index') return -1;
  if (a.slug !== 'index' && b.slug === 'index') return 1;
  return a.slug.localeCompare(b.slug, 'en', { sensitivity: 'base' });
};

const buildPageBody = (doc) => {
  const pageRoute = toWikiRoute(doc.slug);
  const pageUrl = `${WEBSITE_BASE}/#${pageRoute}`;
  const sourceUrl = `${RAW_BASE}/wiki/${doc.relativePath}`;
  const llmsUrl = toLlmsPageUrl(doc.slug);

  return [
    `# ClawSec Wiki · ${doc.title}`,
    '',
    'LLM-ready export for a single wiki page.',
    '',
    '## Canonical',
    `- Wiki page: ${pageUrl}`,
    `- LLM export: ${llmsUrl}`,
    `- Source markdown: ${sourceUrl}`,
    '',
    '## Markdown',
    '',
    doc.content.trim(),
    '',
  ].join('\n');
};

const buildFallbackIndexBody = (docs) => {
  const lines = [
    '# ClawSec Wiki llms.txt',
    '',
    'LLM-readable index for wiki pages.',
    '',
    `Website wiki root: ${WEBSITE_BASE}/#/wiki`,
    `GitHub wiki mirror: ${REPO_BASE}/wiki`,
    `Canonical source of truth: ${REPO_BASE}/tree/main/wiki`,
    '',
    '## Generated Page Exports',
  ];

  for (const doc of docs) {
    const pageRoute = toWikiRoute(doc.slug);
    const pageUrl = `${WEBSITE_BASE}/#${pageRoute}`;
    const llmsUrl = toLlmsPageUrl(doc.slug);
    lines.push(`- ${doc.title}: ${llmsUrl} (page: ${pageUrl})`);
  }

  return `${lines.join('\n')}\n`;
};

const main = async () => {
  try {
    const wikiStat = await fs.stat(WIKI_ROOT).catch(() => null);
    if (!wikiStat || !wikiStat.isDirectory()) {
      throw new Error('wiki/ directory not found.');
    }

    const markdownFiles = await walkMarkdownFiles(WIKI_ROOT);
    const docs = [];

    for (const fullPath of markdownFiles) {
      const relativePath = toPosix(path.relative(WIKI_ROOT, fullPath));
      const slug = relativePath.replace(/\.md$/i, '').toLowerCase();
      const rawContent = await fs.readFile(fullPath, 'utf8');
      const content = stripFrontmatter(rawContent);
      const title = extractTitleFromMarkdown(rawContent, relativePath);
      docs.push({ relativePath, slug, title, content });
    }

    docs.sort(sortDocs);
    const pageDocs = docs.filter((doc) => !isWikiIndexSlug(doc.slug));
    const indexDoc = docs.find((doc) => isWikiIndexSlug(doc.slug));

    // `public/wiki/` is fully generated; wipe stale output before regenerating.
    await fs.rm(PUBLIC_WIKI_ROOT, { recursive: true, force: true });
    await fs.mkdir(PUBLIC_WIKI_ROOT, { recursive: true });

    for (const doc of pageDocs) {
      const outputFile = path.join(PUBLIC_WIKI_ROOT, doc.slug, 'llms.txt');
      await fs.mkdir(path.dirname(outputFile), { recursive: true });
      await fs.writeFile(outputFile, buildPageBody(doc), 'utf8');
    }

    const indexBody = indexDoc ? buildPageBody(indexDoc) : buildFallbackIndexBody(pageDocs);
    await fs.writeFile(LLM_INDEX_FILE, indexBody, 'utf8');

    // Keep logs short for CI readability.
    console.log(`Generated ${pageDocs.length} page llms.txt exports and /wiki/llms.txt`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Failed to generate wiki llms exports: ${message}`);
    process.exit(1);
  }
};

await main();
