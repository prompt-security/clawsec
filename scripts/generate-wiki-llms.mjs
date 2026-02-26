#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const WIKI_ROOT = path.join(REPO_ROOT, 'wiki');
const PUBLIC_WIKI_ROOT = path.join(REPO_ROOT, 'public', 'wiki');
const LLM_PAGES_ROOT = path.join(PUBLIC_WIKI_ROOT, 'llms');
const LLM_INDEX_FILE = path.join(PUBLIC_WIKI_ROOT, 'llms.txt');

const WEBSITE_BASE = 'https://clawsec.prompt.security';
const REPO_BASE = 'https://github.com/prompt-security/clawsec';
const RAW_BASE = 'https://raw.githubusercontent.com/prompt-security/clawsec/main';

const FRONTMATTER_REGEX = /^---\s*\n[\s\S]*?\n---\s*\n/;

const toPosix = (inputPath) => inputPath.split(path.sep).join('/');

const fallbackTitleFromPath = (filePath) => {
  const filename = filePath.split('/').pop() ?? filePath;
  const stem = filename.replace(/\.md$/i, '');
  return stem
    .split(/[-_]/)
    .filter(Boolean)
    .map((part) => {
      if (part.toUpperCase() === part && part.length > 1) return part;
      return part.charAt(0).toUpperCase() + part.slice(1);
    })
    .join(' ');
};

const stripFrontmatter = (content) => content.replace(FRONTMATTER_REGEX, '');

const extractTitle = (content, filePath) => {
  const cleaned = stripFrontmatter(content).trim();
  const match = cleaned.match(/^#\s+(.+)$/m);
  return match?.[1]?.trim() || fallbackTitleFromPath(filePath);
};

const toWebsiteRoute = (slug) => (slug === 'index' ? '/wiki' : `/wiki/${slug}`);

const toLlmsPageUrl = (slug) => `${WEBSITE_BASE}/wiki/llms/${slug}.txt`;

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
  const pageRoute = toWebsiteRoute(doc.slug);
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

const buildIndexBody = (docs) => {
  const lines = [
    '# ClawSec Wiki llms.txt',
    '',
    'LLM-readable index for wiki pages. A generated `.txt` export exists for each page.',
    '',
    `Website wiki root: ${WEBSITE_BASE}/#/wiki`,
    `GitHub wiki mirror: ${REPO_BASE}/wiki`,
    `Canonical source of truth: ${REPO_BASE}/tree/main/wiki`,
    '',
    '## Generated Page Exports',
  ];

  for (const doc of docs) {
    const pageRoute = toWebsiteRoute(doc.slug);
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
      const title = extractTitle(rawContent, relativePath);
      docs.push({ relativePath, slug, title, content });
    }

    docs.sort(sortDocs);

    await fs.mkdir(PUBLIC_WIKI_ROOT, { recursive: true });
    await fs.rm(LLM_PAGES_ROOT, { recursive: true, force: true });
    await fs.mkdir(LLM_PAGES_ROOT, { recursive: true });

    for (const doc of docs) {
      const outputFile = path.join(LLM_PAGES_ROOT, `${doc.slug}.txt`);
      await fs.mkdir(path.dirname(outputFile), { recursive: true });
      await fs.writeFile(outputFile, buildPageBody(doc), 'utf8');
    }

    await fs.writeFile(LLM_INDEX_FILE, buildIndexBody(docs), 'utf8');

    // Keep logs short for CI readability.
    console.log(`Generated ${docs.length} wiki llms page exports and /wiki/llms.txt`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Failed to generate wiki llms exports: ${message}`);
    process.exit(1);
  }
};

await main();
