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
  resolveWikiLinkTarget,
  toWikiLlmsPath,
  toWikiRoute,
} from '../utils/wikiPathHelpers.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const WIKI_ROOT = path.join(REPO_ROOT, 'wiki');
const PUBLIC_WIKI_ROOT = path.join(REPO_ROOT, 'public', 'wiki');

const WEBSITE_BASE = 'https://clawsec.prompt.security';
const REPO_BASE = 'https://github.com/prompt-security/clawsec';
const RAW_BASE = 'https://raw.githubusercontent.com/prompt-security/clawsec/main';

const toPosix = (inputPath) => inputPath.split(path.sep).join('/');
const toLlmsPageUrl = (slug) => `${WEBSITE_BASE}${toWikiLlmsPath(slug)}`;

// Wiki markdown uses repo-relative links (`overview.md`, `../assets/x.svg`), which only resolve
// inside the wiki/ tree. Exported llms.txt files are served from the website, so internal links
// must be rewritten to absolute URLs or they 404 for anyone following them.
const rewriteInternalLinks = (content, docRelativePath, slugSet) =>
  content.replace(/\]\(([^)\s]+)\)/g, (match, href) => {
    const target = resolveWikiLinkTarget(docRelativePath, href);
    if (!target) return match; // external, hash-only, or root-absolute — leave as-is

    const { path: resolvedPath, hash } = target;
    const targetSlug = resolvedPath.toLowerCase().endsWith('.md')
      ? resolvedPath.replace(/\.md$/i, '').toLowerCase()
      : null;

    if (!targetSlug || !slugSet.has(targetSlug)) {
      return `](${RAW_BASE}/wiki/${resolvedPath}${hash})`;
    }

    return `](${WEBSITE_BASE}/#${toWikiRoute(targetSlug)}${hash})`;
  });

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

const buildPageBody = (doc, slugSet) => {
  const pageRoute = toWikiRoute(doc.slug);
  const pageUrl = `${WEBSITE_BASE}/#${pageRoute}`;
  const sourceUrl = `${RAW_BASE}/wiki/${doc.relativePath}`;
  const llmsUrl = toLlmsPageUrl(doc.slug);
  const content = rewriteInternalLinks(doc.content, doc.relativePath, slugSet).trim();

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
    content,
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

/**
 * Generate llms.txt exports for every wiki page under `wikiRoot`, writing them to
 * `publicWikiRoot`. Returns the list of generated output files (index included) so
 * callers — including tests — can inspect exactly what was produced.
 * @param {{ wikiRoot: string, publicWikiRoot: string }} options
 * @returns {Promise<{ pageCount: number, outputFiles: string[] }>}
 */
export const generateWikiLlms = async ({ wikiRoot, publicWikiRoot }) => {
  const wikiStat = await fs.stat(wikiRoot).catch(() => null);
  if (!wikiStat || !wikiStat.isDirectory()) {
    throw new Error(`wiki/ directory not found at ${wikiRoot}.`);
  }

  const markdownFiles = await walkMarkdownFiles(wikiRoot);
  const docs = [];

  for (const fullPath of markdownFiles) {
    const relativePath = toPosix(path.relative(wikiRoot, fullPath));
    const slug = relativePath.replace(/\.md$/i, '').toLowerCase();
    const rawContent = await fs.readFile(fullPath, 'utf8');
    const content = stripFrontmatter(rawContent);
    const title = extractTitleFromMarkdown(rawContent, relativePath);
    docs.push({ relativePath, slug, title, content });
  }

  docs.sort(sortDocs);
  const pageDocs = docs.filter((doc) => !isWikiIndexSlug(doc.slug));
  const indexDoc = docs.find((doc) => isWikiIndexSlug(doc.slug));
  const slugSet = new Set(docs.map((doc) => doc.slug));

  // `public/wiki/` is fully generated; wipe stale output before regenerating.
  await fs.rm(publicWikiRoot, { recursive: true, force: true });
  await fs.mkdir(publicWikiRoot, { recursive: true });

  const outputFiles = [];

  for (const doc of pageDocs) {
    const outputFile = path.join(publicWikiRoot, doc.slug, 'llms.txt');
    await fs.mkdir(path.dirname(outputFile), { recursive: true });
    await fs.writeFile(outputFile, buildPageBody(doc, slugSet), 'utf8');
    outputFiles.push(outputFile);
  }

  const indexFile = path.join(publicWikiRoot, 'llms.txt');
  const indexBody = indexDoc ? buildPageBody(indexDoc, slugSet) : buildFallbackIndexBody(pageDocs);
  await fs.writeFile(indexFile, indexBody, 'utf8');
  outputFiles.push(indexFile);

  return { pageCount: pageDocs.length, outputFiles };
};

const isDirectRun = () => {
  if (!process.argv[1]) return false;
  return fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
};

if (isDirectRun()) {
  try {
    const { pageCount } = await generateWikiLlms({ wikiRoot: WIKI_ROOT, publicWikiRoot: PUBLIC_WIKI_ROOT });
    // Keep logs short for CI readability.
    console.log(`Generated ${pageCount} page llms.txt exports and /wiki/llms.txt`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Failed to generate wiki llms exports: ${message}`);
    process.exit(1);
  }
}
