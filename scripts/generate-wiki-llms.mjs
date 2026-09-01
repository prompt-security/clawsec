#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  extractTitleFromMarkdown,
  stripFrontmatter,
} from '../utils/markdownHelpers.mjs';
import {
  isExternalHref,
  isWikiIndexSlug,
  splitWikiHash,
  toWikiLlmsPath,
  toWikiRoute,
} from '../utils/wikiPathHelpers.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const WIKI_ROOT = path.join(REPO_ROOT, 'wiki');
const PUBLIC_ROOT = path.join(REPO_ROOT, 'public');
const PUBLIC_WIKI_ROOT = path.join(PUBLIC_ROOT, 'wiki');

export const WEBSITE_BASE = 'https://clawsec.prompt.security';
export const REPO_BASE = 'https://github.com/prompt-security/clawsec';
export const RAW_BASE = 'https://raw.githubusercontent.com/prompt-security/clawsec/main';

const toPosix = (inputPath) => inputPath.split(path.sep).join('/');
const toLlmsPageUrl = (slug) => `${WEBSITE_BASE}${toWikiLlmsPath(slug)}`;

// llms.txt v2: "The links in an llms.txt file should therefore point to LLM-friendly
// content, such as the markdown versions of pages." We publish a clean `.md` alternate
// per page and point every generated link at that, not at the SPA route — a `#/wiki/...`
// fragment is never sent to the server, so an agent following it receives the app shell
// with none of the page content.
export const toWikiMarkdownPath = (slug) => `/wiki/${slug}.md`;
const toWikiMarkdownUrl = (slug) => `${WEBSITE_BASE}${toWikiMarkdownPath(slug)}`;

// Resolve a wiki-relative link, tracking how many `..` segments climb past the wiki root
// (`aboveWikiRoot`). wikiPathHelpers' resolveWikiLinkTarget clamps `..` at the wiki root
// instead of counting the overflow, so it can't tell "wiki/CONTRIBUTING.md" apart from
// "../CONTRIBUTING.md" written from wiki/ itself — both normalize to the same string,
// even though the wiki content actually lives one directory below the repo root and real
// pages link out to root-level docs (e.g. wiki/exploitability-scoring.md -> CONTRIBUTING.md).
// Losing that distinction here would point the raw-GitHub fallback at a `wiki/`-prefixed
// path that doesn't exist.
const resolveLinkPath = (docRelativePath, targetPath) => {
  const baseDirParts = docRelativePath.includes('/')
    ? docRelativePath.split('/').slice(0, -1)
    : [];
  const parts = [...baseDirParts];
  let aboveWikiRoot = 0;

  for (const segment of targetPath.split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      if (parts.length > 0) parts.pop();
      else aboveWikiRoot += 1;
      continue;
    }
    parts.push(segment);
  }

  return { path: parts.join('/'), aboveWikiRoot };
};

// Wiki markdown uses repo-relative links (`overview.md`, `../assets/x.svg`), which only resolve
// inside the wiki/ tree. Exported llms.txt files are served from the website, so internal links
// must be rewritten to absolute URLs or they 404 for anyone following them.
const rewriteInternalLinks = (content, docRelativePath, slugSet) =>
  content.replace(/\]\(([^)\s]+)\)/g, (match, href) => {
    if (!href || isExternalHref(href) || href.startsWith('#') || href.startsWith('/')) {
      return match; // external, hash-only, or root-absolute — leave as-is
    }

    const { path: rawTarget, hash } = splitWikiHash(href);
    if (!rawTarget) return match;

    const { path: resolvedPath, aboveWikiRoot } = resolveLinkPath(docRelativePath, rawTarget);
    if (!resolvedPath) return match;

    if (aboveWikiRoot > 0) {
      // Escapes the wiki/ tree (e.g. `../CONTRIBUTING.md`) — resolve against the repo root,
      // not `wiki/`. There is no website route for content outside the wiki tree.
      return `](${RAW_BASE}/${resolvedPath}${hash})`;
    }

    const targetSlug = resolvedPath.toLowerCase().endsWith('.md')
      ? resolvedPath.replace(/\.md$/i, '').toLowerCase()
      : null;

    if (!targetSlug || !slugSet.has(targetSlug)) {
      return `](${RAW_BASE}/wiki/${resolvedPath}${hash})`;
    }

    return `](${toWikiMarkdownUrl(targetSlug)}${hash})`;
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

// Group the wiki's own INDEX.md link lists by their H2 heading, so the generated index
// mirrors the curated ordering maintained in wiki/INDEX.md rather than inventing one.
// Only list items that resolve to a real wiki page are kept; prose sections (Summary,
// Update Notes, Source References) yield no entries and are dropped.
const extractIndexSections = (indexDoc, docsBySlug) => {
  if (!indexDoc) return [];

  const sections = [];
  let current = null;

  for (const line of indexDoc.content.split(/\r?\n/)) {
    const heading = /^##\s+(.+?)\s*$/.exec(line);
    if (heading) {
      current = { title: heading[1], entries: [] };
      sections.push(current);
      continue;
    }

    const item = /^\s*-\s+\[([^\]]+)\]\(([^)\s]+)\)/.exec(line);
    if (!current || !item) continue;

    const [, label, href] = item;
    const { path: resolvedPath, aboveWikiRoot } = resolveLinkPath(indexDoc.relativePath, splitWikiHash(href).path);
    if (aboveWikiRoot > 0 || !resolvedPath.toLowerCase().endsWith('.md')) continue;

    const slug = resolvedPath.replace(/\.md$/i, '').toLowerCase();
    const doc = docsBySlug.get(slug);
    if (doc) current.entries.push({ label, doc });
  }

  return sections.filter((section) => section.entries.length > 0);
};

// llms.txt v2 structure: a single H1, a blockquote summary, optional prose, then H2
// sections whose bodies are link lists. Anything else (notably a second H1, or an entire
// page body inlined under an H2) breaks the format agents are told to expect.
const buildLlmsIndex = ({ h1, summary, notes, sections, extraSections = [] }) => {
  const lines = [`# ${h1}`, '', `> ${summary}`, ''];

  for (const note of notes) lines.push(note, '');

  for (const section of sections) {
    lines.push(`## ${section.title}`);
    for (const entry of section.entries) {
      lines.push(`- [${entry.label}](${toWikiMarkdownUrl(entry.doc.slug)})`);
    }
    lines.push('');
  }

  for (const section of extraSections) {
    lines.push(`## ${section.title}`);
    for (const entry of section.entries) {
      lines.push(entry.note ? `- [${entry.label}](${entry.url}): ${entry.note}` : `- [${entry.label}](${entry.url})`);
    }
    lines.push('');
  }

  return `${lines.join('\n').trimEnd()}\n`;
};

// Fallback when wiki/INDEX.md is missing: one flat section listing every page.
const buildFallbackSections = (docs) => [
  { title: 'Pages', entries: docs.map((doc) => ({ label: doc.title, doc })) },
];

/**
 * Generate llms.txt exports for every wiki page under `wikiRoot`, writing them to
 * `publicWikiRoot`. Returns the list of generated output files (index included) so
 * callers — including tests — can inspect exactly what was produced.
 * @param {{ wikiRoot: string, publicWikiRoot: string }} options
 * @returns {Promise<{ pageCount: number, outputFiles: string[] }>}
 */
export const generateWikiLlms = async ({ wikiRoot, publicWikiRoot, publicRoot }) => {
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
  const markdownFilesWritten = [];

  for (const doc of docs) {
    // The `.md` alternate is the LLM-friendly content surface the index links to.
    const markdownFile = path.join(publicWikiRoot, `${doc.slug}.md`);
    await fs.mkdir(path.dirname(markdownFile), { recursive: true });
    await fs.writeFile(markdownFile, `${rewriteInternalLinks(doc.content, doc.relativePath, slugSet).trim()}\n`, 'utf8');
    markdownFilesWritten.push(markdownFile);

    // Retained unchanged so anything already consuming /wiki/<slug>/llms.txt keeps working.
    if (isWikiIndexSlug(doc.slug)) continue;
    const outputFile = path.join(publicWikiRoot, doc.slug, 'llms.txt');
    await fs.mkdir(path.dirname(outputFile), { recursive: true });
    await fs.writeFile(outputFile, buildPageBody(doc, slugSet), 'utf8');
    outputFiles.push(outputFile);
  }

  const docsBySlug = new Map(docs.map((doc) => [doc.slug, doc]));
  const sections = indexDoc
    ? extractIndexSections(indexDoc, docsBySlug)
    : buildFallbackSections(pageDocs);

  const wikiIndexBody = buildLlmsIndex({
    h1: 'ClawSec Wiki',
    summary:
      'Full repository wiki for ClawSec, a security skill suite for AI agents covering the web '
      + 'catalog, signed advisory feed, and per-skill release packaging. Every link below points to '
      + 'the markdown version of a page.',
    notes: [
      `Canonical source of truth: ${REPO_BASE}/tree/main/wiki`,
      `Human-readable wiki: ${WEBSITE_BASE}/#/wiki`,
    ],
    sections,
  });
  const wikiIndexFile = path.join(publicWikiRoot, 'llms.txt');
  await fs.writeFile(wikiIndexFile, wikiIndexBody, 'utf8');
  outputFiles.push(wikiIndexFile);

  // Site-root index. Spec: a file "covers the pages under its path, and the most specific
  // file applies", so this points at the wiki index rather than duplicating its entries.
  let rootIndexFile = null;
  if (publicRoot) {
    const rootIndexBody = buildLlmsIndex({
      h1: 'ClawSec',
      summary:
        'Security skill suite for AI agents: integrity checks, drift detection, and a signed '
        + 'advisory feed, distributed as installable skills for OpenClaw and NanoClaw.',
      notes: [`Repository: ${REPO_BASE}`],
      sections: [],
      extraSections: [
        {
          title: 'Docs',
          entries: [
            {
              label: 'ClawSec Wiki',
              url: `${WEBSITE_BASE}/wiki/llms.txt`,
              note: 'index of every wiki page, in markdown',
            },
          ],
        },
      ],
    });
    rootIndexFile = path.join(publicRoot, 'llms.txt');
    await fs.mkdir(publicRoot, { recursive: true });
    await fs.writeFile(rootIndexFile, rootIndexBody, 'utf8');
    outputFiles.push(rootIndexFile);
  }

  return {
    pageCount: pageDocs.length,
    outputFiles,
    markdownFiles: markdownFilesWritten,
    rootIndexFile,
  };
};

const isDirectRun = () => {
  if (!process.argv[1]) return false;
  return fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
};

if (isDirectRun()) {
  try {
    const { pageCount, markdownFiles } = await generateWikiLlms({
      wikiRoot: WIKI_ROOT,
      publicWikiRoot: PUBLIC_WIKI_ROOT,
      publicRoot: PUBLIC_ROOT,
    });
    // Keep logs short for CI readability.
    console.log(
      `Generated ${markdownFiles.length} wiki .md alternates, ${pageCount} page llms.txt exports, /wiki/llms.txt and /llms.txt`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Failed to generate wiki llms exports: ${message}`);
    process.exit(1);
  }
}
