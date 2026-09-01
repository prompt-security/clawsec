import assert from 'node:assert/strict';
import { access, mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { generateWikiLlms, RAW_BASE, WEBSITE_BASE } from './generate-wiki-llms.mjs';
import { toWikiRoute } from '../utils/wikiPathHelpers.mjs';

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

const writeFixture = async (root, relativePath, content) => {
  const fullPath = path.join(root, relativePath);
  await mkdir(path.dirname(fullPath), { recursive: true });
  await writeFile(fullPath, content, 'utf8');
};

const extractLinkTargets = (content) =>
  [...content.matchAll(/\]\(([^)\s]+)\)/g)].map(([, target]) => target);

const isAbsoluteHref = (target) =>
  /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(target) || target.startsWith('/') || target.startsWith('#');

const toSlug = (outputFile, publicWikiRoot) => {
  const relDir = path.relative(publicWikiRoot, path.dirname(outputFile));
  return relDir === '' ? 'index' : relDir.split(path.sep).join('/');
};

test('generateWikiLlms rewrites internal wiki links to absolute URLs', async () => {
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'clawsec-wiki-llms-'));
  const wikiRoot = path.join(tmpRoot, 'wiki');
  const publicWikiRoot = path.join(tmpRoot, 'public-wiki');

  await writeFixture(wikiRoot, 'INDEX.md', [
    '# Wiki Index',
    '',
    '- [Overview](overview.md)',
    '- [Missing page](missing-page.md)',
    '- [External](https://example.com/docs)',
    '- [Same-page section](#summary)',
    '- [Root absolute](/wiki/overview)',
    '',
  ].join('\n'));
  await writeFixture(wikiRoot, 'overview.md', [
    '# Overview',
    '',
    'See [Automation](modules/automation.md#dry-run).',
    '',
    '![Logo](assets/logo.svg)',
    '',
  ].join('\n'));
  await writeFixture(wikiRoot, 'modules/automation.md', '# Automation\n');

  await generateWikiLlms({ wikiRoot, publicWikiRoot });

  const index = await readFile(path.join(publicWikiRoot, 'llms.txt'), 'utf8');
  assert.match(index, /\[Overview\]\(https:\/\/clawsec\.prompt\.security\/#\/wiki\/overview\)/);
  assert.match(
    index,
    /\[Missing page\]\(https:\/\/raw\.githubusercontent\.com\/prompt-security\/clawsec\/main\/wiki\/missing-page\.md\)/,
  );
  assert.match(index, /\[External\]\(https:\/\/example\.com\/docs\)/);
  assert.match(index, /\[Same-page section\]\(#summary\)/);
  assert.match(index, /\[Root absolute\]\(\/wiki\/overview\)/);
  assert.ok(extractLinkTargets(index).every(isAbsoluteHref));

  const overview = await readFile(path.join(publicWikiRoot, 'overview', 'llms.txt'), 'utf8');
  assert.match(
    overview,
    /\[Automation\]\(https:\/\/clawsec\.prompt\.security\/#\/wiki\/modules\/automation#dry-run\)/,
  );
  assert.match(
    overview,
    /!\[Logo\]\(https:\/\/raw\.githubusercontent\.com\/prompt-security\/clawsec\/main\/wiki\/assets\/logo\.svg\)/,
  );
  assert.ok(extractLinkTargets(overview).every(isAbsoluteHref));

  await rm(tmpRoot, { recursive: true, force: true });
});

test('generateWikiLlms resolves links that climb above the wiki root against the repo root, not wiki/', async () => {
  // Regression fixture for a real defect: wiki content lives one directory below the repo
  // root, and real pages link out to root-level docs (e.g. wiki/exploitability-scoring.md's
  // `../CONTRIBUTING.md`, or wiki/de/exploitability-scoring.md's `../../CONTRIBUTING.md` —
  // both name the same repo-root file from different nesting depths). A resolver that clamps
  // `..` at the wiki root instead of counting the overflow can't tell that apart from an
  // in-wiki reference, and ends up emitting a `wiki/`-prefixed raw URL that 404s.
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'clawsec-wiki-llms-escape-'));
  const wikiRoot = path.join(tmpRoot, 'wiki');
  const publicWikiRoot = path.join(tmpRoot, 'public-wiki');

  await writeFixture(tmpRoot, 'CONTRIBUTING.md', '# Contributing\n');
  await writeFixture(wikiRoot, 'top-level.md', [
    '# Top Level',
    '',
    'See [CONTRIBUTING](../CONTRIBUTING.md).',
    '',
  ].join('\n'));
  await writeFixture(wikiRoot, 'de/nested.md', [
    '# Nested',
    '',
    'See [CONTRIBUTING](../../CONTRIBUTING.md).',
    '',
  ].join('\n'));

  await generateWikiLlms({ wikiRoot, publicWikiRoot });

  const expectedLink = `[CONTRIBUTING](${RAW_BASE}/CONTRIBUTING.md)`;
  const wrongLink = `${RAW_BASE}/wiki/CONTRIBUTING.md`;

  const topLevel = await readFile(path.join(publicWikiRoot, 'top-level', 'llms.txt'), 'utf8');
  assert.ok(topLevel.includes(expectedLink), `expected ${expectedLink} in top-level export`);
  assert.ok(!topLevel.includes(wrongLink), `must not resolve into a nonexistent wiki/-prefixed path`);

  const nested = await readFile(path.join(publicWikiRoot, 'de', 'nested', 'llms.txt'), 'utf8');
  assert.ok(nested.includes(expectedLink), `expected ${expectedLink} in nested export`);
  assert.ok(!nested.includes(wrongLink), `must not resolve into a nonexistent wiki/-prefixed path`);

  await rm(tmpRoot, { recursive: true, force: true });
});

test('generateWikiLlms only emits internal links that resolve to a real target, across the actual wiki/', async () => {
  const wikiRoot = path.join(REPO_ROOT, 'wiki');
  const publicWikiRoot = await mkdtemp(path.join(os.tmpdir(), 'clawsec-wiki-llms-real-'));

  const { pageCount, outputFiles } = await generateWikiLlms({ wikiRoot, publicWikiRoot });
  assert.ok(pageCount > 0, 'expected at least one wiki page to be exported');

  const knownRoutes = new Set(outputFiles.map((file) => toWikiRoute(toSlug(file, publicWikiRoot))));
  const websitePrefix = `${WEBSITE_BASE}/#`;
  const rawPrefix = `${RAW_BASE}/`;

  const brokenLinksByFile = new Map();

  for (const outputFile of outputFiles) {
    const content = await readFile(outputFile, 'utf8');
    const broken = [];

    for (const target of extractLinkTargets(content)) {
      if (target.startsWith('#')) continue; // same-page anchor

      if (!isAbsoluteHref(target)) {
        broken.push(`relative link left unrewritten: ${target}`);
        continue;
      }

      if (target.startsWith(rawPrefix)) {
        // The one check that actually catches a wrong-but-absolute URL: does the path this
        // points at exist in the repo? A `wiki/`-prefixed path for a repo-root file passes
        // every "is it absolute" check and still 404s — only an existence check catches it.
        const repoRelativePath = target.slice(rawPrefix.length).split('#')[0];
        const exists = await access(path.join(REPO_ROOT, repoRelativePath))
          .then(() => true)
          .catch(() => false);
        if (!exists) broken.push(`raw link points at a path that does not exist in the repo: ${target}`);
        continue;
      }

      if (target.startsWith(websitePrefix)) {
        const route = target.slice(websitePrefix.length).split('#')[0];
        if (!knownRoutes.has(route)) {
          broken.push(`website link points at a route with no generated export: ${target}`);
        }
      }
    }

    if (broken.length > 0) {
      brokenLinksByFile.set(path.relative(publicWikiRoot, outputFile), broken);
    }
  }

  assert.deepEqual(
    [...brokenLinksByFile.entries()],
    [],
    'every internal wiki link must resolve to something that actually exists — a relative link, ' +
      'or an absolute URL pointing at a nonexistent path, 404s once served from the website ' +
      '(see issue #349)',
  );

  await rm(publicWikiRoot, { recursive: true, force: true });
});

test('wiki export verification workflow covers the llms.txt generator', async () => {
  const verifyWorkflow = await readFile(
    new URL('../.github/workflows/wiki-export-verify.yml', import.meta.url),
    'utf8',
  );

  assert.match(
    verifyWorkflow,
    /paths:[\s\S]*scripts\/generate-wiki-llms\.mjs/,
    'wiki export verification workflow must run when the llms.txt generator changes',
  );
  assert.match(
    verifyWorkflow,
    /paths:[\s\S]*scripts\/test-wiki-llms-export\.mjs/,
    'wiki export verification workflow must run when this test file changes',
  );
  assert.match(
    verifyWorkflow,
    /name: Test wiki llms\.txt export[\s\S]*node scripts\/test-wiki-llms-export\.mjs/,
    'wiki export verification workflow must run the llms.txt export test before merge',
  );
});
