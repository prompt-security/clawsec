import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { generateWikiLlms } from './generate-wiki-llms.mjs';

const writeFixture = async (root, relativePath, content) => {
  const fullPath = path.join(root, relativePath);
  await mkdir(path.dirname(fullPath), { recursive: true });
  await writeFile(fullPath, content, 'utf8');
};

// Any `](something)` whose target isn't absolute (http(s)://, mailto:, a bare `#hash`,
// or root-absolute `/...`) is a link that only resolved inside the wiki/ source tree.
// Once exported into llms.txt and served from the website, that link is dead.
const findDeadRelativeLinks = (content) =>
  [...content.matchAll(/\]\(([^)\s]+)\)/g)]
    .map(([, target]) => target)
    .filter((target) => !/^([a-zA-Z][a-zA-Z0-9+.-]*:|\/|#)/.test(target));

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
  assert.deepEqual(findDeadRelativeLinks(index), []);

  const overview = await readFile(path.join(publicWikiRoot, 'overview', 'llms.txt'), 'utf8');
  assert.match(
    overview,
    /\[Automation\]\(https:\/\/clawsec\.prompt\.security\/#\/wiki\/modules\/automation#dry-run\)/,
  );
  assert.match(
    overview,
    /!\[Logo\]\(https:\/\/raw\.githubusercontent\.com\/prompt-security\/clawsec\/main\/wiki\/assets\/logo\.svg\)/,
  );
  assert.deepEqual(findDeadRelativeLinks(overview), []);

  await rm(tmpRoot, { recursive: true, force: true });
});

test('generateWikiLlms ships no dead relative links across the real wiki/ export', async () => {
  const wikiRoot = fileURLToPath(new URL('../wiki', import.meta.url));
  const publicWikiRoot = await mkdtemp(path.join(os.tmpdir(), 'clawsec-wiki-llms-real-'));

  const { pageCount, outputFiles } = await generateWikiLlms({ wikiRoot, publicWikiRoot });

  assert.ok(pageCount > 0, 'expected at least one wiki page to be exported');
  assert.ok(outputFiles.length > 0);

  const deadLinksByFile = new Map();
  for (const outputFile of outputFiles) {
    const content = await readFile(outputFile, 'utf8');
    const dead = findDeadRelativeLinks(content);
    if (dead.length > 0) deadLinksByFile.set(path.relative(publicWikiRoot, outputFile), dead);
  }

  assert.deepEqual(
    [...deadLinksByFile.entries()],
    [],
    'every internal wiki link must be rewritten to an absolute URL before export — a relative ' +
      'link here 404s once served from the website (see issue #349)',
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
