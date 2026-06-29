import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, writeFile, mkdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { buildGithubWikiExport } from './build-github-wiki-export.mjs';

const writeFixture = async (root, relativePath, content) => {
  const fullPath = path.join(root, relativePath);
  await mkdir(path.dirname(fullPath), { recursive: true });
  await writeFile(fullPath, content, 'utf8');
};

const listFiles = async (root) => {
  const entries = await readdir(root, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(entry.parentPath, entry.name))
    .map((fullPath) => path.relative(root, fullPath).replace(/\\/g, '/'))
    .sort();
};

test('buildGithubWikiExport flattens nested wiki pages and rewrites markdown links', async () => {
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'clawsec-wiki-export-'));
  const sourceDir = path.join(tmpRoot, 'wiki');
  const outputDir = path.join(tmpRoot, 'export');

  await writeFixture(sourceDir, 'INDEX.md', [
    '# Wiki Index',
    '',
    '- [Overview](overview.md)',
    '- [Spanish](es/INDEX.md)',
    '- [Automation](modules/automation-release.md#dry-run)',
    '',
  ].join('\n'));
  await writeFixture(sourceDir, 'overview.md', [
    '# Overview',
    '',
    'See [Automation](modules/automation-release.md).',
    '',
  ].join('\n'));
  await writeFixture(sourceDir, 'es/INDEX.md', [
    '# Indice',
    '',
    '- [Resumen](overview.md)',
    '- [English overview](../overview.md)',
    '',
  ].join('\n'));
  await writeFixture(sourceDir, 'es/overview.md', '# Resumen\n');
  await writeFixture(sourceDir, 'es/media.md', [
    '# Media',
    '',
    '![Logo](../assets/logo.png)',
    '[Logo download](../assets/logo.png)',
    '',
  ].join('\n'));
  await writeFixture(sourceDir, 'modules/automation-release.md', '# Automation\n');
  await writeFixture(sourceDir, 'assets/logo.png', 'fake-png');

  const result = await buildGithubWikiExport({ sourceDir, outputDir });

  assert.deepEqual(await listFiles(outputDir), [
    'Home.md',
    'assets/logo.png',
    'es-Home.md',
    'es-media.md',
    'es-overview.md',
    'modules-automation-release.md',
    'overview.md',
  ]);
  assert.deepEqual(
    result.files.map((file) => [file.sourcePath, file.outputPath]),
    [
      ['INDEX.md', 'Home.md'],
      ['es/INDEX.md', 'es-Home.md'],
      ['es/media.md', 'es-media.md'],
      ['es/overview.md', 'es-overview.md'],
      ['modules/automation-release.md', 'modules-automation-release.md'],
      ['overview.md', 'overview.md'],
    ],
  );

  const home = await readFile(path.join(outputDir, 'Home.md'), 'utf8');
  assert.match(home, /\[Overview\]\(overview\.md\)/);
  assert.match(home, /\[Spanish\]\(es-Home\.md\)/);
  assert.match(home, /\[Automation\]\(modules-automation-release\.md#dry-run\)/);
  assert.doesNotMatch(home, /es\/INDEX\.md|modules\/automation-release\.md/);

  const spanishHome = await readFile(path.join(outputDir, 'es-Home.md'), 'utf8');
  assert.match(spanishHome, /\[Resumen\]\(es-overview\.md\)/);
  assert.match(spanishHome, /\[English overview\]\(overview\.md\)/);

  const media = await readFile(path.join(outputDir, 'es-media.md'), 'utf8');
  assert.match(media, /!\[Logo\]\(assets\/logo\.png\)/);
  assert.match(media, /\[Logo download\]\(assets\/logo\.png\)/);
  assert.doesNotMatch(media, /\.\.\/assets\/logo\.png/);
});

test('buildGithubWikiExport rejects flattened filename collisions', async () => {
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'clawsec-wiki-export-collision-'));
  const sourceDir = path.join(tmpRoot, 'wiki');
  const outputDir = path.join(tmpRoot, 'export');

  await writeFixture(sourceDir, 'foo/bar.md', '# Nested\n');
  await writeFixture(sourceDir, 'foo-bar.md', '# Flat\n');

  await assert.rejects(
    buildGithubWikiExport({ sourceDir, outputDir }),
    /Flattened wiki export collision/,
  );
});

test('wiki workflows verify pull requests without publishing and publish flattened sync output', async () => {
  const verifyWorkflow = await readFile(
    new URL('../.github/workflows/wiki-export-verify.yml', import.meta.url),
    'utf8',
  );
  const syncWorkflow = await readFile(
    new URL('../.github/workflows/wiki-sync.yml', import.meta.url),
    'utf8',
  );

  assert.match(
    verifyWorkflow,
    /pull_request:[\s\S]*scripts\/test-wiki-sync-export\.mjs/,
    'wiki export verification workflow must run on pull requests that change the export test',
  );
  assert.match(
    verifyWorkflow,
    /name: Test wiki export transform[\s\S]*node scripts\/test-wiki-sync-export\.mjs/,
    'wiki export verification workflow must run the deterministic export test before merge',
  );
  assert.doesNotMatch(
    syncWorkflow,
    /pull_request:/,
    'wiki sync workflow must not run on pull_request events',
  );
  assert.match(
    syncWorkflow,
    /name: Test wiki export transform[\s\S]*node scripts\/test-wiki-sync-export\.mjs/,
    'wiki sync workflow must run the deterministic export test before publishing',
  );
  assert.match(
    syncWorkflow,
    /node scripts\/build-github-wiki-export\.mjs --source wiki --output "\$WIKI_EXPORT"/,
    'wiki sync workflow must publish the flattened export directory',
  );
  assert.doesNotMatch(
    syncWorkflow,
    /rsync -a --delete --exclude '\.git\/' wiki\/ "\$WIKI_TMP\/"/,
    'wiki sync workflow must not rsync the nested source wiki directly',
  );
});
