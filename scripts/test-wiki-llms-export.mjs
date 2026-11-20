import assert from 'node:assert/strict';
import { access, mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { generateWikiLlms, RAW_BASE, WEBSITE_BASE } from './generate-wiki-llms.mjs';

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

// The rewriter parses the plain `](dest)` form only. That covers all wiki content today,
// but CommonMark also allows titles (`](a.md "t")`), angle-bracket destinations
// (`](<a b.md>)`), and parenthesized paths — forms the rewriter would silently pass
// through (leaving a dead relative link) or truncate. The danger is that a validator
// using the same grammar is blind to exactly those cases and reports success.
//
// So rather than teaching both sides full CommonMark for forms no page uses, flag any
// `](` the rewriter cannot faithfully handle and fail loudly. If someone adds one later,
// CI says so instead of shipping another dead link.
const findUnparseableLinkForms = (content) => {
  const problems = [];

  for (const [snippet] of content.matchAll(/\]\((?![^)\s]+\))[^\n]{0,60}/g)) {
    problems.push(`unsupported link form (title / angle-bracket / spaced destination): ${snippet}`);
  }

  for (const [, target] of content.matchAll(/\]\(([^)\s]+)\)/g)) {
    if (target.includes('(')) {
      problems.push(`destination truncated at an unbalanced parenthesis: ${target}`);
    }
  }

  return problems;
};

test('wiki links resolve to the markdown alternate, not the SPA route', async () => {
  // llms.txt v2: "The links in an llms.txt file should therefore point to LLM-friendly
  // content, such as the markdown versions of pages." A `#/wiki/...` fragment is never
  // sent to the server, so linking there hands an agent the app shell and no content.
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'clawsec-wiki-llms-'));
  const wikiRoot = path.join(tmpRoot, 'wiki');
  const publicWikiRoot = path.join(tmpRoot, 'public', 'wiki');

  await writeFixture(wikiRoot, 'INDEX.md', [
    '# Wiki Index',
    '',
    '## Start Here',
    '- [Overview](overview.md)',
    '- [Missing page](missing-page.md)',
    '- [External](https://example.com/docs)',
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

  const overviewMd = await readFile(path.join(publicWikiRoot, 'overview.md'), 'utf8');
  assert.match(
    overviewMd,
    /\[Automation\]\(https:\/\/clawsec\.prompt\.security\/wiki\/modules\/automation\.md#dry-run\)/,
    'in-wiki link must point at the .md alternate, preserving the hash',
  );
  assert.doesNotMatch(overviewMd, /\/#\/wiki\//, 'must not emit SPA hash routes as link targets');
  assert.match(
    overviewMd,
    /!\[Logo\]\(https:\/\/raw\.githubusercontent\.com\/prompt-security\/clawsec\/main\/wiki\/assets\/logo\.svg\)/,
    'assets have no .md alternate and fall back to raw source',
  );

  const index = await readFile(path.join(publicWikiRoot, 'llms.txt'), 'utf8');
  assert.match(index, /- \[Overview\]\(https:\/\/clawsec\.prompt\.security\/wiki\/overview\.md\)/);
  assert.doesNotMatch(index, /\/#\/wiki\/overview/);
  // Entries that resolve to no wiki page are dropped from the index rather than shipped dead.
  assert.doesNotMatch(index, /Missing page/);

  await rm(tmpRoot, { recursive: true, force: true });
});

test('generated llms.txt files follow the v2 structure', async () => {
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'clawsec-wiki-llms-v2-'));
  const wikiRoot = path.join(tmpRoot, 'wiki');
  const publicRoot = path.join(tmpRoot, 'public');
  const publicWikiRoot = path.join(publicRoot, 'wiki');

  await writeFixture(wikiRoot, 'INDEX.md', [
    '# Wiki Index',
    '',
    '## Summary',
    '- Prose only, no links, so this section is dropped.',
    '',
    '## Start Here',
    '- [Overview](overview.md)',
    '',
  ].join('\n'));
  await writeFixture(wikiRoot, 'overview.md', '# Overview\n\nBody.\n');

  const { rootIndexFile } = await generateWikiLlms({ wikiRoot, publicWikiRoot, publicRoot });
  assert.ok(rootIndexFile, 'a site-root /llms.txt must be generated');

  for (const file of [rootIndexFile, path.join(publicWikiRoot, 'llms.txt')]) {
    const body = await readFile(file, 'utf8');
    const lines = body.split('\n');

    // "An H1 with the name of the project or site. This is the only required section."
    const h1s = lines.filter((line) => /^# /.test(line));
    assert.equal(h1s.length, 1, `${path.basename(file)} must contain exactly one H1, got ${h1s.length}`);
    assert.match(lines[0], /^# /, 'the H1 must be the first line');

    // "A blockquote with a short summary of the project."
    assert.ok(
      lines.some((line) => line.startsWith('> ')),
      `${path.basename(file)} must contain a blockquote summary`,
    );

    // "Zero or more markdown sections delimited by H2 headers, containing file lists of URLs."
    // Every line under an H2 must be a link list item — never an inlined page body.
    let inSection = false;
    for (const line of lines) {
      if (/^## /.test(line)) { inSection = true; continue; }
      if (!inSection || line.trim() === '') continue;
      assert.match(
        line,
        /^- \[[^\]]+\]\([^)]+\)/,
        `${path.basename(file)}: content under an H2 must be a link list item, got: ${line}`,
      );
    }
  }

  // A prose-only section contributes no links and must not be emitted as an empty H2.
  const wikiIndex = await readFile(path.join(publicWikiRoot, 'llms.txt'), 'utf8');
  assert.doesNotMatch(wikiIndex, /^## Summary$/m);
  assert.match(wikiIndex, /^## Start Here$/m);

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
  const publicWikiRoot = path.join(tmpRoot, 'public', 'wiki');

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

  for (const relativePath of ['top-level.md', path.join('de', 'nested.md')]) {
    const body = await readFile(path.join(publicWikiRoot, relativePath), 'utf8');
    assert.ok(body.includes(expectedLink), `expected ${expectedLink} in ${relativePath}`);
    assert.ok(!body.includes(wrongLink), `${relativePath} must not resolve into a wiki/-prefixed path`);
  }

  await rm(tmpRoot, { recursive: true, force: true });
});

test('the export gate rejects link forms the rewriter cannot faithfully handle', async () => {
  // No wiki page uses these CommonMark forms today, and the rewriter does not parse them.
  // What must not happen is the validator sharing that blind spot and reporting success —
  // that is how a dead link ships unnoticed (the #349 failure mode). Assert it fails loudly.
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'clawsec-wiki-llms-forms-'));
  const wikiRoot = path.join(tmpRoot, 'wiki');
  const publicWikiRoot = path.join(tmpRoot, 'public', 'wiki');

  await writeFixture(wikiRoot, 'INDEX.md', '# Wiki Index\n');
  await writeFixture(wikiRoot, 'page.md', [
    '# Page',
    '',
    '- [Titled](overview.md "page title")',
    '- [Angled](<assets/my image.svg>)',
    '- [Parenthesized](spec_(v2).md)',
    '',
  ].join('\n'));
  await writeFixture(wikiRoot, 'overview.md', '# Overview\n');

  await generateWikiLlms({ wikiRoot, publicWikiRoot });
  const page = await readFile(path.join(publicWikiRoot, 'page.md'), 'utf8');

  const problems = findUnparseableLinkForms(page);
  assert.equal(problems.length, 3, `expected all three unsupported forms flagged, got: ${problems}`);
  assert.ok(problems.some((p) => p.includes('page title')));
  assert.ok(problems.some((p) => p.includes('my image.svg')));
  assert.ok(problems.some((p) => p.includes('spec_(v2')));

  assert.equal(findUnparseableLinkForms('[Overview](overview.md)').length, 0);

  await rm(tmpRoot, { recursive: true, force: true });
});

test('every emitted link resolves to a real target, across the actual wiki/', async () => {
  const wikiRoot = path.join(REPO_ROOT, 'wiki');
  const publicRoot = await mkdtemp(path.join(os.tmpdir(), 'clawsec-wiki-llms-real-'));
  const publicWikiRoot = path.join(publicRoot, 'wiki');

  const { pageCount, outputFiles, markdownFiles } = await generateWikiLlms({
    wikiRoot,
    publicWikiRoot,
    publicRoot,
  });
  assert.ok(pageCount > 0, 'expected at least one wiki page to be exported');
  assert.ok(markdownFiles.length > 0, 'expected .md alternates to be generated');

  // Every markdown alternate the generator produced, addressable as the index links it.
  const publishedMarkdown = new Set(
    markdownFiles.map((file) => `/wiki/${path.relative(publicWikiRoot, file).split(path.sep).join('/')}`),
  );

  const rawPrefix = `${RAW_BASE}/`;
  const brokenLinksByFile = new Map();

  for (const outputFile of [...outputFiles, ...markdownFiles]) {
    const content = await readFile(outputFile, 'utf8');
    const broken = findUnparseableLinkForms(content);

    for (const target of extractLinkTargets(content)) {
      if (target.startsWith('#')) continue;

      if (!isAbsoluteHref(target)) {
        broken.push(`relative link left unrewritten: ${target}`);
        continue;
      }

      if (target.includes('/#/wiki/')) {
        broken.push(`links to an SPA hash route, which serves no content to agents: ${target}`);
        continue;
      }

      if (target.startsWith(rawPrefix)) {
        // Catches a wrong-but-absolute URL: a `wiki/`-prefixed path for a repo-root file
        // passes every "is it absolute" check and still 404s.
        const repoRelativePath = target.slice(rawPrefix.length).split('#')[0];
        const exists = await access(path.join(REPO_ROOT, repoRelativePath))
          .then(() => true)
          .catch(() => false);
        if (!exists) broken.push(`raw link points at a path that does not exist in the repo: ${target}`);
        continue;
      }

      if (target.startsWith(WEBSITE_BASE)) {
        const sitePath = target.slice(WEBSITE_BASE.length).split('#')[0];
        // The wiki index is a generated artifact, not a markdown alternate.
        if (sitePath === '/wiki/llms.txt') continue;
        if (!publishedMarkdown.has(sitePath)) {
          broken.push(`site link points at a file that is not generated: ${target}`);
        }
      }
    }

    if (broken.length > 0) {
      brokenLinksByFile.set(path.relative(publicRoot, outputFile), broken);
    }
  }

  assert.deepEqual(
    [...brokenLinksByFile.entries()],
    [],
    'every emitted link must resolve to something that actually exists — a relative link, an '
      + 'SPA hash route, or an absolute URL pointing at a nonexistent path all dead-end for the '
      + 'agents these files exist for (see issue #349)',
  );

  await rm(publicRoot, { recursive: true, force: true });
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
