import { copyFile, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  normalizeWikiPath,
  resolveWikiLinkTarget,
} from '../utils/wikiPathHelpers.mjs';

const MARKDOWN_EXTENSION = /\.md$/i;
const MARKDOWN_LINK_PATTERN = /(\]\()([^)\s]+)(\))/g;
const SIDEBAR_OUTPUT_PATH = '_Sidebar.md';
const ROOT_SIDEBAR_SECTIONS = [
  'Start Here',
  'Guides',
  'Operations',
  'Modules',
  'Glossary',
  'Generation Metadata',
];
const LANGUAGE_PAGE_ORDER = [
  'INDEX.md',
  'overview.md',
  'architecture.md',
  'localization.md',
  'dependencies.md',
  'data-flow.md',
  'configuration.md',
  'testing.md',
  'workflow.md',
  'security.md',
  'security-signing-runbook.md',
  'migration-signed-feed.md',
  'platform-verification.md',
  'remediation-plan.md',
  'exploitability-scoring.md',
  'glossary.md',
  'GENERATION.md',
];

const listFiles = async (rootDir) => {
  const files = [];

  const walk = async (relativeDir = '') => {
    const absoluteDir = path.join(rootDir, relativeDir);
    const entries = await readdir(absoluteDir, { withFileTypes: true });
    for (const entry of entries) {
      const relativePath = relativeDir
        ? normalizeWikiPath(`${relativeDir}/${entry.name}`)
        : entry.name;

      if (entry.isDirectory()) {
        await walk(relativePath);
      } else if (entry.isFile()) {
        files.push(relativePath);
      }
    }
  };

  await walk();
  return files.sort();
};

const toFlattenedMarkdownPath = (sourcePath) => {
  const withoutExtension = sourcePath.replace(MARKDOWN_EXTENSION, '');
  const parts = withoutExtension.split('/').filter(Boolean);
  const lastPart = parts.at(-1) ?? '';

  if (parts.length === 1 && lastPart.toLowerCase() === 'index') {
    return 'Home.md';
  }

  if (lastPart.toLowerCase() === 'index') {
    return `${[...parts.slice(0, -1), 'Home'].join('-')}.md`;
  }

  return `${parts.join('-')}.md`;
};

const buildMarkdownPathMap = (markdownFiles) => {
  const sourceToOutput = new Map();
  const outputToSource = new Map();

  for (const sourcePath of markdownFiles) {
    const outputPath = toFlattenedMarkdownPath(sourcePath);
    const outputKey = outputPath.toLowerCase();
    const existingSource = outputToSource.get(outputKey);

    if (existingSource) {
      throw new Error(
        `Flattened wiki export collision: ${existingSource} and ${sourcePath} both map to ${outputPath}`,
      );
    }

    sourceToOutput.set(sourcePath.toLowerCase(), outputPath);
    outputToSource.set(outputKey, sourcePath);
  }

  return sourceToOutput;
};

const toGithubWikiPageHref = (outputPath) =>
  outputPath.replace(MARKDOWN_EXTENSION, '');

const formatLanguagePageLabel = (relativePath) => {
  if (relativePath.toLowerCase() === 'index.md') return 'Home';
  return relativePath
    .replace(MARKDOWN_EXTENSION, '')
    .replace(/\//g, ' / ')
    .replace(/-/g, ' ');
};

const compareLanguagePages = (left, right) => {
  const leftIndex = LANGUAGE_PAGE_ORDER.findIndex(
    (page) => page.toLowerCase() === left.toLowerCase(),
  );
  const rightIndex = LANGUAGE_PAGE_ORDER.findIndex(
    (page) => page.toLowerCase() === right.toLowerCase(),
  );

  if (leftIndex !== -1 || rightIndex !== -1) {
    if (leftIndex === -1) return 1;
    if (rightIndex === -1) return -1;
    return leftIndex - rightIndex;
  }

  return left.localeCompare(right);
};

const extractLinkedSections = ({ content, currentFilePath, sourceToOutput }) => {
  const sections = new Map();
  let currentSection = '';

  for (const line of content.split(/\r?\n/)) {
    const headingMatch = /^##\s+(.+?)\s*$/.exec(line);
    if (headingMatch) {
      currentSection = headingMatch[1];
      if (!sections.has(currentSection)) sections.set(currentSection, []);
      continue;
    }

    const linkMatch = /^\s*-\s+\[([^\]]+)\]\(([^)\s]+)\)/.exec(line);
    if (!currentSection || !linkMatch) continue;

    const [, label, href] = linkMatch;
    const target = resolveWikiLinkTarget(currentFilePath, href);
    if (!target || !MARKDOWN_EXTENSION.test(target.path)) continue;

    const outputPath = sourceToOutput.get(target.path.toLowerCase());
    if (!outputPath) continue;

    sections.get(currentSection).push({
      label,
      sourcePath: target.path,
      href: toGithubWikiPageHref(outputPath),
    });
  }

  return sections;
};

const buildLanguageGroups = ({ markdownFiles, rootSections, sourceToOutput }) => {
  const translations = rootSections.get('Translations') ?? [];
  const orderedLanguageCodes = translations
    .map(({ sourcePath }) => /^([^/]+)\/INDEX\.md$/i.exec(sourcePath)?.[1])
    .filter(Boolean);
  const languageCodes = orderedLanguageCodes.length > 0
    ? orderedLanguageCodes
    : markdownFiles
      .map((sourcePath) => /^([^/]+)\/INDEX\.md$/i.exec(sourcePath)?.[1])
      .filter(Boolean)
      .sort();

  return languageCodes.map((languageCode) => {
    const languagePrefix = `${languageCode}/`;
    const pages = markdownFiles
      .filter((sourcePath) => sourcePath.startsWith(languagePrefix))
      .map((sourcePath) => ({
        sourcePath,
        relativePath: sourcePath.slice(languagePrefix.length),
      }))
      .sort((left, right) => compareLanguagePages(left.relativePath, right.relativePath))
      .map(({ sourcePath, relativePath }) => ({
        label: formatLanguagePageLabel(relativePath),
        href: toGithubWikiPageHref(sourceToOutput.get(sourcePath.toLowerCase())),
      }));

    return {
      code: languageCode,
      pages,
    };
  });
};

const appendSidebarEntries = (lines, entries) => {
  for (const entry of entries) {
    lines.push(`- [${entry.label}](${entry.href})`);
  }
};

const buildSidebarContent = ({ rootIndexContent, markdownFiles, sourceToOutput }) => {
  const rootSections = extractLinkedSections({
    content: rootIndexContent,
    currentFilePath: 'INDEX.md',
    sourceToOutput,
  });
  const languageGroups = buildLanguageGroups({ markdownFiles, rootSections, sourceToOutput });
  const lines = [
    '# ClawSec Wiki',
    '',
    '- [Home](Home)',
    '',
  ];

  for (const sectionTitle of ROOT_SIDEBAR_SECTIONS) {
    const entries = rootSections.get(sectionTitle) ?? [];
    if (entries.length === 0) continue;
    lines.push(`## ${sectionTitle}`);
    appendSidebarEntries(lines, entries);
    lines.push('');
  }

  if (languageGroups.length > 0) {
    lines.push('## Translations');
    for (const group of languageGroups) {
      const homeHref = group.pages.find((page) => page.label === 'Home')?.href;
      lines.push(homeHref ? `- **[${group.code}](${homeHref})**` : `- **${group.code}**`);
      for (const page of group.pages.filter((entry) => entry.label !== 'Home')) {
        lines.push(`  - [${page.label}](${page.href})`);
      }
    }
    lines.push('');
  }

  return `${lines.join('\n').trimEnd()}\n`;
};

const rewriteMarkdownLinks = ({ content, sourcePath, sourceToOutput, assetPaths }) =>
  content.replace(MARKDOWN_LINK_PATTERN, (match, prefix, href, suffix) => {
    const target = resolveWikiLinkTarget(sourcePath, href);
    if (!target) return match;

    const targetKey = target.path.toLowerCase();
    if (MARKDOWN_EXTENSION.test(target.path)) {
      const outputPath = sourceToOutput.get(targetKey);
      return outputPath
        ? `${prefix}${toGithubWikiPageHref(outputPath)}${target.hash}${suffix}`
        : match;
    }

    const outputPath = assetPaths.has(targetKey) ? target.path : null;
    if (!outputPath) return match;

    return `${prefix}${outputPath}${target.hash}${suffix}`;
  });

/**
 * Build the flattened markdown tree that GitHub Wiki can display without
 * duplicate basename entries.
 *
 * @param {{ sourceDir: string, outputDir: string }} options
 * @returns {Promise<{ files: Array<{ sourcePath: string, outputPath: string }>, sidebar: string, assets: string[] }>}
 */
export const buildGithubWikiExport = async ({ sourceDir, outputDir }) => {
  if (!sourceDir) throw new Error('sourceDir is required');
  if (!outputDir) throw new Error('outputDir is required');

  const files = await listFiles(sourceDir);
  const markdownFiles = files.filter((file) => MARKDOWN_EXTENSION.test(file));
  const assetFiles = files.filter((file) => !MARKDOWN_EXTENSION.test(file));
  const sourceToOutput = buildMarkdownPathMap(markdownFiles);
  const assetPaths = new Set(assetFiles.map((file) => file.toLowerCase()));

  await rm(outputDir, { recursive: true, force: true });
  await mkdir(outputDir, { recursive: true });

  const exportedFiles = [];
  for (const sourcePath of markdownFiles) {
    const outputPath = sourceToOutput.get(sourcePath.toLowerCase());
    const sourceFullPath = path.join(sourceDir, sourcePath);
    const outputFullPath = path.join(outputDir, outputPath);
    const content = await readFile(sourceFullPath, 'utf8');

    await mkdir(path.dirname(outputFullPath), { recursive: true });
    await writeFile(
      outputFullPath,
      rewriteMarkdownLinks({ content, sourcePath, sourceToOutput, assetPaths }),
      'utf8',
    );
    exportedFiles.push({ sourcePath, outputPath });
  }

  const rootIndexPath = path.join(sourceDir, 'INDEX.md');
  const rootIndexContent = await readFile(rootIndexPath, 'utf8');
  await writeFile(
    path.join(outputDir, SIDEBAR_OUTPUT_PATH),
    buildSidebarContent({ rootIndexContent, markdownFiles, sourceToOutput }),
    'utf8',
  );

  for (const sourcePath of assetFiles) {
    const sourceFullPath = path.join(sourceDir, sourcePath);
    const outputFullPath = path.join(outputDir, sourcePath);
    await mkdir(path.dirname(outputFullPath), { recursive: true });
    await copyFile(sourceFullPath, outputFullPath);
  }

  return {
    files: exportedFiles,
    sidebar: SIDEBAR_OUTPUT_PATH,
    assets: assetFiles,
  };
};

const parseArgs = (argv) => {
  const options = {
    sourceDir: 'wiki',
    outputDir: '',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];

    if (arg === '--source') {
      options.sourceDir = next;
      i += 1;
    } else if (arg === '--output') {
      options.outputDir = next;
      i += 1;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!options.outputDir) {
    throw new Error('Usage: node scripts/build-github-wiki-export.mjs [--source wiki] --output <dir>');
  }

  return options;
};

const isDirectRun = () => {
  if (!process.argv[1]) return false;
  return fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
};

if (isDirectRun()) {
  const result = await buildGithubWikiExport(parseArgs(process.argv.slice(2)));
  console.log(
    `Exported ${result.files.length} wiki pages, ${result.sidebar}, and ${result.assets.length} assets.`,
  );
}
