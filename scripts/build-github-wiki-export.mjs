import { copyFile, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MARKDOWN_EXTENSION = /\.md$/i;
const MARKDOWN_LINK_PATTERN = /(\]\()([^)\s]+\.md(?:#[^)]+)?)(\))/g;
const EXTERNAL_HREF_PATTERN = /^[a-zA-Z][a-zA-Z0-9+.-]*:|^\/\//;

const toPosixPath = (value) => String(value ?? '').replace(/\\/g, '/');

const normalizeRelativePath = (value) => path.posix.normalize(toPosixPath(value)).replace(/^\.\//, '');

const splitHash = (value) => {
  const hashIndex = value.indexOf('#');
  if (hashIndex === -1) return { pathname: value, hash: '' };
  return {
    pathname: value.slice(0, hashIndex),
    hash: value.slice(hashIndex),
  };
};

const listFiles = async (rootDir) => {
  const files = [];

  const walk = async (relativeDir = '') => {
    const absoluteDir = path.join(rootDir, relativeDir);
    const entries = await readdir(absoluteDir, { withFileTypes: true });
    for (const entry of entries) {
      const relativePath = relativeDir
        ? path.posix.join(toPosixPath(relativeDir), entry.name)
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

const resolveMarkdownTarget = (sourcePath, href) => {
  if (!href || EXTERNAL_HREF_PATTERN.test(href) || href.startsWith('#') || href.startsWith('/')) {
    return null;
  }

  const { pathname, hash } = splitHash(href);
  if (!MARKDOWN_EXTENSION.test(pathname)) return null;

  const sourceDir = path.posix.dirname(sourcePath);
  const resolvedPath = normalizeRelativePath(
    sourceDir === '.' ? pathname : path.posix.join(sourceDir, pathname),
  );

  return {
    sourcePath: resolvedPath,
    hash,
  };
};

const rewriteMarkdownLinks = ({ content, sourcePath, sourceToOutput }) =>
  content.replace(MARKDOWN_LINK_PATTERN, (match, prefix, href, suffix) => {
    const target = resolveMarkdownTarget(sourcePath, href);
    if (!target) return match;

    const outputPath = sourceToOutput.get(target.sourcePath.toLowerCase());
    if (!outputPath) return match;

    return `${prefix}${outputPath}${target.hash}${suffix}`;
  });

/**
 * Build the flattened markdown tree that GitHub Wiki can display without
 * duplicate basename entries.
 *
 * @param {{ sourceDir: string, outputDir: string }} options
 * @returns {Promise<{ files: Array<{ sourcePath: string, outputPath: string }>, assets: string[] }>}
 */
export const buildGithubWikiExport = async ({ sourceDir, outputDir }) => {
  if (!sourceDir) throw new Error('sourceDir is required');
  if (!outputDir) throw new Error('outputDir is required');

  const files = await listFiles(sourceDir);
  const markdownFiles = files.filter((file) => MARKDOWN_EXTENSION.test(file));
  const assetFiles = files.filter((file) => !MARKDOWN_EXTENSION.test(file));
  const sourceToOutput = buildMarkdownPathMap(markdownFiles);

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
      rewriteMarkdownLinks({ content, sourcePath, sourceToOutput }),
      'utf8',
    );
    exportedFiles.push({ sourcePath, outputPath });
  }

  for (const sourcePath of assetFiles) {
    const sourceFullPath = path.join(sourceDir, sourcePath);
    const outputFullPath = path.join(outputDir, sourcePath);
    await mkdir(path.dirname(outputFullPath), { recursive: true });
    await copyFile(sourceFullPath, outputFullPath);
  }

  return {
    files: exportedFiles,
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
  console.log(`Exported ${result.files.length} wiki pages and ${result.assets.length} assets.`);
}
