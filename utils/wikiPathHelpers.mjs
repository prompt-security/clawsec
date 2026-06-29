/**
 * Normalize a wiki-relative path without allowing it to escape above the wiki root.
 * @param {string} value
 * @returns {string}
 */
export const normalizeWikiPath = (value) => {
  const clean = String(value ?? '').replace(/\\/g, '/');
  const parts = [];
  for (const part of clean.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') {
      if (parts.length > 0) parts.pop();
      continue;
    }
    parts.push(part);
  }
  return parts.join('/');
};

/**
 * Return the directory portion of a wiki-relative path.
 * @param {string} value
 * @returns {string}
 */
const wikiDirname = (value) => {
  const normalized = normalizeWikiPath(value);
  const idx = normalized.lastIndexOf('/');
  return idx === -1 ? '' : normalized.slice(0, idx);
};

/**
 * Resolve a wiki-relative link from the file that contains it.
 * @param {string} currentFilePath
 * @param {string} targetPath
 * @returns {string}
 */
export const resolveWikiPathFromFile = (currentFilePath, targetPath) => {
  if (!targetPath) return normalizeWikiPath(currentFilePath);
  if (targetPath.startsWith('/')) return normalizeWikiPath(targetPath.slice(1));
  const baseDir = wikiDirname(currentFilePath);
  return normalizeWikiPath(baseDir ? `${baseDir}/${targetPath}` : targetPath);
};

/**
 * Split a URL/hash fragment from a wiki link target.
 * @param {string} value
 * @returns {{ path: string, hash: string }}
 */
export const splitWikiHash = (value) => {
  const text = String(value ?? '');
  const idx = text.indexOf('#');
  if (idx === -1) return { path: text, hash: '' };
  return { path: text.slice(0, idx), hash: text.slice(idx) };
};

/**
 * Return whether an href points outside the wiki/link resolver.
 * @param {string} href
 * @returns {boolean}
 */
export const isExternalHref = (href) =>
  /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(String(href ?? '')) || String(href ?? '').startsWith('//');

/**
 * Resolve an internal wiki link target from the file that contains it.
 * External URLs, root-absolute URLs, and same-page hash links return null.
 * @param {string} currentFilePath
 * @param {string} href
 * @returns {{ path: string, hash: string } | null}
 */
export const resolveWikiLinkTarget = (currentFilePath, href) => {
  const text = String(href ?? '');
  if (!text || isExternalHref(text) || text.startsWith('#') || text.startsWith('/')) {
    return null;
  }

  const { path, hash } = splitWikiHash(text);
  if (!path) return null;

  return {
    path: resolveWikiPathFromFile(currentFilePath, path),
    hash,
  };
};

/**
 * Normalize a wiki slug for route/path construction.
 * @param {string} slug
 * @returns {string}
 */
const normalizeWikiSlug = (slug) =>
  normalizeWikiPath(slug).replace(/^\/+|\/+$/g, '');

/**
 * Return whether a slug represents the wiki index page.
 * @param {string} slug
 * @returns {boolean}
 */
export const isWikiIndexSlug = (slug) => normalizeWikiSlug(slug).toLowerCase() === 'index';

/**
 * Convert a wiki slug to app route path.
 * @param {string} slug
 * @returns {string}
 */
export const toWikiRoute = (slug) => {
  const normalized = normalizeWikiSlug(slug);
  if (!normalized || isWikiIndexSlug(normalized)) return '/wiki';
  return `/wiki/${normalized}`;
};

/**
 * Convert a wiki slug to its llms.txt endpoint path.
 * @param {string} slug
 * @returns {string}
 */
export const toWikiLlmsPath = (slug) => {
  const normalized = normalizeWikiSlug(slug);
  if (!normalized || isWikiIndexSlug(normalized)) return '/wiki/llms.txt';
  return `/wiki/${normalized}/llms.txt`;
};
