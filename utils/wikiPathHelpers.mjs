/**
 * Normalize a wiki slug for route/path construction.
 * @param {string} slug
 * @returns {string}
 */
const normalizeWikiSlug = (slug) =>
  String(slug ?? '')
    .replace(/\\/g, '/')
    .replace(/^\/+|\/+$/g, '');

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
