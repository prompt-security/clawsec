const FRONTMATTER_REGEX = /^---\s*\n[\s\S]*?\n---\s*\n/;

/**
 * Remove a leading YAML frontmatter block from markdown content.
 * @param {string} content
 * @returns {string}
 */
export const stripFrontmatter = (content) =>
  String(content ?? '').replace(FRONTMATTER_REGEX, '');

/**
 * Build a readable fallback title from a markdown file path.
 * @param {string} filePath
 * @returns {string}
 */
export const fallbackTitleFromPath = (filePath) => {
  const normalized = String(filePath ?? '');
  const filename = normalized.split('/').pop() ?? normalized;
  const stem = filename.replace(/\.md$/i, '');
  return stem
    .split(/[-_]/)
    .filter(Boolean)
    .map((part) => {
      if (part.toUpperCase() === part && part.length > 1) return part;
      return part.charAt(0).toUpperCase() + part.slice(1);
    })
    .join(' ');
};

/**
 * Extract the first H1 title from markdown; fall back to path-derived title.
 * @param {string} content
 * @param {string} filePath
 * @returns {string}
 */
export const extractTitleFromMarkdown = (content, filePath) => {
  const cleaned = stripFrontmatter(content).trim();
  const match = cleaned.match(/^#\s+(.+)$/m);
  return match?.[1]?.trim() || fallbackTitleFromPath(filePath);
};
