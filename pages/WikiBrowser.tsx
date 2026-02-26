import React, { useMemo } from 'react';
import { BookOpenText, ExternalLink, FileText } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import Markdown from 'react-markdown';
import type { Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Footer } from '../components/Footer';
import { defaultMarkdownComponents } from '../utils/markdownComponents';
import {
  extractTitleFromMarkdown,
  fallbackTitleFromPath,
  stripFrontmatter,
} from '../utils/markdownHelpers.mjs';
import {
  isWikiIndexSlug,
  toWikiLlmsPath,
  toWikiRoute,
} from '../utils/wikiPathHelpers.mjs';

interface WikiDoc {
  filePath: string;
  slug: string;
  title: string;
  content: string;
}

const normalizePath = (path: string): string => {
  const clean = path.replace(/\\/g, '/');
  const parts: string[] = [];
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

const dirname = (path: string): string => {
  const idx = path.lastIndexOf('/');
  return idx === -1 ? '' : path.slice(0, idx);
};

const resolveFromFile = (currentFilePath: string, targetPath: string): string => {
  if (!targetPath) return currentFilePath;
  if (targetPath.startsWith('/')) return normalizePath(targetPath.slice(1));
  const baseDir = dirname(currentFilePath);
  const joined = baseDir ? `${baseDir}/${targetPath}` : targetPath;
  return normalizePath(joined);
};

const splitHash = (href: string): { path: string; hash: string } => {
  const idx = href.indexOf('#');
  if (idx === -1) return { path: href, hash: '' };
  return { path: href.slice(0, idx), hash: href.slice(idx) };
};

const toWikiRelativePath = (globPath: string): string =>
  globPath.replace(/^\.\.\/wiki\//, '').replace(/\\/g, '/');

const isExternalHref = (href: string): boolean =>
  /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(href) || href.startsWith('//');

const ALLOWED_LINK_SCHEMES = new Set(['http:', 'https:', 'mailto:', 'tel:']);
const ALLOWED_IMAGE_SCHEMES = new Set(['http:', 'https:']);

const sanitizeHref = (href: string): string | null => {
  const trimmed = href.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('//')) return null;

  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:)/);
  if (!schemeMatch) return trimmed;

  return ALLOWED_LINK_SCHEMES.has(schemeMatch[1].toLowerCase()) ? trimmed : null;
};

const sanitizeImageSrc = (src: string): string | null => {
  const trimmed = src.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('//')) return null;

  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:)/);
  if (!schemeMatch) return trimmed;

  return ALLOWED_IMAGE_SCHEMES.has(schemeMatch[1].toLowerCase()) ? trimmed : null;
};

const markdownModules = import.meta.glob('../wiki/**/*.md', {
  eager: true,
  query: '?raw',
  import: 'default',
}) as Record<string, string>;

const assetModules = import.meta.glob('../wiki/**/*.{png,jpg,jpeg,gif,svg,webp,avif}', {
  eager: true,
  import: 'default',
}) as Record<string, string>;

const wikiDocs: WikiDoc[] = Object.entries(markdownModules)
  .map(([globPath, content]) => {
    const filePath = toWikiRelativePath(globPath);
    return {
      filePath,
      slug: filePath.replace(/\.md$/i, ''),
      title: extractTitleFromMarkdown(content, filePath),
      content: stripFrontmatter(content).trim(),
    };
  })
  .sort((a, b) => {
    const aIndex = a.slug.toLowerCase() === 'index';
    const bIndex = b.slug.toLowerCase() === 'index';
    if (aIndex && !bIndex) return -1;
    if (!aIndex && bIndex) return 1;

    const aModule = a.filePath.startsWith('modules/');
    const bModule = b.filePath.startsWith('modules/');
    if (aModule !== bModule) return aModule ? 1 : -1;

    return a.title.localeCompare(b.title, 'en', { sensitivity: 'base' });
  });

const wikiDocBySlug = new Map<string, WikiDoc>(
  wikiDocs.map((doc) => [doc.slug.toLowerCase(), doc]),
);

const wikiDocByFilePath = new Map<string, WikiDoc>(
  wikiDocs.map((doc) => [doc.filePath.toLowerCase(), doc]),
);

const wikiAssetByPath = new Map<string, string>(
  Object.entries(assetModules).map(([globPath, assetUrl]) => [
    toWikiRelativePath(globPath).toLowerCase(),
    assetUrl,
  ]),
);

const defaultDoc = wikiDocBySlug.get('index') ?? wikiDocs[0] ?? null;

const toGroupName = (filePath: string): string => {
  if (!filePath.includes('/')) return 'Core';
  if (filePath.startsWith('modules/')) return 'Modules';
  const [firstSegment] = filePath.split('/');
  return fallbackTitleFromPath(firstSegment);
};

export const WikiBrowser: React.FC = () => {
  const params = useParams<{ '*': string }>();
  const wildcard = params['*'] ?? '';
  const normalizedWildcard = wildcard.replace(/^\/+|\/+$/g, '');
  let requested = '';
  let decodeFailed = false;
  try {
    requested = decodeURIComponent(normalizedWildcard);
  } catch (error) {
    decodeFailed = normalizedWildcard.length > 0;
    console.warn('Failed to decode wiki route segment', { wildcard, error });
    requested = '';
  }
  const requestedSlug = requested || 'INDEX';

  const selectedDoc = wikiDocBySlug.get(requestedSlug.toLowerCase()) ?? defaultDoc;
  const notFound =
    (decodeFailed && normalizedWildcard.length > 0) ||
    (requested.length > 0 && !wikiDocBySlug.has(requestedSlug.toLowerCase()));

  const groupedDocs = useMemo(() => {
    const map = new Map<string, WikiDoc[]>();
    for (const doc of wikiDocs) {
      const group = toGroupName(doc.filePath);
      const existing = map.get(group) ?? [];
      existing.push(doc);
      map.set(group, existing);
    }

    const preferredOrder = ['Core', 'Modules'];
    return Array.from(map.entries())
      .sort(([a], [b]) => {
        const idxA = preferredOrder.indexOf(a);
        const idxB = preferredOrder.indexOf(b);
        if (idxA !== -1 || idxB !== -1) {
          if (idxA === -1) return 1;
          if (idxB === -1) return -1;
          return idxA - idxB;
        }
        return a.localeCompare(b, 'en', { sensitivity: 'base' });
      })
      .map(([name, docs]) => ({
        name,
        docs: docs.sort((a, b) =>
          a.title.localeCompare(b.title, 'en', { sensitivity: 'base' }),
        ),
      }));
  }, []);

  if (!selectedDoc) {
    return (
      <div className="pt-[52px] py-20 text-center space-y-4">
        <BookOpenText className="w-12 h-12 text-gray-500 mx-auto" />
        <h1 className="text-2xl text-white">Wiki unavailable</h1>
        <p className="text-gray-400">No markdown files were found in the wiki source.</p>
      </div>
    );
  }

  const activeSlug = selectedDoc.slug.toLowerCase();
  const pageLlmsPath = toWikiLlmsPath(activeSlug);
  const showWikiLlmsIndexLink = !isWikiIndexSlug(activeSlug);

  const resolveWikiRouteFromHref = (href: string): string | null => {
    if (!href || isExternalHref(href) || href.startsWith('mailto:') || href.startsWith('tel:')) {
      return null;
    }
    const { path, hash } = splitHash(href);
    if (!path || !path.toLowerCase().endsWith('.md')) return null;

    const resolvedFilePath = resolveFromFile(selectedDoc.filePath, path).toLowerCase();
    const targetDoc = wikiDocByFilePath.get(resolvedFilePath);
    if (!targetDoc) return null;
    return `${toWikiRoute(targetDoc.slug)}${hash}`;
  };

  const resolveAssetUrl = (srcOrHref: string): string | null => {
    if (!srcOrHref || isExternalHref(srcOrHref) || srcOrHref.startsWith('/')) return null;
    const { path } = splitHash(srcOrHref);
    if (!path) return null;
    const resolvedAssetPath = resolveFromFile(selectedDoc.filePath, path).toLowerCase();
    return wikiAssetByPath.get(resolvedAssetPath) ?? null;
  };

  const wikiMarkdownComponents: Components = {
    ...defaultMarkdownComponents,
    a: ({ href, children }) => {
      if (!href) return <span className="text-gray-300">{children}</span>;

      const wikiRoute = resolveWikiRouteFromHref(href);
      if (wikiRoute) {
        return (
          <Link to={wikiRoute} className="text-clawd-accent hover:underline">
            {children}
          </Link>
        );
      }

      const assetHref = resolveAssetUrl(href);
      const finalHref = assetHref ?? href;
      const safeHref = sanitizeHref(finalHref);
      if (!safeHref) {
        return <span className="text-gray-300">{children}</span>;
      }
      const external = isExternalHref(safeHref);

      return (
        <a
          href={safeHref}
          target={external ? '_blank' : undefined}
          rel={external ? 'noopener noreferrer' : undefined}
          className="text-clawd-accent hover:underline"
        >
          {children}
        </a>
      );
    },
    img: ({ src, alt }) => {
      const resolvedSrc = src ? resolveAssetUrl(src) : null;
      const finalSrc = resolvedSrc ?? (src ? sanitizeImageSrc(src) : null);
      if (!finalSrc) {
        return <span className="text-gray-500 text-sm">[image blocked]</span>;
      }
      return (
        <img
          src={finalSrc}
          alt={alt ?? ''}
          className="max-w-full h-auto rounded-lg border border-clawd-700 bg-clawd-900/40 p-2 my-4"
          loading="lazy"
        />
      );
    },
  };

  return (
    <div className="pt-[52px] space-y-8">
      <section className="space-y-3">
        <h1 className="text-3xl md:text-4xl text-white flex items-center gap-3">
          <BookOpenText className="text-clawd-accent" />
          Wiki
        </h1>
        <p className="text-gray-400 max-w-3xl">
          Full repository wiki rendered from markdown in <code className="text-gray-300">wiki/</code>.
          This is the same source synced to GitHub Wiki.
        </p>
        <div className="flex flex-wrap gap-3">
          <a
            href={pageLlmsPath}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md bg-clawd-700 hover:bg-clawd-600 text-white text-sm transition-colors"
          >
            <FileText size={15} />
            Page llms.txt
          </a>
          {showWikiLlmsIndexLink && (
            <a
              href="/wiki/llms.txt"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md bg-clawd-800 border border-clawd-700 hover:border-clawd-accent text-white text-sm transition-colors"
            >
              <FileText size={15} />
              Wiki llms.txt Index
            </a>
          )}
          <a
            href="https://github.com/prompt-security/clawsec/wiki"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md border border-clawd-700 hover:border-clawd-accent text-gray-200 text-sm transition-colors"
          >
            <ExternalLink size={15} />
            GitHub Wiki
          </a>
        </div>
      </section>

      <div className="grid lg:grid-cols-[280px_minmax(0,1fr)] gap-6 items-start">
        <aside className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-4 lg:sticky lg:top-20 max-h-[calc(100vh-7rem)] overflow-auto">
          <div className="space-y-5">
            {groupedDocs.map((group) => (
              <section key={group.name} className="space-y-2">
                <h2 className="text-xs uppercase tracking-wide text-gray-400">{group.name}</h2>
                <div className="space-y-1">
                  {group.docs.map((doc) => {
                    const isActive = activeSlug === doc.slug.toLowerCase();
                    return (
                      <Link
                        key={doc.filePath}
                        to={toWikiRoute(doc.slug)}
                        className={`block px-3 py-2 rounded-md text-sm transition-colors ${
                          isActive
                            ? 'bg-white/10 text-white border border-white/10'
                            : 'text-gray-300 hover:text-white hover:bg-white/5'
                        }`}
                      >
                        {doc.title}
                      </Link>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>
        </aside>

        <section className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-4 sm:p-6 md:p-8 overflow-x-hidden">
          {notFound && (
            <div className="mb-6 p-3 rounded-md border border-orange-800 bg-orange-900/20 text-orange-200 text-sm">
              Wiki page not found for <code>{requested}</code>. Showing <strong>{selectedDoc.title}</strong> instead.
            </div>
          )}

          <Markdown
            remarkPlugins={[remarkGfm]}
            components={wikiMarkdownComponents}
          >
            {selectedDoc.content}
          </Markdown>
        </section>
      </div>

      <Footer />
    </div>
  );
};
