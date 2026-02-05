import React, { useState, useEffect, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Copy, Check, Download, ExternalLink, FileText, Shield } from 'lucide-react';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Footer } from '../components/Footer';
import type { SkillJson, SkillChecksums } from '../types';

// Strip YAML frontmatter from markdown content
const stripFrontmatter = (content: string): string => {
  const frontmatterRegex = /^---\s*\n[\s\S]*?\n---\s*\n/;
  return content.replace(frontmatterRegex, '');
};

export const SkillDetail: React.FC = () => {
  const { skillId } = useParams<{ skillId: string }>();
  const [skillData, setSkillData] = useState<SkillJson | null>(null);
  const [checksums, setChecksums] = useState<SkillChecksums | null>(null);
  const [doc, setDoc] = useState<{ filename: string; content: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    const fetchSkillData = async () => {
      if (!skillId) return;

      try {
        setDoc(null);

        // Fetch skill.json
        const skillResponse = await fetch(`./skills/${skillId}/skill.json`);
        if (!skillResponse.ok) {
          throw new Error('Skill not found');
        }
        const skill = await skillResponse.json();
        setSkillData(skill);

        // Fetch checksums.json
        try {
          const checksumsResponse = await fetch(`./skills/${skillId}/checksums.json`);
          if (checksumsResponse.ok) {
            const checksumsData = await checksumsResponse.json();
            setChecksums(checksumsData);
          }
        } catch {
          // Checksums not available
        }

        // Fetch documentation (README.md preferred, fallback to SKILL.md).
        // Note: Dev servers may fall back to serving index.html with 200 for missing files;
        // guard against accidentally rendering HTML as docs.
        try {
          const isProbablyHtmlDocument = (text: string) => {
            const start = text.trimStart().slice(0, 200).toLowerCase();
            return start.startsWith('<!doctype html') || start.startsWith('<html');
          };

          const stripYamlFrontmatter = (text: string) => {
            const match = text.match(/^---\\s*\\n[\\s\\S]*?\\n---\\s*\\n/);
            return match ? text.slice(match[0].length) : text;
          };

          const fetchDocFile = async (filename: string) => {
            const response = await fetch(`./skills/${skillId}/${filename}`, {
              headers: { Accept: 'text/plain' }
            });
            if (!response.ok) return null;

            const contentType = response.headers.get('content-type') ?? '';
            const rawText = await response.text();

            if (contentType.includes('text/html') || isProbablyHtmlDocument(rawText)) return null;

            const text =
              filename === 'SKILL.md' ? stripYamlFrontmatter(rawText).trim() : rawText.trim();

            return text.length > 0 ? text : null;
          };

          const candidates = ['README.md', 'SKILL.md'];
          for (const filename of candidates) {
            const content = await fetchDocFile(filename);
            if (content) {
              setDoc({ filename, content });
              break;
            }
          }
        } catch {
          // Documentation not available
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load skill');
      } finally {
        setLoading(false);
      }
    };

    fetchSkillData();
  }, [skillId]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const installCommand = skillData
    ? `curl -sLO https://clawsec.prompt.security/releases/download/${skillData.name}-v${skillData.version}/${skillData.name}.skill`
    : '';

  const releasePageUrl = useMemo(() => {
    if (!skillData) return '';

    try {
      const url = new URL(skillData.homepage);
      if (url.hostname === 'github.com') {
        const [owner, repo] = url.pathname.split('/').filter(Boolean);
        if (owner && repo) {
          const repoBase = `${url.origin}/${owner}/${repo.replace(/\\.git$/, '')}`;
          return `${repoBase}/releases/tag/${skillData.name}-v${skillData.version}`;
        }
      }
    } catch {
      // ignore invalid URLs
    }

    return skillData.homepage;
  }, [skillData]);

  if (loading) {
    return (
      <div className="py-16 text-center">
        <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-clawd-accent"></div>
        <p className="mt-4 text-gray-400">Loading skill...</p>
      </div>
    );
  }

  if (error || !skillData) {
    return (
      <div className="py-16 text-center">
        <Shield className="w-16 h-16 mx-auto text-gray-600 mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Skill Not Found</h2>
        <p className="text-gray-400 mb-4">{error || 'This skill does not exist'}</p>
        <Link to="/skills" className="text-clawd-accent hover:underline">
          Back to Skills Catalog
        </Link>
      </div>
    );
  }

  return (
    <div className="pt-8 space-y-8">
      {/* Back Link */}
      <Link
        to="/skills"
        className="inline-flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
      >
        <ArrowLeft size={20} />
        Back to Skills
      </Link>

      {/* Header */}
      <section className="flex flex-col md:flex-row md:items-start md:justify-between gap-6">
        <div className="flex items-start gap-4">
          <span className="text-4xl">{skillData.openclaw?.emoji || '📦'}</span>
          <div>
            <h1 className="text-3xl font-bold text-white mb-1">{skillData.name}</h1>
            <div className="flex items-center gap-3 text-sm">
              <span className="text-gray-500 font-mono">v{skillData.version}</span>
              {/* Category badge - hidden for now, uncomment when we have multiple categories
              <span className="text-gray-500 bg-clawd-800 px-2 py-0.5 rounded">
                {skillData.openclaw?.category || 'utility'}
              </span>
              */}
            </div>
          </div>
        </div>

        <div className="flex gap-3">
          <a
            href={releasePageUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-clawd-800 border border-clawd-700 rounded-lg text-white hover:border-clawd-accent transition-colors"
          >
            <ExternalLink size={16} />
            Release Page
          </a>
        </div>
      </section>

      {/* Description */}
      <section className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-6">
        <p className="text-gray-300 text-lg">{skillData.description}</p>
      </section>

      {/* Install Command */}
      <section className="space-y-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Download size={20} />
          Quick Install
        </h2>
        <div className="bg-clawd-800 rounded-lg p-3 sm:p-4 flex items-center justify-between gap-2 sm:gap-4">
          <code className="text-gray-200 font-mono text-xs sm:text-sm overflow-x-auto break-all min-w-0 flex-1">
            {installCommand}
          </code>
          <button
            onClick={() => handleCopy(installCommand, 'install')}
            className="flex-shrink-0 p-2 rounded-md bg-clawd-700 hover:bg-clawd-600 transition-colors"
            title="Copy to clipboard"
          >
            {copied === 'install' ? (
              <Check size={20} className="text-green-400" />
            ) : (
              <Copy size={20} className="text-gray-400" />
            )}
          </button>
        </div>
      </section>

      {/* Checksums */}
      {checksums && Object.keys(checksums.files).length > 0 && (
        <section className="space-y-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield size={20} />
            File Checksums
          </h2>
          <div className="bg-clawd-800/50 border border-clawd-700 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
            <table className="w-full min-w-[500px]">
              <thead>
                <tr className="border-b border-clawd-700">
                  <th className="text-left px-3 sm:px-4 py-3 text-gray-400 font-medium text-xs sm:text-sm">File</th>
                  <th className="text-left px-3 sm:px-4 py-3 text-gray-400 font-medium text-xs sm:text-sm">SHA256</th>
                  <th className="text-right px-3 sm:px-4 py-3 text-gray-400 font-medium text-xs sm:text-sm">Size</th>
                  <th className="px-3 sm:px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {(Object.entries(checksums.files) as Array<
                  [string, SkillChecksums['files'][string]]
                >).map(([filename, info]) => {
                  const displayPath = info.path ?? filename;

                  return (
                    <tr key={filename} className="border-b border-clawd-700/50 last:border-0">
                      <td className="px-3 sm:px-4 py-3 font-mono text-xs sm:text-sm">
                        {info.url ? (
                          <a
                            href={info.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-white hover:text-clawd-accent hover:underline"
                            title={info.url}
                          >
                            {displayPath}
                          </a>
                        ) : (
                          <span className="text-white">{displayPath}</span>
                        )}
                      </td>
                      <td className="px-3 sm:px-4 py-3 font-mono text-xs text-gray-400 truncate max-w-[120px] sm:max-w-[200px]">
                        {info.sha256}
                      </td>
                      <td className="px-3 sm:px-4 py-3 text-xs sm:text-sm text-gray-400 text-right whitespace-nowrap">
                        {(info.size / 1024).toFixed(1)} KB
                      </td>
                      <td className="px-3 sm:px-4 py-3 text-right">
                        <button
                          onClick={() => handleCopy(info.sha256, filename)}
                          className="p-1.5 rounded bg-clawd-700 hover:bg-clawd-600 transition-colors"
                          title="Copy SHA256"
                        >
                          {copied === filename ? (
                            <Check size={14} className="text-green-400" />
                          ) : (
                            <Copy size={14} className="text-gray-400" />
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            </div>
          </div>
        </section>
      )}

      {/* Documentation */}
      {doc && (
        <section className="space-y-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <FileText size={20} />
            Documentation <span className="text-sm font-normal text-gray-500">({doc.filename})</span>
          </h2>
          <div className="skill-docs bg-clawd-800/50 border border-clawd-700 rounded-xl p-4 sm:p-6 md:p-8 overflow-x-hidden">
            <Markdown
              remarkPlugins={[remarkGfm]}
              components={{
                h1: ({ children }) => (
                  <h1 className="text-2xl font-bold text-white border-b border-clawd-700 pb-3 mb-6 mt-0">
                    {children}
                  </h1>
                ),
                h2: ({ children }) => (
                  <h2 className="text-xl font-bold text-white mt-8 mb-4">{children}</h2>
                ),
                h3: ({ children }) => (
                  <h3 className="text-lg font-semibold text-white mt-6 mb-3">{children}</h3>
                ),
                h4: ({ children }) => (
                  <h4 className="text-base font-semibold text-white mt-4 mb-2">{children}</h4>
                ),
                p: ({ children }) => (
                  <p className="text-gray-300 leading-relaxed mb-4">{children}</p>
                ),
                a: ({ href, children }) => (
                  <a
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-clawd-accent hover:underline"
                  >
                    {children}
                  </a>
                ),
                ul: ({ children }) => (
                  <ul className="list-disc list-inside text-gray-300 space-y-2 mb-4 ml-4">
                    {children}
                  </ul>
                ),
                ol: ({ children }) => (
                  <ol className="list-decimal list-inside text-gray-300 space-y-2 mb-4 ml-4">
                    {children}
                  </ol>
                ),
                li: ({ children }) => (
                  <li className="text-gray-300">{children}</li>
                ),
                blockquote: ({ children }) => (
                  <blockquote className="border-l-4 border-clawd-accent pl-4 py-2 my-4 bg-clawd-900/50 rounded-r text-gray-400 italic">
                    {children}
                  </blockquote>
                ),
                code: ({ className, children }) => {
                  const isInline = !className;
                  if (isInline) {
                    return (
                      <code className="text-orange-300 bg-clawd-900 px-1.5 py-0.5 rounded text-sm font-mono">
                        {children}
                      </code>
                    );
                  }
                  return (
                    <code className="text-gray-200 text-sm font-mono">{children}</code>
                  );
                },
                pre: ({ children }) => (
                  <pre className="bg-clawd-900 border border-clawd-700 rounded-lg p-3 sm:p-4 overflow-x-auto mb-4 text-xs sm:text-sm max-w-full">
                    {children}
                  </pre>
                ),
                table: ({ children }) => (
                  <div className="overflow-x-auto mb-6 -mx-4 sm:mx-0 px-4 sm:px-0">
                    <table className="w-full border-collapse text-xs sm:text-sm min-w-[300px]">
                      {children}
                    </table>
                  </div>
                ),
                thead: ({ children }) => (
                  <thead className="bg-clawd-900 border-b border-clawd-600">
                    {children}
                  </thead>
                ),
                tbody: ({ children }) => <tbody>{children}</tbody>,
                tr: ({ children }) => (
                  <tr className="border-b border-clawd-700/50">{children}</tr>
                ),
                th: ({ children }) => (
                  <th className="text-left px-4 py-3 text-gray-300 font-semibold">
                    {children}
                  </th>
                ),
                td: ({ children }) => (
                  <td className="px-4 py-3 text-gray-300">{children}</td>
                ),
                hr: () => <hr className="border-clawd-700 my-6" />,
                strong: ({ children }) => (
                  <strong className="text-white font-semibold">{children}</strong>
                ),
                em: ({ children }) => (
                  <em className="text-gray-200">{children}</em>
                ),
              }}
            >
              {stripFrontmatter(doc.content)}
            </Markdown>
          </div>
        </section>
      )}

      {/* Metadata */}
      <section className="grid md:grid-cols-2 gap-6">
        <div className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-6 space-y-4">
          <h3 className="font-bold text-white">Metadata</h3>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between">
              <dt className="text-gray-500">Author</dt>
              <dd className="text-white">{skillData.author}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-gray-500">License</dt>
              <dd className="text-white">{skillData.license}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-gray-500">Category</dt>
              <dd className="text-white">{skillData.openclaw?.category}</dd>
            </div>
          </dl>
        </div>

        {skillData.openclaw?.triggers && skillData.openclaw.triggers.length > 0 && (
          <div className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-6 space-y-4">
            <h3 className="font-bold text-white">Trigger Phrases</h3>
            <div className="flex flex-wrap gap-2">
              {skillData.openclaw.triggers.slice(0, 8).map((trigger) => (
                <span
                  key={trigger}
                  className="text-xs bg-clawd-700 text-gray-300 px-2 py-1 rounded"
                >
                  "{trigger}"
                </span>
              ))}
            </div>
          </div>
        )}
      </section>

      <Footer />
    </div>
  );
};
