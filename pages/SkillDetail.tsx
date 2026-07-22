import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Copy, Check, Download, ExternalLink, FileText, Shield } from 'lucide-react';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Footer } from '../components/Footer';
import type {
  SkillChecksums,
  SkillDetailLoadResult,
  SkillLifecycleView,
} from '../types';
import { getPlatformDescriptor } from '../utils/advisoryPlatforms';
import { defaultMarkdownComponents } from '../utils/markdownComponents';
import { stripFrontmatter } from '../utils/markdownHelpers.mjs';
import { getRecommendedSkillPlatforms, resolveSkillPlatformMetadata } from '../utils/skillPlatforms';
import {
  getSkillLifecycleView,
  loadSkillDetailData,
} from '../utils/skillCatalogInstallability.mjs';

const RELEASE_REPO_URL = 'https://github.com/prompt-security/clawsec';
const isAbortError = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && 'name' in error && error.name === 'AbortError';

export const SkillDetail: React.FC = () => {
  const { skillId } = useParams<{ skillId: string }>();
  const [detail, setDetail] = useState<SkillDetailLoadResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    const fetchSkillData = async () => {
      setLoading(true);
      setDetail(null);
      setCopied(null);

      if (!skillId) {
        const view = getSkillLifecycleView('blocked') as SkillLifecycleView;
        setDetail({
          state: 'blocked',
          reason: 'The requested skill has no catalog identity.',
          record: null,
          skillData: null,
          checksums: null,
          doc: null,
          view,
        });
        setLoading(false);
        return;
      }

      try {
        const result = await loadSkillDetailData(fetch, skillId, {
          signal: controller.signal,
        }) as SkillDetailLoadResult;
        if (!active) return;

        setDetail({
          ...result,
          view: getSkillLifecycleView(result.state) as SkillLifecycleView,
        });
      } catch (err) {
        if (!active || isAbortError(err)) return;

        setDetail({
          state: 'blocked',
          reason: 'The verified catalog could not authorize this skill detail page.',
          record: null,
          skillData: null,
          checksums: null,
          doc: null,
          view: getSkillLifecycleView('blocked') as SkillLifecycleView,
        });
      } finally {
        if (active) setLoading(false);
      }
    };

    fetchSkillData();

    return () => {
      active = false;
      controller.abort();
    };
  }, [skillId]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  if (loading) {
    return (
      <div className="py-16 text-center">
        <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-clawd-accent"></div>
        <p className="mt-4 text-gray-400">Loading skill...</p>
      </div>
    );
  }

  if (!detail || detail.state === 'blocked') {
    return (
      <div className="py-16 text-center" role="status">
        <Shield className="w-16 h-16 mx-auto text-amber-300 mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Skill Details Unavailable</h2>
        <p className="text-gray-400 mb-4">
          {detail?.reason || 'The verified catalog did not authorize this skill detail page.'}
        </p>
        <Link to="/skills" className="text-clawd-accent hover:underline">
          Back to Skills Catalog
        </Link>
      </div>
    );
  }

  if (detail.state === 'historical') {
    if (
      !detail.record ||
      detail.record.id !== skillId ||
      !detail.view.historicalEvidence
    ) {
      return (
        <div className="py-16 text-center" role="status">
          <Shield className="w-16 h-16 mx-auto text-amber-300 mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Historical Record Unavailable</h2>
          <p className="text-gray-400 mb-4">The catalog record is missing required historical evidence.</p>
          <Link to="/skills" className="text-clawd-accent hover:underline">
            Back to Skills Catalog
          </Link>
        </div>
      );
    }

    const record = detail.record;
    const releaseEvidenceUrl = `${RELEASE_REPO_URL}/releases/tag/${encodeURIComponent(record.tag)}`;
    const checksumEvidenceUrl = `/skills/${encodeURIComponent(record.id)}/checksums.json`;

    return (
      <div className="pt-8 space-y-8">
        <Link
          to="/skills"
          className="inline-flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
        >
          <ArrowLeft size={20} />
          Back to Skills
        </Link>

        <section
          className="rounded-xl border border-amber-500/60 bg-amber-500/10 p-6 space-y-4"
          role="status"
        >
          <div className="flex items-start gap-4">
            <Shield className="mt-1 h-8 w-8 flex-none text-amber-300" />
            <div className="space-y-2">
              <p className="text-sm font-semibold uppercase tracking-wide text-amber-200">
                Historical — not installable
              </p>
              <h1 className="text-3xl font-bold text-white">{record.name}</h1>
              <p className="font-mono text-sm text-gray-400">v{record.version}</p>
              <p className="text-gray-300">{record.description}</p>
              <p className="text-sm text-amber-100">
                {detail.reason || 'This record is retained as historical evidence only. Installation and activation are disabled.'}
              </p>
            </div>
          </div>
        </section>

        <section className="space-y-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield size={20} />
            Historical evidence
          </h2>
          <p className="text-sm text-gray-400">
            These links document the retired release. They do not authorize installation, activation, or execution.
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            <a
              href={releaseEvidenceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-between gap-3 rounded-lg border border-clawd-700 bg-clawd-800 p-4 text-white hover:border-amber-500/60"
            >
              <span>GitHub release/tag</span>
              <ExternalLink size={16} className="text-amber-200" />
            </a>
            <a
              href={checksumEvidenceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-between gap-3 rounded-lg border border-clawd-700 bg-clawd-800 p-4 text-white hover:border-amber-500/60"
            >
              <span>Checksum manifest</span>
              <ExternalLink size={16} className="text-amber-200" />
            </a>
          </div>
        </section>

        <Footer />
      </div>
    );
  }

  const { record, skillData, checksums, doc, view } = detail;
  if (!record || record.id !== skillId || !skillData || !view.canInstall) {
    return (
      <div className="py-16 text-center" role="status">
        <Shield className="w-16 h-16 mx-auto text-amber-300 mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Installation Unavailable</h2>
        <p className="text-gray-400 mb-4">The verified catalog did not authorize an installation path.</p>
        <Link to="/skills" className="text-clawd-accent hover:underline">
          Back to Skills Catalog
        </Link>
      </div>
    );
  }

  const releaseTag = record.tag;
  const skillInstructionsUrl = `${RELEASE_REPO_URL}/releases/download/${encodeURIComponent(releaseTag)}/SKILL.md`;
  const recommendedPlatforms = getRecommendedSkillPlatforms(skillData);
  const isOpenClawSkill = recommendedPlatforms.includes('openclaw');
  const installCommand = isOpenClawSkill
    ? `npx clawhub@latest install ${skillData.name}`
    : `curl -sLO ${skillInstructionsUrl}`;
  const installLabel = isOpenClawSkill ? 'Via ClawHub' : 'Via SKILL.md instructions';
  const installHelp = isOpenClawSkill
    ? 'Recommended for OpenClaw-compatible skills.'
    : 'Pull the published instruction file and follow the platform-specific setup steps.';
  const platformMetadata = resolveSkillPlatformMetadata(skillData);
  const triggers = Array.isArray(platformMetadata.triggers) ? platformMetadata.triggers : [];
  let releasePageUrl = `${RELEASE_REPO_URL}/releases/tag/${encodeURIComponent(releaseTag)}`;

  try {
    const url = new URL(skillData.homepage);
    if (url.hostname === 'github.com') {
      const [owner, repo] = url.pathname.split('/').filter(Boolean);
      if (owner && repo) {
        const repoBase = `${url.origin}/${owner}/${repo.replace(/\\.git$/, '')}`;
        releasePageUrl = `${repoBase}/releases/tag/${encodeURIComponent(releaseTag)}`;
      }
    }
  } catch {
    // Keep the canonical repository release URL.
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
          <span className="text-4xl">{platformMetadata?.emoji || '📦'}</span>
          <div>
            <h1 className="text-3xl font-bold text-white mb-1">{skillData.name}</h1>
            <div className="flex items-center gap-3 text-sm">
              <span className="text-gray-500 font-mono">v{skillData.version}</span>
              {view.showPlatforms && recommendedPlatforms.slice(0, 4).map((platform) => {
                const descriptor = getPlatformDescriptor(platform);

                return (
                  <span
                    key={platform}
                    className={`text-xs px-2 py-0.5 rounded-md ${descriptor.classes}`}
                  >
                    {descriptor.label}
                  </span>
                );
              })}
              {/* Category badge - hidden for now, uncomment when we have multiple categories
              <span className="text-gray-500 bg-clawd-800 px-2 py-0.5 rounded">
                {platformMetadata?.category || 'utility'}
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
      {view.canInstall && view.showCopyControls && (
        <section className="space-y-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Download size={20} />
            Quick Install
          </h2>
          <div>
            <p className="text-sm font-medium text-white">{installLabel}</p>
            <p className="text-sm text-gray-400">{installHelp}</p>
          </div>
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
      )}

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
      {view.showDocumentation && doc && (
        <section className="space-y-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <FileText size={20} />
            Documentation <span className="text-sm font-normal text-gray-500">({doc.filename})</span>
          </h2>
          <div className="skill-docs bg-clawd-800/50 border border-clawd-700 rounded-xl p-4 sm:p-6 md:p-8 overflow-x-hidden">
            <Markdown
              remarkPlugins={[remarkGfm]}
              components={defaultMarkdownComponents}
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
              <dd className="text-white">{platformMetadata?.category || 'utility'}</dd>
            </div>
          </dl>
        </div>

        {view.showTriggers && triggers.length > 0 && (
          <div className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-6 space-y-4">
            <h3 className="font-bold text-white">Trigger Phrases</h3>
            <div className="flex flex-wrap gap-2">
              {triggers.slice(0, 8).map((trigger) => (
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
