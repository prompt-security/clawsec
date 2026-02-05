import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, ExternalLink, Shield, AlertTriangle, Github, User, Bot } from 'lucide-react';
import { Footer } from '../components/Footer';
import { Advisory, AdvisoryFeed } from '../types';
import { ADVISORY_FEED_URL, LOCAL_FEED_PATH } from '../constants';

export const AdvisoryDetail: React.FC = () => {
  const { advisoryId } = useParams<{ advisoryId: string }>();
  const [advisory, setAdvisory] = useState<Advisory | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchAdvisory = async () => {
      if (!advisoryId) return;

      try {
        // Try local feed first (for development), then fall back to GitHub releases
        let response = await fetch(LOCAL_FEED_PATH);

        if (!response.ok) {
          response = await fetch(ADVISORY_FEED_URL);
        }

        if (!response.ok) {
          throw new Error(`Failed to fetch feed: ${response.status}`);
        }

        const feed: AdvisoryFeed = await response.json();
        const found = feed.advisories.find((a) => a.id === decodeURIComponent(advisoryId));

        if (!found) {
          throw new Error('Advisory not found');
        }

        setAdvisory(found);
      } catch (err) {
        console.error('Failed to fetch advisory:', err);
        setError(err instanceof Error ? err.message : 'Failed to load advisory');
      } finally {
        setLoading(false);
      }
    };

    fetchAdvisory();
  }, [advisoryId]);

  const formatDate = (dateStr: string) => {
    try {
      return new Date(dateStr).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return dateStr;
    }
  };

  const getSeverityClasses = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case 'malicious_skill':
        return 'Malicious Skill';
      case 'vulnerable_skill':
        return 'Vulnerable Skill';
      case 'prompt_injection':
        return 'Prompt Injection';
      case 'attack_pattern':
        return 'Attack Pattern';
      case 'best_practice':
        return 'Best Practice';
      case 'tampering_attempt':
        return 'Tampering Attempt';
      default:
        return type;
    }
  };

  // Determine source - defaults to "Prompt Security Staff" when absent
  const getSource = (adv: Advisory) => {
    return adv.source || 'Prompt Security Staff';
  };

  // Determine if this is a community report
  const isCommunityReport = advisory?.github_issue_url;

  if (loading) {
    return (
      <div className="py-16 text-center">
        <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-clawd-accent"></div>
        <p className="mt-4 text-gray-400">Loading advisory...</p>
      </div>
    );
  }

  if (error || !advisory) {
    return (
      <div className="py-16 text-center">
        <Shield className="w-16 h-16 mx-auto text-gray-600 mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Advisory Not Found</h2>
        <p className="text-gray-400 mb-4">{error || 'This advisory does not exist'}</p>
        <Link to="/feed" className="text-clawd-accent hover:underline">
          Back to Security Feed
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto pt-8 space-y-8">
      {/* Back Link */}
      <Link
        to="/feed"
        className="inline-flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
      >
        <ArrowLeft size={20} />
        Back to Security Feed
      </Link>

      {/* Header */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <span className={`text-sm font-bold px-3 py-1.5 rounded uppercase border ${getSeverityClasses(advisory.severity)}`}>
            {advisory.severity}
            {advisory.cvss_score && <span className="ml-2 opacity-75">CVSS {advisory.cvss_score}</span>}
          </span>
          <span className="text-sm px-3 py-1.5 rounded bg-clawd-700 text-gray-300">
            {getTypeLabel(advisory.type)}
          </span>
          <span className="text-sm text-gray-500">
            Published {formatDate(advisory.published)}
          </span>
        </div>

        <h1 className="text-3xl font-bold text-white">{advisory.id}</h1>
        <p className="text-xl text-gray-300">{advisory.title}</p>
      </section>

      {/* Description */}
      <section className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-6">
        <h2 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
          <AlertTriangle size={20} className="text-orange-400" />
          Description
        </h2>
        <p className="text-gray-300 leading-relaxed whitespace-pre-wrap">{advisory.description}</p>
      </section>

      {/* Recommended Action */}
      <section className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-6">
        <h2 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
          <Shield size={20} className="text-green-400" />
          Recommended Action
        </h2>
        <p className="text-gray-300 leading-relaxed">{advisory.action}</p>
      </section>

      {/* Affected Components */}
      {advisory.affected && advisory.affected.length > 0 && (
        <section className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-6">
          <h2 className="text-lg font-bold text-white mb-3">Affected Components</h2>
          <ul className="list-disc list-inside space-y-1">
            {advisory.affected.map((item, index) => (
              <li key={index} className="text-gray-300">{item}</li>
            ))}
          </ul>
        </section>
      )}

      {/* References */}
      {advisory.references && advisory.references.length > 0 && (
        <section className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-6">
          <h2 className="text-lg font-bold text-white mb-3">References</h2>
          <ul className="space-y-2">
            {advisory.references.map((ref, index) => (
              <li key={index}>
                <a
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-clawd-accent hover:underline text-sm flex items-center gap-1 break-all"
                >
                  <ExternalLink size={14} className="flex-shrink-0" />
                  {ref}
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* External Link - NVD or GitHub Issue */}
      <section className="flex flex-wrap gap-4">
        {isCommunityReport && advisory.github_issue_url ? (
          <a
            href={advisory.github_issue_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-clawd-700 hover:bg-clawd-600 text-white font-medium transition-colors"
          >
            <Github size={18} />
            View GitHub Report
          </a>
        ) : advisory.nvd_url ? (
          <a
            href={advisory.nvd_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-clawd-700 hover:bg-clawd-600 text-white font-medium transition-colors"
          >
            <ExternalLink size={18} />
            View on NVD
          </a>
        ) : null}
      </section>

      {/* Metadata */}
      <section className="bg-clawd-800/50 border border-clawd-700 rounded-xl p-6">
        <h3 className="font-bold text-white mb-4">Metadata</h3>
        <dl className="grid md:grid-cols-2 gap-4 text-sm">
          <div className="flex justify-between md:block">
            <dt className="text-gray-500 mb-1">Source</dt>
            <dd className="text-white">{getSource(advisory)}</dd>
          </div>
          {advisory.cvss_score && (
            <div className="flex justify-between md:block">
              <dt className="text-gray-500 mb-1">CVSS Score</dt>
              <dd className="text-white">{advisory.cvss_score}</dd>
            </div>
          )}
          <div className="flex justify-between md:block">
            <dt className="text-gray-500 mb-1">Type</dt>
            <dd className="text-white">{getTypeLabel(advisory.type)}</dd>
          </div>
          <div className="flex justify-between md:block">
            <dt className="text-gray-500 mb-1">Published</dt>
            <dd className="text-white">{formatDate(advisory.published)}</dd>
          </div>
          {/* Reporter info - subtle display for community reports */}
          {advisory.reporter && (
            <>
              {advisory.reporter.agent_name && (
                <div className="flex justify-between md:block">
                  <dt className="text-gray-500 mb-1">Reported By</dt>
                  <dd className="text-white flex items-center gap-1">
                    {advisory.reporter.opener_type === 'agent' ? (
                      <Bot size={14} className="text-clawd-accent" />
                    ) : (
                      <User size={14} className="text-clawd-accent" />
                    )}
                    {advisory.reporter.agent_name}
                  </dd>
                </div>
              )}
              {advisory.reporter.opener_type && (
                <div className="flex justify-between md:block">
                  <dt className="text-gray-500 mb-1">Reporter Type</dt>
                  <dd className="text-white capitalize">{advisory.reporter.opener_type}</dd>
                </div>
              )}
            </>
          )}
        </dl>
      </section>

      <Footer />
    </div>
  );
};
