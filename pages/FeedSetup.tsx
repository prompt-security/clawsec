import React, { useState, useEffect } from 'react';
import { Rss, RefreshCw, Loader2, AlertTriangle, ChevronLeft, ChevronRight, Download, Users, AlertCircle } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Footer } from '../components/Footer';
import { AdvisoryCard } from '../components/AdvisoryCard';
import { Advisory, AdvisoryFeed } from '../types';
import {
  ADVISORY_FEED_URL,
  LEGACY_ADVISORY_FEED_URL,
  LOCAL_FEED_PATH,
} from '../constants';

const ITEMS_PER_PAGE = 9;

const SEVERITY_TABS = [
  { value: 'all',      label: 'All',      active: 'bg-clawd-accent text-white',                                    inactive: 'bg-clawd-800 text-gray-400 border border-clawd-700 hover:border-clawd-accent/50' },
  { value: 'critical', label: 'Critical', active: 'bg-red-500/20 text-red-400 border-2 border-red-400',            inactive: 'bg-clawd-800 text-gray-400 border border-clawd-700 hover:border-red-400/50' },
  { value: 'high',     label: 'High',     active: 'bg-orange-500/20 text-orange-400 border-2 border-orange-400',   inactive: 'bg-clawd-800 text-gray-400 border border-clawd-700 hover:border-orange-400/50' },
  { value: 'medium',   label: 'Medium',   active: 'bg-yellow-500/20 text-yellow-400 border-2 border-yellow-400',   inactive: 'bg-clawd-800 text-gray-400 border border-clawd-700 hover:border-yellow-400/50' },
  { value: 'low',      label: 'Low',      active: 'bg-blue-500/20 text-blue-400 border-2 border-blue-400',         inactive: 'bg-clawd-800 text-gray-400 border border-clawd-700 hover:border-blue-400/50' },
] as const;

export const FeedSetup: React.FC = () => {
  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [filteredAdvisories, setFilteredAdvisories] = useState<Advisory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');

  useEffect(() => {
    const fetchAdvisories = async () => {
      setLoading(true);
      setError(null);

      try {
        // Try local feed first (dev), then canonical hosted endpoint, then legacy mirror.
        let response = await fetch(LOCAL_FEED_PATH);

        if (!response.ok) {
          response = await fetch(ADVISORY_FEED_URL);
        }

        if (!response.ok) {
          response = await fetch(LEGACY_ADVISORY_FEED_URL);
        }

        if (!response.ok) {
          throw new Error(`Failed to fetch feed: ${response.status}`);
        }

        const feed: AdvisoryFeed = await response.json();
        setAdvisories(feed.advisories || []);
        setFilteredAdvisories(feed.advisories || []);
        setLastUpdated(feed.updated);
      } catch (err) {
        console.error('Failed to fetch advisories:', err);
        setError('Unable to load security advisories. The feed may be temporarily unavailable.');
        setAdvisories([]);
        setFilteredAdvisories([]);
      } finally {
        setLoading(false);
      }
    };

    fetchAdvisories();
  }, []);

  useEffect(() => {
    let result = advisories;

    // Apply severity filter
    if (selectedSeverity !== 'all') {
      result = result.filter((advisory) => advisory.severity === selectedSeverity);
    }

    setFilteredAdvisories(result);
    // Reset to page 1 when filter changes
    setCurrentPage(1);
  }, [selectedSeverity, advisories]);

  const formatDate = (dateStr: string) => {
    try {
      return new Date(dateStr).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    } catch {
      return dateStr;
    }
  };

  // Pagination calculations
  const totalPages = Math.ceil(filteredAdvisories.length / ITEMS_PER_PAGE);
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  const endIndex = startIndex + ITEMS_PER_PAGE;
  const currentAdvisories = filteredAdvisories.slice(startIndex, endIndex);

  const goToPage = (page: number) => {
    setCurrentPage(Math.max(1, Math.min(page, totalPages)));
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="max-w-4xl mx-auto pt-[52px] space-y-12">
      <section className="text-center space-y-4">
        <h1 className="text-3xl md:text-4xl text-white">Security Hardening Feed</h1>
        <p className="text-gray-400 max-w-2xl mx-auto">
          A continuous stream of security advisories from NVD CVE data and staff-approved community reports. 
          This feed is automatically updated with OpenClaw and NanoClaw-related vulnerabilities and verified security incidents.
        </p>
        {lastUpdated && (
          <p className="text-xs text-gray-500">
            Last updated: {formatDate(lastUpdated)}
          </p>
        )}
      </section>

      <section>
        {/* Severity Filter Tabs */}
        <div className="flex flex-wrap justify-center gap-3 mb-8">
          {SEVERITY_TABS.map(({ value, label, active, inactive }) => (
            <button
              key={value}
              onClick={() => setSelectedSeverity(value)}
              className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
                selectedSeverity === value ? active : inactive
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 text-clawd-accent animate-spin" />
            <span className="ml-3 text-gray-400">Loading advisories...</span>
          </div>
        ) : error ? (
          <div className="flex items-center justify-center py-12 text-center">
            <AlertTriangle className="w-6 h-6 text-orange-400 mr-2" />
            <span className="text-gray-400">{error}</span>
          </div>
        ) : filteredAdvisories.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-gray-400">
              {advisories.length === 0
                ? 'No security advisories at this time. Check back later.'
                : 'No advisories found for the selected severity level.'}
            </p>
          </div>
        ) : (
          <>
            <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
              {currentAdvisories.map((item) => (
                <AdvisoryCard key={item.id} advisory={item} formatDate={formatDate} />
              ))}
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="flex items-center justify-center gap-4 mt-8">
                <button
                  onClick={() => goToPage(currentPage - 1)}
                  disabled={currentPage === 1}
                  className="flex items-center gap-1 px-4 py-2 rounded-lg bg-clawd-800 border border-clawd-700 text-white hover:border-clawd-accent disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:border-clawd-700 transition-colors"
                >
                  <ChevronLeft size={18} />
                  Previous
                </button>
                <span className="text-gray-400 text-sm">
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  onClick={() => goToPage(currentPage + 1)}
                  disabled={currentPage === totalPages}
                  className="flex items-center gap-1 px-4 py-2 rounded-lg bg-clawd-800 border border-clawd-700 text-white hover:border-clawd-accent disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:border-clawd-700 transition-colors"
                >
                  Next
                  <ChevronRight size={18} />
                </button>
              </div>
            )}

            {filteredAdvisories.length > 0 && (
              <p className="text-center text-sm text-gray-500 mt-4">
                Showing {startIndex + 1}-{Math.min(endIndex, filteredAdvisories.length)} of {filteredAdvisories.length} advisories
                {selectedSeverity !== 'all' && ` (${advisories.length} total)`}
              </p>
            )}
          </>
        )}
      </section>

      <section className="bg-clawd-900 border border-clawd-700 rounded-xl overflow-hidden">
        <div className="bg-clawd-800 px-6 py-4 border-b border-clawd-700 flex items-center justify-between">
          <h2 className="font-bold text-white flex items-center gap-2">
            <Rss size={18} className="text-clawd-accent" />
            Agent Integration Instructions
          </h2>
          <span className="text-xs font-mono text-gray-500">SKILLS-BASED</span>
        </div>
        <div className="p-6 space-y-6">
          <p className="text-gray-300 text-sm">
            Activate following skills from the suite to participate.
          </p>

          {/* clawsec-feed skill */}
          <Link
            to="/skills/clawsec-feed"
            className="flex items-start gap-4 p-4 rounded-lg bg-clawd-800/50 border border-clawd-700 hover:border-clawd-accent/50 transition-colors group"
          >
            <span className="text-2xl">📡</span>
            <div className="flex-1">
              <h4 className="text-white font-bold text-sm group-hover:text-clawd-accent transition-colors flex items-center gap-2">
                clawsec-feed
                <Download size={14} className="text-gray-500" />
              </h4>
              <p className="text-xs text-gray-400 mt-1">
                Subscribe your agent to receive security advisories via heartbeat. Automatically polls the feed and notifies you of critical and high severity threats.
              </p>
            </div>
          </Link>

          {/* clawtributor skill */}
          <Link
            to="/skills/clawtributor"
            className="flex items-start gap-4 p-4 rounded-lg bg-clawd-800/50 border border-clawd-700 hover:border-clawd-accent/50 transition-colors group"
          >
            <span className="text-2xl">🤝</span>
            <div className="flex-1">
              <h4 className="text-white font-bold text-sm group-hover:text-clawd-accent transition-colors flex items-center gap-2">
                clawtributor
                <Users size={14} className="text-gray-500" />
              </h4>
              <p className="text-xs text-gray-400 mt-1">
                Opt-in to community incident reporting. Your agent can automatically submit security reports when it detects malicious prompts or suspicious skill behavior.
              </p>
            </div>
          </Link>

          <div className="flex items-start gap-4 p-4 rounded-lg bg-blue-900/10 border border-blue-900/30">
            <RefreshCw className="text-blue-400 w-5 h-5 mt-1" />
            <div>
              <h4 className="text-blue-400 font-bold text-sm">Collective Security</h4>
              <p className="text-xs text-gray-400 mt-1">
                When agents share threat intelligence, the entire ecosystem becomes safer. Reports are reviewed by staff before publication to ensure quality and privacy.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="text-center pt-8 border-t border-clawd-700">
        <h3 className="text-white font-bold mb-4">Human looking to contribute</h3>
        <p className="text-gray-400 text-sm mb-6 max-w-xl mx-auto">
          Found a prompt injection vector or malicious skill? Help the community by submitting a security incident report via GitHub Issue.
          All submissions are reviewed by staff before publication to the advisory feed.
        </p>
        <a
          href="https://github.com/prompt-security/clawsec/issues/new?template=security_incident_report.md"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-clawd-700 hover:bg-clawd-600 text-white font-medium transition-colors"
        >
          <AlertCircle size={18} />
          Submit Report
        </a>
      </section>

      <Footer />
    </div>
  );
};
