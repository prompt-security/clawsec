import React from 'react';
import { Link } from 'react-router-dom';
import { ExternalLink, Github } from 'lucide-react';
import { Advisory } from '../types';

interface AdvisoryCardProps {
  advisory: Advisory;
  formatDate: (dateStr: string) => string;
}

export const AdvisoryCard: React.FC<AdvisoryCardProps> = ({ advisory, formatDate }) => {
  const getSeverityClasses = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/20 text-red-400';
      case 'high':
        return 'bg-orange-500/20 text-orange-400';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400';
      default:
        return 'bg-blue-500/20 text-blue-400';
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

  const getPlatformLabel = (platform: string) => {
    switch (platform) {
      case 'openclaw':
        return 'OpenClaw';
      case 'nanoclaw':
        return 'NanoClaw';
      case 'hermes':
        return 'Hermes';
      default:
        return platform;
    }
  };

  const getPlatformClasses = (platform: string) => {
    switch (platform) {
      case 'openclaw':
        return 'bg-clawd-accent/20 text-clawd-accent border border-clawd-accent/40';
      case 'nanoclaw':
        return 'bg-clawd-secondary/20 text-clawd-secondary border border-clawd-secondary/40';
      case 'hermes':
        return 'bg-emerald-500/20 text-emerald-300 border border-emerald-400/40';
      default:
        return 'bg-clawd-700 text-gray-300 border border-clawd-600';
    }
  };

  // Determine if this is a community report (has github_issue_url) or NVD/staff advisory
  const isCommunityReport = !!advisory.github_issue_url;

  return (
    <Link
      to={`/feed/${encodeURIComponent(advisory.id)}`}
      className="block h-full bg-clawd-800 border border-clawd-700 rounded-xl p-5 hover:border-clawd-accent/30 transition-all group cursor-pointer"
    >
      <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-2 gap-y-2 mb-3">
        <div className="flex min-w-0 flex-wrap gap-2">
          <span className={`text-xs font-bold px-2 py-1 rounded uppercase ${getSeverityClasses(advisory.severity)}`}>
            {advisory.severity}
            {advisory.cvss_score && <span className="ml-1 opacity-75">({advisory.cvss_score})</span>}
          </span>
          <span className="text-xs px-2 py-1 rounded bg-clawd-700 text-gray-400 min-w-0 max-w-full truncate">
            {getTypeLabel(advisory.type)}
          </span>
        </div>
        <span className="text-xs text-gray-500 font-mono text-right whitespace-nowrap">{formatDate(advisory.published)}</span>
      </div>
      <h3 className="text-white font-bold mb-2 group-hover:text-clawd-accent transition-colors text-sm">
        {advisory.id}
      </h3>
      <p className="text-sm text-gray-400 line-clamp-3 mb-3">{advisory.title}</p>

      {advisory.platforms && advisory.platforms.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1.5">
          {advisory.platforms.map((platform) => (
            <span
              key={`${advisory.id}-${platform}`}
              className={`text-[11px] px-2 py-0.5 rounded uppercase tracking-wide ${getPlatformClasses(platform)}`}
            >
              {getPlatformLabel(platform)}
            </span>
          ))}
        </div>
      )}
      
      {/* External link - stop propagation to allow clicking without navigating to detail */}
      {isCommunityReport && advisory.github_issue_url ? (
        <span
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            window.open(advisory.github_issue_url, '_blank', 'noopener,noreferrer');
          }}
          className="inline-flex items-center gap-1 text-xs text-clawd-accent hover:underline cursor-pointer"
        >
          View GitHub Report <Github size={12} />
        </span>
      ) : advisory.nvd_url ? (
        <span
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            window.open(advisory.nvd_url, '_blank', 'noopener,noreferrer');
          }}
          className="inline-flex items-center gap-1 text-xs text-clawd-accent hover:underline cursor-pointer"
        >
          View on NVD <ExternalLink size={12} />
        </span>
      ) : null}
    </Link>
  );
};
