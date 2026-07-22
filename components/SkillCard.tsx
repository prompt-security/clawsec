import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import type { SkillMetadata } from '../types';
import { getPlatformDescriptor } from '../utils/advisoryPlatforms';

interface SkillCardProps {
  skill: SkillMetadata;
}

export const SkillCard: React.FC<SkillCardProps> = ({ skill }) => {
  const isInstallable = skill.installable !== false;
  const platforms = isInstallable && Array.isArray(skill.platforms) ? skill.platforms.slice(0, 4) : [];

  return (
    <Link
      to={`/skills/${encodeURIComponent(skill.id)}`}
      className={`group block bg-clawd-800 border rounded-lg p-5 hover:bg-clawd-800/80 transition-all duration-200 ${
        isInstallable
          ? 'border-clawd-700 hover:border-clawd-accent/30'
          : 'border-amber-500/50 hover:border-amber-400/70'
      }`}
    >
      <div className="flex items-center gap-3 mb-3">
        <span className="text-2xl">{isInstallable ? skill.emoji || '📦' : '📦'}</span>
        <div className="min-w-0">
          <h3 className="font-bold text-white group-hover:text-clawd-accent transition-colors">
            {skill.name}
          </h3>
          <span className="text-xs text-gray-500 font-mono">v{skill.version}</span>
        </div>
      </div>

      {!isInstallable && (
        <div
          className="mb-3 inline-flex rounded-md border border-amber-500/50 bg-amber-500/10 px-2.5 py-1 text-xs font-semibold text-amber-200"
          role="status"
        >
          Historical — not installable
        </div>
      )}

      <p className="text-sm text-gray-400 mb-4 line-clamp-2">
        {skill.description}
      </p>

      {platforms.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-4" aria-label="Recommended platforms">
          {platforms.map((platform) => {
            const descriptor = getPlatformDescriptor(platform);

            return (
              <span
                key={platform}
                className={`text-[11px] leading-none px-2 py-1 rounded-md ${descriptor.classes}`}
              >
                {descriptor.label}
              </span>
            );
          })}
        </div>
      )}

      <div className="flex items-center justify-between">
        {/* Category badge - hidden for now, uncomment when we have multiple categories
        <span className="text-xs text-gray-500 bg-clawd-700 px-2 py-1 rounded">
          {skill.category || 'utility'}
        </span>
        */}
        <span
          className={`text-sm flex items-center gap-1 transition-opacity ml-auto ${
            isInstallable
              ? 'text-clawd-accent opacity-0 group-hover:opacity-100'
              : 'text-amber-200 opacity-100'
          }`}
        >
          {isInstallable ? 'View details' : 'View historical details'} <ArrowRight size={14} />
        </span>
      </div>
    </Link>
  );
};
