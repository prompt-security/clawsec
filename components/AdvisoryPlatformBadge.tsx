import React from 'react';

interface PlatformDescriptor {
  label: string;
  classes: string;
}

const normalizePlatformSlug = (platform: string) => platform.trim().toLowerCase();

export const getPlatformDescriptor = (platform: string): PlatformDescriptor => {
  const normalized = normalizePlatformSlug(platform);

  switch (normalized) {
    case 'openclaw':
      return {
        label: 'OpenClaw',
        classes: 'bg-clawd-accent/20 text-clawd-accent border border-clawd-accent/40',
      };
    case 'nanoclaw':
      return {
        label: 'NanoClaw',
        classes: 'bg-clawd-secondary/20 text-clawd-secondary border border-clawd-secondary/40',
      };
    case 'hermes':
      return {
        label: 'Hermes',
        classes: 'bg-emerald-500/20 text-emerald-300 border border-emerald-400/40',
      };
    default:
      return {
        label: platform.trim() || platform,
        classes: 'bg-clawd-700 text-gray-300 border border-clawd-600',
      };
  }
};

interface AdvisoryPlatformBadgeProps {
  platform: string;
  className?: string;
}

export const AdvisoryPlatformBadge: React.FC<AdvisoryPlatformBadgeProps> = ({
  platform,
  className,
}) => {
  const { label, classes } = getPlatformDescriptor(platform);
  const badgeClasses = ['uppercase tracking-wide', classes, className]
    .filter(Boolean)
    .join(' ');

  return <span className={badgeClasses}>{label}</span>;
};
