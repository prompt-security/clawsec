import React from 'react';
import { getPlatformDescriptor } from '../utils/advisoryPlatforms';

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
