import { CORE_PLATFORM_SLUGS } from '../types';

export interface PlatformDescriptor {
  label: string;
  classes: string;
}

export const normalizePlatformSlug = (platform: string) => platform.trim().toLowerCase();

const PLATFORM_DESCRIPTOR_BY_SLUG: Record<string, PlatformDescriptor> = {
  openclaw: {
    label: 'OpenClaw',
    classes: 'bg-clawd-accent/20 text-clawd-accent border border-clawd-accent/40',
  },
  nanoclaw: {
    label: 'NanoClaw',
    classes: 'bg-clawd-secondary/20 text-clawd-secondary border border-clawd-secondary/40',
  },
  hermes: {
    label: 'Hermes',
    classes: 'bg-emerald-500/20 text-emerald-300 border border-emerald-400/40',
  },
};

const CORE_PLATFORM_SET = new Set<string>(CORE_PLATFORM_SLUGS);

export const isCorePlatformSlug = (platform: string) =>
  CORE_PLATFORM_SET.has(normalizePlatformSlug(platform));

export const getPlatformDescriptor = (platform: string): PlatformDescriptor => {
  const normalized = normalizePlatformSlug(platform);
  return PLATFORM_DESCRIPTOR_BY_SLUG[normalized] ?? {
    label: platform.trim() || platform,
    classes: 'bg-clawd-700 text-gray-300 border border-clawd-600',
  };
};
