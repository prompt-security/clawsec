import { CORE_PLATFORM_SLUGS, type AdvisoryPlatformFilter } from '../types';

export interface PlatformDescriptor {
  label: string;
  classes: string;
}

export const normalizePlatformSlug = (platform: string) => platform.trim().toLowerCase();

const PLATFORM_DESCRIPTOR_BY_SLUG: Record<string, PlatformDescriptor> = {
  openclaw: {
    label: 'OpenClaw',
    classes: 'bg-clawd-800 text-clawd-accent border border-clawd-accent/40',
  },
  nanoclaw: {
    label: 'NanoClaw',
    classes: 'bg-clawd-800 text-clawd-500 border border-clawd-500/40',
  },
  hermes: {
    label: 'Hermes',
    classes: 'bg-clawd-800 text-emerald-300 border border-emerald-400/40',
  },
  picoclaw: {
    label: 'Picoclaw',
    classes: 'bg-clawd-800 text-cyan-300 border border-cyan-400/40',
  },
};

const CORE_PLATFORM_SET = new Set<string>(CORE_PLATFORM_SLUGS);

export const isCorePlatformSlug = (platform: string) =>
  CORE_PLATFORM_SET.has(normalizePlatformSlug(platform));

/**
 * Reads a `platforms` field off advisory or skill metadata. Both documents are
 * fetched at runtime, so the value is untrusted: anything that is not an array
 * of non-empty strings is read as "declares no platform".
 */
export const readPlatformSlugs = (platforms: unknown): string[] => {
  if (!Array.isArray(platforms)) return [];
  return platforms
    .filter((platform): platform is string => typeof platform === 'string')
    .map(normalizePlatformSlug)
    .filter(Boolean);
};

export const hasNonCorePlatform = (platforms: unknown) =>
  readPlatformSlugs(platforms).some((platform) => !isCorePlatformSlug(platform));

/**
 * Shared by the advisory feed and the skills catalog so the two filters cannot
 * drift. An entry naming no platform is treated as applying everywhere.
 */
export const matchesPlatformFilter = (
  platforms: unknown,
  filter: AdvisoryPlatformFilter,
): boolean => {
  if (filter === 'all') return true;
  if (filter === 'other') return hasNonCorePlatform(platforms);

  const slugs = readPlatformSlugs(platforms);
  return slugs.length === 0 || slugs.includes(filter);
};

export const getPlatformDescriptor = (platform: string): PlatformDescriptor => {
  const normalized = normalizePlatformSlug(platform);
  return PLATFORM_DESCRIPTOR_BY_SLUG[normalized] ?? {
    label: platform.trim() || platform,
    classes: 'bg-clawd-800 text-gray-300 border border-clawd-700',
  };
};
