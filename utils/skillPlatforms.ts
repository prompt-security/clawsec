import {
  CORE_PLATFORM_SLUGS,
  type AdvisoryPlatformSlug,
  type CorePlatformSlug,
  type SkillJson,
  type SkillPlatformMetadata,
} from '../types';

export const SKILL_PLATFORM_METADATA_KEYS = CORE_PLATFORM_SLUGS;

const normalizePlatformSlug = (platform: string) => platform.trim().toLowerCase();

export const isSkillPlatformMetadataObject = (value: unknown): value is SkillPlatformMetadata => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const maybe = value as Record<string, unknown>;
  return 'emoji' in maybe || 'category' in maybe || 'triggers' in maybe;
};

export const getRecommendedSkillPlatforms = (skill: SkillJson): AdvisoryPlatformSlug[] => {
  const platforms = new Set<string>();

  if (Array.isArray(skill.platforms)) {
    for (const platform of skill.platforms) {
      if (typeof platform === 'string' && platform.trim()) {
        platforms.add(normalizePlatformSlug(platform));
      }
    }
  }

  if (typeof skill.platform === 'string' && skill.platform.trim()) {
    platforms.add(normalizePlatformSlug(skill.platform));
  }

  for (const key of SKILL_PLATFORM_METADATA_KEYS) {
    if (isSkillPlatformMetadataObject(skill[key])) {
      platforms.add(key);
    }
  }

  return [...platforms] as AdvisoryPlatformSlug[];
};

export const resolveSkillPlatformMetadata = (skill: SkillJson): SkillPlatformMetadata => {
  for (const platform of getRecommendedSkillPlatforms(skill)) {
    if ((SKILL_PLATFORM_METADATA_KEYS as readonly string[]).includes(platform)) {
      const platformBlock = skill[platform as CorePlatformSlug];
      if (isSkillPlatformMetadataObject(platformBlock)) return platformBlock;
    }
  }

  for (const key of SKILL_PLATFORM_METADATA_KEYS) {
    const fallbackBlock = skill[key];
    if (isSkillPlatformMetadataObject(fallbackBlock)) return fallbackBlock;
  }

  return {};
};
