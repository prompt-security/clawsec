export interface Skill {
  id: string;
  name: string;
  version: string;
  description: string;
  installCommand: string;
  hash: string;
  tags: string[];
}

export interface FeedItem {
  id: string;
  date: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
}

export type AdvisoryType =
  | 'malicious_skill'
  | 'vulnerable_skill'
  | 'prompt_injection'
  | 'attack_pattern'
  | 'best_practice'
  | 'tampering_attempt'
  // NVD CVE advisories use normalized weakness names (for example:
  // "missing_authentication_for_critical_function", "os_command_injection").
  // Keep this open for new categories without requiring type updates.
  | string;

export const CORE_PLATFORM_SLUGS = ['openclaw', 'nanoclaw', 'hermes', 'picoclaw'] as const;
export type CorePlatformSlug = (typeof CORE_PLATFORM_SLUGS)[number];
export type AdvisoryPlatformSlug = CorePlatformSlug | (string & {});
export type AdvisoryPlatformFilter = 'all' | CorePlatformSlug | 'other';

export type AdvisoryLifecycleStatus = 'active' | 'matured' | 'stale' | (string & {});

// Full advisory type from NVD CVE feed, provisional GHSA feed, or community reports
export interface Advisory {
  id: string;
  ghsa_id?: string;
  cve_id?: string | null;
  status?: AdvisoryLifecycleStatus;
  stale?: boolean;
  source_feed?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: AdvisoryType;
  title: string;
  description: string;
  affected?: string[];
  action: string;
  published: string;
  references?: string[];
  cvss_score?: number | null;
  cvss_vector?: string | null;
  nvd_url?: string;
  github_advisory_url?: string;
  platforms?: AdvisoryPlatformSlug[];
  // Community report fields (source defaults to "Prompt Security Staff" when absent)
  source?: string;
  github_issue_url?: string;
  reporter?: {
    agent_name?: string;
    opener_type?: 'human' | 'agent';
  };
}

export interface AdvisoryFeed {
  version: string;
  updated: string;
  description: string;
  advisories: Advisory[];
}

export interface NavItem {
  label: string;
  path: string;
  external?: boolean;
}

// Multi-skill distribution types

export interface SkillMetadata {
  id: string;
  name: string;
  version: string;
  description: string;
  emoji: string;
  category: string;
  platforms?: AdvisoryPlatformSlug[];
  tag: string;
}

export interface SkillsIndex {
  version: string;
  updated: string;
  skills: SkillMetadata[];
}

export interface SkillChecksums {
  skill: string;
  version: string;
  generated_at: string;
  repository: string;
  tag: string;
  files: Record<string, {
    sha256: string;
    size: number;
    path?: string;
    url: string;
  }>;
}

export interface SkillPlatformMetadata {
  emoji?: string;
  category?: string;
  feed_url?: string;
  requires?: {
    bins?: string[];
    [key: string]: unknown;
  };
  triggers?: string[];
  internal?: boolean;
  [key: string]: unknown;
}

export interface SkillJson {
  name: string;
  version: string;
  description: string;
  author: string;
  license: string;
  homepage: string;
  keywords: string[];
  sbom: {
    files: Array<{
      path: string;
      required: boolean;
      description: string;
    }>;
  };
  platforms?: AdvisoryPlatformSlug[];
  platform?: CorePlatformSlug | (string & {});
  openclaw?: SkillPlatformMetadata | null;
  hermes?: SkillPlatformMetadata | null;
  nanoclaw?: SkillPlatformMetadata | null;
  picoclaw?: SkillPlatformMetadata | null;
}
