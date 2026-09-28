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

/**
 * Security-relevant infrastructure that can be affected independently of the
 * agent runtime it contains. Keep this separate from CORE_PLATFORM_SLUGS:
 * those values also drive skill installation and release metadata, while
 * these components are advisory targets only.
 */
export const INFRASTRUCTURE_COMPONENT_SLUGS = ['openshell', 'nemoclaw'] as const;
export type InfrastructureComponentSlug = (typeof INFRASTRUCTURE_COMPONENT_SLUGS)[number];

export const PROTECTED_COMPONENT_SLUGS = [
  ...CORE_PLATFORM_SLUGS,
  ...INFRASTRUCTURE_COMPONENT_SLUGS,
] as const;
export type ProtectedComponentSlug = (typeof PROTECTED_COMPONENT_SLUGS)[number];
export type ProtectedComponentKind =
  | 'agent-runtime'
  | 'sandbox-runtime'
  | 'agent-stack'
  | 'skill-package';

// `platforms` is the legacy feed field name. It now identifies every protected
// component layer, not only top-level agent runtimes.
export type AdvisoryPlatformSlug = ProtectedComponentSlug | (string & {});
export type AdvisoryPlatformFilter = 'all' | ProtectedComponentSlug | 'other';
export type SkillPlatformFilter = 'all' | CorePlatformSlug | 'other';

export type AdvisoryLifecycleStatus = 'active' | 'matured' | 'stale' | (string & {});

// Full advisory type from NVD CVE feed, provisional GHSA feed, or community reports
export interface Advisory {
  id: string;
  ghsa_id?: string;
  ghsa_ids?: string[];
  cve_id?: string | null;
  aliases?: string[];
  status?: AdvisoryLifecycleStatus;
  stale?: boolean;
  source_feed?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: AdvisoryType;
  title: string;
  description: string;
  affected?: string[];
  patched?: string[];
  action: string;
  published: string;
  references?: string[];
  cvss_score?: number | null;
  cvss_vector?: string | null;
  ghsa_cvss_score?: number | null;
  ghsa_cvss_vector?: string | null;
  cwe_ids?: string[];
  credits?: string[];
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
