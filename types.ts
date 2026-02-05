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

// Full advisory type from NVD CVE feed or community reports
export interface Advisory {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: 'malicious_skill' | 'vulnerable_skill' | 'prompt_injection' | 'attack_pattern' | 'best_practice' | 'tampering_attempt';
  title: string;
  description: string;
  affected?: string[];
  action: string;
  published: string;
  references?: string[];
  cvss_score?: number | null;
  nvd_url?: string;
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
  openclaw: {
    emoji: string;
    category: string;
    feed_url?: string;
    requires?: {
      bins?: string[];
    };
    triggers: string[];
  };
}