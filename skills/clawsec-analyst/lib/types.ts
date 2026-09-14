/**
 * Type definitions for clawsec-analyst skill
 * Defines types for advisory feed, policies, and analysis results
 */

// Advisory Feed Types (based on advisories/feed.json schema)

export type Advisory = {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  nvd_category_id?: string;
  title: string;
  description: string;
  affected: string[];
  action: string;
  published: string;
  updated?: string;
  references?: string[];
  cvss_score?: number;
  nvd_url?: string;
  platforms?: string[];
  application?: string | string[];
};

export type FeedPayload = {
  version: string;
  updated: string;
  description?: string;
  advisories: Advisory[];
};

// Analysis Result Types

export type AdvisoryAnalysis = {
  advisoryId: string;
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  rationale: string;
  affected_components: string[];
  recommended_actions: string[];
  confidence: number; // 0.0 to 1.0
};

export type RiskAssessment = {
  skillName: string;
  riskScore: number; // 0-100
  severity: 'critical' | 'high' | 'medium' | 'low';
  findings: RiskFinding[];
  matchedAdvisories: AdvisoryMatch[];
  recommendation: 'approve' | 'review' | 'block';
  rationale: string;
};

export type RiskFinding = {
  category: 'filesystem' | 'network' | 'execution' | 'dependencies' | 'permissions';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  evidence: string;
};

export type AdvisoryMatch = {
  advisory: Advisory;
  matchedDependency: string;
  matchReason: string;
};

// Policy Types

export type PolicyParseResult = {
  policy: StructuredPolicy | null;
  confidence: number; // 0.0 to 1.0
  ambiguities: string[];
};

export type StructuredPolicy = {
  id: string;
  type: PolicyType;
  condition: PolicyCondition;
  action: PolicyAction;
  description: string;
  createdAt: string;
};

export type PolicyType =
  | 'advisory-severity'
  | 'filesystem-access'
  | 'network-access'
  | 'dependency-vulnerability'
  | 'risk-score'
  | 'custom';

export type PolicyCondition = {
  operator: 'equals' | 'contains' | 'greater_than' | 'less_than' | 'matches_regex';
  field: string;
  value: string | number | string[];
};

export type PolicyAction =
  | 'block'
  | 'warn'
  | 'require_approval'
  | 'log'
  | 'allow';

// State Management Types

export type AnalystState = {
  schema_version: string;
  last_feed_check: string | null;
  last_feed_updated: string | null;
  cached_analyses: Record<string, CachedAnalysis>;
  policies: StructuredPolicy[];
  analysis_history: AnalysisHistoryEntry[];
};

export type CachedAnalysis = {
  advisoryId: string;
  analysis: AdvisoryAnalysis;
  timestamp: string;
  cacheVersion: string;
};

export type AnalysisHistoryEntry = {
  timestamp: string;
  type: 'advisory_triage' | 'risk_assessment' | 'policy_parse';
  targetId: string;
  result: 'success' | 'error' | 'skipped';
  details?: string;
};

// Skill Metadata Types (for risk assessment)

export type SkillMetadata = {
  name: string;
  version: string;
  description?: string;
  author?: string;
  license?: string;
  files: string[];
  dependencies?: Record<string, string>;
  openclaw?: {
    emoji?: string;
    triggers?: string[];
    required_bins?: string[];
  };
};

// Hook Event Type (for OpenClaw integration)

export type HookEvent = {
  type?: string;
  action?: string;
  messages?: string[];
};

// Error Types

export type AnalystError = {
  code: string;
  message: string;
  details?: unknown;
  recoverable: boolean;
};

export type ErrorCode =
  | 'MISSING_API_KEY'
  | 'RATE_LIMIT_EXCEEDED'
  | 'NETWORK_FAILURE'
  | 'INVALID_ADVISORY_SCHEMA'
  | 'SIGNATURE_VERIFICATION_FAILED'
  | 'POLICY_AMBIGUOUS'
  | 'CACHE_READ_ERROR'
  | 'CLAUDE_API_ERROR';
