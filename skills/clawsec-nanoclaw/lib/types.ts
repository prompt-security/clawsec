/**
 * TypeScript types for NanoClaw Skill Installer
 * Adapted from ClawSec's guarded skill installer
 */

export interface Advisory {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: 'vulnerable_skill' | 'malicious_skill' | 'prompt_injection' | string;
  title: string;
  description: string;
  affected: string[]; // e.g., ["skill-name@1.0.0", "skill-name@1.0.1"]
  action: string;
  published: string;
  references: string[];
  cvss_score?: number;
  nvd_url?: string;
  source?: string;
  github_issue_url?: string;
  reporter?: {
    agent_name?: string;
    opener_type?: string;
  };
}

export interface AdvisoryFeed {
  version: string;
  updated: string;
  description: string;
  advisories: Advisory[];
}

export interface AdvisoryMatch {
  advisory: Advisory;
  matchedSpecifier: string;
  isHighRisk: boolean;
}

export interface ReputationResult {
  score: number; // 0-100
  warnings: string[];
  virusTotalFlags: string[];
  safe: boolean;
}

export interface SkillMetadata {
  slug: string;
  name: string;
  version: string;
  description: string;
  author: string;
  created: string;
  updated: string;
  downloads: number;
}

export interface InspectSkillResult {
  skill: SkillMetadata;
  reputation: ReputationResult;
  advisories: AdvisoryMatch[];
  overallStatus: 'safe' | 'reputation_warning' | 'advisory_warning' | 'blocked';
}

export interface SkillInstallRequest {
  request_id: string;
  user_jid: string;
  group_jid: string;
  skill_slug: string;
  skill_version: string | null;
  reputation_score: number;
  reputation_warnings: string[];
  advisories: AdvisoryMatch[];
  created_at: number; // Unix timestamp
  expires_at: number; // Unix timestamp
  status: 'pending' | 'confirmed' | 'expired' | 'cancelled';
  confirmed_at: number | null;
}

export interface ChecksumsManifest {
  schema_version: string;
  algorithm: 'sha256';
  files: Record<string, string>; // filename -> hex digest
}

export interface SignatureVerificationOptions {
  signatureUrl?: string;
  checksumsUrl?: string;
  checksumsSignatureUrl?: string;
  publicKeyPem: string;
  checksumsPublicKeyPem?: string;
  allowUnsigned?: boolean;
  verifyChecksumManifest?: boolean;
}

export interface AffectedSpecifier {
  name: string;
  versionSpec: string; // e.g., "1.0.0", "^1.0.0", "*"
}

// MCP Tool Request/Response Types

export interface InspectSkillRequest {
  slug: string;
  version?: string;
}

export interface RequestSkillInstallRequest {
  slug: string;
  version?: string;
  target_group_jid?: string;
}

export interface RequestSkillInstallResponse {
  request_id: string;
  status: 'safe' | 'reputation_warning' | 'advisory_warning' | 'blocked';
  reputation?: ReputationResult;
  advisories?: AdvisoryMatch[];
  message: string;
}

export interface ConfirmSkillInstallRequest {
  request_id: string;
  acknowledge_reputation?: boolean;
  acknowledge_advisories?: boolean;
}

export interface ConfirmSkillInstallResponse {
  status: 'installed' | 'failed';
  installed_path?: string;
  error?: string;
}

export interface ListSkillsRequest {
  target_group_jid?: string;
}

export interface ListSkillsResponse {
  skills: Array<{
    slug: string;
    version: string;
    installed_at: string;
    path: string;
  }>;
}

export interface RemoveSkillRequest {
  slug: string;
  target_group_jid?: string;
}

export interface RemoveSkillResponse {
  status: 'removed' | 'not_found';
  message: string;
}

// IPC Task Types

export interface IpcSkillInstallRequest {
  type: 'skill_install_request';
  slug: string;
  version?: string;
  target_group_jid?: string;
  user_jid: string;
  group_folder: string;
  timestamp: string;
}

export interface IpcSkillInstallConfirm {
  type: 'skill_install_confirm';
  request_id: string;
  acknowledge_reputation: boolean;
  acknowledge_advisories: boolean;
  user_jid: string;
  group_folder: string;
  timestamp: string;
}

export interface IpcSkillRemove {
  type: 'skill_remove';
  slug: string;
  target_group_jid?: string;
  user_jid: string;
  group_folder: string;
  timestamp: string;
}

// Database Schema

export interface SkillInstallRequestRow {
  request_id: string;
  user_jid: string;
  group_jid: string;
  skill_slug: string;
  skill_version: string | null;
  reputation_score: number;
  reputation_warnings_json: string; // JSON array
  advisories_json: string; // JSON array
  created_at: number;
  expires_at: number;
  status: 'pending' | 'confirmed' | 'expired' | 'cancelled';
  confirmed_at: number | null;
}

export interface InstalledSkillRow {
  slug: string;
  version: string;
  installed_at: string;
  installed_by: string; // user_jid
  path: string;
  metadata_json: string; // SkillMetadata as JSON
}

// Skill Signature Verification Types (Phase 1)

/**
 * IPC request for skill signature verification
 */
export interface VerifySkillSignatureRequest {
  type: 'verify_skill_signature';
  requestId: string;
  groupFolder: string;
  timestamp: string;
  packagePath: string;
  signaturePath: string;
  publicKeyPem?: string;      // Optional: override default public key
  allowUnsigned?: boolean;    // Optional: allow missing signature (default: false)
}

/**
 * IPC response for skill signature verification
 */
export interface VerifySkillSignatureResponse {
  success: boolean;
  message: string;
  data?: {
    valid: boolean;
    signer: string;            // 'clawsec' or custom signer identifier
    packageHash: string;       // SHA-256 of package
    verifiedAt: string;        // ISO timestamp
    algorithm: 'Ed25519';
  };
  error?: {
    code: 'SIGNATURE_INVALID' | 'FILE_NOT_FOUND' | 'CRYPTO_ERROR' | 'SERVICE_UNAVAILABLE';
    details?: unknown;
  };
}

/**
 * MCP tool parameters for package verification
 */
export interface VerifySkillPackageParams {
  packagePath: string;
  signaturePath?: string;     // Optional: auto-detects .sig if omitted
}
