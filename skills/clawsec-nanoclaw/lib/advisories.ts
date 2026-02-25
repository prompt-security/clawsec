/**
 * Advisory Feed Loading and Matching for NanoClaw
 * Ported from ClawSec's feed.mjs with fail-closed verification
 */

import fs from 'fs/promises';
import path from 'path';
import {
  Advisory,
  AdvisoryFeed,
  AdvisoryMatch,
  AffectedSpecifier,
  SignatureVerificationOptions,
} from './types.js';
import {
  verifySignedPayload,
  parseChecksumsManifest,
  verifyChecksums,
  fetchText,
  defaultChecksumsUrl,
  SecurityPolicyError,
} from './signatures.js';

const DEFAULT_FEED_URL = 'https://clawsec.prompt.security/advisories/feed.json';

/**
 * Validates that a payload is a valid advisory feed.
 */
export function isValidFeedPayload(raw: unknown): raw is AdvisoryFeed {
  if (typeof raw !== 'object' || raw === null) return false;
  const obj = raw as Record<string, unknown>;

  if (typeof obj.version !== 'string' || !obj.version.trim()) return false;
  if (!Array.isArray(obj.advisories)) return false;

  for (const advisory of obj.advisories) {
    if (typeof advisory !== 'object' || advisory === null) return false;
    const adv = advisory as Record<string, unknown>;

    if (typeof adv.id !== 'string' || !adv.id.trim()) return false;
    if (typeof adv.severity !== 'string' || !adv.severity.trim()) return false;
    if (!Array.isArray(adv.affected)) return false;
    if (!adv.affected.every((entry) => typeof entry === 'string' && entry.trim())) return false;
  }

  return true;
}

/**
 * Parses an affected specifier like "skill-name@version-spec".
 */
export function parseAffectedSpecifier(rawSpecifier: string): AffectedSpecifier | null {
  const specifier = rawSpecifier.trim();
  if (!specifier) return null;

  const atIndex = specifier.lastIndexOf('@');
  if (atIndex <= 0) {
    return { name: specifier, versionSpec: '*' };
  }

  return {
    name: specifier.slice(0, atIndex),
    versionSpec: specifier.slice(atIndex + 1),
  };
}

/**
 * Normalizes a skill name for comparison.
 */
export function normalizeSkillName(name: string): string {
  return name.toLowerCase().trim().replace(/[^a-z0-9-]/g, '');
}

/**
 * Checks if a version matches a version specifier.
 * Supports: exact match, semver range (^, ~, *), wildcards
 */
export function versionMatches(version: string, versionSpec: string): boolean {
  const v = version.trim();
  const spec = versionSpec.trim();

  // Wildcard matches everything
  if (spec === '*' || spec === '') return true;

  // Exact match
  if (v === spec) return true;

  // Parse semver components
  const parseVersion = (ver: string): number[] => {
    const match = ver.match(/^(\d+)\.(\d+)\.(\d+)/);
    if (!match) return [];
    return [parseInt(match[1], 10), parseInt(match[2], 10), parseInt(match[3], 10)];
  };

  const vParts = parseVersion(v);
  const specParts = parseVersion(spec.replace(/^[~^]/, ''));

  if (vParts.length === 0 || specParts.length === 0) return false;

  // Caret range (^1.2.3): compatible with 1.x.x where x >= 2.3
  if (spec.startsWith('^')) {
    if (vParts[0] !== specParts[0]) return false;
    if (vParts[0] === 0) {
      // ^0.2.3 means 0.2.x where x >= 3
      if (vParts[1] !== specParts[1]) return false;
      return vParts[2] >= specParts[2];
    }
    // ^1.2.3 means 1.x.x where x.x >= 2.3
    if (vParts[1] > specParts[1]) return true;
    if (vParts[1] < specParts[1]) return false;
    return vParts[2] >= specParts[2];
  }

  // Tilde range (~1.2.3): patch-level compatibility (1.2.x where x >= 3)
  if (spec.startsWith('~')) {
    if (vParts[0] !== specParts[0]) return false;
    if (vParts[1] !== specParts[1]) return false;
    return vParts[2] >= specParts[2];
  }

  return false;
}

/**
 * Loads advisory feed from a remote URL with signature verification.
 */
export async function loadRemoteFeed(
  feedUrl: string,
  options: SignatureVerificationOptions
): Promise<AdvisoryFeed | null> {
  const signatureUrl = options.signatureUrl || `${feedUrl}.sig`;
  const checksumsUrl = options.checksumsUrl || defaultChecksumsUrl(feedUrl);
  const checksumsSignatureUrl = options.checksumsSignatureUrl || `${checksumsUrl}.sig`;
  const publicKeyPem = options.publicKeyPem;
  const checksumsPublicKeyPem = options.checksumsPublicKeyPem || publicKeyPem;
  const allowUnsigned = options.allowUnsigned || false;
  const verifyChecksumManifest = options.verifyChecksumManifest !== false;

  try {
    const payloadRaw = await fetchText(feedUrl);
    if (!payloadRaw) return null;

    if (!allowUnsigned) {
      const signatureRaw = await fetchText(signatureUrl);
      if (!signatureRaw) return null;

      if (!verifySignedPayload(payloadRaw, signatureRaw, publicKeyPem)) {
        return null;
      }

      // Verify checksum manifest if available
      if (verifyChecksumManifest) {
        const checksumsRaw = await fetchText(checksumsUrl);
        const checksumsSignatureRaw = await fetchText(checksumsSignatureUrl);

        // Only proceed if BOTH checksum files are present
        if (checksumsRaw && checksumsSignatureRaw) {
          if (!verifySignedPayload(checksumsRaw, checksumsSignatureRaw, checksumsPublicKeyPem)) {
            return null; // Fail-closed: invalid signature
          }

          const checksumsManifest = parseChecksumsManifest(checksumsRaw);
          const checksumFeedEntry = feedUrl.split('/').pop() || 'feed.json';
          const checksumSignatureEntry = signatureUrl.split('/').pop() || 'feed.json.sig';
          verifyChecksums(checksumsManifest, {
            [checksumFeedEntry]: payloadRaw,
            [checksumSignatureEntry]: signatureRaw,
          });
        }
        // If checksum files missing: continue without checksum verification
        // (feed signature was already verified above)
      }
    }

    try {
      const payload = JSON.parse(payloadRaw);
      if (!isValidFeedPayload(payload)) return null;
      return payload;
    } catch {
      return null;
    }
  } catch (error) {
    // Security policy violations return null to allow graceful fallback to local feed
    if (error instanceof SecurityPolicyError) {
      return null;
    }
    // Re-throw unexpected errors
    throw error;
  }
}

/**
 * Loads advisory feed from a local file with signature verification.
 */
export async function loadLocalFeed(
  feedPath: string,
  options: SignatureVerificationOptions
): Promise<AdvisoryFeed> {
  const signaturePath = options.signatureUrl || `${feedPath}.sig`;
  const checksumsPath = options.checksumsUrl || path.join(path.dirname(feedPath), 'checksums.json');
  const checksumsSignaturePath = options.checksumsSignatureUrl || `${checksumsPath}.sig`;
  const publicKeyPem = options.publicKeyPem;
  const checksumsPublicKeyPem = options.checksumsPublicKeyPem || publicKeyPem;
  const allowUnsigned = options.allowUnsigned || false;
  const verifyChecksumManifest = options.verifyChecksumManifest !== false;

  const payloadRaw = await fs.readFile(feedPath, 'utf8');

  if (!allowUnsigned) {
    const signatureRaw = await fs.readFile(signaturePath, 'utf8');
    if (!verifySignedPayload(payloadRaw, signatureRaw, publicKeyPem)) {
      throw new Error(`Feed signature verification failed for local feed: ${feedPath}`);
    }

    if (verifyChecksumManifest) {
      const checksumsRaw = await fs.readFile(checksumsPath, 'utf8');
      const checksumsSignatureRaw = await fs.readFile(checksumsSignaturePath, 'utf8');

      if (!verifySignedPayload(checksumsRaw, checksumsSignatureRaw, checksumsPublicKeyPem)) {
        throw new Error(`Checksum manifest signature verification failed: ${checksumsPath}`);
      }

      const checksumsManifest = parseChecksumsManifest(checksumsRaw);
      const checksumFeedEntry = path.basename(feedPath);
      const checksumSignatureEntry = path.basename(signaturePath);
      verifyChecksums(checksumsManifest, {
        [checksumFeedEntry]: payloadRaw,
        [checksumSignatureEntry]: signatureRaw,
      });
    }
  }

  const payload = JSON.parse(payloadRaw);
  if (!isValidFeedPayload(payload)) {
    throw new Error(`Invalid advisory feed format: ${feedPath}`);
  }
  return payload;
}

/**
 * Loads advisory feed from remote or falls back to local.
 */
export async function loadFeed(
  feedUrl: string = DEFAULT_FEED_URL,
  localFeedPath: string,
  publicKeyPem: string,
  allowUnsigned: boolean = false
): Promise<{ feed: AdvisoryFeed; source: string }> {
  const options: SignatureVerificationOptions = {
    publicKeyPem,
    allowUnsigned,
    verifyChecksumManifest: true,
  };

  // Try remote feed first
  const remoteFeed = await loadRemoteFeed(feedUrl, options);
  if (remoteFeed) {
    return { feed: remoteFeed, source: `remote:${feedUrl}` };
  }

  // Fall back to local feed
  const localFeed = await loadLocalFeed(localFeedPath, options);
  return { feed: localFeed, source: `local:${localFeedPath}` };
}

/**
 * Checks if an advisory looks high-risk.
 */
export function advisoryLooksHighRisk(advisory: Advisory): boolean {
  const type = advisory.type.toLowerCase();
  const severity = advisory.severity.toLowerCase();
  const combined = `${advisory.title} ${advisory.description} ${advisory.action}`.toLowerCase();

  if (type === 'malicious_skill' || type === 'malicious_plugin') return true;
  if (severity === 'critical') return true;
  if (/\b(malicious|exfiltrate|exfiltration|backdoor|trojan|stealer|credential theft)\b/.test(combined)) return true;
  if (/\b(remove|uninstall|disable|do not use|quarantine)\b/.test(combined)) return true;

  return false;
}

/**
 * Finds advisory matches for a skill.
 */
export function findAdvisoryMatches(
  feed: AdvisoryFeed,
  skillName: string,
  version: string | null
): AdvisoryMatch[] {
  const matches: AdvisoryMatch[] = [];

  for (const advisory of feed.advisories) {
    const affected = advisory.affected || [];
    if (affected.length === 0) continue;

    for (const specifier of affected) {
      const parsed = parseAffectedSpecifier(specifier);
      if (!parsed) continue;

      if (normalizeSkillName(parsed.name) !== normalizeSkillName(skillName)) {
        continue;
      }

      // If version specified, check if it matches
      if (version && !versionMatches(version, parsed.versionSpec)) {
        continue;
      }

      // Match found
      matches.push({
        advisory,
        matchedSpecifier: specifier,
        isHighRisk: advisoryLooksHighRisk(advisory),
      });
      break; // Only count each advisory once
    }
  }

  return matches;
}

/**
 * Removes duplicate strings from an array.
 */
export function uniqueStrings(arr: string[]): string[] {
  return Array.from(new Set(arr));
}
