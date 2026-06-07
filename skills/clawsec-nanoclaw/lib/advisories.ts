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
  type ParsedVersion = {
    major: number;
    minor: number;
    patch: number;
    prerelease: string[];
  };

  const semverPattern = String.raw`v?\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?`;
  const semverRegex = new RegExp(
    String.raw`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`
  );

  const parseVersion = (ver: string): ParsedVersion | null => {
    const match = ver.match(semverRegex);
    if (!match) return null;

    return {
      major: parseInt(match[1], 10),
      minor: parseInt(match[2], 10),
      patch: parseInt(match[3], 10),
      prerelease: match[4] ? match[4].split('.') : [],
    };
  };

  const comparePrereleaseIdentifiers = (left: string, right: string): number => {
    const leftIsNumeric = /^\d+$/.test(left);
    const rightIsNumeric = /^\d+$/.test(right);

    if (leftIsNumeric && rightIsNumeric) {
      const leftValue = parseInt(left, 10);
      const rightValue = parseInt(right, 10);
      if (leftValue > rightValue) return 1;
      if (leftValue < rightValue) return -1;
      return 0;
    }

    if (leftIsNumeric) return -1;
    if (rightIsNumeric) return 1;
    if (left > right) return 1;
    if (left < right) return -1;
    return 0;
  };

  const compareVersions = (left: ParsedVersion, right: ParsedVersion): number => {
    if (left.major > right.major) return 1;
    if (left.major < right.major) return -1;
    if (left.minor > right.minor) return 1;
    if (left.minor < right.minor) return -1;
    if (left.patch > right.patch) return 1;
    if (left.patch < right.patch) return -1;

    if (left.prerelease.length === 0 && right.prerelease.length === 0) return 0;
    if (left.prerelease.length === 0) return 1;
    if (right.prerelease.length === 0) return -1;

    const identifierCount = Math.max(left.prerelease.length, right.prerelease.length);
    for (let index = 0; index < identifierCount; index += 1) {
      const leftIdentifier = left.prerelease[index];
      const rightIdentifier = right.prerelease[index];

      if (leftIdentifier === undefined) return -1;
      if (rightIdentifier === undefined) return 1;

      const comparison = comparePrereleaseIdentifiers(leftIdentifier, rightIdentifier);
      if (comparison !== 0) return comparison;
    }

    return 0;
  };

  const evaluateComparator = (comparator: string): boolean => {
    const match = comparator.trim().match(new RegExp(`^(<=|>=|<|>|=)?\\s*(${semverPattern})$`));
    if (!match) return false;

    const operator = match[1] || '=';
    const comparatorParts = parseVersion(match[2]);
    if (!comparatorParts) return false;

    const comparison = compareVersions(vParts, comparatorParts);
    if (operator === '<') return comparison < 0;
    if (operator === '<=') return comparison <= 0;
    if (operator === '>') return comparison > 0;
    if (operator === '>=') return comparison >= 0;
    return comparison === 0;
  };

  const extractComparatorTokens = (range: string): string[] | null => {
    const tokenPattern = new RegExp(`(?:<=|>=|<|>|=)?\\s*${semverPattern}`, 'g');
    const tokens: string[] = [];
    let cursor = 0;
    let match = tokenPattern.exec(range);

    while (match) {
      const gap = range.slice(cursor, match.index);
      if (!/^[\s,]*$/.test(gap)) return null;

      tokens.push(match[0].trim());
      cursor = match.index + match[0].length;
      match = tokenPattern.exec(range);
    }

    if (!/^[\s,]*$/.test(range.slice(cursor))) return null;
    return tokens.length > 0 ? tokens : null;
  };

  const vParts = parseVersion(v);
  if (!vParts) return true;

  if (/(?:<=|>=|<|>|=)/.test(spec)) {
    const comparatorTokens = extractComparatorTokens(spec);
    if (!comparatorTokens) return false;
    return comparatorTokens.every((token) => evaluateComparator(token));
  }

  const specParts = parseVersion(spec.replace(/^[~^]/, ''));
  if (!specParts) return true;

  // Caret range (^1.2.3): compatible with 1.x.x where x >= 2.3
  if (spec.startsWith('^')) {
    const upperBound =
      specParts.major > 0
        ? { major: specParts.major + 1, minor: 0, patch: 0, prerelease: [] }
        : specParts.minor > 0
          ? { major: 0, minor: specParts.minor + 1, patch: 0, prerelease: [] }
          : { major: 0, minor: 0, patch: specParts.patch + 1, prerelease: [] };

    return compareVersions(vParts, specParts) >= 0 && compareVersions(vParts, upperBound) < 0;
  }

  // Tilde range (~1.2.3): patch-level compatibility (1.2.x where x >= 3)
  if (spec.startsWith('~')) {
    const upperBound = { major: specParts.major, minor: specParts.minor + 1, patch: 0, prerelease: [] };
    return compareVersions(vParts, specParts) >= 0 && compareVersions(vParts, upperBound) < 0;
  }

  if (new RegExp(`^${semverPattern}$`).test(spec)) {
    return compareVersions(vParts, specParts) === 0;
  }

  return true;
}

/**
 * Checks whether an affected specifier matches a skill name/version.
 * Optionally matches against a skill directory name as alias.
 */
export function matchesAffectedSpecifier(
  affected: string,
  skillName: string,
  skillVersion: string | null,
  skillDirName?: string
): boolean {
  const parsed = parseAffectedSpecifier(affected);
  if (!parsed) return false;

  const normalizedTarget = normalizeSkillName(parsed.name);
  const normalizedSkillName = normalizeSkillName(skillName);
  const normalizedDirName = skillDirName ? normalizeSkillName(skillDirName) : null;

  if (normalizedTarget !== normalizedSkillName && normalizedTarget !== normalizedDirName) {
    return false;
  }

  if (!skillVersion) {
    return true;
  }

  return versionMatches(skillVersion, parsed.versionSpec);
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
  const exploitability = (advisory.exploitability_score || 'unknown').toLowerCase();
  const combined = `${advisory.title} ${advisory.description} ${advisory.action}`.toLowerCase();

  if (type.includes('malicious')) return true;
  if (severity === 'critical') return true;
  if (exploitability === 'high') return true;
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
      if (!matchesAffectedSpecifier(specifier, skillName, version)) {
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
