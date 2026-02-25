/**
 * Ed25519 Signature Verification for NanoClaw
 * Ported from ClawSec's feed.mjs
 */

import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import { ChecksumsManifest } from './types.js';

/**
 * Allowed domains for feed/signature fetching.
 * Only connections to these domains are permitted for security.
 */
const ALLOWED_DOMAINS = [
  'clawsec.prompt.security',
  'prompt.security',
  'raw.githubusercontent.com',
  'github.com',
];

/**
 * Custom error class for security policy violations.
 * These errors should always propagate and never be silently caught.
 */
export class SecurityPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecurityPolicyError';
  }
}

/**
 * Creates a secure HTTPS agent with TLS 1.2+ enforcement and certificate validation.
 */
function createSecureAgent(): https.Agent {
  return new https.Agent({
    // Enforce minimum TLS 1.2 (eliminate TLS 1.0, 1.1)
    minVersion: 'TLSv1.2',
    // Ensure certificate validation is enabled (reject unauthorized certificates)
    rejectUnauthorized: true,
    // Use strong cipher suites
    ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
  });
}

/**
 * Validates that a URL is from an allowed domain.
 */
function isAllowedDomain(url: string): boolean {
  try {
    const parsed = new URL(url);

    // Only allow HTTPS protocol
    if (parsed.protocol !== 'https:') {
      return false;
    }

    const hostname = parsed.hostname.toLowerCase();

    // Check if hostname matches any allowed domain
    return ALLOWED_DOMAINS.some(
      (allowed) => hostname === allowed || hostname.endsWith(`.${allowed}`)
    );
  } catch {
    return false;
  }
}

/**
 * Secure wrapper around fetch with TLS enforcement and domain validation.
 */
export async function secureFetch(url: string, options: RequestInit = {}): Promise<Response> {
  // Validate domain before making request
  if (!isAllowedDomain(url)) {
    throw new SecurityPolicyError(
      `Security policy violation: URL domain not allowed. ` +
      `Only connections to ${ALLOWED_DOMAINS.join(', ')} are permitted. ` +
      `Blocked: ${url}`
    );
  }

  // Use secure HTTPS agent with TLS 1.2+ enforcement
  const agent = createSecureAgent();

  return fetch(url, {
    ...options,
    // @ts-expect-error - agent is supported in Node.js fetch
    agent,
  });
}

/**
 * Decodes a signature from various formats (base64 string or JSON).
 */
function decodeSignature(signatureRaw: string): Buffer | null {
  const trimmed = signatureRaw.trim();
  if (!trimmed) return null;

  let encoded = trimmed;
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (typeof parsed === 'object' && parsed !== null && typeof parsed.signature === 'string') {
        encoded = parsed.signature;
      }
    } catch {
      return null;
    }
  }

  const normalized = encoded.replace(/\s+/g, '');
  if (!normalized) return null;

  try {
    return Buffer.from(normalized, 'base64');
  } catch {
    return null;
  }
}

/**
 * Verifies an Ed25519 signature for a payload.
 */
export function verifySignedPayload(
  payloadRaw: string,
  signatureRaw: string,
  publicKeyPem: string
): boolean {
  const signature = decodeSignature(signatureRaw);
  if (!signature) return false;

  const keyPem = publicKeyPem.trim();
  if (!keyPem) return false;

  try {
    const publicKey = crypto.createPublicKey(keyPem);
    return crypto.verify(null, Buffer.from(payloadRaw, 'utf8'), publicKey, signature);
  } catch {
    return false;
  }
}

/**
 * Computes SHA-256 hash of content.
 */
export function sha256Hex(content: string | Buffer): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Computes SHA-256 hash of a file.
 * Convenience wrapper for file-based integrity monitoring and package verification.
 */
export function sha256File(filePath: string): string {
  const data = fs.readFileSync(filePath);
  return sha256Hex(data);
}

/**
 * Loads and validates an Ed25519 public key from PEM format.
 * @throws {SecurityPolicyError} if PEM format is invalid
 */
export function loadPublicKey(pemString: string): crypto.KeyObject {
  const trimmed = pemString.trim();
  if (!trimmed.startsWith('-----BEGIN PUBLIC KEY-----')) {
    throw new SecurityPolicyError('Invalid PEM format: must start with -----BEGIN PUBLIC KEY-----');
  }

  try {
    return crypto.createPublicKey(trimmed);
  } catch (error) {
    throw new SecurityPolicyError(
      `Failed to load public key: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Verifies Ed25519 detached signature for a file.
 * Matches the API of verify_detached_ed25519.mjs from OpenClaw.
 *
 * @param dataPath - Path to the file to verify
 * @param signaturePath - Path to the detached signature file (.sig)
 * @param publicKeyPem - Ed25519 public key in PEM format
 * @returns true if signature is valid, false otherwise
 */
export function verifyDetachedSignature(
  dataPath: string,
  signaturePath: string,
  publicKeyPem: string
): boolean {
  try {
    const data = fs.readFileSync(dataPath);
    const signatureRaw = fs.readFileSync(signaturePath, 'utf8');
    const signature = decodeSignature(signatureRaw);

    if (!signature) return false;

    const publicKey = crypto.createPublicKey(publicKeyPem.trim());
    return crypto.verify(null, data, publicKey, signature);
  } catch {
    return false;
  }
}

/**
 * Verifies detached signature with detailed error information.
 * Useful for debugging signature verification failures.
 *
 * @param dataPath - Path to the file to verify
 * @param signaturePath - Path to the detached signature file (.sig)
 * @param publicKeyPem - Ed25519 public key in PEM format
 * @returns Object with valid flag and optional error message
 */
export function verifyDetachedSignatureWithDetails(
  dataPath: string,
  signaturePath: string,
  publicKeyPem: string
): { valid: boolean; error?: string } {
  try {
    if (!fs.existsSync(dataPath)) {
      return { valid: false, error: 'Data file not found' };
    }
    if (!fs.existsSync(signaturePath)) {
      return { valid: false, error: 'Signature file not found' };
    }

    const data = fs.readFileSync(dataPath);
    const signatureRaw = fs.readFileSync(signaturePath, 'utf8');
    const signature = decodeSignature(signatureRaw);

    if (!signature) {
      return { valid: false, error: 'Invalid signature format' };
    }

    const publicKey = crypto.createPublicKey(publicKeyPem.trim());
    const valid = crypto.verify(null, data, publicKey, signature);

    return { valid, error: valid ? undefined : 'Signature verification failed' };
  } catch (error) {
    return {
      valid: false,
      error: `Verification error: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

/**
 * Verifies multiple files against expected hashes.
 * Returns list of files that don't match their expected hashes.
 *
 * @param files - Map of file paths to expected SHA-256 hashes
 * @returns Array of mismatches with path, expected, and actual hashes
 */
export function verifyFileHashes(
  files: Record<string, string>
): { path: string; expected: string; actual: string }[] {
  const mismatches = [];

  for (const [path, expectedHash] of Object.entries(files)) {
    try {
      const actualHash = sha256File(path);
      if (actualHash !== expectedHash) {
        mismatches.push({ path, expected: expectedHash, actual: actualHash });
      }
    } catch (error) {
      // File missing or unreadable
      mismatches.push({
        path,
        expected: expectedHash,
        actual: `ERROR: ${error instanceof Error ? error.message : String(error)}`
      });
    }
  }

  return mismatches;
}

/**
 * Extracts SHA-256 value from various formats.
 */
function extractSha256Value(value: unknown): string | null {
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return /^[a-f0-9]{64}$/.test(normalized) ? normalized : null;
  }

  if (typeof value === 'object' && value !== null && 'sha256' in value) {
    const sha256 = (value as { sha256: unknown }).sha256;
    if (typeof sha256 === 'string') {
      const normalized = sha256.trim().toLowerCase();
      return /^[a-f0-9]{64}$/.test(normalized) ? normalized : null;
    }
  }

  return null;
}

/**
 * Parses a checksums manifest JSON.
 */
export function parseChecksumsManifest(manifestRaw: string): ChecksumsManifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(manifestRaw);
  } catch {
    throw new Error('Checksum manifest is not valid JSON');
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Checksum manifest must be an object');
  }

  const obj = parsed as Record<string, unknown>;

  const algorithmRaw = typeof obj.algorithm === 'string' ? obj.algorithm.trim().toLowerCase() : 'sha256';
  if (algorithmRaw !== 'sha256') {
    throw new Error(`Unsupported checksum manifest algorithm: ${algorithmRaw || '(empty)'}`);
  }

  // Support legacy manifest formats
  const schemaVersion = (
    typeof obj.schema_version === 'string' ? obj.schema_version.trim() :
    typeof obj.version === 'string' ? obj.version.trim() :
    typeof obj.generated_at === 'string' ? obj.generated_at.trim() :
    '1'
  );

  if (!schemaVersion) {
    throw new Error('Checksum manifest missing schema_version');
  }

  if (typeof obj.files !== 'object' || obj.files === null) {
    throw new Error('Checksum manifest missing files object');
  }

  const files: Record<string, string> = {};
  for (const [key, value] of Object.entries(obj.files)) {
    if (!key.trim()) continue;
    const digest = extractSha256Value(value);
    if (!digest) {
      throw new Error(`Invalid checksum digest entry for ${key}`);
    }
    files[key] = digest;
  }

  if (Object.keys(files).length === 0) {
    throw new Error('Checksum manifest has no usable file digests');
  }

  return {
    schema_version: schemaVersion,
    algorithm: 'sha256',
    files,
  };
}

/**
 * Normalizes a checksum entry name for matching.
 */
function normalizeChecksumEntryName(entryName: string): string {
  return entryName
    .trim()
    .replace(/\\/g, '/')
    .replace(/^(?:\.\/)+/, '')
    .replace(/^\/+/, '');
}

/**
 * Resolves a checksum manifest entry by name.
 */
function resolveChecksumManifestEntry(
  files: Record<string, string>,
  entryName: string
): { key: string; digest: string } | null {
  const normalizedEntry = normalizeChecksumEntryName(entryName);
  if (!normalizedEntry) return null;

  // Try direct match and common variations
  const directCandidates = [
    normalizedEntry,
    normalizedEntry.split('/').pop() || '',
    `advisories/${normalizedEntry.split('/').pop() || ''}`,
  ].filter((c, i, a) => c && a.indexOf(c) === i);

  for (const candidate of directCandidates) {
    if (candidate in files) {
      return { key: candidate, digest: files[candidate] };
    }
  }

  // Try basename matching
  const basename = normalizedEntry.split('/').pop() || '';
  if (!basename) return null;

  const basenameMatches = Object.entries(files).filter(([key]) => {
    const normalizedKey = normalizeChecksumEntryName(key);
    return normalizedKey.split('/').pop() === basename;
  });

  if (basenameMatches.length > 1) {
    throw new Error(
      `Checksum manifest entry is ambiguous for ${entryName}; ` +
      `multiple manifest keys share basename ${basename}`
    );
  }

  if (basenameMatches.length === 1) {
    const [resolvedKey, digest] = basenameMatches[0];
    return { key: resolvedKey, digest };
  }

  return null;
}

/**
 * Verifies checksums for expected entries.
 */
export function verifyChecksums(
  manifest: ChecksumsManifest,
  expectedEntries: Record<string, string | Buffer>
): void {
  for (const [entryName, entryContent] of Object.entries(expectedEntries)) {
    if (!entryName) continue;

    const resolved = resolveChecksumManifestEntry(manifest.files, entryName);
    if (!resolved) {
      throw new Error(`Checksum manifest missing required entry: ${entryName}`);
    }

    const actualDigest = sha256Hex(entryContent);
    if (actualDigest !== resolved.digest) {
      throw new Error(`Checksum mismatch for ${entryName} (manifest key: ${resolved.key})`);
    }
  }
}

/**
 * Fetches text from a URL with timeout.
 */
export async function fetchText(url: string, timeoutMs: number = 10000): Promise<string | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await secureFetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: { accept: 'application/json,text/plain;q=0.9,*/*;q=0.8' },
    });
    if (!response.ok) return null;
    return await response.text();
  } catch (error) {
    // Re-throw security policy violations - these should never be silently caught
    if (error instanceof SecurityPolicyError) {
      throw error;
    }
    // Network errors, timeouts, etc. return null (graceful degradation)
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Default checksums URL from feed URL.
 */
export function defaultChecksumsUrl(feedUrl: string): string {
  try {
    return new URL('checksums.json', feedUrl).toString();
  } catch {
    const fallbackBase = feedUrl.replace(/\/?[^/]*$/, '');
    return `${fallbackBase}/checksums.json`;
  }
}

/**
 * Safely extracts the basename from a URL or file path.
 */
function _safeBasename(urlOrPath: string, fallback: string): string {
  try {
    const parsed = new URL(urlOrPath);
    const pathname = parsed.pathname;
    const lastSlash = pathname.lastIndexOf('/');
    if (lastSlash >= 0 && lastSlash < pathname.length - 1) {
      return pathname.slice(lastSlash + 1);
    }
  } catch {
    const normalized = urlOrPath.trim();
    const lastSlash = normalized.lastIndexOf('/');
    if (lastSlash >= 0 && lastSlash < normalized.length - 1) {
      return normalized.slice(lastSlash + 1);
    }
  }
  return fallback;
}
