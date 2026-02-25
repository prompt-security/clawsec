/**
 * ClawSec Advisory Cache Manager for NanoClaw
 *
 * Manages fetching, verifying, and caching the ClawSec advisory feed.
 * Runs on the host side (not in container).
 *
 * Security:
 * - Ed25519 signature verification using Node.js crypto
 * - Fail-closed policy: invalid signature = reject feed
 * - TLS 1.2+ enforcement with certificate validation
 * - Public key embedded (not user-modifiable)
 * - Cache stored in host-managed directory
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import https from 'node:https';
import path from 'node:path';

// ClawSec public key (from clawsec-signing-public.pem)
const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAS7nijfMcUoOBCj4yOXJX+GYGv2pFl2Yaha1P4v5Cm6A=
-----END PUBLIC KEY-----`;

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const FEED_URL = 'https://clawsec.prompt.security/advisories/feed.json';
const FETCH_TIMEOUT_MS = 10000;

export interface Advisory {
  id: string;
  severity: string;
  type?: string;
  title?: string;
  description?: string;
  action?: string;
  published?: string;
  updated?: string;
  affected: string[];
}

export interface FeedPayload {
  version: string;
  updated?: string;
  advisories: Advisory[];
}

export interface AdvisoryCache {
  feed: FeedPayload;
  fetchedAt: string;
  verified: boolean;
  publicKeyFingerprint: string;
}

interface Logger {
  info(msg: string | object, ...args: unknown[]): void;
  error(msg: string | object, ...args: unknown[]): void;
  warn(msg: string | object, ...args: unknown[]): void;
}

export class AdvisoryCacheManager {
  private cache: AdvisoryCache | null = null;
  private refreshPromise: Promise<void> | null = null;
  private cacheFile: string;
  private logger: Logger;

  constructor(dataDir: string, logger: Logger) {
    this.cacheFile = path.join(dataDir, 'clawsec-advisory-cache.json');
    this.logger = logger;
  }

  /**
   * Initialize cache manager. Loads cache from disk and refreshes if stale.
   */
  async initialize(): Promise<void> {
    await this.loadCacheFromDisk();

    if (!this.cache || this.isCacheStale()) {
      try {
        await this.refresh();
      } catch (error) {
        this.logger.error({ error }, 'Failed to initialize advisory cache');
        // Continue with stale cache if available
      }
    }
  }

  /**
   * Refresh advisory cache from remote feed.
   * Thread-safe: prevents concurrent refreshes.
   */
  async refresh(): Promise<void> {
    // Prevent concurrent refreshes
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this._doRefresh();
    try {
      await this.refreshPromise;
    } finally {
      this.refreshPromise = null;
    }
  }

  /**
   * Get current cache. Returns null if cache is stale or missing.
   */
  getCache(): AdvisoryCache | null {
    if (!this.cache || this.isCacheStale()) {
      return null;
    }
    return this.cache;
  }

  /**
   * Get cache even if stale (for fallback scenarios)
   */
  getCacheAllowStale(): AdvisoryCache | null {
    return this.cache;
  }

  private async _doRefresh(): Promise<void> {
    try {
      this.logger.info('Refreshing advisory cache from ClawSec feed');

      const feed = await this.fetchAndVerifyFeed();
      const fingerprint = this.calculateKeyFingerprint();

      this.cache = {
        feed,
        fetchedAt: new Date().toISOString(),
        verified: true,
        publicKeyFingerprint: fingerprint,
      };

      await this.saveCacheToDisk();
      this.logger.info({
        advisories: feed.advisories.length,
        updated: feed.updated,
      }, 'Advisory cache refreshed successfully');
    } catch (error) {
      this.logger.error({ error }, 'Failed to refresh advisory cache');
      throw error;
    }
  }

  private isCacheStale(): boolean {
    if (!this.cache) return true;
    const age = Date.now() - Date.parse(this.cache.fetchedAt);
    return age > CACHE_TTL_MS;
  }

  private async fetchAndVerifyFeed(): Promise<FeedPayload> {
    // Fetch feed and signature in parallel
    const [payloadRaw, signatureRaw] = await Promise.all([
      this.secureFetch(FEED_URL),
      this.secureFetch(`${FEED_URL}.sig`),
    ]);

    // Verify Ed25519 signature
    if (!this.verifySignature(payloadRaw, signatureRaw)) {
      throw new Error('Feed signature verification failed (Ed25519)');
    }

    // Parse and validate
    const feed = JSON.parse(payloadRaw) as FeedPayload;
    if (!this.isValidFeed(feed)) {
      throw new Error('Invalid feed format');
    }

    return feed;
  }

  private async secureFetch(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      // Create secure HTTPS agent with TLS 1.2+ enforcement
      const agent = new https.Agent({
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true,
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
      });

      const req = https.get(url, {
        agent,
        timeout: FETCH_TIMEOUT_MS,
        headers: {
          'User-Agent': 'NanoClaw/1.0',
          'Accept': 'application/json,text/plain',
        },
      }, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} from ${url}`));
          return;
        }

        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => resolve(data));
        res.on('error', reject);
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Timeout fetching ${url}`));
      });
    });
  }

  private verifySignature(payload: string, signatureBase64: string): boolean {
    try {
      // Decode base64 signature
      const trimmed = signatureBase64.trim();
      let encoded = trimmed;

      // Handle JSON-wrapped signature: {"signature": "base64..."}
      if (trimmed.startsWith('{')) {
        try {
          const parsed = JSON.parse(trimmed);
          if (typeof parsed.signature === 'string') {
            encoded = parsed.signature;
          }
        } catch {
          // Not JSON, use as-is
        }
      }

      const normalized = encoded.replace(/\s+/g, '');
      const sigBuffer = Buffer.from(normalized, 'base64');

      // Verify Ed25519 signature using Node.js crypto
      const publicKey = crypto.createPublicKey(PUBLIC_KEY_PEM);
      return crypto.verify(
        null, // algorithm null = Ed25519 raw mode
        Buffer.from(payload, 'utf8'),
        publicKey,
        sigBuffer
      );
    } catch (error) {
      this.logger.warn({ error }, 'Signature verification failed');
      return false;
    }
  }

  private isValidFeed(feed: unknown): feed is FeedPayload {
    if (typeof feed !== 'object' || !feed) return false;
    const f = feed as FeedPayload;

    if (typeof f.version !== 'string' || !f.version.trim()) return false;
    if (!Array.isArray(f.advisories)) return false;

    // Validate each advisory
    return f.advisories.every((a: unknown) => {
      if (typeof a !== 'object' || !a) return false;
      const advisory = a as Advisory;

      return (
        typeof advisory.id === 'string' &&
        advisory.id.trim() !== '' &&
        typeof advisory.severity === 'string' &&
        advisory.severity.trim() !== '' &&
        Array.isArray(advisory.affected) &&
        advisory.affected.every(
          (affected) => typeof affected === 'string' && affected.trim() !== ''
        )
      );
    });
  }

  private calculateKeyFingerprint(): string {
    const publicKey = crypto.createPublicKey(PUBLIC_KEY_PEM);
    const der = publicKey.export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(der).digest('hex');
  }

  private async loadCacheFromDisk(): Promise<void> {
    try {
      const data = await fs.readFile(this.cacheFile, 'utf8');
      const parsed = JSON.parse(data) as AdvisoryCache;

      // Validate cache structure
      if (this.isValidCache(parsed)) {
        this.cache = parsed;
        this.logger.info({
          age: Date.now() - Date.parse(parsed.fetchedAt),
          advisories: parsed.feed.advisories.length,
        }, 'Loaded advisory cache from disk');
      } else {
        this.logger.warn('Invalid cache format on disk, discarding');
        this.cache = null;
      }
    } catch {
      this.cache = null;
    }
  }

  private isValidCache(cache: unknown): cache is AdvisoryCache {
    if (typeof cache !== 'object' || !cache) return false;
    const c = cache as AdvisoryCache;

    return (
      this.isValidFeed(c.feed) &&
      typeof c.fetchedAt === 'string' &&
      typeof c.verified === 'boolean' &&
      typeof c.publicKeyFingerprint === 'string'
    );
  }

  private async saveCacheToDisk(): Promise<void> {
    if (!this.cache) return;

    try {
      await fs.mkdir(path.dirname(this.cacheFile), { recursive: true });

      // Atomic write: temp file then rename
      const tempFile = `${this.cacheFile}.tmp`;
      await fs.writeFile(tempFile, JSON.stringify(this.cache, null, 2), 'utf8');
      await fs.rename(tempFile, this.cacheFile);

      this.logger.info({ path: this.cacheFile }, 'Advisory cache saved to disk');
    } catch (error) {
      this.logger.error({ error }, 'Failed to save advisory cache to disk');
      throw error;
    }
  }
}

/**
 * Helper: Match advisories against installed skills
 */
export function findAdvisoryMatches(
  advisories: Advisory[],
  skills: Array<{ name: string; version: string | null; dirName: string }>
): Array<{
  advisory: Advisory;
  skill: { name: string; version: string | null; dirName: string };
  matchedAffected: string[];
}> {
  const matches: Array<{
    advisory: Advisory;
    skill: { name: string; version: string | null; dirName: string };
    matchedAffected: string[];
  }> = [];

  for (const advisory of advisories) {
    for (const skill of skills) {
      const matchedAffected: string[] = [];

      for (const affected of advisory.affected) {
        // Parse affected specifier: skill-name or skill-name@version
        const atIndex = affected.lastIndexOf('@');
        const affectedName = atIndex > 0 ? affected.slice(0, atIndex) : affected;
        const _affectedVersion = atIndex > 0 ? affected.slice(atIndex + 1) : '*';

        // Match by name or directory name
        if (affectedName === skill.name || affectedName === skill.dirName) {
          // TODO: implement version range matching
          matchedAffected.push(affected);
        }
      }

      if (matchedAffected.length > 0) {
        matches.push({ advisory, skill, matchedAffected });
      }
    }
  }

  return matches;
}

/**
 * Helper: Evaluate safety recommendation for a skill
 */
export function evaluateSkillSafety(advisories: Advisory[]): {
  safe: boolean;
  recommendation: 'install' | 'block' | 'review';
  reason: string;
} {
  if (advisories.length === 0) {
    return { safe: true, recommendation: 'install', reason: 'No advisories found' };
  }

  const hasMalicious = advisories.some((a) => a.type === 'malicious');
  const hasRemoveAction = advisories.some((a) => a.action === 'remove');
  const hasCritical = advisories.some((a) => a.severity === 'critical');
  const hasHigh = advisories.some((a) => a.severity === 'high');

  if (hasMalicious || hasRemoveAction) {
    return {
      safe: false,
      recommendation: 'block',
      reason: 'Malicious skill or removal recommended',
    };
  }

  if (hasCritical) {
    return {
      safe: false,
      recommendation: 'block',
      reason: 'Critical security advisory',
    };
  }

  if (hasHigh) {
    return {
      safe: false,
      recommendation: 'review',
      reason: 'High severity advisory - user review recommended',
    };
  }

  return {
    safe: false,
    recommendation: 'review',
    reason: 'Advisory found - review before installing',
  };
}
