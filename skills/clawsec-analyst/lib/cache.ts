/**
 * Result caching for offline resilience
 * Caches analysis results to ~/.openclaw/clawsec-analyst-cache/
 * with 7-day expiry to enable graceful degradation when Claude API is unavailable
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import type { CachedAnalysis, AdvisoryAnalysis } from './types.js';

// Type declaration for Node.js error types
interface NodeJSErrnoException extends Error {
  errno?: number;
  code?: string;
  path?: string;
  syscall?: string;
}

// Cache configuration
const CACHE_DIR = path.join(os.homedir(), '.openclaw', 'clawsec-analyst-cache');
const CACHE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const CACHE_VERSION = '1.0';

/**
 * Ensures cache directory exists
 * @returns Promise that resolves when directory is ready
 */
async function ensureCacheDir(): Promise<void> {
  try {
    await fs.mkdir(CACHE_DIR, { recursive: true });
  } catch (error) {
    // Log but don't throw - cache is non-critical
    console.warn(`Failed to create cache directory: ${error}`);
  }
}

/**
 * Generates safe cache file path for advisory ID
 * @param advisoryId - Advisory ID (e.g., CVE-2024-12345, CLAW-2024-0001)
 * @returns Absolute path to cache file
 */
function getCachePath(advisoryId: string): string {
  // Sanitize advisory ID to prevent directory traversal
  const safeId = advisoryId.replace(/[^a-zA-Z0-9\-_.]/g, '_');
  return path.join(CACHE_DIR, `${safeId}.json`);
}

/**
 * Retrieves cached analysis for an advisory
 * @param advisoryId - Advisory ID to look up
 * @returns Cached analysis or null if not found/stale
 */
export async function getCachedAnalysis(advisoryId: string): Promise<AdvisoryAnalysis | null> {
  try {
    const cachePath = getCachePath(advisoryId);
    const content = await fs.readFile(cachePath, 'utf-8');
    const cached: CachedAnalysis = JSON.parse(content);

    // Validate cache structure
    if (!cached.advisoryId || !cached.analysis || !cached.timestamp || !cached.cacheVersion) {
      console.warn(`Invalid cache structure for ${advisoryId}, ignoring`);
      return null;
    }

    // Check cache age
    const cacheTimestamp = new Date(cached.timestamp).getTime();
    const age = Date.now() - cacheTimestamp;

    if (age > CACHE_MAX_AGE_MS) {
      const ageInDays = Math.floor(age / (24 * 60 * 60 * 1000));
      console.warn(`Cache for ${advisoryId} is stale (${ageInDays} days old, max 7 days)`);
      return null;
    }

    // Warn if cache is getting old (> 5 days)
    if (age > 5 * 24 * 60 * 60 * 1000) {
      const ageInDays = Math.floor(age / (24 * 60 * 60 * 1000));
      console.warn(`Cache for ${advisoryId} is ${ageInDays} days old (will expire in ${7 - ageInDays} days)`);
    }

    return cached.analysis;
  } catch (error) {
    // Cache miss is expected - not an error condition
    if ((error as NodeJSErrnoException).code === 'ENOENT') {
      return null;
    }

    // Other errors are unexpected but non-critical
    console.warn(`Failed to read cache for ${advisoryId}:`, error);
    return null;
  }
}

/**
 * Stores analysis result in cache
 * @param advisoryId - Advisory ID
 * @param analysis - Analysis result to cache
 * @returns Promise that resolves when cache is written
 */
export async function setCachedAnalysis(
  advisoryId: string,
  analysis: AdvisoryAnalysis
): Promise<void> {
  try {
    await ensureCacheDir();

    const cached: CachedAnalysis = {
      advisoryId,
      analysis,
      timestamp: new Date().toISOString(),
      cacheVersion: CACHE_VERSION,
    };

    const cachePath = getCachePath(advisoryId);
    await fs.writeFile(cachePath, JSON.stringify(cached, null, 2), 'utf-8');
  } catch (error) {
    // Cache write failure is non-critical - log and continue
    console.warn(`Failed to cache analysis for ${advisoryId}:`, error);
  }
}

/**
 * Clears stale cache entries older than 7 days
 * @returns Promise with number of entries cleared
 */
export async function clearStaleCache(): Promise<number> {
  try {
    const entries = await fs.readdir(CACHE_DIR);
    let clearedCount = 0;

    for (const entry of entries) {
      // Only process .json files
      if (!entry.endsWith('.json')) {
        continue;
      }

      const filePath = path.join(CACHE_DIR, entry);

      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const cached: CachedAnalysis = JSON.parse(content);

        const cacheTimestamp = new Date(cached.timestamp).getTime();
        const age = Date.now() - cacheTimestamp;

        if (age > CACHE_MAX_AGE_MS) {
          await fs.unlink(filePath);
          clearedCount++;
        }
      } catch {
        // If we can't read/parse the file, delete it
        console.warn(`Removing corrupted cache file: ${entry}`);
        await fs.unlink(filePath);
        clearedCount++;
      }
    }

    if (clearedCount > 0) {
      console.log(`Cleared ${clearedCount} stale cache entries`);
    }

    return clearedCount;
  } catch (error) {
    // Cache directory might not exist yet - not an error
    if ((error as NodeJSErrnoException).code === 'ENOENT') {
      return 0;
    }

    console.warn('Failed to clear stale cache:', error);
    return 0;
  }
}

/**
 * Gets cache statistics (for debugging/monitoring)
 * @returns Promise with cache stats
 */
export async function getCacheStats(): Promise<{
  totalEntries: number;
  staleEntries: number;
  totalSizeBytes: number;
  oldestEntryAge: number | null;
}> {
  try {
    const entries = await fs.readdir(CACHE_DIR);
    let totalEntries = 0;
    let staleEntries = 0;
    let totalSizeBytes = 0;
    let oldestEntryAge: number | null = null;

    for (const entry of entries) {
      if (!entry.endsWith('.json')) {
        continue;
      }

      const filePath = path.join(CACHE_DIR, entry);

      try {
        const stat = await fs.stat(filePath);
        totalSizeBytes += stat.size;
        totalEntries++;

        const content = await fs.readFile(filePath, 'utf-8');
        const cached: CachedAnalysis = JSON.parse(content);

        const cacheTimestamp = new Date(cached.timestamp).getTime();
        const age = Date.now() - cacheTimestamp;

        if (age > CACHE_MAX_AGE_MS) {
          staleEntries++;
        }

        if (oldestEntryAge === null || age > oldestEntryAge) {
          oldestEntryAge = age;
        }
      } catch {
        // Skip corrupted entries
        continue;
      }
    }

    return {
      totalEntries,
      staleEntries,
      totalSizeBytes,
      oldestEntryAge,
    };
  } catch (error) {
    if ((error as NodeJSErrnoException).code === 'ENOENT') {
      return {
        totalEntries: 0,
        staleEntries: 0,
        totalSizeBytes: 0,
        oldestEntryAge: null,
      };
    }

    throw error;
  }
}
