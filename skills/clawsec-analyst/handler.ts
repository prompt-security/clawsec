/**
 * ClawSec Analyst - Main Handler
 * OpenClaw hook handler for AI-powered security analysis
 *
 * Events:
 * - agent:bootstrap: Runs on agent initialization, provides security context
 * - command:new: Runs on new commands, provides contextual security guidance
 */

import * as os from 'node:os';
import * as path from 'node:path';
import { ClaudeClient } from './lib/claude-client.js';
import { analyzeAdvisories, filterByPriority } from './lib/advisory-analyzer.js';
import { loadState, persistState } from './lib/state.js';
import { loadLocalFeed, loadRemoteFeed } from './lib/feed-reader.js';
import type { FeedPayload } from './lib/types.js';

/**
 * OpenClaw hook event structure
 */
interface HookEvent {
  type?: string;
  action?: string;
  messages: Array<{
    role: string;
    content: string;
  }>;
  context?: Record<string, unknown>;
}

/**
 * Default configuration values
 */
const DEFAULT_SCAN_INTERVAL_SECONDS = 300;
const DEFAULT_STATE_FILE = path.join(os.homedir(), '.openclaw', 'clawsec-analyst-state.json');
const DEFAULT_FEED_URL = 'https://clawsec.prompt.security/advisories/feed.json';
const DEFAULT_LOCAL_FEED_PATH = path.join(
  os.homedir(),
  '.openclaw',
  'skills',
  'clawsec-suite',
  'advisories',
  'feed.json'
);

/**
 * Parse positive integer from environment variable with fallback
 */
function parsePositiveInteger(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

/**
 * Convert event to canonical event name (type:action)
 */
function toEventName(event: HookEvent): string {
  const eventType = String(event.type ?? '').trim();
  const action = String(event.action ?? '').trim();
  if (!eventType || !action) return '';
  return `${eventType}:${action}`;
}

/**
 * Check if this handler should process the event
 */
function shouldHandleEvent(event: HookEvent): boolean {
  const eventName = toEventName(event);
  return eventName === 'agent:bootstrap' || eventName === 'command:new';
}

/**
 * Convert ISO timestamp to epoch milliseconds
 */
function epochMs(isoTimestamp: string | null): number {
  if (!isoTimestamp) return 0;
  const parsed = Date.parse(isoTimestamp);
  return Number.isNaN(parsed) ? 0 : parsed;
}

/**
 * Check if last scan was recent (within interval)
 */
function scannedRecently(lastScan: string | null, minIntervalSeconds: number): boolean {
  const sinceMs = Date.now() - epochMs(lastScan);
  return sinceMs >= 0 && sinceMs < minIntervalSeconds * 1000;
}

/**
 * Build security analysis message for agent
 */
function buildAnalysisMessage(
  highPriorityCount: number,
  mediumPriorityCount: number,
  eventName: string
): string {
  const totalCritical = highPriorityCount + mediumPriorityCount;

  if (totalCritical === 0) {
    return '';
  }

  const summary = [
    '🔍 **ClawSec Security Analysis**',
    '',
    `Found ${highPriorityCount} HIGH and ${mediumPriorityCount} MEDIUM priority advisories.`,
    '',
  ];

  if (eventName === 'agent:bootstrap') {
    summary.push(
      'Security context: These advisories may affect dependencies or operations in your environment.',
      'Use `/analyze-advisory <CVE-ID>` for detailed analysis.'
    );
  } else {
    summary.push(
      'Consider security implications before proceeding with operations that involve:',
      '- Installing new dependencies',
      '- Executing external commands',
      '- Processing untrusted data',
      '',
      'Use `/assess-skill-risk <skill-path>` to analyze a skill before installation.'
    );
  }

  return summary.join('\n');
}

/**
 * Main hook handler
 * Mutates event.messages in-place (does not return value)
 */
const handler = async (event: HookEvent): Promise<void> => {
  // Only handle relevant events
  if (!shouldHandleEvent(event)) {
    return;
  }

  // Check for required API key
  const apiKey = process.env['ANTHROPIC_API_KEY'];
  if (!apiKey || apiKey.trim() === '') {
    // Don't fail the hook, but log warning
    if (process.env['NODE_ENV'] !== 'test') {
      // eslint-disable-next-line no-console
      console.warn(
        '[clawsec-analyst] ANTHROPIC_API_KEY not set. ' +
        'AI-powered analysis disabled. Set the environment variable to enable.'
      );
    }
    return;
  }

  // Load configuration from environment
  const stateFile = process.env['CLAWSEC_ANALYST_STATE_FILE'] || DEFAULT_STATE_FILE;
  const scanIntervalSeconds = parsePositiveInteger(
    process.env['CLAWSEC_HOOK_INTERVAL_SECONDS'],
    DEFAULT_SCAN_INTERVAL_SECONDS
  );
  const feedUrl = process.env['CLAWSEC_FEED_URL'] || DEFAULT_FEED_URL;
  const localFeedPath = process.env['CLAWSEC_LOCAL_FEED'] || DEFAULT_LOCAL_FEED_PATH;
  const allowUnsigned = process.env['CLAWSEC_ALLOW_UNSIGNED_FEED'] === '1';

  // Check if we should run (rate limiting)
  const eventName = toEventName(event);
  const forceScan = eventName === 'command:new';
  const state = await loadState(stateFile);

  if (!forceScan && scannedRecently(state.last_feed_check, scanIntervalSeconds)) {
    // Too soon since last scan, skip
    return;
  }

  // Initialize Claude client
  const claudeClient = new ClaudeClient({ apiKey });

  // Perform advisory analysis
  try {
    const nowIso = new Date().toISOString();
    state.last_feed_check = nowIso;

    // Load advisory feed (try remote first, then local fallback)
    let feed: FeedPayload | null = null;

    try {
      feed = await loadRemoteFeed(feedUrl, {
        allowUnsigned,
      });
    } catch (remoteError) {
      if (process.env['NODE_ENV'] !== 'test') {
        // eslint-disable-next-line no-console
        console.warn('[clawsec-analyst] Remote feed unavailable, trying local fallback:', remoteError);
      }

      try {
        feed = await loadLocalFeed(localFeedPath, {
          allowUnsigned,
        });
      } catch (localError) {
        if (process.env['NODE_ENV'] !== 'test') {
          // eslint-disable-next-line no-console
          console.warn('[clawsec-analyst] Local feed unavailable:', localError);
        }
      }
    }

    if (!feed || !feed.advisories || feed.advisories.length === 0) {
      // No advisories to analyze
      return;
    }

    // Analyze advisories from feed
    const allAnalyses = await analyzeAdvisories(feed.advisories, claudeClient);

    // Filter to only HIGH and MEDIUM priority
    const analysisResults = filterByPriority(allAnalyses, 'MEDIUM');

    // Count priority advisories
    const highPriorityCount = analysisResults.filter(a => a.priority === 'HIGH').length;
    const mediumPriorityCount = analysisResults.filter(a => a.priority === 'MEDIUM').length;

    // Build message for agent
    const message = buildAnalysisMessage(highPriorityCount, mediumPriorityCount, eventName);

    // Mutate event.messages in-place (OpenClaw hook pattern)
    if (message) {
      event.messages.push({
        role: 'assistant',
        content: message,
      });
    }

    // Update state with latest analysis
    state.last_feed_updated = nowIso;

    // Store analysis results in history (keep last 50 entries)
    state.analysis_history.push({
      timestamp: nowIso,
      type: 'advisory_triage',
      targetId: 'feed',
      result: 'success',
      details: `Found ${highPriorityCount} HIGH, ${mediumPriorityCount} MEDIUM priority advisories`,
    });

    // Trim history to last 50 entries
    if (state.analysis_history.length > 50) {
      state.analysis_history = state.analysis_history.slice(-50);
    }

    // Persist state
    await persistState(stateFile, state);

  } catch (error) {
    // Don't fail the hook on analysis errors
    if (process.env['NODE_ENV'] !== 'test') {
      // eslint-disable-next-line no-console
      console.warn('[clawsec-analyst] Analysis failed:', error);
    }

    // Log error to state
    const nowIso = new Date().toISOString();
    state.analysis_history.push({
      timestamp: nowIso,
      type: 'advisory_triage',
      targetId: 'feed',
      result: 'error',
      details: `Analysis failed: ${error instanceof Error ? error.message : String(error)}`,
    });

    await persistState(stateFile, state);
  }
};

export default handler;
