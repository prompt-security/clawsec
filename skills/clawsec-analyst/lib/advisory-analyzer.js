/**
 * Advisory triage analyzer
 * Analyzes security advisories using Claude API to assess actual risk,
 * identify affected components, and recommend remediation actions
 */
import { getCachedAnalysis, setCachedAnalysis } from './cache.js';
/**
 * Analyzes a single advisory and returns structured analysis
 * @param advisory - Advisory to analyze
 * @param client - Claude API client instance
 * @returns Promise with structured analysis result
 */
export async function analyzeAdvisory(advisory, client) {
    // Validate advisory has required fields
    if (!advisory.id || !advisory.severity || !advisory.description) {
        throw createError('INVALID_ADVISORY_SCHEMA', `Advisory missing required fields (id: ${advisory.id})`, false);
    }
    // Try to get cached analysis first
    try {
        const cached = await getCachedAnalysis(advisory.id);
        if (cached) {
            if (process.env['NODE_ENV'] !== 'test') {
                // eslint-disable-next-line no-console
                console.log(`Using cached analysis for ${advisory.id}`);
            }
            return cached;
        }
    }
    catch (error) {
        // Cache errors are non-critical, continue with API call
        if (process.env['NODE_ENV'] !== 'test') {
            // eslint-disable-next-line no-console
            console.warn(`Cache lookup failed for ${advisory.id}:`, error);
        }
    }
    // Call Claude API for analysis
    try {
        const responseText = await client.analyzeAdvisory(advisory);
        // Parse JSON response
        const analysis = parseAnalysisResponse(advisory.id, responseText);
        // Cache the result for offline resilience
        await setCachedAnalysis(advisory.id, analysis);
        return analysis;
    }
    catch (error) {
        // If API fails, try to use cached analysis (even if stale)
        if (process.env['NODE_ENV'] !== 'test') {
            // eslint-disable-next-line no-console
            console.warn(`Claude API failed for ${advisory.id}, checking cache...`, error);
        }
        const cached = await getCachedAnalysis(advisory.id);
        if (cached) {
            if (process.env['NODE_ENV'] !== 'test') {
                // eslint-disable-next-line no-console
                console.warn(`Using cached analysis for ${advisory.id} (may be outdated)`);
            }
            return cached;
        }
        // No cache available, re-throw the error
        throw createError('CLAUDE_API_ERROR', `Claude API unavailable and no cache found for ${advisory.id}: ${error.message}`, false);
    }
}
/**
 * Analyzes multiple advisories in batch
 * @param advisories - Array of advisories to analyze
 * @param client - Claude API client instance
 * @returns Promise with array of analysis results
 */
export async function analyzeAdvisories(advisories, client) {
    const results = [];
    // Process advisories sequentially to avoid rate limits
    // In production, this could be parallelized with a concurrency limit
    for (const advisory of advisories) {
        try {
            const analysis = await analyzeAdvisory(advisory, client);
            results.push(analysis);
        }
        catch (error) {
            // Log error but continue processing other advisories
            if (process.env['NODE_ENV'] !== 'test') {
                // eslint-disable-next-line no-console
                console.error(`Failed to analyze advisory ${advisory.id}:`, error);
            }
            // Add a fallback analysis with LOW priority for failed analyses
            results.push(createFallbackAnalysis(advisory));
        }
    }
    return results;
}
/**
 * Filters advisories by priority threshold
 * @param analyses - Array of analysis results
 * @param minPriority - Minimum priority to include (HIGH, MEDIUM, or LOW)
 * @returns Filtered array of high-priority analyses
 */
export function filterByPriority(analyses, minPriority = 'MEDIUM') {
    const priorityOrder = {
        HIGH: 3,
        MEDIUM: 2,
        LOW: 1,
    };
    const threshold = priorityOrder[minPriority];
    return analyses.filter(analysis => {
        const analysisPriority = priorityOrder[analysis.priority];
        return analysisPriority >= threshold;
    });
}
/**
 * Parses Claude API response text into structured AdvisoryAnalysis
 * @param advisoryId - Advisory ID for error context
 * @param responseText - Raw text response from Claude API
 * @returns Parsed and validated AdvisoryAnalysis object
 */
function parseAnalysisResponse(advisoryId, responseText) {
    try {
        // Extract JSON from response (Claude may wrap it in markdown code blocks)
        let jsonText = responseText.trim();
        // Remove markdown code blocks if present
        if (jsonText.startsWith('```json')) {
            jsonText = jsonText.replace(/^```json\s*/, '').replace(/\s*```$/, '');
        }
        else if (jsonText.startsWith('```')) {
            jsonText = jsonText.replace(/^```\s*/, '').replace(/\s*```$/, '');
        }
        const parsed = JSON.parse(jsonText);
        // Validate required fields
        if (!parsed.priority || !parsed.rationale || !parsed.affected_components || !parsed.recommended_actions) {
            throw new Error('Missing required fields in Claude API response');
        }
        // Validate priority value
        if (!['HIGH', 'MEDIUM', 'LOW'].includes(parsed.priority)) {
            throw new Error(`Invalid priority value: ${parsed.priority}`);
        }
        // Validate arrays
        if (!Array.isArray(parsed.affected_components) || !Array.isArray(parsed.recommended_actions)) {
            throw new Error('affected_components and recommended_actions must be arrays');
        }
        // Validate confidence if present
        const confidence = typeof parsed.confidence === 'number' ? parsed.confidence : 0.8;
        if (confidence < 0 || confidence > 1) {
            throw new Error(`Invalid confidence value: ${confidence}`);
        }
        return {
            advisoryId,
            priority: parsed.priority,
            rationale: parsed.rationale,
            affected_components: parsed.affected_components,
            recommended_actions: parsed.recommended_actions,
            confidence,
        };
    }
    catch (error) {
        throw createError('CLAUDE_API_ERROR', `Failed to parse Claude API response for ${advisoryId}: ${error.message}`, false);
    }
}
/**
 * Creates a fallback analysis when Claude API fails and no cache is available
 * @param advisory - Advisory that failed to analyze
 * @returns Basic fallback analysis based on advisory metadata
 */
function createFallbackAnalysis(advisory) {
    // Map advisory severity to priority (conservative approach)
    const severityToPriority = {
        critical: 'HIGH',
        high: 'HIGH',
        medium: 'MEDIUM',
        low: 'LOW',
    };
    const priority = severityToPriority[advisory.severity] || 'MEDIUM';
    return {
        advisoryId: advisory.id,
        priority,
        rationale: `Fallback analysis: ${advisory.description.substring(0, 200)}... (AI analysis unavailable, using advisory metadata)`,
        affected_components: advisory.affected || [],
        recommended_actions: [
            advisory.action || 'Review advisory and assess impact',
            'Consult security team for guidance',
            'Monitor for updated information',
        ],
        confidence: 0.5, // Low confidence for fallback analysis
    };
}
/**
 * Create a typed AnalystError
 * @param code - Error code
 * @param message - Error message
 * @param recoverable - Whether error is recoverable
 * @returns Typed AnalystError object
 */
function createError(code, message, recoverable) {
    return {
        code,
        message,
        recoverable,
    };
}
