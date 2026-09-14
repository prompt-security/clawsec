/**
 * Pre-installation risk assessor for skills
 * Analyzes skill metadata and SBOM to identify security risks
 * Cross-references dependencies against advisory feed
 */
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { ClaudeClient } from './claude-client.js';
import { loadLocalFeed, loadRemoteFeed, parseAffectedSpecifier } from './feed-reader.js';
/**
 * Risk score calculation thresholds
 */
const RISK_THRESHOLDS = {
    CRITICAL: 80,
    HIGH: 60,
    MEDIUM: 30,
    LOW: 0,
};
/**
 * Default configuration values
 */
const DEFAULT_CONFIG = {
    localFeedPath: 'advisories/feed.json',
    remoteFeedUrl: 'https://clawsec.prompt.security/advisories/feed.json',
    allowUnsigned: process.env['CLAWSEC_ALLOW_UNSIGNED_FEED'] === '1',
};
/**
 * Parses skill.json file
 * @param skillJsonPath - Path to skill.json file
 * @returns Parsed skill metadata
 */
async function parseSkillJson(skillJsonPath) {
    try {
        const content = await fs.readFile(skillJsonPath, 'utf-8');
        const parsed = JSON.parse(content);
        // Validate required fields
        if (!parsed.name || typeof parsed.name !== 'string') {
            throw new Error('skill.json missing required field: name');
        }
        if (!parsed.version || typeof parsed.version !== 'string') {
            throw new Error('skill.json missing required field: version');
        }
        if (!Array.isArray(parsed.files)) {
            throw new Error('skill.json missing required field: files (SBOM)');
        }
        return parsed;
    }
    catch (error) {
        if (error.code === 'ENOENT') {
            throw new Error(`skill.json not found: ${skillJsonPath}`);
        }
        throw new Error(`Failed to parse skill.json: ${error.message}`);
    }
}
/**
 * Reads SKILL.md file if it exists
 * @param skillMdPath - Path to SKILL.md file
 * @returns SKILL.md content or null if not found
 */
async function readSkillMd(skillMdPath) {
    try {
        return await fs.readFile(skillMdPath, 'utf-8');
    }
    catch (error) {
        if (error.code === 'ENOENT') {
            return null;
        }
        // Log but don't fail - SKILL.md is optional for risk assessment
        console.warn(`Failed to read SKILL.md: ${error.message}`);
        return null;
    }
}
/**
 * Loads advisory feed with fallback to local if remote fails
 * @param config - Risk assessment configuration
 * @returns Advisory feed payload
 */
async function loadAdvisoryFeed(config) {
    const remoteFeedUrl = config.remoteFeedUrl || DEFAULT_CONFIG.remoteFeedUrl;
    const localFeedPath = config.localFeedPath || DEFAULT_CONFIG.localFeedPath;
    const allowUnsigned = config.allowUnsigned ?? DEFAULT_CONFIG.allowUnsigned;
    // Try remote feed first
    try {
        const remoteFeed = await loadRemoteFeed(remoteFeedUrl, {
            publicKeyPem: config.publicKeyPem,
            allowUnsigned,
        });
        if (remoteFeed) {
            return remoteFeed;
        }
    }
    catch (error) {
        console.warn(`Failed to load remote feed from ${remoteFeedUrl}:`, error.message);
    }
    // Fallback to local feed
    try {
        return await loadLocalFeed(localFeedPath, {
            publicKeyPem: config.publicKeyPem,
            allowUnsigned,
        });
    }
    catch (error) {
        throw new Error(`Failed to load advisory feed (tried remote and local): ${error.message}`);
    }
}
/**
 * Matches skill dependencies against advisory feed
 * @param skillMetadata - Parsed skill metadata
 * @param feed - Advisory feed payload
 * @returns Array of matched advisories
 */
function matchDependenciesAgainstFeed(skillMetadata, feed) {
    const matches = [];
    const dependencies = skillMetadata.dependencies || {};
    const skillName = skillMetadata.name;
    for (const advisory of feed.advisories) {
        for (const affected of advisory.affected) {
            // Parse affected specifier (e.g., "package@1.0.0", "cpe:2.3:...")
            const parsed = parseAffectedSpecifier(affected);
            if (!parsed) {
                continue;
            }
            // Check if skill name matches
            if (parsed.name === skillName) {
                matches.push({
                    advisory,
                    matchedDependency: skillName,
                    matchReason: `Skill name matches advisory affected component: ${affected}`,
                });
                continue;
            }
            // Check if any dependency matches
            for (const [depName, depVersion] of Object.entries(dependencies)) {
                if (parsed.name === depName) {
                    // Simple version matching - exact or wildcard
                    // More sophisticated semver matching would require additional library
                    const versionMatches = parsed.versionSpec === '*' ||
                        parsed.versionSpec === depVersion ||
                        depVersion === '*';
                    if (versionMatches) {
                        matches.push({
                            advisory,
                            matchedDependency: `${depName}@${depVersion}`,
                            matchReason: `Dependency matches advisory: ${affected}`,
                        });
                    }
                }
            }
        }
    }
    return matches;
}
/**
 * Analyzes skill for security risks using Claude API
 * @param skillMetadata - Parsed skill metadata
 * @param skillMd - SKILL.md content (if available)
 * @param advisoryMatches - Matched advisories from feed
 * @param claudeClient - Claude API client
 * @returns Claude's risk assessment response
 */
async function analyzeSkillWithClaude(skillMetadata, skillMd, advisoryMatches, claudeClient) {
    // Build comprehensive metadata for Claude analysis
    const analysisPayload = {
        skillMetadata,
        skillMdExcerpt: skillMd ? skillMd.substring(0, 2000) : null, // Limit SKILL.md to first 2000 chars
        matchedAdvisories: advisoryMatches.map(match => ({
            advisoryId: match.advisory.id,
            severity: match.advisory.severity,
            title: match.advisory.title,
            description: match.advisory.description,
            matchedDependency: match.matchedDependency,
            matchReason: match.matchReason,
            cvssScore: match.advisory.cvss_score,
        })),
        requiredBinaries: skillMetadata.openclaw?.required_bins || [],
        fileCount: skillMetadata.files.length,
        hasDependencies: Object.keys(skillMetadata.dependencies || {}).length > 0,
    };
    return await claudeClient.assessSkillRisk(analysisPayload);
}
/**
 * Parses Claude's JSON response into RiskAssessment
 * @param response - Raw JSON response from Claude
 * @param skillName - Skill name
 * @param advisoryMatches - Matched advisories from feed
 * @returns Structured risk assessment
 */
function parseClaudeResponse(response, skillName, advisoryMatches) {
    try {
        // Extract JSON from response (Claude might wrap it in markdown)
        const jsonMatch = response.match(/\{[\s\S]*\}/);
        if (!jsonMatch) {
            throw new Error('No JSON found in Claude response');
        }
        const parsed = JSON.parse(jsonMatch[0]);
        // Validate required fields
        if (typeof parsed.riskScore !== 'number' || parsed.riskScore < 0 || parsed.riskScore > 100) {
            throw new Error('Invalid riskScore in Claude response');
        }
        if (!['critical', 'high', 'medium', 'low'].includes(parsed.severity)) {
            throw new Error('Invalid severity in Claude response');
        }
        if (!Array.isArray(parsed.findings)) {
            throw new Error('Invalid findings array in Claude response');
        }
        if (!['approve', 'review', 'block'].includes(parsed.recommendation)) {
            throw new Error('Invalid recommendation in Claude response');
        }
        if (typeof parsed.rationale !== 'string') {
            throw new Error('Invalid rationale in Claude response');
        }
        return {
            skillName,
            riskScore: parsed.riskScore,
            severity: parsed.severity,
            findings: parsed.findings,
            matchedAdvisories: advisoryMatches,
            recommendation: parsed.recommendation,
            rationale: parsed.rationale,
        };
    }
    catch (error) {
        throw new Error(`Failed to parse Claude response: ${error.message}`);
    }
}
/**
 * Calculates fallback risk score based on advisory matches
 * (used when Claude API is unavailable)
 * @param advisoryMatches - Matched advisories
 * @returns Risk score 0-100
 */
function calculateFallbackRiskScore(advisoryMatches) {
    if (advisoryMatches.length === 0) {
        return 10; // Base score for any skill installation
    }
    let score = 10;
    for (const match of advisoryMatches) {
        const advisory = match.advisory;
        // Add score based on severity
        switch (advisory.severity.toLowerCase()) {
            case 'critical':
                score += 30;
                break;
            case 'high':
                score += 20;
                break;
            case 'medium':
                score += 10;
                break;
            case 'low':
                score += 5;
                break;
        }
        // Add score based on CVSS score if available
        if (advisory.cvss_score) {
            score += Math.floor(advisory.cvss_score);
        }
    }
    // Cap at 100
    return Math.min(score, 100);
}
/**
 * Generates fallback risk assessment when Claude API is unavailable
 * @param skillName - Skill name
 * @param advisoryMatches - Matched advisories
 * @returns Fallback risk assessment
 */
function generateFallbackAssessment(skillName, advisoryMatches) {
    const riskScore = calculateFallbackRiskScore(advisoryMatches);
    let severity;
    let recommendation;
    if (riskScore >= RISK_THRESHOLDS.CRITICAL) {
        severity = 'critical';
        recommendation = 'block';
    }
    else if (riskScore >= RISK_THRESHOLDS.HIGH) {
        severity = 'high';
        recommendation = 'review';
    }
    else if (riskScore >= RISK_THRESHOLDS.MEDIUM) {
        severity = 'medium';
        recommendation = 'review';
    }
    else {
        severity = 'low';
        recommendation = 'approve';
    }
    const findings = advisoryMatches.map(match => ({
        category: 'dependencies',
        severity: match.advisory.severity,
        description: `Known vulnerability: ${match.advisory.id}`,
        evidence: `${match.matchedDependency} - ${match.advisory.description}`,
    }));
    const rationale = advisoryMatches.length > 0
        ? `Fallback assessment based on ${advisoryMatches.length} matched advisory/advisories. ` +
            `Claude API was unavailable for detailed analysis. Risk score calculated from advisory severity.`
        : `No known vulnerabilities found in advisory feed. Base risk score assigned. ` +
            `Claude API was unavailable for detailed analysis.`;
    return {
        skillName,
        riskScore,
        severity,
        findings,
        matchedAdvisories: advisoryMatches,
        recommendation,
        rationale,
    };
}
/**
 * Assesses security risk for a skill before installation
 * @param skillDir - Path to skill directory (containing skill.json)
 * @param config - Risk assessment configuration
 * @returns Risk assessment with score 0-100
 */
export async function assessSkillRisk(skillDir, config = {}) {
    // Parse skill metadata
    const skillJsonPath = path.join(skillDir, 'skill.json');
    const skillMdPath = path.join(skillDir, 'SKILL.md');
    const skillMetadata = await parseSkillJson(skillJsonPath);
    const skillMd = await readSkillMd(skillMdPath);
    // Load advisory feed
    const feed = await loadAdvisoryFeed(config);
    // Match dependencies against advisory feed
    const advisoryMatches = matchDependenciesAgainstFeed(skillMetadata, feed);
    // Create Claude client if not provided
    const claudeClient = config.claudeClient || new ClaudeClient();
    // Analyze with Claude API
    try {
        const claudeResponse = await analyzeSkillWithClaude(skillMetadata, skillMd, advisoryMatches, claudeClient);
        return parseClaudeResponse(claudeResponse, skillMetadata.name, advisoryMatches);
    }
    catch (error) {
        console.warn('Claude API analysis failed, using fallback assessment:', error.message);
        return generateFallbackAssessment(skillMetadata.name, advisoryMatches);
    }
}
/**
 * Batch assess multiple skills
 * @param skillDirs - Array of skill directory paths
 * @param config - Risk assessment configuration
 * @returns Array of risk assessments
 */
export async function assessMultipleSkills(skillDirs, config = {}) {
    const assessments = [];
    for (const skillDir of skillDirs) {
        try {
            const assessment = await assessSkillRisk(skillDir, config);
            assessments.push(assessment);
        }
        catch (error) {
            console.warn(`Failed to assess skill at ${skillDir}:`, error.message);
            // Continue with other skills
        }
    }
    return assessments;
}
/**
 * Formats risk assessment as human-readable text
 * @param assessment - Risk assessment result
 * @returns Formatted text report
 */
export function formatRiskAssessment(assessment) {
    const lines = [];
    lines.push(`# Risk Assessment: ${assessment.skillName}`);
    lines.push('');
    lines.push(`**Risk Score:** ${assessment.riskScore}/100 (${assessment.severity.toUpperCase()})`);
    lines.push(`**Recommendation:** ${assessment.recommendation.toUpperCase()}`);
    lines.push('');
    lines.push('## Rationale');
    lines.push(assessment.rationale);
    lines.push('');
    if (assessment.findings.length > 0) {
        lines.push('## Security Findings');
        for (const finding of assessment.findings) {
            lines.push(`- **[${finding.severity.toUpperCase()}] ${finding.category}**`);
            lines.push(`  ${finding.description}`);
            lines.push(`  Evidence: ${finding.evidence}`);
            lines.push('');
        }
    }
    if (assessment.matchedAdvisories.length > 0) {
        lines.push('## Matched Advisories');
        for (const match of assessment.matchedAdvisories) {
            lines.push(`- **${match.advisory.id}** (${match.advisory.severity})`);
            lines.push(`  ${match.advisory.title}`);
            lines.push(`  Matched: ${match.matchedDependency}`);
            lines.push(`  Reason: ${match.matchReason}`);
            lines.push('');
        }
    }
    return lines.join('\n');
}
