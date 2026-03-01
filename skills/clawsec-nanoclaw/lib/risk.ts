/**
 * Shared advisory risk evaluation for NanoClaw host + MCP layers.
 */

export type SkillSafetyRecommendation = 'install' | 'block' | 'review';

export interface AdvisoryRiskInput {
  severity?: string;
  type?: string;
  action?: string;
  exploitability_score?: string;
}

export interface AdvisoryRiskEvaluation {
  safe: boolean;
  recommendation: SkillSafetyRecommendation;
  reason: string;
}

export function normalizeExploitabilityScore(score: unknown): 'high' | 'medium' | 'low' | 'unknown' {
  const value = String(score || '').toLowerCase().trim();
  if (value === 'high' || value === 'medium' || value === 'low') {
    return value;
  }
  return 'unknown';
}

export function evaluateAdvisoryRisk(advisories: AdvisoryRiskInput[]): AdvisoryRiskEvaluation {
  if (advisories.length === 0) {
    return { safe: true, recommendation: 'install', reason: 'No advisories found' };
  }

  const hasMalicious = advisories.some((a) => String(a.type || '').toLowerCase().includes('malicious'));
  const hasRemoveAction = advisories.some((a) =>
    /\b(remove|uninstall|disable|quarantine|block)\b/i.test(String(a.action || ''))
  );
  const hasCritical = advisories.some((a) => String(a.severity || '').toLowerCase() === 'critical');
  const hasHigh = advisories.some((a) => String(a.severity || '').toLowerCase() === 'high');
  const hasHighExploitability = advisories.some(
    (a) => normalizeExploitabilityScore(a.exploitability_score) === 'high'
  );

  if (hasMalicious || hasRemoveAction) {
    return {
      safe: false,
      recommendation: 'block',
      reason: 'Malicious skill or removal recommended by ClawSec',
    };
  }

  if (hasCritical && hasHighExploitability) {
    return {
      safe: false,
      recommendation: 'block',
      reason: 'Critical advisory with high exploitability context - do not install',
    };
  }

  if (hasCritical) {
    return {
      safe: false,
      recommendation: 'block',
      reason: 'Critical security advisory - do not install',
    };
  }

  if (hasHighExploitability) {
    return {
      safe: false,
      recommendation: 'review',
      reason: 'High exploitability advisory - urgent user review strongly recommended',
    };
  }

  if (hasHigh) {
    return {
      safe: false,
      recommendation: 'review',
      reason: 'High severity advisory - user review strongly recommended',
    };
  }

  return {
    safe: false,
    recommendation: 'review',
    reason: 'Advisory found - review details before installing',
  };
}
