/**
 * Natural language policy parser
 * Converts plain English security policies into structured, enforceable rules
 * using Claude API for semantic understanding
 */

import { ClaudeClient } from './claude-client.js';
import type {
  PolicyParseResult,
  StructuredPolicy,
  AnalystError,
} from './types.js';
import * as crypto from 'node:crypto';

// Confidence threshold for policy acceptance
const CONFIDENCE_THRESHOLD = 0.7;

/**
 * Response structure from Claude API for policy parsing
 */
interface ClaudePolicyResponse {
  policy: {
    type: string;
    condition: {
      operator: string;
      field: string;
      value: string | number | string[];
    };
    action: string;
    description: string;
  };
  confidence: number;
  ambiguities: string[];
}

/**
 * Parse a natural language policy statement into structured format
 * @param nlPolicy - Natural language policy statement
 * @param client - Claude API client instance
 * @returns Promise with structured policy or error if too ambiguous
 */
export async function parsePolicy(
  nlPolicy: string,
  client: ClaudeClient
): Promise<PolicyParseResult> {
  // Validate input
  if (!nlPolicy || nlPolicy.trim().length === 0) {
    throw createError(
      'POLICY_AMBIGUOUS',
      'Policy statement cannot be empty',
      false
    );
  }

  if (nlPolicy.trim().length < 10) {
    throw createError(
      'POLICY_AMBIGUOUS',
      'Policy statement is too short to parse meaningfully (minimum 10 characters)',
      false
    );
  }

  // Call Claude API for policy parsing
  try {
    const responseText = await client.parsePolicy(nlPolicy);

    // Parse JSON response
    const parsedResponse = parsePolicyResponse(responseText);

    // Check confidence threshold
    if (parsedResponse.confidence < CONFIDENCE_THRESHOLD) {
      return {
        policy: null,
        confidence: parsedResponse.confidence,
        ambiguities: parsedResponse.ambiguities.length > 0
          ? parsedResponse.ambiguities
          : ['Policy statement is too ambiguous to parse with sufficient confidence'],
      };
    }

    // Validate parsed policy structure
    validatePolicyStructure(parsedResponse.policy);

    // Create structured policy with metadata
    const structuredPolicy: StructuredPolicy = {
      id: generatePolicyId(),
      type: parsedResponse.policy.type as StructuredPolicy['type'],
      condition: {
        operator: parsedResponse.policy.condition.operator as StructuredPolicy['condition']['operator'],
        field: parsedResponse.policy.condition.field,
        value: parsedResponse.policy.condition.value,
      },
      action: parsedResponse.policy.action as StructuredPolicy['action'],
      description: parsedResponse.policy.description,
      createdAt: new Date().toISOString(),
    };

    return {
      policy: structuredPolicy,
      confidence: parsedResponse.confidence,
      ambiguities: parsedResponse.ambiguities,
    };
  } catch (error) {
    // Check if it's already an AnalystError
    if (isAnalystError(error)) {
      throw error;
    }

    throw createError(
      'CLAUDE_API_ERROR',
      `Failed to parse policy: ${(error as Error).message}`,
      false
    );
  }
}

/**
 * Parse multiple policies in batch
 * @param nlPolicies - Array of natural language policy statements
 * @param client - Claude API client instance
 * @returns Promise with array of parse results
 */
export async function parsePolicies(
  nlPolicies: string[],
  client: ClaudeClient
): Promise<PolicyParseResult[]> {
  const results: PolicyParseResult[] = [];

  // Process policies sequentially to avoid rate limits
  for (const nlPolicy of nlPolicies) {
    try {
      const result = await parsePolicy(nlPolicy, client);
      results.push(result);
    } catch (error) {
      // On error, push a null result with zero confidence
      results.push({
        policy: null,
        confidence: 0,
        ambiguities: [(error as Error).message],
      });
    }
  }

  return results;
}

/**
 * Validate a policy statement without fully parsing it
 * Returns suggestions for improvement if the policy is likely to fail
 * @param nlPolicy - Natural language policy statement
 * @param client - Claude API client instance
 * @returns Promise with validation result and suggestions
 */
export async function validatePolicyStatement(
  nlPolicy: string,
  client: ClaudeClient
): Promise<{ valid: boolean; suggestions: string[] }> {
  try {
    const result = await parsePolicy(nlPolicy, client);

    if (result.confidence < CONFIDENCE_THRESHOLD) {
      return {
        valid: false,
        suggestions: [
          'Policy statement is too ambiguous',
          ...result.ambiguities,
          'Try to be more specific about:',
          '  - What condition triggers the policy',
          '  - What action should be taken',
          '  - What specific values or thresholds to check',
        ],
      };
    }

    return {
      valid: true,
      suggestions: result.ambiguities.length > 0
        ? ['Policy is valid but has minor ambiguities:', ...result.ambiguities]
        : [],
    };
  } catch (error) {
    return {
      valid: false,
      suggestions: [(error as Error).message],
    };
  }
}

/**
 * Parse Claude API response for policy parsing
 * @param responseText - Raw text response from Claude API
 * @returns Parsed policy response
 */
function parsePolicyResponse(responseText: string): ClaudePolicyResponse {
  try {
    // Extract JSON from response (may be wrapped in markdown code blocks)
    const jsonMatch = responseText.match(/```json\s*([\s\S]*?)\s*```/);
    const jsonText = jsonMatch ? jsonMatch[1] : responseText;

    const parsed = JSON.parse(jsonText.trim());

    // Validate response structure
    if (!parsed.policy || typeof parsed.confidence !== 'number') {
      throw new Error('Invalid response structure: missing policy or confidence');
    }

    if (!parsed.policy.type || !parsed.policy.condition || !parsed.policy.action) {
      throw new Error('Invalid policy structure: missing type, condition, or action');
    }

    if (!Array.isArray(parsed.ambiguities)) {
      // Ambiguities is optional, default to empty array
      parsed.ambiguities = [];
    }

    return parsed as ClaudePolicyResponse;
  } catch (error) {
    throw createError(
      'CLAUDE_API_ERROR',
      `Failed to parse Claude API response: ${(error as Error).message}. Response: ${responseText.substring(0, 200)}...`,
      false
    );
  }
}

/**
 * Validate that parsed policy has valid structure
 * @param policy - Parsed policy object
 */
function validatePolicyStructure(policy: ClaudePolicyResponse['policy']): void {
  const validTypes = [
    'advisory-severity',
    'filesystem-access',
    'network-access',
    'dependency-vulnerability',
    'risk-score',
    'custom',
  ];

  const validOperators = [
    'equals',
    'contains',
    'greater_than',
    'less_than',
    'matches_regex',
  ];

  const validActions = [
    'block',
    'warn',
    'require_approval',
    'log',
    'allow',
  ];

  if (!validTypes.includes(policy.type)) {
    throw createError(
      'POLICY_AMBIGUOUS',
      `Invalid policy type: ${policy.type}. Must be one of: ${validTypes.join(', ')}`,
      false
    );
  }

  if (!validOperators.includes(policy.condition.operator)) {
    throw createError(
      'POLICY_AMBIGUOUS',
      `Invalid condition operator: ${policy.condition.operator}. Must be one of: ${validOperators.join(', ')}`,
      false
    );
  }

  if (!validActions.includes(policy.action)) {
    throw createError(
      'POLICY_AMBIGUOUS',
      `Invalid policy action: ${policy.action}. Must be one of: ${validActions.join(', ')}`,
      false
    );
  }

  if (!policy.condition.field || policy.condition.field.trim().length === 0) {
    throw createError(
      'POLICY_AMBIGUOUS',
      'Policy condition must specify a field to evaluate',
      false
    );
  }

  if (policy.condition.value === undefined || policy.condition.value === null) {
    throw createError(
      'POLICY_AMBIGUOUS',
      'Policy condition must specify a value to compare',
      false
    );
  }
}

/**
 * Generate a unique policy ID
 * @returns Policy ID in format: policy-{timestamp}-{random}
 */
function generatePolicyId(): string {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomBytes(4).toString('hex');
  return `policy-${timestamp}-${random}`;
}

/**
 * Format a policy parse result for display
 * @param result - Policy parse result
 * @returns Human-readable formatted string
 */
export function formatPolicyResult(result: PolicyParseResult): string {
  const lines: string[] = [];

  lines.push('=== Policy Parse Result ===');
  lines.push(`Confidence: ${(result.confidence * 100).toFixed(1)}% (threshold: ${CONFIDENCE_THRESHOLD * 100}%)`);

  if (result.ambiguities.length > 0) {
    lines.push('\nAmbiguities:');
    result.ambiguities.forEach(amb => lines.push(`  - ${amb}`));
  }

  if (result.policy) {
    lines.push('\n=== Structured Policy ===');
    lines.push(`ID: ${result.policy.id}`);
    lines.push(`Type: ${result.policy.type}`);
    lines.push(`Action: ${result.policy.action}`);
    lines.push(`Description: ${result.policy.description}`);
    lines.push('\nCondition:');
    lines.push(`  Field: ${result.policy.condition.field}`);
    lines.push(`  Operator: ${result.policy.condition.operator}`);
    lines.push(`  Value: ${JSON.stringify(result.policy.condition.value)}`);
    lines.push(`\nCreated: ${result.policy.createdAt}`);
  } else {
    lines.push('\n❌ Policy failed to parse (confidence too low)');
    lines.push('\nSuggestions:');
    lines.push('  - Be more specific about conditions and actions');
    lines.push('  - Avoid ambiguous terms like "dangerous" or "risky"');
    lines.push('  - Specify exact values or thresholds');
  }

  return lines.join('\n');
}

/**
 * Check if an error is an AnalystError
 * @param error - Error to check
 * @returns True if error is an AnalystError
 */
function isAnalystError(error: unknown): error is AnalystError {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    'message' in error &&
    'recoverable' in error
  );
}

/**
 * Create a typed AnalystError
 * @param code - Error code
 * @param message - Error message
 * @param recoverable - Whether error is recoverable
 * @returns AnalystError
 */
function createError(
  code: string,
  message: string,
  recoverable: boolean
): AnalystError {
  return {
    code,
    message,
    recoverable,
  };
}

/**
 * Get the confidence threshold for policy acceptance
 * @returns Confidence threshold (0.0 to 1.0)
 */
export function getConfidenceThreshold(): number {
  return CONFIDENCE_THRESHOLD;
}
