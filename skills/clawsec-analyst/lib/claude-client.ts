/**
 * Claude API client wrapper with retry logic and error handling
 * Implements exponential backoff for rate limits and transient failures
 */

import Anthropic from '@anthropic-ai/sdk';
import type { AnalystError, ErrorCode } from './types.js';

// Default configuration
const DEFAULT_MODEL = 'claude-sonnet-4-5-20250929';
const DEFAULT_MAX_TOKENS = 2048;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_INITIAL_DELAY_MS = 1000;

/**
 * Claude API client configuration
 */
export interface ClaudeClientConfig {
  apiKey?: string;
  model?: string;
  maxTokens?: number;
  maxRetries?: number;
  initialDelayMs?: number;
}

/**
 * Claude API request options
 */
export interface ClaudeRequestOptions {
  model?: string;
  maxTokens?: number;
  systemPrompt?: string;
}

/**
 * Claude API client for security analysis
 */
export class ClaudeClient {
  private client: Anthropic;
  private config: Required<ClaudeClientConfig>;

  constructor(config: ClaudeClientConfig = {}) {
    // Get API key from config or environment
    const apiKey = config.apiKey || process.env['ANTHROPIC_API_KEY'];

    if (!apiKey) {
      throw this.createError(
        'MISSING_API_KEY',
        'ANTHROPIC_API_KEY environment variable is required. Get your key from https://console.anthropic.com/',
        false
      );
    }

    this.client = new Anthropic({ apiKey });

    this.config = {
      apiKey,
      model: config.model || DEFAULT_MODEL,
      maxTokens: config.maxTokens || DEFAULT_MAX_TOKENS,
      maxRetries: config.maxRetries || DEFAULT_MAX_RETRIES,
      initialDelayMs: config.initialDelayMs || DEFAULT_INITIAL_DELAY_MS,
    };
  }

  /**
   * Send a message to Claude API with retry logic
   */
  async sendMessage(
    userMessage: string,
    options: ClaudeRequestOptions = {}
  ): Promise<string> {
    const model = options.model || this.config.model;
    const maxTokens = options.maxTokens || this.config.maxTokens;

    const messages: Anthropic.MessageParam[] = [
      { role: 'user', content: userMessage }
    ];

    const requestParams: Anthropic.MessageCreateParams = {
      model,
      max_tokens: maxTokens,
      messages,
    };

    // Add system prompt if provided
    if (options.systemPrompt) {
      requestParams.system = options.systemPrompt;
    }

    // Execute with retry logic
    const response = await this.callWithRetry(async () => {
      return await this.client.messages.create(requestParams);
    });

    // Extract text from response
    const textContent = response.content.find(
      (block): block is Anthropic.TextBlock => block.type === 'text'
    );

    if (!textContent) {
      throw this.createError(
        'CLAUDE_API_ERROR',
        'No text content in Claude API response',
        false
      );
    }

    return textContent.text;
  }

  /**
   * Analyze security advisory with structured prompt
   */
  async analyzeAdvisory(advisory: unknown): Promise<string> {
    const prompt = `Analyze this security advisory and provide a structured assessment.

Advisory Data:
${JSON.stringify(advisory, null, 2)}

Provide your analysis in the following JSON format:
{
  "priority": "HIGH" | "MEDIUM" | "LOW",
  "rationale": "detailed explanation of priority assessment",
  "affected_components": ["list", "of", "affected", "components"],
  "recommended_actions": ["prioritized", "list", "of", "remediation", "steps"],
  "confidence": 0.0-1.0
}`;

    return await this.sendMessage(prompt, {
      systemPrompt: 'You are a security analyst specializing in vulnerability triage and risk assessment. Provide structured, actionable security analysis.',
    });
  }

  /**
   * Assess risk for skill installation
   */
  async assessSkillRisk(skillMetadata: unknown): Promise<string> {
    const prompt = `Assess the security risk of installing this skill.

Skill Metadata:
${JSON.stringify(skillMetadata, null, 2)}

Provide your assessment in the following JSON format:
{
  "riskScore": 0-100,
  "severity": "critical" | "high" | "medium" | "low",
  "findings": [
    {
      "category": "filesystem" | "network" | "execution" | "dependencies" | "permissions",
      "severity": "critical" | "high" | "medium" | "low",
      "description": "detailed finding description",
      "evidence": "specific evidence from metadata"
    }
  ],
  "recommendation": "approve" | "review" | "block",
  "rationale": "detailed explanation of risk score and recommendation"
}`;

    return await this.sendMessage(prompt, {
      systemPrompt: 'You are a security analyst specializing in supply chain security and code review. Identify potential security risks in skill installations.',
    });
  }

  /**
   * Parse natural language security policy
   */
  async parsePolicy(naturalLanguagePolicy: string): Promise<string> {
    const prompt = `Parse this natural language security policy into a structured format.

Policy Statement: "${naturalLanguagePolicy}"

Provide your analysis in the following JSON format:
{
  "policy": {
    "type": "advisory-severity" | "filesystem-access" | "network-access" | "dependency-vulnerability" | "risk-score" | "custom",
    "condition": {
      "operator": "equals" | "contains" | "greater_than" | "less_than" | "matches_regex",
      "field": "field name to evaluate",
      "value": "value or pattern to match"
    },
    "action": "block" | "warn" | "require_approval" | "log" | "allow",
    "description": "human-readable description of the policy"
  },
  "confidence": 0.0-1.0,
  "ambiguities": ["list", "of", "any", "ambiguous", "aspects"]
}

If the policy statement is too ambiguous or unimplementable, set confidence < 0.7 and list specific ambiguities.`;

    return await this.sendMessage(prompt, {
      systemPrompt: 'You are a security policy analyst. Parse natural language policies into structured, enforceable rules.',
    });
  }

  /**
   * Execute a function with exponential backoff retry logic
   */
  private async callWithRetry<T>(
    fn: () => Promise<T>,
  ): Promise<T> {
    let lastError: Error | undefined;
    const maxRetries = this.config.maxRetries;
    const initialDelayMs = this.config.initialDelayMs;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error as Error;

        // Check if error is retryable
        const isRetryable = this.isRetryableError(error);

        if (!isRetryable || attempt === maxRetries) {
          // Convert to AnalystError if it's an API error
          if (error instanceof Anthropic.APIError) {
            throw this.createErrorFromAPIError(error);
          }
          throw error;
        }

        // Calculate delay with exponential backoff: 1s, 2s, 4s
        const delayMs = initialDelayMs * Math.pow(2, attempt);

        // Log retry attempt (not to console in production)
        if (process.env['NODE_ENV'] !== 'test') {
          console.warn(
            `Claude API error (attempt ${attempt + 1}/${maxRetries + 1}): ${(error as Error).message}. Retrying in ${delayMs}ms...`
          );
        }

        await this.sleep(delayMs);
      }
    }

    throw lastError!;
  }

  /**
   * Determine if an error is retryable
   */
  private isRetryableError(error: unknown): boolean {
    if (!(error instanceof Anthropic.APIError)) {
      // Network errors and other non-API errors are retryable
      return true;
    }

    // Retry on rate limits (429)
    if (error.status === 429) {
      return true;
    }

    // Retry on server errors (5xx)
    if (error.status && error.status >= 500 && error.status < 600) {
      return true;
    }

    // Don't retry on client errors (4xx) except 429
    // This includes 401 (auth), 400 (bad request), 403 (forbidden), etc.
    return false;
  }

  /**
   * Create an AnalystError from Anthropic APIError
   */
  private createErrorFromAPIError(error: InstanceType<typeof Anthropic.APIError>): AnalystError {
    let code: ErrorCode = 'CLAUDE_API_ERROR';
    let message = error.message;

    if (error.status === 401) {
      code = 'MISSING_API_KEY';
      message = 'Invalid or missing API key. Check your ANTHROPIC_API_KEY.';
    } else if (error.status === 429) {
      code = 'RATE_LIMIT_EXCEEDED';
      message = 'Claude API rate limit exceeded. Please try again later.';
    } else if (error.status && error.status >= 500) {
      code = 'NETWORK_FAILURE';
      message = `Claude API server error: ${error.message}`;
    }

    return this.createError(code, message, error.status === 429 || (error.status !== undefined && error.status >= 500));
  }

  /**
   * Create a typed AnalystError
   */
  private createError(
    code: ErrorCode,
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
   * Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get current configuration (for testing/debugging)
   */
  getConfig(): Readonly<Required<ClaudeClientConfig>> {
    return { ...this.config };
  }
}

/**
 * Create a default Claude client instance
 */
export function createClaudeClient(config?: ClaudeClientConfig): ClaudeClient {
  return new ClaudeClient(config);
}
