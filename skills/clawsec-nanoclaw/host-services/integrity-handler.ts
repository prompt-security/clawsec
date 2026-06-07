/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * ClawSec File Integrity Monitoring IPC Handler for NanoClaw Host
 *
 * Add these handlers to /workspace/project/src/ipc.ts
 *
 * This processes integrity monitoring requests from agents running in containers.
 */

import fs from 'fs';
import path from 'path';
import { IntegrityMonitor } from '../guardian/integrity-monitor';

const RESULT_DIR = '/workspace/ipc/clawsec_results';
const REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

// ============================================================================
// Integrity Service (Singleton)
// ============================================================================

export class IntegrityService {
  private monitor: IntegrityMonitor | null = null;
  private initialized = false;

  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      this.monitor = new IntegrityMonitor({
        policyPath: '/workspace/project/skills/clawsec-nanoclaw/guardian/policy.json',
        stateDir: '/workspace/project/data/soul-guardian'
      });

      // Initialize baselines on first run
      await this.monitor.init('system', 'initial baseline');

      this.initialized = true;
      console.log('[IntegrityService] Initialized successfully');
    } catch (error) {
      console.error('[IntegrityService] Initialization failed:', error);
      throw error;
    }
  }

  getMonitor(): IntegrityMonitor {
    if (!this.monitor) {
      throw new Error('IntegrityService not initialized');
    }
    return this.monitor;
  }

  isInitialized(): boolean {
    return this.initialized;
  }
}

// Global singleton instance
let integrityServiceInstance: IntegrityService | null = null;

export function getIntegrityService(): IntegrityService {
  if (!integrityServiceInstance) {
    integrityServiceInstance = new IntegrityService();
  }
  return integrityServiceInstance;
}

// ============================================================================
// IPC Handler Integration
// ============================================================================

/**
 * Add this to the IpcDeps interface in /workspace/project/src/ipc.ts:
 *
 * export interface IpcDeps {
 *   // ... existing deps
 *   integrityService?: IntegrityService;
 * }
 */

/**
 * Add these cases to the switch statement in processTaskIpc:
 */

export async function handleIntegrityIpc(
  task: any,
  deps: { integrityService?: IntegrityService },
  logger: any
): Promise<void> {
  const { type, requestId, groupFolder: _groupFolder } = task;
  const validatedRequestId = validateRequestId(requestId);

  if (!validatedRequestId) {
    logger.warn({ type, requestId }, 'Invalid integrity IPC request id');
    return;
  }

  const safeTask = { ...task, requestId: validatedRequestId };

  if (!deps.integrityService) {
    logger.warn({ task }, 'IntegrityService not available');
    writeResult(validatedRequestId, {
      success: false,
      error: 'IntegrityService not initialized'
    });
    return;
  }

  const service = deps.integrityService;

  if (!service.isInitialized()) {
    try {
      await service.initialize();
    } catch (error) {
      logger.error({ error }, 'Failed to initialize IntegrityService');
      writeResult(validatedRequestId, {
        success: false,
        error: `Initialization failed: ${error instanceof Error ? error.message : String(error)}`
      });
      return;
    }
  }

  switch (type) {
    case 'integrity_check':
      await handleIntegrityCheck(safeTask, service, logger);
      break;

    case 'integrity_approve':
      await handleIntegrityApprove(safeTask, service, logger);
      break;

    case 'integrity_status':
      await handleIntegrityStatus(safeTask, service, logger);
      break;

    case 'integrity_verify_audit':
      await handleIntegrityVerifyAudit(safeTask, service, logger);
      break;

    default:
      logger.warn({ type }, 'Unknown integrity task type');
  }
}

// ============================================================================
// Individual Handlers
// ============================================================================

async function handleIntegrityCheck(
  task: any,
  service: IntegrityService,
  logger: any
): Promise<void> {
  const { requestId, mode, autoRestore, groupFolder } = task;

  logger.info({ requestId, groupFolder }, 'Processing integrity_check');

  try {
    const monitor = service.getMonitor();

    if (mode === 'status') {
      // Status mode: just return baseline info
      const status = monitor.getStatus();
      writeResult(requestId, {
        success: true,
        mode: 'status',
        ...status
      });
    } else {
      // Check mode: detect drift and optionally restore
      const result = await monitor.checkIntegrity(autoRestore !== false, 'agent');

      writeResult(requestId, result);

      if (result.drift_detected) {
        logger.warn(
          { requestId, drifted: result.summary.drifted, restored: result.summary.restored },
          'Integrity drift detected'
        );
      } else {
        logger.info({ requestId }, 'Integrity check passed');
      }
    }
  } catch (error) {
    logger.error({ error, requestId }, 'Integrity check failed');
    writeResult(requestId, {
      success: false,
      error: error instanceof Error ? error.message : String(error)
    });
  }
}

async function handleIntegrityApprove(
  task: any,
  service: IntegrityService,
  logger: any
): Promise<void> {
  const { requestId, path: filePath, note, approvedBy, groupFolder } = task;

  logger.info({ requestId, filePath, groupFolder }, 'Processing integrity_approve');

  try {
    const monitor = service.getMonitor();

    await monitor.approveChange(filePath, approvedBy || 'agent', note || '');

    writeResult(requestId, {
      success: true,
      path: filePath,
      approved_at: new Date().toISOString(),
      approved_by: approvedBy,
      note
    });

    logger.info({ requestId, filePath }, 'File change approved');
  } catch (error) {
    logger.error({ error, requestId, filePath }, 'Approve change failed');
    writeResult(requestId, {
      success: false,
      error: error instanceof Error ? error.message : String(error),
      path: filePath
    });
  }
}

async function handleIntegrityStatus(
  task: any,
  service: IntegrityService,
  logger: any
): Promise<void> {
  const { requestId, path: filePath, groupFolder } = task;

  logger.info({ requestId, filePath, groupFolder }, 'Processing integrity_status');

  try {
    const monitor = service.getMonitor();
    const status = monitor.getStatus(filePath);

    writeResult(requestId, {
      success: true,
      ...status
    });

    logger.info({ requestId }, 'Status retrieved');
  } catch (error) {
    logger.error({ error, requestId }, 'Status check failed');
    writeResult(requestId, {
      success: false,
      error: error instanceof Error ? error.message : String(error)
    });
  }
}

async function handleIntegrityVerifyAudit(
  task: any,
  service: IntegrityService,
  logger: any
): Promise<void> {
  const { requestId, groupFolder } = task;

  logger.info({ requestId, groupFolder }, 'Processing integrity_verify_audit');

  try {
    const monitor = service.getMonitor();
    const verification = monitor.verifyAuditChain();

    writeResult(requestId, {
      success: true,
      ...verification
    });

    if (!verification.valid) {
      logger.error({ requestId, errors: verification.errors }, 'Audit chain verification failed');
    } else {
      logger.info({ requestId, entries: verification.entries }, 'Audit chain verified');
    }
  } catch (error) {
    logger.error({ error, requestId }, 'Audit verification failed');
    writeResult(requestId, {
      success: false,
      error: error instanceof Error ? error.message : String(error)
    });
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function validateRequestId(requestId: unknown): string | null {
  if (typeof requestId !== 'string') return null;
  const normalized = requestId.trim();
  if (!REQUEST_ID_PATTERN.test(normalized)) return null;
  return normalized;
}

function resolveResultPath(requestId: string): string {
  const safeRequestId = validateRequestId(requestId);
  if (!safeRequestId) {
    throw new Error('Invalid integrity IPC request id');
  }

  const resultDir = RESULT_DIR;
  const normalizedResultDir = path.resolve(resultDir);
  const resultPath = path.resolve(normalizedResultDir, `${safeRequestId}.json`);
  const relativePath = path.relative(normalizedResultDir, resultPath);

  if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
    throw new Error('Integrity IPC result path escapes result directory');
  }

  return resultPath;
}

function writeResult(requestId: string, result: any): void {
  const resultPath = resolveResultPath(requestId);
  const resultDir = path.dirname(resultPath);

  // Ensure directory exists
  if (!fs.existsSync(resultDir)) {
    fs.mkdirSync(resultDir, { recursive: true });
  }

  fs.writeFileSync(resultPath, JSON.stringify(result, null, 2));
}

// ============================================================================
// Integration Instructions
// ============================================================================

/**
 * To integrate into NanoClaw host process:
 *
 * 1. Add IntegrityService to IpcDeps in src/ipc.ts:
 *
 *    import { IntegrityService, getIntegrityService } from '../skills/clawsec-nanoclaw/host-services/integrity-handler';
 *
 *    export interface IpcDeps {
 *      // ... existing deps
 *      integrityService?: IntegrityService;
 *    }
 *
 * 2. Initialize in main.ts:
 *
 *    const integrityService = getIntegrityService();
 *    await integrityService.initialize();
 *
 *    const ipcDeps: IpcDeps = {
 *      // ... existing deps
 *      integrityService
 *    };
 *
 * 3. Add handler calls in processTaskIpc switch statement:
 *
 *    case 'integrity_check':
 *    case 'integrity_approve':
 *    case 'integrity_status':
 *    case 'integrity_verify_audit':
 *      await handleIntegrityIpc(task, deps, logger);
 *      break;
 *
 * 4. Ensure /workspace/ipc/clawsec_results/ directory exists and is writable
 *
 * 5. Ensure /workspace/project/data/soul-guardian/ directory exists and is writable
 */

// Example scheduled task for continuous monitoring:
//
// schedule_task({
//   prompt: `
//     Run clawsec_check_integrity to check for file tampering.
//     If drift_detected is true and files were restored, send alert:
//     "SECURITY: Unauthorized changes detected and reverted in:
//     [list restored files with their paths]
//     Review patches in /workspace/project/data/soul-guardian/patches/"
//   `,
//   schedule_type: 'cron',
//   schedule_value: '*/30 * * * *',  // Every 30 minutes
//   context_mode: 'isolated'
// });
