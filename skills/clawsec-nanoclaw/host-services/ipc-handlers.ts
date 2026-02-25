/**
 * ClawSec Advisory Feed IPC Handler Additions for NanoClaw
 *
 * Add this case to the switch statement in /workspace/project/src/ipc.ts
 * inside the processTaskIpc function.
 *
 * This handler processes advisory cache refresh requests from agents.
 */

import { AdvisoryCacheManager } from './advisory-cache';
import { SkillSignatureVerifier } from './skill-signature-handler';

// Add to IpcDeps interface:
export interface IpcDeps {
  advisoryCacheManager?: AdvisoryCacheManager;
  signatureVerifier?: SkillSignatureVerifier;
}

interface IpcLogger {
  info(obj: Record<string, unknown>, msg?: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type IpcTask = Record<string, any>;

/**
 * Placeholder for the host-side writeResponse function.
 * The actual implementation lives in the NanoClaw host process.
 */
declare function writeResponse(requestId: string, data: Record<string, unknown>): Promise<void>;

/**
 * Handle advisory and signature IPC tasks.
 *
 * In the host process, call this from the processTaskIpc switch statement
 * for the 'refresh_advisory_cache' and 'verify_skill_signature' cases.
 */
export async function handleAdvisoryIpc(
  task: IpcTask,
  deps: IpcDeps,
  logger: IpcLogger,
  sourceGroup: string,
): Promise<void> {
  switch (task.type) {
    case 'refresh_advisory_cache':
      // Any group can request cache refresh (rate-limited by cache manager)
      logger.info({ sourceGroup }, 'Advisory cache refresh requested via IPC');
      if (deps.advisoryCacheManager) {
        try {
          await deps.advisoryCacheManager.refresh();
          logger.info({ sourceGroup }, 'Advisory cache refreshed successfully');
        } catch (error) {
          logger.error({ error, sourceGroup }, 'Advisory cache refresh failed');
        }
      } else {
        logger.warn({ sourceGroup }, 'Advisory cache manager not initialized');
      }
      break;

    case 'verify_skill_signature': {
      // Skill signature verification (Phase 1)
      const { requestId, packagePath, signaturePath, publicKeyPem, allowUnsigned } = task;

      logger.info({ sourceGroup, requestId, packagePath }, 'Verifying skill signature');

      try {
        if (!deps.signatureVerifier) {
          throw new Error('Signature verification service not available');
        }

        const result = await deps.signatureVerifier.verify({
          packagePath,
          signaturePath,
          publicKeyPem,
          allowUnsigned: allowUnsigned || false,
        });

        await writeResponse(requestId, {
          success: true,
          message: result.valid ? 'Signature valid' : 'Signature invalid',
          data: result,
        });

        logger.info(
          { sourceGroup, requestId, valid: result.valid, signer: result.signer },
          'Signature verification completed'
        );
      } catch (error: unknown) {
        const err = error as Error & { code?: string };
        logger.error({ error, sourceGroup, requestId, packagePath }, 'Signature verification failed');

        const errorCode = err.code || 'CRYPTO_ERROR';
        await writeResponse(requestId, {
          success: false,
          message: err.message || 'Verification failed',
          error: {
            code: errorCode,
            details: error
          }
        });
      }
      break;
    }
  }
}
