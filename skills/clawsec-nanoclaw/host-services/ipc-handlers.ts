/**
 * ClawSec Advisory Feed IPC Handler Additions for NanoClaw
 *
 * Add this case to the switch statement in /workspace/project/src/ipc.ts
 * inside the processTaskIpc function.
 *
 * This handler processes advisory cache refresh requests from agents.
 */

// Add to IpcDeps interface:
export interface IpcDeps {
  // ... existing deps
  advisoryCacheManager?: AdvisoryCacheManager; // Add this line
}

// Add to processTaskIpc switch statement:

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
