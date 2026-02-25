/**
 * ClawSec File Integrity Monitoring MCP Tools for NanoClaw
 *
 * Add these tools to /workspace/project/container/agent-runner/src/ipc-mcp-stdio.ts
 *
 * These tools run in the container context and communicate with the host-side
 * integrity monitor via IPC.
 */

import fs from 'fs';
import path from 'path';
import { z } from 'zod';

// These variables are provided by the host environment (ipc-mcp-stdio.ts)
// when this code is integrated into the NanoClaw container agent.
/* eslint-disable @typescript-eslint/no-explicit-any */
declare const server: { tool: (...args: any[]) => void };
declare function writeIpcFile(dir: string, data: any): void;
declare const TASKS_DIR: string;
declare const groupFolder: string;
/* eslint-enable @typescript-eslint/no-explicit-any */

// Result waiting helper
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function waitForResult(requestId: string, timeoutMs: number = 60000): Promise<any> {
  const resultDir = '/workspace/ipc/clawsec_results';
  const resultPath = path.join(resultDir, `${requestId}.json`);

  const startTime = Date.now();
  while (Date.now() - startTime < timeoutMs) {
    if (fs.existsSync(resultPath)) {
      const result = JSON.parse(fs.readFileSync(resultPath, 'utf-8'));
      fs.unlinkSync(resultPath); // Cleanup
      return result;
    }
    await new Promise(resolve => setTimeout(resolve, 1000)); // Poll every 1s
  }

  throw new Error(`Timeout waiting for result: ${requestId}`);
}

// ============================================================================
// MCP Tool 1: clawsec_check_integrity
// ============================================================================

server.tool(
  'clawsec_check_integrity',
  'Check protected files for unauthorized changes (drift). Automatically restores critical files to approved baselines. Use this for scheduled integrity monitoring or manual security checks.',
  {
    mode: z.enum(['check', 'status']).optional().describe('check=detect drift and restore, status=view baselines only (default: check)'),
    autoRestore: z.boolean().optional().describe('Auto-restore files in restore mode (default: true)'),
  },
  async (args) => {
    const requestId = `integrity-check-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    // Write IPC request
    writeIpcFile(TASKS_DIR, {
      type: 'integrity_check',
      requestId,
      mode: args.mode || 'check',
      autoRestore: args.autoRestore !== false,
      groupFolder,
      timestamp: new Date().toISOString()
    });

    try {
      // Wait for result
      const result = await waitForResult(requestId, 60000);

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
        isError: !result.success
      };
    } catch (error) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: `Integrity check failed: ${error instanceof Error ? error.message : String(error)}`
          }, null, 2)
        }],
        isError: true
      };
    }
  }
);

// ============================================================================
// MCP Tool 2: clawsec_approve_change
// ============================================================================

server.tool(
  'clawsec_approve_change',
  'Approve an intentional file modification as the new approved baseline. Use this after making legitimate changes to protected files (e.g., updating CLAUDE.md or registered_groups.json).',
  {
    path: z.string().describe('Absolute path to file to approve (e.g., /workspace/group/CLAUDE.md)'),
    note: z.string().optional().describe('Optional note explaining why this change is being approved'),
  },
  async (args) => {
    const requestId = `integrity-approve-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    // Write IPC request
    writeIpcFile(TASKS_DIR, {
      type: 'integrity_approve',
      requestId,
      path: args.path,
      note: args.note || '',
      approvedBy: 'agent', // In production, should be user JID
      groupFolder,
      timestamp: new Date().toISOString()
    });

    try {
      const result = await waitForResult(requestId, 30000);

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
        isError: !result.success
      };
    } catch (error) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: `Approve failed: ${error instanceof Error ? error.message : String(error)}`
          }, null, 2)
        }],
        isError: true
      };
    }
  }
);

// ============================================================================
// MCP Tool 3: clawsec_integrity_status
// ============================================================================

server.tool(
  'clawsec_integrity_status',
  'View current baseline status for protected files without checking for drift. Use this to see what files are monitored, when baselines were created, and their current hashes.',
  {
    path: z.string().optional().describe('Optional: specific file path to check. If omitted, shows all protected files.'),
  },
  async (args) => {
    const requestId = `integrity-status-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    writeIpcFile(TASKS_DIR, {
      type: 'integrity_status',
      requestId,
      path: args.path,
      groupFolder,
      timestamp: new Date().toISOString()
    });

    try {
      const result = await waitForResult(requestId, 30000);

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
        isError: !result.success
      };
    } catch (error) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: `Status check failed: ${error instanceof Error ? error.message : String(error)}`
          }, null, 2)
        }],
        isError: true
      };
    }
  }
);

// ============================================================================
// MCP Tool 4: clawsec_verify_audit
// ============================================================================

server.tool(
  'clawsec_verify_audit',
  'Verify the integrity of the audit log hash chain. Use this to detect if the audit log has been tampered with. A valid chain proves all logged events are authentic.',
  {},
  async () => {
    const requestId = `integrity-verify-audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    writeIpcFile(TASKS_DIR, {
      type: 'integrity_verify_audit',
      requestId,
      groupFolder,
      timestamp: new Date().toISOString()
    });

    try {
      const result = await waitForResult(requestId, 30000);

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
        isError: !result.success
      };
    } catch (error) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: `Audit verification failed: ${error instanceof Error ? error.message : String(error)}`
          }, null, 2)
        }],
        isError: true
      };
    }
  }
);

// ============================================================================
// Usage Examples (for documentation)
// ============================================================================

// Usage Examples (for documentation):
//
// Example 1: Scheduled Integrity Check
//
// schedule_task({
//   prompt: 'Check file integrity with clawsec_check_integrity...',
//   schedule_type: 'cron',
//   schedule_value: '0,30 * * * *',  // Every 30 minutes
//   context_mode: 'isolated'
// });
//
// Example 2: Pre-Deployment Check
//
// const check = await tools.clawsec_check_integrity({ mode: 'check', autoRestore: false });
// if (check.drift_detected) { ... }
//
// Example 3: Approve Legitimate Changes
//
// await tools.clawsec_approve_change({
//   path: '/workspace/group/CLAUDE.md',
//   note: 'Updated agent instructions to include new skill'
// });
//
// Example 4: Audit Verification
//
// const audit = await tools.clawsec_verify_audit();
// if (!audit.valid) { ... }
