/**
 * ClawSec Skill Signature Verification MCP Tool for NanoClaw
 *
 * Add this tool to /workspace/project/container/agent-runner/src/ipc-mcp-stdio.ts
 *
 * This tool verifies Ed25519 signatures on skill packages to prevent supply chain attacks.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
import fs from 'fs';
import path from 'path';
import { z } from 'zod';

// These variables are provided by the host environment (ipc-mcp-stdio.ts)
// when this code is integrated into the NanoClaw container agent.
declare const server: { tool: (...args: any[]) => void };
declare function writeIpcFile(dir: string, data: any): void;
declare const TASKS_DIR: string;
declare const groupFolder: string;

// Result waiting helper
async function waitForResult(requestId: string, timeoutMs: number = 5000): Promise<any> {
  const resultDir = '/workspace/ipc/clawsec_results';
  const resultPath = path.join(resultDir, `${requestId}.json`);

  const startTime = Date.now();
  while (Date.now() - startTime < timeoutMs) {
    if (fs.existsSync(resultPath)) {
      const result = JSON.parse(fs.readFileSync(resultPath, 'utf-8'));
      fs.unlinkSync(resultPath); // Cleanup
      return result;
    }
    await new Promise(resolve => setTimeout(resolve, 100)); // Poll every 100ms
  }

  throw new Error(`Timeout waiting for result: ${requestId}`);
}

// ============================================================================
// MCP Tool: clawsec_verify_skill_package
// ============================================================================

server.tool(
  'clawsec_verify_skill_package',
  'Verify Ed25519 signature of a skill package before installation. Prevents installation of tampered or malicious skill packages by checking ClawSec signatures.',
  {
    packagePath: z.string().describe('Absolute path to skill package (.tar.gz or .zip)'),
    signaturePath: z.string().optional().describe('Path to signature file. If omitted, auto-detects <packagePath>.sig'),
  },
  async (args: { packagePath: string; signaturePath?: string }) => {
    const requestId = `verify-signature-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const sigPath = args.signaturePath || `${args.packagePath}.sig`;

    // Validate package file exists
    if (!fs.existsSync(args.packagePath)) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            valid: false,
            recommendation: 'block',
            error: `Package file not found: ${args.packagePath}`
          }, null, 2)
        }],
        isError: true
      };
    }

    // Write IPC request to host
    writeIpcFile(TASKS_DIR, {
      type: 'verify_skill_signature',
      requestId,
      groupFolder,
      timestamp: new Date().toISOString(),
      packagePath: args.packagePath,
      signaturePath: sigPath,
    });

    try {
      // Wait for host to verify (5 second timeout)
      const result = await waitForResult(requestId, 5000);

      if (!result.success) {
        // Service error or file not found
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              success: false,
              valid: false,
              recommendation: 'block',
              packagePath: args.packagePath,
              signaturePath: sigPath,
              error: result.message || 'Verification failed',
              reason: result.error?.code || 'UNKNOWN_ERROR'
            }, null, 2)
          }],
          isError: true
        };
      }

      // Check if signature is valid
      if (!result.data?.valid) {
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              success: true,
              valid: false,
              recommendation: 'block',
              packagePath: args.packagePath,
              signaturePath: sigPath,
              reason: result.data?.error || 'Signature verification failed',
              packageInfo: {
                sha256: result.data?.packageHash || 'unknown'
              }
            }, null, 2)
          }],
        };
      }

      // Signature valid!
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: true,
            valid: true,
            recommendation: 'install',
            packagePath: args.packagePath,
            signaturePath: sigPath,
            signer: result.data.signer,
            algorithm: result.data.algorithm,
            verifiedAt: result.data.verifiedAt,
            packageInfo: {
              size: fs.statSync(args.packagePath).size,
              sha256: result.data.packageHash
            }
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            valid: false,
            recommendation: 'block',
            error: `Verification timeout or error: ${error instanceof Error ? error.message : String(error)}`
          }, null, 2)
        }],
        isError: true
      };
    }
  }
);
