/**
 * File Integrity Monitor for NanoClaw
 *
 * TypeScript port of ClawSec's soul-guardian with NanoClaw-specific adaptations.
 *
 * Key Features:
 * - SHA-256 baseline tracking for protected files
 * - Drift detection with unified diff generation
 * - Auto-restore for critical files (with quarantine)
 * - Hash-chained tamper-evident audit log
 * - Per-file policy (restore/alert/ignore modes)
 *
 * Security Model:
 * - Baselines stored on host only (containers access via IPC)
 * - Atomic file operations for restores
 * - Refuses to operate on symlinks
 * - Hash-chained audit log prevents tampering
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
// glob is available when running in the NanoClaw host environment.
// For type checking in the clawsec repo, we declare a minimal interface.
// eslint-disable-next-line @typescript-eslint/no-namespace
declare namespace glob {
  function sync(pattern: string, options?: { nodir?: boolean }): string[];
}

// ============================================================================
// Types
// ============================================================================

export interface PolicyTarget {
  path?: string;
  pattern?: string;
  mode: 'restore' | 'alert' | 'ignore';
  priority: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}

export interface Policy {
  version: number;
  description: string;
  nanoclaw_version: string;
  targets: PolicyTarget[];
  notes?: string[];
}

export interface FileBaseline {
  sha256: string;
  approved_at: string;
  approved_by: string;
  mode: 'restore' | 'alert' | 'ignore';
  priority: string;
}

export interface BaselinesManifest {
  schema_version: string;
  algorithm: 'sha256';
  created_at: string;
  files: Record<string, FileBaseline>;
}

export interface AuditEntry {
  ts: string;
  event: 'init' | 'drift' | 'restore' | 'approve' | 'error';
  actor: string;
  note?: string;
  path: string;
  mode?: string;
  expected_sha?: string;
  found_sha?: string;
  patch_path?: string;
  quarantine_path?: string;
  error?: string;
  chain?: {
    prev: string;
    hash: string;
  };
}

export interface DriftedFile {
  path: string;
  mode: 'restore' | 'alert';
  expected_sha: string;
  found_sha: string;
  patch_path: string;
  restored: boolean;
  quarantine_path?: string;
  error?: string;
}

export interface CheckResult {
  success: boolean;
  timestamp: string;
  drift_detected: boolean;
  files: Array<{
    path: string;
    status: 'ok' | 'drifted' | 'restored' | 'error';
    mode: string;
    expected_sha?: string;
    found_sha?: string;
    patch_path?: string;
    quarantine_path?: string;
    error?: string;
  }>;
  summary: {
    total: number;
    ok: number;
    drifted: number;
    restored: number;
    alerted: number;
    errors: number;
  };
}

export interface IntegrityMonitorOptions {
  policyPath: string;
  stateDir: string;
}

// ============================================================================
// Constants
// ============================================================================

const CHAIN_GENESIS = '0'.repeat(64);

// ============================================================================
// Utility Functions
// ============================================================================

function utcNowIso(): string {
  return new Date().toISOString();
}

function sha256Hex(data: Buffer | string): string {
  const hash = crypto.createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
}

function sha256File(filePath: string): string {
  const data = fs.readFileSync(filePath);
  return sha256Hex(data);
}

function isSymlink(filePath: string): boolean {
  try {
    const stats = fs.lstatSync(filePath);
    return stats.isSymbolicLink();
  } catch {
    return false;
  }
}

function refuseSymlink(filePath: string): void {
  if (isSymlink(filePath)) {
    throw new Error(`Refusing to operate on symlink: ${filePath}`);
  }
}

function ensureDir(dirPath: string): void {
  fs.mkdirSync(dirPath, { recursive: true });
}

function atomicWrite(filePath: string, data: string | Buffer): void {
  ensureDir(path.dirname(filePath));
  const tmpPath = `${filePath}.tmp.${Date.now()}`;
  fs.writeFileSync(tmpPath, data);
  fs.renameSync(tmpPath, filePath);
}

function unifiedDiff(oldText: string, newText: string, oldLabel: string, newLabel: string): string {
  // Simple unified diff implementation
  const oldLines = oldText.split('\n');
  const newLines = newText.split('\n');

  const lines: string[] = [];
  lines.push(`--- ${oldLabel}`);
  lines.push(`+++ ${newLabel}`);
  lines.push(`@@ -1,${oldLines.length} +1,${newLines.length} @@`);

  for (let i = 0; i < Math.max(oldLines.length, newLines.length); i++) {
    if (i < oldLines.length && i < newLines.length) {
      if (oldLines[i] !== newLines[i]) {
        lines.push(`-${oldLines[i]}`);
        lines.push(`+${newLines[i]}`);
      } else {
        lines.push(` ${oldLines[i]}`);
      }
    } else if (i < oldLines.length) {
      lines.push(`-${oldLines[i]}`);
    } else {
      lines.push(`+${newLines[i]}`);
    }
  }

  return lines.join('\n');
}

function safePatchTag(tag: string): string {
  return tag.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 40) || 'patch';
}

// ============================================================================
// Integrity Monitor Class
// ============================================================================

export class IntegrityMonitor {
  private policyPath: string;
  private stateDir: string;
  private baselinesPath: string;
  private auditPath: string;
  private approvedDir: string;
  private patchesDir: string;
  private quarantineDir: string;

  private policy: Policy | null = null;
  private baselines: BaselinesManifest | null = null;

  constructor(options: IntegrityMonitorOptions) {
    this.policyPath = options.policyPath;
    this.stateDir = options.stateDir;
    this.baselinesPath = path.join(this.stateDir, 'baselines.json');
    this.auditPath = path.join(this.stateDir, 'audit.jsonl');
    this.approvedDir = path.join(this.stateDir, 'approved');
    this.patchesDir = path.join(this.stateDir, 'patches');
    this.quarantineDir = path.join(this.stateDir, 'quarantine');
  }

  // --------------------------------------------------------------------------
  // Initialization
  // --------------------------------------------------------------------------

  async init(actor: string = 'system', note: string = 'initial baseline'): Promise<void> {
    ensureDir(this.stateDir);
    ensureDir(this.approvedDir);
    ensureDir(this.patchesDir);
    ensureDir(this.quarantineDir);

    // Load policy
    this.policy = this.loadPolicy();

    // Load or create baselines
    this.baselines = this.loadBaselines();

    // Resolve targets and initialize missing baselines
    const targets = this.resolveTargets();
    let initialized = false;

    for (const target of targets) {
      if (target.mode === 'ignore') continue;

      try {
        if (!fs.existsSync(target.path)) continue;

        refuseSymlink(target.path);

        // Check if already has baseline
        if (this.baselines.files[target.path]) continue;

        // Create baseline
        const sha = sha256File(target.path);
        const snapshot = path.join(this.approvedDir, path.basename(target.path));
        fs.copyFileSync(target.path, snapshot);

        this.baselines.files[target.path] = {
          sha256: sha,
          approved_at: utcNowIso(),
          approved_by: actor,
          mode: target.mode,
          priority: target.priority
        };

        this.appendAudit({
          ts: utcNowIso(),
          event: 'init',
          actor,
          note,
          path: target.path,
          mode: target.mode,
          expected_sha: sha
        });

        initialized = true;
      } catch (error) {
        console.error(`Failed to initialize baseline for ${target.path}:`, error);
      }
    }

    if (initialized) {
      this.saveBaselines();
    }
  }

  // --------------------------------------------------------------------------
  // Policy Management
  // --------------------------------------------------------------------------

  private loadPolicy(): Policy {
    const raw = fs.readFileSync(this.policyPath, 'utf-8');
    return JSON.parse(raw);
  }

  private resolveTargets(): Array<{ path: string; mode: 'restore' | 'alert' | 'ignore'; priority: string }> {
    if (!this.policy) throw new Error('Policy not loaded');

    const targets: Array<{ path: string; mode: 'restore' | 'alert' | 'ignore'; priority: string }> = [];

    for (const target of this.policy.targets) {
      if (target.path) {
        // Direct path
        targets.push({
          path: target.path,
          mode: target.mode,
          priority: target.priority
        });
      } else if (target.pattern) {
        // Glob pattern
        try {
          const matches = glob.sync(target.pattern, { nodir: true });
          for (const match of matches) {
            targets.push({
              path: path.resolve(match),
              mode: target.mode,
              priority: target.priority
            });
          }
        } catch (error) {
          console.error(`Failed to expand pattern ${target.pattern}:`, error);
        }
      }
    }

    return targets;
  }

  // --------------------------------------------------------------------------
  // Baseline Management
  // --------------------------------------------------------------------------

  private loadBaselines(): BaselinesManifest {
    if (fs.existsSync(this.baselinesPath)) {
      const raw = fs.readFileSync(this.baselinesPath, 'utf-8');
      return JSON.parse(raw);
    }

    return {
      schema_version: '1',
      algorithm: 'sha256',
      created_at: utcNowIso(),
      files: {}
    };
  }

  private saveBaselines(): void {
    const data = JSON.stringify(this.baselines, null, 2);
    atomicWrite(this.baselinesPath, data);
  }

  // --------------------------------------------------------------------------
  // Audit Log with Hash Chaining
  // --------------------------------------------------------------------------

  private getLastAuditHash(): string {
    if (!fs.existsSync(this.auditPath)) {
      return CHAIN_GENESIS;
    }

    const content = fs.readFileSync(this.auditPath, 'utf-8');
    const lines = content.trim().split('\n').filter(l => l.trim());

    if (lines.length === 0) {
      return CHAIN_GENESIS;
    }

    try {
      const lastEntry = JSON.parse(lines[lines.length - 1]);
      return lastEntry.chain?.hash || CHAIN_GENESIS;
    } catch {
      return CHAIN_GENESIS;
    }
  }

  private appendAudit(entry: Omit<AuditEntry, 'chain'>): void {
    ensureDir(path.dirname(this.auditPath));

    const prevHash = this.getLastAuditHash();

    // Compute current hash
    const entryWithoutChain = { ...entry };
    const payload = prevHash + '\n' + JSON.stringify(entryWithoutChain, Object.keys(entryWithoutChain).sort());
    const currentHash = sha256Hex(payload);

    const record: AuditEntry = {
      ...entry,
      chain: {
        prev: prevHash,
        hash: currentHash
      }
    };

    fs.appendFileSync(this.auditPath, JSON.stringify(record) + '\n');
  }

  // --------------------------------------------------------------------------
  // Drift Detection
  // --------------------------------------------------------------------------

  async checkIntegrity(autoRestore: boolean = true, actor: string = 'agent'): Promise<CheckResult> {
    if (!this.baselines) {
      throw new Error('Baselines not loaded. Call init() first.');
    }

    const result: CheckResult = {
      success: true,
      timestamp: utcNowIso(),
      drift_detected: false,
      files: [],
      summary: {
        total: 0,
        ok: 0,
        drifted: 0,
        restored: 0,
        alerted: 0,
        errors: 0
      }
    };

    for (const [filePath, baseline] of Object.entries(this.baselines.files)) {
      result.summary.total++;

      try {
        if (!fs.existsSync(filePath)) {
          result.files.push({
            path: filePath,
            status: 'error',
            mode: baseline.mode,
            error: 'File not found'
          });
          result.summary.errors++;

          this.appendAudit({
            ts: utcNowIso(),
            event: 'error',
            actor,
            path: filePath,
            error: 'File not found'
          });

          continue;
        }

        refuseSymlink(filePath);

        const currentSha = sha256File(filePath);

        if (currentSha === baseline.sha256) {
          // No drift
          result.files.push({
            path: filePath,
            status: 'ok',
            mode: baseline.mode,
            expected_sha: baseline.sha256,
            found_sha: currentSha
          });
          result.summary.ok++;
          continue;
        }

        // Drift detected
        result.drift_detected = true;
        result.summary.drifted++;

        // Generate diff
        const snapshot = path.join(this.approvedDir, path.basename(filePath));
        const oldText = fs.existsSync(snapshot) ? fs.readFileSync(snapshot, 'utf-8') : '';
        const newText = fs.readFileSync(filePath, 'utf-8');
        const diff = unifiedDiff(oldText, newText, `approved/${path.basename(filePath)}`, path.basename(filePath));

        const patchPath = path.join(
          this.patchesDir,
          `${new Date().toISOString().replace(/[:.]/g, '-')}-drift-${safePatchTag(path.basename(filePath))}.patch`
        );
        fs.writeFileSync(patchPath, diff);

        this.appendAudit({
          ts: utcNowIso(),
          event: 'drift',
          actor,
          path: filePath,
          mode: baseline.mode,
          expected_sha: baseline.sha256,
          found_sha: currentSha,
          patch_path: patchPath
        });

        // Handle based on mode
        if (baseline.mode === 'restore' && autoRestore) {
          // Auto-restore
          try {
            const quarantinePath = path.join(
              this.quarantineDir,
              `${safePatchTag(path.basename(filePath))}.${Date.now()}.quarantine`
            );
            fs.copyFileSync(filePath, quarantinePath);

            if (fs.existsSync(snapshot)) {
              atomicWrite(filePath, fs.readFileSync(snapshot));
            }

            this.appendAudit({
              ts: utcNowIso(),
              event: 'restore',
              actor,
              path: filePath,
              mode: baseline.mode,
              quarantine_path: quarantinePath
            });

            result.files.push({
              path: filePath,
              status: 'restored',
              mode: baseline.mode,
              expected_sha: baseline.sha256,
              found_sha: currentSha,
              patch_path: patchPath,
              quarantine_path: quarantinePath
            });
            result.summary.restored++;
          } catch (error) {
            result.files.push({
              path: filePath,
              status: 'error',
              mode: baseline.mode,
              expected_sha: baseline.sha256,
              found_sha: currentSha,
              patch_path: patchPath,
              error: `Restore failed: ${error instanceof Error ? error.message : String(error)}`
            });
            result.summary.errors++;
          }
        } else {
          // Alert only
          result.files.push({
            path: filePath,
            status: 'drifted',
            mode: baseline.mode,
            expected_sha: baseline.sha256,
            found_sha: currentSha,
            patch_path: patchPath
          });
          result.summary.alerted++;
        }

      } catch (error) {
        result.files.push({
          path: filePath,
          status: 'error',
          mode: baseline.mode,
          error: error instanceof Error ? error.message : String(error)
        });
        result.summary.errors++;

        this.appendAudit({
          ts: utcNowIso(),
          event: 'error',
          actor,
          path: filePath,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Approve Changes
  // --------------------------------------------------------------------------

  async approveChange(filePath: string, actor: string, note: string = ''): Promise<void> {
    if (!this.baselines) {
      throw new Error('Baselines not loaded');
    }

    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    refuseSymlink(filePath);

    const previousSha = this.baselines.files[filePath]?.sha256;
    const currentSha = sha256File(filePath);

    // Generate diff
    const snapshot = path.join(this.approvedDir, path.basename(filePath));
    const oldText = fs.existsSync(snapshot) ? fs.readFileSync(snapshot, 'utf-8') : '';
    const newText = fs.readFileSync(filePath, 'utf-8');
    const diff = unifiedDiff(oldText, newText, `approved/${path.basename(filePath)}`, path.basename(filePath));

    const patchPath = path.join(
      this.patchesDir,
      `${new Date().toISOString().replace(/[:.]/g, '-')}-approve-${safePatchTag(path.basename(filePath))}.patch`
    );
    fs.writeFileSync(patchPath, diff);

    // Update baseline
    if (!this.baselines.files[filePath]) {
      // Find mode from policy
      const targets = this.resolveTargets();
      const target = targets.find(t => t.path === filePath);
      if (!target) {
        throw new Error(`File ${filePath} not in policy`);
      }

      this.baselines.files[filePath] = {
        sha256: currentSha,
        approved_at: utcNowIso(),
        approved_by: actor,
        mode: target.mode,
        priority: target.priority
      };
    } else {
      this.baselines.files[filePath].sha256 = currentSha;
      this.baselines.files[filePath].approved_at = utcNowIso();
      this.baselines.files[filePath].approved_by = actor;
    }

    // Update snapshot
    fs.copyFileSync(filePath, snapshot);

    // Save and audit
    this.saveBaselines();

    this.appendAudit({
      ts: utcNowIso(),
      event: 'approve',
      actor,
      note,
      path: filePath,
      expected_sha: previousSha,
      found_sha: currentSha,
      patch_path: patchPath
    });
  }

  // --------------------------------------------------------------------------
  // Status and Verification
  // --------------------------------------------------------------------------

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getStatus(filePath?: string): any {
    if (!this.baselines) {
      throw new Error('Baselines not loaded');
    }

    const files = filePath
      ? { [filePath]: this.baselines.files[filePath] }
      : this.baselines.files;

    return {
      baseline_age: this.baselines.created_at,
      files: Object.entries(files).map(([path, baseline]) => ({
        path,
        mode: baseline?.mode,
        priority: baseline?.priority,
        has_baseline: !!baseline,
        baseline_sha: baseline?.sha256,
        approved_at: baseline?.approved_at,
        snapshot_exists: fs.existsSync(this.approvedDir + '/' + path.split('/').pop())
      }))
    };
  }

  verifyAuditChain(): { valid: boolean; entries: number; errors: string[] } {
    if (!fs.existsSync(this.auditPath)) {
      return { valid: true, entries: 0, errors: [] };
    }

    const content = fs.readFileSync(this.auditPath, 'utf-8');
    const lines = content.trim().split('\n').filter(l => l.trim());

    const errors: string[] = [];
    let prevHash = CHAIN_GENESIS;

    for (let i = 0; i < lines.length; i++) {
      try {
        const entry: AuditEntry = JSON.parse(lines[i]);

        if (entry.chain?.prev !== prevHash) {
          errors.push(`Line ${i + 1}: Chain break (expected prev=${prevHash}, got=${entry.chain?.prev})`);
        }

        const entryWithoutChain = { ...entry };
        delete entryWithoutChain.chain;
        const payload = prevHash + '\n' + JSON.stringify(entryWithoutChain, Object.keys(entryWithoutChain).sort());
        const expectedHash = sha256Hex(payload);

        if (entry.chain?.hash !== expectedHash) {
          errors.push(`Line ${i + 1}: Hash mismatch`);
        }

        prevHash = entry.chain?.hash || CHAIN_GENESIS;
      } catch (error) {
        errors.push(`Line ${i + 1}: Parse error - ${error}`);
      }
    }

    return {
      valid: errors.length === 0,
      entries: lines.length,
      errors
    };
  }
}
