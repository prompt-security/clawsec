import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SKILL_ROOT = path.resolve(__dirname, '..');

function readSkillFile(relativePath) {
  return fs.readFileSync(path.join(SKILL_ROOT, relativePath), 'utf8');
}

test('signature verifier enforces pinned key and path policy', () => {
  const source = readSkillFile('host-services/skill-signature-handler.ts');

  assert.ok(!source.includes('publicKeyPem?: string'), 'publicKeyPem override must be removed');
  assert.ok(!source.includes('allowUnsigned?: boolean'), 'allowUnsigned override must be removed');

  assert.ok(source.includes('const ALLOWED_PACKAGE_ROOTS'), 'must define allowed package roots');
  assert.ok(source.includes('validatePackagePath('), 'must validate package path before hashing');
  assert.ok(source.includes('validateSignaturePath('), 'must validate signature path before verification');
});

test('IPC advisory handler does not forward key or unsigned overrides', () => {
  const source = readSkillFile('host-services/ipc-handlers.ts');

  assert.ok(!source.includes('publicKeyPem'), 'IPC handler must not accept publicKeyPem override');
  assert.ok(!source.includes('allowUnsigned'), 'IPC handler must not accept allowUnsigned override');
});

test('MCP signature tool validates filesystem boundaries', () => {
  const source = readSkillFile('mcp-tools/signature-verification.ts');

  assert.ok(source.includes('const ALLOWED_VERIFICATION_ROOTS'), 'must define allowed verification roots');
  assert.ok(source.includes('validatePackagePath('), 'must validate package path in MCP layer');
  assert.ok(source.includes('validateSignaturePath('), 'must validate signature path in MCP layer');
});

test('integrity approvals are restricted to policy targets', () => {
  const source = readSkillFile('guardian/integrity-monitor.ts');

  assert.ok(source.includes('const normalizedFilePath = path.resolve(filePath);'), 'must normalize approved path');
  assert.ok(
    source.includes("if (!target || target.mode === 'ignore')"),
    'must require approved file to exist in non-ignored policy target list'
  );
});

test('integrity targets and baselines use normalized absolute paths', () => {
  const source = readSkillFile('guardian/integrity-monitor.ts');

  assert.ok(source.includes('path: path.resolve(target.path)'), 'resolveTargets must normalize direct target paths');
  assert.ok(source.includes('const normalizedFilePath = path.resolve(filePath);'), 'status/approval lookups must normalize file paths');
  assert.ok(source.includes('normalizedFiles[path.resolve(filePath)] = baseline;'), 'loaded baselines must be normalized to absolute keys');
});
