import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from 'typescript';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SKILL_ROOT = path.resolve(__dirname, '..');

function readSkillFile(relativePath) {
  return fs.readFileSync(path.join(SKILL_ROOT, relativePath), 'utf8');
}

function extractFunctionSource(source, functionName) {
  const marker = `export function ${functionName}`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing ${functionName} export`);

  const bodyStart = source.indexOf('{', start);
  assert.notEqual(bodyStart, -1, `missing ${functionName} body`);

  let depth = 0;
  for (let index = bodyStart; index < source.length; index += 1) {
    const char = source[index];
    if (char === '{') depth += 1;
    if (char === '}') depth -= 1;
    if (depth === 0) {
      return source.slice(start, index + 1).replace('export ', '');
    }
  }

  throw new Error(`unterminated ${functionName} body`);
}

function loadVersionMatcher() {
  const source = readSkillFile('lib/advisories.ts');
  const fnSource = extractFunctionSource(source, 'versionMatches');
  const js = ts.transpileModule(
    `${fnSource}\nglobalThis.versionMatches = versionMatches;`,
    {
      compilerOptions: {
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ES2022,
      },
    }
  ).outputText;

  const context = { globalThis: {} };
  vm.runInNewContext(js, context);
  return context.globalThis.versionMatches;
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

test('advisory matcher handles comparator ranges and fails closed on malformed specs', () => {
  const versionMatches = loadVersionMatcher();

  assert.equal(versionMatches('2026.4.20', '<2026.5.18'), true, 'less-than comparator must match vulnerable versions');
  assert.equal(versionMatches('2026.5.18', '<2026.5.18'), false, 'less-than comparator must exclude patched versions');
  assert.equal(versionMatches('2026.5.18', '<=2026.5.18'), true, 'less-than-or-equal comparator must match boundary versions');
  assert.equal(versionMatches('1.4.0', '>=1.2.0 <2.0.0'), true, 'composite comparator ranges must match all clauses');
  assert.equal(versionMatches('2.0.0', '>=1.2.0 <2.0.0'), false, 'composite comparator ranges must reject failed clauses');
  assert.equal(versionMatches('0.0.2', '<= 0.0.2'), true, 'spaced comparators must match boundary versions');
  assert.equal(versionMatches('0.0.3', '<= 0.0.2'), false, 'spaced comparators must reject versions outside range');
  assert.equal(versionMatches('1.2.3', '>= 1.0.0 <'), false, 'partially parsed comparator ranges must not match everything');
  assert.equal(versionMatches('1.2.3', 'not-a-range'), true, 'unparseable advisory specifiers must fail closed');
});

test('advisory matcher preserves semver prerelease precedence', () => {
  const versionMatches = loadVersionMatcher();

  assert.equal(versionMatches('1.2.3-beta.1', '1.2.3'), false, 'prereleases must not collapse into releases');
  assert.equal(versionMatches('1.2.3-beta.1', '=1.2.3'), false, 'explicit equality must honor prerelease data');
  assert.equal(versionMatches('1.2.3-beta.1', '<1.2.3'), true, 'prereleases must compare lower than releases');
  assert.equal(versionMatches('1.2.3', '>1.2.3-beta.1'), true, 'releases must compare higher than prereleases');
  assert.equal(versionMatches('1.2.3-beta.2', '<1.2.3-beta.10'), true, 'numeric prerelease identifiers must compare numerically');
  assert.equal(versionMatches('1.2.3+build.1', '=1.2.3+build.2'), true, 'build metadata must not affect precedence');
  assert.equal(versionMatches('1.2.3-beta.1', '^1.2.3'), false, 'caret lower bounds must honor prerelease precedence');
  assert.equal(versionMatches('1.2.3-beta.1', '~1.2.3'), false, 'tilde lower bounds must honor prerelease precedence');
});

test('integrity IPC result writer validates request ids and result path containment', () => {
  const source = readSkillFile('host-services/integrity-handler.ts');

  assert.ok(source.includes('validateRequestId(requestId)'), 'writeResult must validate request ids before writing');
  assert.ok(source.includes('resolveResultPath(requestId)'), 'writeResult must resolve result paths through a boundary helper');
  assert.ok(source.includes('path.resolve(resultDir)'), 'result directory must be normalized before containment checks');
  assert.ok(source.includes('path.relative(normalizedResultDir, resultPath)'), 'result path must be compared relative to the intended directory');
});
