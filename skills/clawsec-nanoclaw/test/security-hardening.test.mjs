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

function transpileCommonJs(source) {
  return ts.transpileModule(source, {
    compilerOptions: {
      esModuleInterop: true,
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
}

function loadAdvisoriesModule() {
  const module = { exports: {} };
  const context = {
    exports: module.exports,
    module,
    require(specifier) {
      if (specifier === 'fs/promises') return {};
      if (specifier === 'path') return path;
      if (specifier === './signatures.js') return {};
      throw new Error(`unexpected advisories import: ${specifier}`);
    },
  };

  vm.runInNewContext(
    transpileCommonJs(readSkillFile('lib/advisories.ts')),
    context,
    { filename: 'lib/advisories.ts' }
  );
  return module.exports;
}

function loadVersionMatcher() {
  return loadAdvisoriesModule().versionMatches;
}

function loadAdvisoryToolHandlers(cacheData, installedSkills) {
  const handlers = new Map();
  const module = { exports: {} };
  const schema = {
    describe() { return this; },
    optional() { return this; },
  };
  const fsStub = {
    readFileSync(filePath) {
      if (filePath === '/workspace/project/data/clawsec-advisory-cache.json') {
        return JSON.stringify(cacheData);
      }

      const dirName = path.basename(path.dirname(filePath));
      const skill = installedSkills.find(entry => entry.dirName === dirName);
      if (!skill) throw new Error(`unexpected skill metadata path: ${filePath}`);
      return JSON.stringify({ name: skill.name, version: skill.version });
    },
    readdirSync() {
      return installedSkills.map(skill => ({
        isDirectory: () => true,
        name: skill.dirName,
      }));
    },
  };
  const advisoriesModule = loadAdvisoriesModule();
  const context = {
    exports: module.exports,
    module,
    process,
    require(specifier) {
      if (specifier === 'fs') return fsStub;
      if (specifier === 'path') return path;
      if (specifier === 'zod') {
        return {
          z: {
            boolean: () => schema,
            enum: () => schema,
            number: () => schema,
            string: () => schema,
          },
        };
      }
      if (specifier === '../lib/advisories.js') return advisoriesModule;
      if (specifier === '../lib/risk.js') {
        return {
          evaluateAdvisoryRisk: () => ({
            safe: false,
            recommendation: 'review',
            reason: 'Matched advisory requires review',
          }),
          normalizeExploitabilityScore: score => score || 'unknown',
        };
      }
      throw new Error(`unexpected advisory-tools import: ${specifier}`);
    },
    server: {
      tool(name, _description, _schema, handler) {
        handlers.set(name, handler);
      },
    },
    writeIpcFile() {},
    TASKS_DIR: '/tasks',
    groupFolder: 'test-group',
  };

  vm.runInNewContext(
    transpileCommonJs(readSkillFile('mcp-tools/advisory-tools.ts')),
    context,
    { filename: 'mcp-tools/advisory-tools.ts' }
  );
  return handlers;
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

test('MCP advisory tools surface unmapped Hermes identities as indeterminate', async () => {
  const advisoryBase = {
    severity: 'high',
    type: 'vulnerable_skill',
    title: 'Hermes advisory',
    description: 'Test advisory',
    action: 'Review before use',
    published: '2026-05-29',
    references: [],
  };
  const cacheData = {
    fetchedAt: new Date().toISOString(),
    feed: {
      version: '1',
      updated: '2026-05-29',
      description: 'Test feed',
      advisories: [
        {
          ...advisoryBase,
          id: 'HERMES-DATE-BUILD',
          affected: ['hermes@2026.5.29.2'],
        },
        {
          ...advisoryBase,
          id: 'HERMES-SEMVER',
          affected: ['hermes@>=0.7.0 <0.9.0'],
        },
      ],
    },
  };
  const handlers = loadAdvisoryToolHandlers(cacheData, [{
    name: 'hermes',
    version: '0.8.0',
    dirName: 'hermes',
  }]);

  const scanResponse = await handlers.get('clawsec_check_advisories')({ installRoot: '/skills' });
  const scan = JSON.parse(scanResponse.content[0].text);
  const scanById = Object.fromEntries(scan.matches.map(match => [match.advisory.id, match]));

  assert.deepEqual(scanById['HERMES-DATE-BUILD'].matchedAffected, ['hermes@2026.5.29.2']);
  assert.deepEqual(scanById['HERMES-DATE-BUILD'].indeterminateAffected, ['hermes@2026.5.29.2']);
  assert.equal(scanById['HERMES-DATE-BUILD'].versionIndeterminate, true);
  assert.deepEqual(scanById['HERMES-SEMVER'].matchedAffected, ['hermes@>=0.7.0 <0.9.0']);
  assert.deepEqual(scanById['HERMES-SEMVER'].indeterminateAffected, []);
  assert.equal(scanById['HERMES-SEMVER'].versionIndeterminate, false);

  const safetyResponse = await handlers.get('clawsec_check_skill_safety')({
    skillName: 'hermes',
    skillVersion: '0.8.0',
  });
  const safety = JSON.parse(safetyResponse.content[0].text);
  const safetyById = Object.fromEntries(safety.advisories.map(advisory => [advisory.id, advisory]));

  assert.equal(safety.versionIndeterminate, true);
  assert.deepEqual(safety.indeterminateAffected, ['hermes@2026.5.29.2']);
  assert.equal(safetyById['HERMES-DATE-BUILD'].versionIndeterminate, true);
  assert.equal(safetyById['HERMES-SEMVER'].versionIndeterminate, false);

  const dateBuildHandlers = loadAdvisoryToolHandlers(cacheData, [{
    name: 'hermes',
    version: '2026.5.29.2',
    dirName: 'hermes',
  }]);
  const dateBuildScanResponse = await dateBuildHandlers.get('clawsec_check_advisories')({
    installRoot: '/skills',
  });
  const dateBuildScan = JSON.parse(dateBuildScanResponse.content[0].text);
  const dateBuildScanById = Object.fromEntries(
    dateBuildScan.matches.map(match => [match.advisory.id, match])
  );

  assert.deepEqual(
    dateBuildScanById['HERMES-SEMVER'].matchedAffected,
    ['hermes@>=0.7.0 <0.9.0'],
    'a SemVer advisory must still fail closed for an installed Hermes date-build identity'
  );
  assert.deepEqual(
    dateBuildScanById['HERMES-SEMVER'].indeterminateAffected,
    ['hermes@>=0.7.0 <0.9.0']
  );
  assert.equal(dateBuildScanById['HERMES-SEMVER'].versionIndeterminate, true);

  const dateBuildSafetyResponse = await dateBuildHandlers.get('clawsec_check_skill_safety')({
    skillName: 'hermes',
    skillVersion: '2026.5.29.2',
  });
  const dateBuildSafety = JSON.parse(dateBuildSafetyResponse.content[0].text);
  const dateBuildSafetyById = Object.fromEntries(
    dateBuildSafety.advisories.map(advisory => [advisory.id, advisory])
  );

  assert.equal(dateBuildSafety.safe, false, 'indeterminate identity matches must fail closed');
  assert.equal(dateBuildSafety.versionIndeterminate, true);
  assert.deepEqual(dateBuildSafety.indeterminateAffected, ['hermes@>=0.7.0 <0.9.0']);
  assert.equal(dateBuildSafetyById['HERMES-SEMVER'].versionIndeterminate, true);
});

test('integrity IPC result writer validates request ids and result path containment', () => {
  const source = readSkillFile('host-services/integrity-handler.ts');

  assert.ok(source.includes('validateRequestId(requestId)'), 'writeResult must validate request ids before writing');
  assert.ok(source.includes('resolveResultPath(requestId)'), 'writeResult must resolve result paths through a boundary helper');
  assert.ok(source.includes('path.resolve(resultDir)'), 'result directory must be normalized before containment checks');
  assert.ok(source.includes('path.relative(normalizedResultDir, resultPath)'), 'result path must be compared relative to the intended directory');
});
