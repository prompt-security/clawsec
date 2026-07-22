import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const testDir = path.dirname(fileURLToPath(import.meta.url));
const skillRoot = path.resolve(testDir, '..');

function read(relativePath) {
  return fs.readFileSync(path.join(skillRoot, relativePath), 'utf8');
}

function frontmatterValue(markdown, key) {
  const match = markdown.match(new RegExp(`^${key}:\\s*(.+)$`, 'm'));
  assert.ok(match, `SKILL.md frontmatter must define ${key}`);
  return match[1].trim();
}

const skillJson = JSON.parse(read('skill.json'));
const skill = read('SKILL.md');
const readme = read('README.md');
const install = read('INSTALL.md');
const signing = read('docs/SKILL_SIGNING.md');
const integrity = read('docs/INTEGRITY.md');
const changelog = read('CHANGELOG.md');
const signatureTool = read('mcp-tools/signature-verification.ts');
const advisoryTool = read('mcp-tools/advisory-tools.ts');

assert.equal(skillJson.version, '0.0.11', 'skill.json must carry the truthfulness release version');
assert.equal(frontmatterValue(skill, 'version'), '0.0.11', 'SKILL.md must match skill.json version');
assert.match(skillJson.description, /deprecated[\s\S]*runtime-unverified/i);
assert.equal(skillJson.installable, false, 'a deprecated unverified template must be non-installable');
assert.deepEqual(skillJson.capabilities, [], 'an unverified template must not advertise active capabilities');
assert.equal(skillJson.nanoclaw?.status, 'deprecated-runtime-unverified');
assert.equal(skillJson.nanoclaw?.lineage, 'v1-era');
assert.equal(skillJson.nanoclaw?.runtime_verified, false);
assert.deepEqual(skillJson.nanoclaw?.supported_versions, []);
assert.deepEqual(skillJson.nanoclaw?.incompatible_generations, ['v2']);
assert.equal(skillJson.nanoclaw?.requires, undefined, 'unverified metadata must not advertise runtime requirements');
assert.equal(skillJson.nanoclaw?.integration, undefined, 'historical paths must not be presented as an active integration');

const statusDocuments = new Map([
  ['skill.json description', skillJson.description],
  ['SKILL.md', skill],
  ['README.md', readme],
  ['INSTALL.md', install],
  ['docs/SKILL_SIGNING.md', signing],
  ['docs/INTEGRITY.md', integrity],
]);

for (const [label, text] of statusDocuments) {
  assert.match(text, /(?:v1-era|NanoClaw v1)/i, `${label} must identify the historical v1-era lineage`);
  assert.match(text, /(?:runtime-unverified|runtime unverified|unverified)/i,
    `${label} must state that runtime support is unverified`);
  assert.match(text, /NanoClaw v2[\s\S]{0,120}incompatible|incompatible[\s\S]{0,120}NanoClaw v2/i,
    `${label} must state NanoClaw v2 incompatibility`);
}

for (const [label, text] of [['SKILL.md', skill], ['README.md', readme]]) {
  assert.match(text, /NanoClaw has no reviewed direct Agent Skills CLI target/i,
    `${label} must state that NanoClaw has no reviewed direct target`);
  assert.match(text, /\[[^\]]*(?:install|integration)[^\]]*\]\(\.\/INSTALL\.md\)/i,
    `${label} must link the packaged historical integration record`);
  assert.doesNotMatch(text, /npx\s+skills\s+add/i,
    `${label} must not present a Skills CLI install command`);
}

for (const [label, text] of statusDocuments) {
  assert.doesNotMatch(text, />=\s*0\.1\.0\s*<\s*2\.0\.0/i,
    `${label} must not advertise the invented legacy support range`);
  assert.doesNotMatch(text, /Supported NanoClaw range:\s*`?[^\n]*\d+\.\d+/i,
    `${label} must not advertise a numeric support range`);
  assert.doesNotMatch(text, /SQLite IPC/i,
    `${label} must use the explicit two-database boundary terminology`);
}

assert.match(install, /not an installation guide/i);
assert.match(install, /declare[\s\S]*emit no JavaScript/i,
  'the historical record must explain the ambient-declaration runtime failure');
assert.match(install, /ES modules[\s\S]*do not inherit lexical variables/i,
  'the historical record must explain the module-scope failure');
assert.match(install, /glob[\s\S]{0,180}(?:no runtime implementation|unbound)/i,
  'the historical record must identify the unbound glob implementation');
assert.match(install, /writeResponse[\s\S]{0,180}(?:imports or implements no|no implementation)/i,
  'the historical record must identify the missing writeResponse implementation');
assert.match(install, /__dirname[\s\S]{0,180}ES module/i,
  'the historical record must identify the CommonJS __dirname use in ESM');
assert.doesNotMatch(install, /docker-compose\s+(?:down|up)|docker\s+compose\s+(?:down|up)/i,
  'the withdrawn record must not retain false service commands');
assert.doesNotMatch(install, /\bcp\s+-r\b|\bimport\s+['"][.]{1,2}\//i,
  'the withdrawn record must not contain actionable legacy copy/import steps');

assert.match(integrity, /not an active integrity guardian/i);
assert.match(integrity, /Automatic restoration[\s\S]*must remain off/i);
assert.doesNotMatch(integrity, /schedule_task\s*\(/i,
  'historical integrity documentation must not include an activation example');

assert.match(signing, /not a supported package-verification workflow/i);
assert.match(signing, /signed `checksums\.json` manifest/i);
assert.match(signing, /machine-readable `install` recommendation must not be treated as installation authority/i);
assert.doesNotMatch(signing, /Safe to install|proceed with extraction|extractPackage\(/i,
  'historical signing documentation must not authorize installation');

assert.doesNotMatch(skill, /prevents installation of vulnerable skills/i,
  'the skill must not claim ownership of a host installer');
assert.doesNotMatch(readme, /ClawSec now supports NanoClaw/i,
  'the README must not make an unqualified support claim');
assert.doesNotMatch(signatureTool, /prevents installation/i,
  'the signature tool description must not claim ownership of a host installer');
assert.match(signatureTool, /host installer or operator must enforce/i,
  'the historical signature source must still identify who would enforce a result');
assert.doesNotMatch(advisoryTool, /safe to install based on/i,
  'the advisory source must not present a feed result as complete installation safety');
assert.match(advisoryTool, /host installer or operator must enforce/i,
  'the historical advisory source must still identify who would enforce a result');

const packagedPaths = skillJson.sbom?.files?.map((entry) => entry.path) ?? [];
const expectedPackagedPaths = [
  'CHANGELOG.md',
  'INSTALL.md',
  'SKILL.md',
  'docs/INTEGRITY.md',
  'docs/SKILL_SIGNING.md',
];
assert.deepEqual([...packagedPaths].sort(), expectedPackagedPaths,
  'the release SBOM must contain only essential migration and status documentation');
for (const packagedPath of packagedPaths) {
  assert.doesNotMatch(packagedPath, /\.ts$/i,
    'the release SBOM must not ship runtime-unverified TypeScript');
  assert.doesNotMatch(packagedPath, /(?:^|\/)policy\.json$/i,
    'the release SBOM must not ship the historical policy JSON');
  assert.doesNotMatch(packagedPath, /\.pem$/i,
    'the release SBOM must not ship historical PEM material');
}
assert.match(skill, /successor[\s\S]{0,180}current published release[\s\S]{0,180}acceptance evidence/i,
  'successor availability must require current release and acceptance evidence');
assert.match(skill, /live logs[\s\S]{0,180}runtime execution evidence as unknown/i,
  'missing live-log access must leave runtime evidence unknown');
assert.match(skill, /upstream material observed on 2026-07-22[\s\S]{0,180}Reverify/i,
  'observed upstream facts must carry a revalidation requirement');
assert.match(changelog, /^## \[0\.0\.11\] - 2026-07-22$/m,
  'CHANGELOG.md must record the truthfulness release');
assert.match(changelog, /runtime-unverified NanoClaw v1-era integration prototype/i);
assert.match(changelog, /packaged user-facing Markdown/i,
  'the changelog must scope instruction removal to the packaged Markdown');
assert.match(changelog, /Excluded runtime-unverified TypeScript, policy JSON, and PEM artifacts from the release SBOM/i,
  'the changelog must record the documentation-only release boundary');

assert.ok(skill.split('\n').length < 500, 'SKILL.md must remain concise enough for skill context');

console.log('NanoClaw legacy status contract tests passed.');
