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
assert.equal(
  skillJson.nanoclaw?.requires?.nanoclaw,
  '>=0.1.0 <2.0.0',
  'legacy package metadata must exclude NanoClaw v2',
);

const compatibilityDocuments = new Map([
  ['skill.json description', skillJson.description],
  ['SKILL.md', skill],
  ['README.md', readme],
  ['INSTALL.md', install],
  ['docs/SKILL_SIGNING.md', signing],
  ['docs/INTEGRITY.md', integrity],
]);

for (const [label, text] of compatibilityDocuments) {
  assert.match(text, /(?:NanoClaw v1|pre-v2)/i, `${label} must identify the legacy v1/pre-v2 scope`);
  assert.match(text, /NanoClaw v2[\s\S]{0,100}incompatible|incompatible[\s\S]{0,100}NanoClaw v2/i,
    `${label} must state NanoClaw v2 incompatibility`);
}

for (const [label, text] of [['SKILL.md', skill], ['README.md', readme]]) {
  assert.doesNotMatch(
    text,
    /npx\s+skills\s+add[\s\S]{0,160}(?:-a|--agent)\s+openclaw/i,
    `${label} must not present an OpenClaw-targeted installer command for NanoClaw`,
  );
}

for (const [label, text] of [['SKILL.md', skill], ['README.md', readme], ['INSTALL.md', install]]) {
  assert.doesNotMatch(text, /Every 6 hours \(automatic\)/i, `${label} must not claim automatic scheduling`);
}

assert.doesNotMatch(skill, /prevents installation of vulnerable skills/i,
  'the advisory tool must not claim ownership of the host installer');
assert.doesNotMatch(readme, /ClawSec now supports NanoClaw/i,
  'the legacy README must not make an unqualified current-support claim');
assert.doesNotMatch(signatureTool, /prevents installation/i,
  'the signature tool must not claim ownership of the host installer');
assert.match(signatureTool, /host installer or operator must enforce/i,
  'the signature tool must identify who enforces its recommendation');
assert.doesNotMatch(signatureTool, /install\/block\/review/i,
  'the signature tool must not advertise an unreachable review recommendation');
assert.doesNotMatch(advisoryTool, /safe to install based on/i,
  'the advisory tool must not present its feed result as complete installation safety');
assert.match(advisoryTool, /host installer or operator must enforce/i,
  'the advisory tool must identify who enforces its recommendation');

for (const [label, text] of compatibilityDocuments) {
  let offset = 0;
  while ((offset = text.indexOf('schedule_task(', offset)) !== -1) {
    const context = text.slice(Math.max(0, offset - 320), offset);
    assert.match(
      context,
      /Legacy NanoClaw v1 Scheduler Example|Compatibility boundary/i,
      `${label} must scope every retained schedule_task example to legacy NanoClaw v1`,
    );
    offset += 'schedule_task('.length;
  }
}

assert.match(signing, /Publisher Workflow Is Out of Scope/,
  'legacy signing documentation must reject an invented publisher workflow');
assert.match(signing, /does not accept caller-selected publisher keys/i,
  'legacy signing documentation must describe pinned-key behavior');
assert.match(signing, /has no dual-key or dual-signature rotation protocol/i,
  'legacy signing documentation must describe the actual single-key verifier');
assert.doesNotMatch(signing, /comes from ClawSec \(or trusted publisher\)/i,
  'legacy signing documentation must not claim arbitrary publisher trust');
assert.doesNotMatch(signing, /During transition, support \*\*dual signatures\*\*/i,
  'legacy signing documentation must not claim unsupported dual-signature rotation');
assert.doesNotMatch(signing, /Agents can verify with either key during the overlap period/i,
  'legacy signing documentation must not claim unsupported multi-key verification');
assert.doesNotMatch(signing, /Safe to install|Installation blocked|proceed with extraction|extractPackage\(/i,
  'legacy signing examples must not treat verification as installation authority');
assert.match(signing, /requiresOperatorApproval|operator approval is still required/i,
  'legacy signing examples must preserve explicit operator approval');
assert.doesNotMatch(signing, /"install"\s*\|\s*"block"\s*\|\s*"review"|case 'review'/i,
  'legacy signing documentation must list only implemented recommendation outcomes');
assert.doesNotMatch(skill, /if\s*\(safety\.safe\)\s*await installSkill|Proceed with installation/i,
  'the skill must not treat advisory output as installation authorization');

assert.match(changelog, /^## \[0\.0\.11\] - 2026-07-22$/m,
  'CHANGELOG.md must record the truthfulness release');
