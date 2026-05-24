import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  buildConsolidatedAdvisoryFeed,
  buildGhsaWithoutCveFeed,
  normalizeGhsaAdvisory,
} from './ghsa-without-cve-feed.mjs';

const now = '2026-05-24T00:00:00Z';

function cveAdvisory(overrides = {}) {
  return {
    id: 'CVE-2026-1111',
    severity: 'high',
    type: 'code_injection',
    title: 'OpenClaw command execution advisory',
    description: 'OpenClaw allowed unsafe tool execution in a guarded workspace.',
    affected: ['openclaw@<2026.5.20'],
    patched: ['openclaw@2026.5.20'],
    platforms: ['openclaw'],
    action: 'Update OpenClaw and verify guarded workspace execution.',
    published: '2026-05-01T00:00:00Z',
    updated: '2026-05-01T00:00:00Z',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-1111'],
    nvd_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1111',
    ...overrides,
  };
}

function ghsaAdvisory(overrides = {}) {
  return {
    ghsa_id: 'GHSA-actv-1111-2222',
    cve_id: null,
    html_url: 'https://github.com/openclaw/openclaw/security/advisories/GHSA-actv-1111-2222',
    summary: 'OpenClaw advisory without CVE',
    description: 'OpenClaw published a public GitHub advisory before CVE assignment.',
    severity: 'high',
    published_at: '2026-05-20T00:00:00Z',
    updated_at: '2026-05-21T00:00:00Z',
    vulnerabilities: [
      {
        package: { ecosystem: 'npm', name: 'openclaw' },
        vulnerable_version_range: '<2026.5.21',
        patched_versions: '2026.5.21',
      },
    ],
    cvss: {
      vector_string: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
      score: 7.8,
    },
    cwe_ids: ['CWE-94'],
    credits: [{ login: 'security-researcher', type: 'reporter' }],
    ...overrides,
  };
}

function signBuffer(data, privateKey) {
  return sign(null, data, privateKey).toString('base64');
}

function verifySignature(data, signature, publicKey) {
  return verify(null, data, publicKey, Buffer.from(signature, 'base64'));
}

async function writeJson(filePath, value) {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

const tempDir = await mkdtemp(path.join(tmpdir(), 'clawsec-nvd-ghsa-ci-dry-run-'));
const canonicalFeedPath = path.join(tempDir, 'advisories/feed.json');
const ghsaFeedPath = path.join(tempDir, 'advisories/ghsa-without-cve.json');
const skillFeedPath = path.join(tempDir, 'skills/clawsec-feed/advisories/feed.json');

const existingCanonicalFeed = {
  version: '1.0.0',
  updated: '2026-05-23T00:00:00Z',
  description: 'Community-driven security advisory feed for ClawSec',
  advisories: [
    cveAdvisory({
      id: 'CVE-2026-1111',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2026-1111',
        'https://github.com/openclaw/openclaw/security/advisories/GHSA-matd-1111-2222',
      ],
    }),
  ],
};
const nvdPollResultFeed = {
  ...existingCanonicalFeed,
  updated: now,
  advisories: [
    cveAdvisory({
      id: 'CVE-2026-2222',
      title: 'Fresh NVD advisory from the poll window',
      published: '2026-05-24T00:00:00Z',
      updated: '2026-05-24T00:00:00Z',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2026-2222',
        'https://github.com/openclaw/openclaw/security/advisories/GHSA-cvea-1111-2222',
      ],
      nvd_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-2222',
    }),
    ...existingCanonicalFeed.advisories,
  ],
};
const existingGhsaFeed = {
  version: '0.1.0',
  updated: '2026-05-20T00:00:00Z',
  advisories: [
    normalizeGhsaAdvisory(ghsaAdvisory({ ghsa_id: 'GHSA-matd-1111-2222' }), {
      now: '2026-05-20T00:00:00Z',
      repository: 'openclaw/openclaw',
      staleAfterDays: 60,
    }),
  ],
};
const fetchedGhsaAdvisories = [
  {
    repository: 'openclaw/openclaw',
    advisories: [
      ghsaAdvisory({ ghsa_id: 'GHSA-actv-1111-2222' }),
      ghsaAdvisory({ ghsa_id: 'GHSA-matd-1111-2222' }),
      ghsaAdvisory({ ghsa_id: 'GHSA-cvea-1111-2222', cve_id: 'CVE-2026-2222' }),
    ],
  },
];

const ghsaFeed = buildGhsaWithoutCveFeed({
  fetched: fetchedGhsaAdvisories,
  existingFeed: existingGhsaFeed,
  nvdFeed: nvdPollResultFeed,
  now,
  staleAfterDays: 60,
});
assert.deepEqual(
  ghsaFeed.advisories.map((entry) => [entry.id, entry.status, entry.cve_id]),
  [
    ['GHSA-actv-1111-2222', 'active', null],
    ['GHSA-matd-1111-2222', 'matured', 'CVE-2026-1111'],
  ],
  'GHSA dry run should retain active GHSA-only advisories and mature tracked GHSAs',
);

const consolidatedFeed = buildConsolidatedAdvisoryFeed({
  canonicalFeed: nvdPollResultFeed,
  ghsaFeed,
  now,
});
assert.deepEqual(
  consolidatedFeed.advisories.map((entry) => entry.id),
  ['CVE-2026-2222', 'GHSA-actv-1111-2222', 'CVE-2026-1111'],
  'Consolidated feed should include NVD CVEs plus active GHSA-only advisories without duplicate matured GHSAs',
);
assert.equal(consolidatedFeed.advisories[1].source_feed, 'ghsa-without-cve');
assert.equal(consolidatedFeed.updated, nvdPollResultFeed.updated);

await writeJson(canonicalFeedPath, consolidatedFeed);
await writeJson(ghsaFeedPath, ghsaFeed);
await writeJson(skillFeedPath, consolidatedFeed);

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const canonicalFeedBytes = await readFile(canonicalFeedPath);
const ghsaFeedBytes = await readFile(ghsaFeedPath);
const skillFeedBytes = await readFile(skillFeedPath);
const canonicalSignature = signBuffer(canonicalFeedBytes, privateKey);
const ghsaSignature = signBuffer(ghsaFeedBytes, privateKey);

await writeFile(`${canonicalFeedPath}.sig`, `${canonicalSignature}\n`);
await writeFile(`${ghsaFeedPath}.sig`, `${ghsaSignature}\n`);
await writeFile(`${skillFeedPath}.sig`, `${canonicalSignature}\n`);

assert.deepEqual(skillFeedBytes, canonicalFeedBytes, 'skill advisory feed must match the signed agent feed');
assert.ok(
  verifySignature(canonicalFeedBytes, canonicalSignature, publicKey),
  'canonical consolidated feed signature must verify',
);
assert.ok(verifySignature(skillFeedBytes, canonicalSignature, publicKey), 'skill feed signature must verify');
assert.ok(verifySignature(ghsaFeedBytes, ghsaSignature, publicKey), 'GHSA source feed signature must verify');

console.log(
  `NVD + GHSA dry run passed: ${consolidatedFeed.advisories.length} consolidated advisories, ${ghsaFeed.advisories.length} GHSA source advisories, signatures verified.`,
);
