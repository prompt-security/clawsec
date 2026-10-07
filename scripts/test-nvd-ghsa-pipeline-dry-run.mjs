import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildConsolidatedAdvisoryFeed,
  buildGhsaWithoutCveFeed,
  normalizeGhsaAdvisory,
} from './ghsa-without-cve-feed.mjs';
import { validateAdvisoryFeed } from './ci/validate_advisory_feed.mjs';

const now = '2026-05-24T00:00:00Z';
const scriptsDir = path.dirname(fileURLToPath(import.meta.url));
const backfillScript = await readFile(new URL('./backfill-exploitability.sh', import.meta.url), 'utf8');

const backfillValidationIndex = backfillScript.indexOf(
  'node "$PROJECT_ROOT/scripts/ci/validate_advisory_feed.mjs" "$TEMP_DIR/feed_final.json"',
);
const backfillReplacementIndex = backfillScript.indexOf('cp "$TEMP_DIR/feed_final.json" "$FEED_PATH"');
const backfillSigningIndex = backfillScript.indexOf(
  'sign_and_verify_feed_signature "$TEMP_DIR/feed_final.json" "$CANDIDATE_SIGNATURE"',
);
const backfillPublicationIndex = backfillScript.indexOf(
  'publish_feed_transaction "$TEMP_DIR/feed_final.json" "$CANDIDATE_SIGNATURE"',
);
assert.ok(
  backfillValidationIndex !== -1 && backfillReplacementIndex === -1,
  'Exploitability backfill must strictly validate its complete candidate before replacing the existing feed',
);
assert.ok(
  backfillValidationIndex < backfillSigningIndex && backfillSigningIndex < backfillPublicationIndex,
  'Exploitability backfill must sign and verify validated candidate bytes before transactional publication',
);

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
    authoritative_nvd_affected: ['openclaw@<2026.5.20'],
    synthesized_from_ghsa: false,
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-1111'],
    nvd_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1111',
    ...overrides,
  };
}

function ghsaAdvisory(overrides = {}) {
  const ghsaId = overrides.ghsa_id || 'GHSA-actv-1111-2222';
  return {
    ghsa_id: ghsaId,
    cve_id: null,
    html_url: `https://github.com/openclaw/openclaw/security/advisories/${ghsaId}`,
    summary: 'OpenClaw advisory without CVE',
    description: 'OpenClaw published a public GitHub advisory before CVE assignment.',
    severity: 'high',
    state: 'published',
    withdrawn_at: null,
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
      ghsaAdvisory({ ghsa_id: 'GHSA-lagd-1111-2222', cve_id: 'CVE-2026-4444' }),
      ghsaAdvisory({ ghsa_id: 'GHSA-rjct-1111-2222', cve_id: 'CVE-2026-3333' }),
    ],
  },
];

const rejectedNvdRecords = [
  {
    cve: {
      id: 'CVE-2026-3333',
      vulnStatus: 'Rejected',
      published: '2026-05-22T00:00:00Z',
      descriptions: [{ lang: 'en', value: 'Rejected upstream CVE.' }],
      references: [],
      metrics: {},
      configurations: [
        {
          nodes: [
            {
              cpeMatch: [
                {
                  vulnerable: true,
                  criteria: 'cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:*:*:*',
                  versionEndExcluding: '2026.5.21',
                },
              ],
            },
          ],
        },
      ],
    },
  },
];
const transformedRejectedRecords = JSON.parse(
  execFileSync(
    'jq',
    ['-L', scriptsDir, 'include "nvd-advisory-transform"; [.[] | nvd_advisory]'],
    { encoding: 'utf8', input: JSON.stringify(rejectedNvdRecords) },
  ),
);
assert.deepEqual(
  transformedRejectedRecords,
  [],
  'Rejected NVD records must be excluded from canonical advisory transformation',
);
const rejectedCveIds = JSON.parse(
  execFileSync(
    'jq',
    ['-L', scriptsDir, 'include "nvd-advisory-transform"; [.[] | select(is_rejected) | .cve.id]'],
    { encoding: 'utf8', input: JSON.stringify(rejectedNvdRecords) },
  ),
);

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
    ['GHSA-cvea-1111-2222', 'matured', 'CVE-2026-2222'],
    ['GHSA-lagd-1111-2222', 'matured', 'CVE-2026-4444'],
    ['GHSA-matd-1111-2222', 'matured', 'CVE-2026-1111'],
    ['GHSA-rjct-1111-2222', 'matured', 'CVE-2026-3333'],
  ],
  'GHSA dry run should retain active advisories and every CVE-backed advisory needed for enrichment',
);

const consolidatedFeed = buildConsolidatedAdvisoryFeed({
  canonicalFeed: nvdPollResultFeed,
  ghsaFeed,
  rejectedCveIds,
  now,
});
assert.deepEqual(
  consolidatedFeed.advisories.map((entry) => entry.id),
  [
    'CVE-2026-2222',
    'GHSA-actv-1111-2222',
    'GHSA-lagd-1111-2222',
    'GHSA-rjct-1111-2222',
    'CVE-2026-1111',
  ],
  'Consolidation must retain valid GHSAs through NVD delay or rejection without synthesizing CVE identities',
);
assert.equal('rejected_cve_ids' in consolidatedFeed, false, 'The signed feed must not publish a global rejection inventory');
assert.equal(
  consolidatedFeed.advisories.some((entry) => entry.id === 'CVE-2026-3333'),
  false,
  'Rejected CVEs must stay absent after GHSA consolidation',
);
assert.equal(
  consolidatedFeed.advisories.some((entry) => entry.id === 'CVE-2026-4444'),
  false,
  'A GHSA CVE alias must not become canonical before a non-rejected NVD record is observed',
);
assert.ok(consolidatedFeed.advisories.some((entry) => entry.id === 'GHSA-lagd-1111-2222'));
assert.deepEqual(
  consolidatedFeed.advisories.find((entry) => entry.id === 'GHSA-rjct-1111-2222')?.aliases,
  ['GHSA-rjct-1111-2222', 'CVE-2026-3333'],
  'The retained GHSA may preserve the rejected CVE as a non-canonical alias',
);
const followupConsolidatedFeed = buildConsolidatedAdvisoryFeed({
  canonicalFeed: consolidatedFeed,
  ghsaFeed,
  now: '2026-05-25T00:00:00Z',
});
assert.equal(
  followupConsolidatedFeed.advisories.some((entry) => entry.id === 'CVE-2026-3333'),
  false,
  'A later GHSA-only run must not synthesize a CVE without an NVD-backed canonical record',
);
assert.ok(
  followupConsolidatedFeed.advisories.some((entry) => entry.id === 'GHSA-rjct-1111-2222'),
  'A later GHSA-only run must continue to retain the valid GHSA identity',
);
assert.equal(validateAdvisoryFeed(consolidatedFeed), consolidatedFeed);
assert.equal(consolidatedFeed.advisories[1].source_feed, 'ghsa-without-cve');
const enrichedCve = consolidatedFeed.advisories.find((entry) => entry.id === 'CVE-2026-2222');
assert.equal(enrichedCve.ghsa_id, 'GHSA-cvea-1111-2222');
assert.deepEqual(enrichedCve.aliases, ['CVE-2026-2222', 'GHSA-cvea-1111-2222']);
assert.ok(enrichedCve.patched.includes('openclaw@2026.5.21'));
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
