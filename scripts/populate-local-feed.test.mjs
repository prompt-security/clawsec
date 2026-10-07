#!/usr/bin/env node

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));
const workdir = await mkdtemp(path.join(tmpdir(), 'clawsec-local-feed-'));
const projectRoot = path.join(workdir, 'project');
const projectScripts = path.join(projectRoot, 'scripts');
const binDir = path.join(workdir, 'bin');

function advisory(id, overrides = {}) {
  return {
    id,
    severity: 'medium',
    type: 'unspecified_weakness',
    nvd_category_id: null,
    cwe_ids: [],
    authoritative_canonical_cwe_ids: [],
    title: `Old title for ${id}`,
    description: `Old description for ${id}`,
    affected: ['openclaw@<2026.9.0'],
    authoritative_nvd_affected: ['openclaw@<2026.9.0'],
    synthesized_from_ghsa: false,
    platforms: ['openclaw'],
    authoritative_canonical_platforms: ['openclaw'],
    action: 'Keep the existing operator guidance.',
    published: '2026-08-01T00:00:00.000',
    updated: '2026-08-01T00:00:00.000',
    references: [`https://example.test/old/${id}`],
    cvss_score: 5.0,
    cvss_vector: 'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N',
    nvd_url: `https://nvd.nist.gov/vuln/detail/${id}`,
    exploitability_score: 'medium',
    exploitability_rationale: 'Existing local analysis must survive an NVD-only correction.',
    attack_vector_analysis: { is_network_accessible: false },
    exploit_detection: { public_exploit_available: false },
    ...overrides,
  };
}

function nvdRecord(id, overrides = {}) {
  return {
    cve: {
      id,
      vulnStatus: 'Analyzed',
      published: '2026-08-01T00:00:00.000',
      lastModified: '2026-10-01T12:34:56.000',
      descriptions: [
        {
          lang: 'en',
          value: 'Corrected OpenClaw remote command execution description from NVD.',
        },
      ],
      weaknesses: [{ description: [{ lang: 'en', value: 'CWE-94' }] }],
      references: [
        { url: `https://nvd.nist.gov/vuln/detail/${id}` },
        { url: 'https://github.com/openclaw/openclaw/security/advisories/GHSA-test-1111-2222' },
      ],
      metrics: {
        cvssMetricV31: [
          {
            cvssData: {
              baseScore: 9.8,
              vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            },
          },
        ],
      },
      configurations: [
        {
          operator: 'OR',
          nodes: [
            {
              operator: 'OR',
              cpeMatch: [
                {
                  vulnerable: true,
                  criteria: 'cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:*:*:*',
                  versionStartIncluding: '2026.9.0',
                  versionEndExcluding: '2026.10.0',
                },
              ],
            },
          ],
        },
      ],
      ...overrides,
    },
  };
}

try {
  await mkdir(path.join(projectScripts, 'ci'), { recursive: true });
  await mkdir(binDir, { recursive: true });
  await cp(path.join(scriptsDir, 'populate-local-feed.sh'), path.join(projectScripts, 'populate-local-feed.sh'));
  await cp(path.join(scriptsDir, 'feed-utils.sh'), path.join(projectScripts, 'feed-utils.sh'));
  await cp(path.join(scriptsDir, 'nvd-advisory-transform.jq'), path.join(projectScripts, 'nvd-advisory-transform.jq'));
  await chmod(path.join(projectScripts, 'populate-local-feed.sh'), 0o755);

  await writeFile(
    path.join(projectScripts, 'ci', 'enrich_exploitability.sh'),
    '#!/usr/bin/env bash\nset -euo pipefail\necho "unexpected enrichment call" >&2\nexit 97\n',
  );
  await chmod(path.join(projectScripts, 'ci', 'enrich_exploitability.sh'), 0o755);
  await cp(
    path.join(scriptsDir, 'ci', 'validate_advisory_feed.mjs'),
    path.join(projectScripts, 'ci', 'validate_advisory_feed.mjs'),
  );
  await mkdir(path.join(projectRoot, 'skills', 'hermes-attestation-guardian', 'lib'), { recursive: true });
  await cp(
    path.join(scriptsDir, '..', 'skills', 'hermes-attestation-guardian', 'lib', 'semver.mjs'),
    path.join(projectRoot, 'skills', 'hermes-attestation-guardian', 'lib', 'semver.mjs'),
  );

  const correctedId = 'CVE-2026-91001';
  const retractedId = 'CVE-2026-91002';
  const untouchedIds = ['CVE-2026-91003', 'CVE-2026-91004', 'CVE-2026-91005'];
  const feed = {
    version: '1.0.0',
    updated: '2026-09-30T00:00:00Z',
    description: 'Local feed correction test',
    advisories: [
      advisory(correctedId, {
        affected: ['nanoclaw@<1.0.0', 'openshell@<0.0.20'],
        authoritative_nvd_affected: ['nanoclaw@<1.0.0'],
        authoritative_ghsa_affected: ['openshell@<0.0.20'],
        synthesized_from_ghsa: true,
        platforms: ['nanoclaw', 'openshell'],
        authoritative_canonical_platforms: ['nanoclaw'],
        authoritative_ghsa_platforms: ['openshell'],
        cwe_ids: ['CWE-79'],
        authoritative_ghsa_cwe_ids: ['CWE-79'],
        ghsa_id: 'GHSA-old1-1111-2222',
        ghsa_ids: ['GHSA-old1-1111-2222'],
        aliases: [correctedId, 'GHSA-old1-1111-2222'],
        references: [
          `https://nvd.nist.gov/vuln/detail/${correctedId}`,
          'https://github.com/openclaw/openclaw/security/advisories/GHSA-old1-1111-2222',
        ],
      }),
      advisory(retractedId),
      ...untouchedIds.map((id) => advisory(id)),
    ],
  };
  const feedPath = path.join(workdir, 'feed.json');
  const skillFeedPath = path.join(workdir, 'skill-feed.json');
  const suiteFeedPath = path.join(workdir, 'suite-feed.json');
  const publicFeedPath = path.join(workdir, 'public-feed.json');
  await writeFile(feedPath, `${JSON.stringify(feed, null, 2)}\n`);

  const retractedRecord = nvdRecord(retractedId, {
    descriptions: [{ lang: 'en', value: 'NVD removed the protected product and version applicability.' }],
    configurations: [],
  });
  const responsePath = path.join(workdir, 'nvd-response.json');

  await writeFile(
    path.join(binDir, 'curl'),
    `#!/usr/bin/env bash
set -euo pipefail
output=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-o' ]; then
    output="$2"
    shift 2
  else
    shift
  fi
done
cp "$NVD_TEST_RESPONSE" "$output"
printf '200'
`,
  );
  await chmod(path.join(binDir, 'curl'), 0o755);
  await writeFile(path.join(binDir, 'sleep'), '#!/usr/bin/env bash\nexit 0\n');
  await chmod(path.join(binDir, 'sleep'), 0o755);

  async function runPopulator(vulnerabilities) {
    await writeFile(
      responsePath,
      `${JSON.stringify(
        {
          vulnerabilities,
          totalResults: vulnerabilities.length,
          startIndex: 0,
          resultsPerPage: vulnerabilities.length,
        },
        null,
        2,
      )}\n`,
    );
    return execFileSync(path.join(projectScripts, 'populate-local-feed.sh'), ['--days', '1'], {
      cwd: projectRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${binDir}:${process.env.PATH}`,
        NVD_TEST_RESPONSE: responsePath,
        FEED_PATH: feedPath,
        SKILL_FEED_PATH: skillFeedPath,
        SUITE_FEED_PATH: suiteFeedPath,
        PUBLIC_FEED_PATH: publicFeedPath,
      },
    });
  }

  const correctionOutput = await runPopulator([nvdRecord(correctedId)]);

  const correctedFeed = JSON.parse(await readFile(feedPath, 'utf8'));
  const corrected = correctedFeed.advisories.find(({ id }) => id === correctedId);

  assert.ok(corrected, 'the corrected CVE must remain in the local feed');
  assert.equal(corrected.severity, 'critical');
  assert.equal(corrected.type, 'code_injection');
  assert.equal(corrected.nvd_category_id, 'CWE-94');
  assert.deepEqual(corrected.authoritative_canonical_cwe_ids, ['CWE-94']);
  assert.equal(corrected.cvss_score, 9.8);
  assert.equal(corrected.cvss_vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(corrected.updated, '2026-10-01T12:34:56.000');
  assert.deepEqual(corrected.authoritative_nvd_affected, ['openclaw@>=2026.9.0 <2026.10.0']);
  assert.deepEqual(corrected.authoritative_ghsa_affected, ['openshell@<0.0.20']);
  assert.deepEqual(corrected.affected, [
    'openclaw@>=2026.9.0 <2026.10.0',
    'openshell@<0.0.20',
  ]);
  assert.equal(corrected.synthesized_from_ghsa, false);
  assert.deepEqual(corrected.platforms, ['openclaw', 'openshell']);
  assert.deepEqual(corrected.authoritative_canonical_platforms, ['openclaw']);
  assert.deepEqual(corrected.authoritative_ghsa_platforms, ['openshell']);
  assert.deepEqual(corrected.cwe_ids, ['CWE-79', 'CWE-94']);
  assert.deepEqual(corrected.authoritative_ghsa_cwe_ids, ['CWE-79']);
  assert.equal(corrected.description, 'Corrected OpenClaw remote command execution description from NVD.');
  assert.equal(corrected.title, 'Corrected OpenClaw remote command execution description from NVD.');
  assert.deepEqual(corrected.references, [
    'https://github.com/openclaw/openclaw/security/advisories/GHSA-old1-1111-2222',
    'https://github.com/openclaw/openclaw/security/advisories/GHSA-test-1111-2222',
    `https://nvd.nist.gov/vuln/detail/${correctedId}`,
  ]);
  assert.equal(corrected.exploitability_score, 'medium', 'NVD corrections must preserve local enrichment');
  assert.equal(
    corrected.exploitability_rationale,
    'Existing local analysis must survive an NVD-only correction.',
    'NVD corrections must preserve local exploitability rationale',
  );
  assert.deepEqual(corrected.attack_vector_analysis, { is_network_accessible: false });
  assert.deepEqual(corrected.exploit_detection, { public_exploit_available: false });
  assert.equal(corrected.action, 'Keep the existing operator guidance.');
  assert.ok(
    correctedFeed.advisories.some(({ id }) => id === retractedId),
    'a CVE outside the current modification window must remain untouched',
  );
  assert.match(correctionOutput, /Updated advisories: 1/);
  assert.match(correctionOutput, /Advisories retracted: 0/);

  const correctedPublished = '2026-07-31T23:59:59.000';
  const publishedOnlyOutput = await runPopulator([
    nvdRecord(correctedId, { published: correctedPublished }),
  ]);
  const publishedCorrectedFeed = JSON.parse(await readFile(feedPath, 'utf8'));
  assert.equal(
    publishedCorrectedFeed.advisories.find(({ id }) => id === correctedId)?.published,
    correctedPublished,
    'a published-only NVD correction must update the existing local advisory',
  );
  assert.match(publishedOnlyOutput, /Updated advisories: 1/);
  assert.match(publishedOnlyOutput, /Advisories retracted: 0/);

  const retractionOutput = await runPopulator([retractedRecord]);
  const updatedFeed = JSON.parse(await readFile(feedPath, 'utf8'));

  assert.equal(
    updatedFeed.advisories.some(({ id }) => id === retractedId),
    false,
    'an existing CVE fetched without protected product/version scope must still be retracted',
  );
  for (const id of untouchedIds) {
    assert.ok(updatedFeed.advisories.some((advisoryEntry) => advisoryEntry.id === id), `${id} must be retained`);
  }
  assert.equal(
    updatedFeed.advisories.find(({ id }) => id === correctedId)?.cvss_score,
    9.8,
    'a corrected CVE outside the next modification response must remain corrected',
  );

  assert.match(retractionOutput, /Updated advisories: 0/);
  assert.match(retractionOutput, /Advisories retracted: 1/);

  await writeFile(
    responsePath,
    `${JSON.stringify(
      {
        vulnerabilities: [
          nvdRecord(correctedId, {
            descriptions: [{ lang: 'en', value: 'NVD removed the protected scope from this record.' }],
            configurations: [],
          }),
        ],
        totalResults: 1,
        startIndex: 0,
        resultsPerPage: 1,
      },
      null,
      2,
    )}\n`,
  );
  const materialRetraction = spawnSync(
    path.join(projectScripts, 'populate-local-feed.sh'),
    ['--days', '1'],
    {
      cwd: projectRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${binDir}:${process.env.PATH}`,
        NVD_TEST_RESPONSE: responsePath,
        FEED_PATH: feedPath,
        SKILL_FEED_PATH: skillFeedPath,
        SUITE_FEED_PATH: suiteFeedPath,
        PUBLIC_FEED_PATH: publicFeedPath,
      },
    },
  );
  assert.notEqual(materialRetraction.status, 0, 'a 25% incremental identity drop must still fail closed');
  assert.match(materialRetraction.stderr, /refusing incremental update because it would retract 1 of 4 existing CVEs/i);
  assert.deepEqual(
    JSON.parse(await readFile(feedPath, 'utf8')),
    updatedFeed,
    'the material-drop guard must abort before replacing the local feed',
  );
  assert.deepEqual(JSON.parse(await readFile(skillFeedPath, 'utf8')), updatedFeed);
  assert.deepEqual(JSON.parse(await readFile(suiteFeedPath, 'utf8')), updatedFeed);
  assert.deepEqual(JSON.parse(await readFile(publicFeedPath, 'utf8')), updatedFeed);

  console.log('Local incremental feed correction test passed');
} finally {
  await rm(workdir, { recursive: true, force: true });
}
