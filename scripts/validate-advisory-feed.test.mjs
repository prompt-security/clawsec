import assert from "node:assert/strict";
import test from "node:test";

import { validateAdvisoryFeed } from "./ci/validate_advisory_feed.mjs";

function advisory(overrides = {}) {
  return {
    id: "CLAW-2026-1000",
    severity: "high",
    title: "Scoped advisory",
    description: "A protected component is affected.",
    action: "Upgrade the affected component.",
    published: "2026-09-01T00:00:00Z",
    updated: "2026-09-01T00:00:00Z",
    affected: ["openclaw@<2026.9.1"],
    platforms: ["openclaw"],
    ...overrides,
  };
}

function nvdAdvisory(overrides = {}) {
  return advisory({
    id: "CVE-2026-1000",
    authoritative_nvd_affected: ["openclaw@<2026.9.1"],
    synthesized_from_ghsa: false,
    ...overrides,
  });
}

function feed(advisories) {
  return {
    version: "1.0.0",
    updated: "2026-09-28T00:00:00Z",
    advisories,
  };
}

function ghsaSourceAdvisory(overrides = {}) {
  const id = overrides.id || "GHSA-src1-1111-2222";
  const cveId = overrides.cve_id === undefined ? null : overrides.cve_id;
  const githubAdvisoryUrl = `https://github.com/openclaw/openclaw/security/advisories/${id}`;
  return {
    id,
    ghsa_id: id,
    cve_id: cveId,
    status: cveId ? "matured" : "active",
    stale: false,
    stale_after_days: 60,
    severity: "high",
    type: "github_security_advisory",
    nvd_category_id: "CWE-94",
    title: "Scoped GHSA",
    description: "A protected component is affected.",
    affected: ["openclaw@<2026.9.1"],
    patched: ["openclaw@2026.9.1"],
    platforms: ["openclaw"],
    action: "Upgrade the affected component.",
    published: "2026-09-01T00:00:00Z",
    updated: "2026-09-01T00:00:00Z",
    withdrawn_at: null,
    references: [
      githubAdvisoryUrl,
      ...(cveId ? [`https://nvd.nist.gov/vuln/detail/${cveId}`] : []),
    ],
    source: "GitHub Security Advisory",
    repository: "openclaw/openclaw",
    github_advisory_url: githubAdvisoryUrl,
    nvd_url: cveId ? `https://nvd.nist.gov/vuln/detail/${cveId}` : null,
    cvss_score: 8.1,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    cwe_ids: ["CWE-94"],
    credits: ["researcher"],
    aliases: [id, ...(cveId ? [cveId] : [])],
    ...overrides,
  };
}

function hermesGlobalGhsaSourceAdvisory(overrides = {}) {
  const id = overrides.id || "GHSA-hrm1-1111-2222";
  const cveId = overrides.cve_id === undefined ? "CVE-2026-53869" : overrides.cve_id;
  const githubAdvisoryUrl = `https://github.com/advisories/${id}`;
  return ghsaSourceAdvisory({
    id,
    ghsa_id: id,
    cve_id: cveId,
    status: cveId ? "matured" : "active",
    nvd_category_id: "CWE-306",
    affected: ["hermes-agent@< 0.16.0"],
    patched: ["hermes-agent@0.16.0"],
    platforms: ["hermes"],
    repository: "nousresearch/hermes-agent",
    github_advisory_url: githubAdvisoryUrl,
    references: [
      githubAdvisoryUrl,
      ...(cveId ? [`https://nvd.nist.gov/vuln/detail/${cveId}`] : []),
    ],
    nvd_url: cveId ? `https://nvd.nist.gov/vuln/detail/${cveId}` : null,
    cwe_ids: ["CWE-306"],
    aliases: [id, ...(cveId ? [cveId] : [])],
    ghsa_source_kind: "global_reviewed_package",
    ghsa_source_ecosystem: "pip",
    ghsa_source_package: "hermes-agent",
    github_reviewed_at: "2026-06-19T14:47:03Z",
    ...overrides,
  });
}

function ghsaSourceFeed({ advisories = [], enrichmentAdvisories = [], excludedIds = [] } = {}) {
  return {
    version: "0.1.0",
    updated: "2026-09-28T00:00:00Z",
    stale_after_days: 60,
    enrichment_advisories: enrichmentAdvisories,
    excluded_advisory_ids: excludedIds,
    advisories,
  };
}

test("accepts scoped package selectors and canonical aliases", () => {
  const value = feed([
      nvdAdvisory({
        ghsa_id: "GHSA-test-1111-2222",
        cve_id: "CVE-2026-1000",
        aliases: ["CVE-2026-1000", "GHSA-test-1111-2222"],
        affected: ["@openclaw/plugin@>=1.0.0 <1.2.0"],
        authoritative_nvd_affected: ["@openclaw/plugin@>=1.0.0 <1.2.0"],
        platforms: ["openclaw", "openshell"],
      }),
    ]);

  assert.equal(validateAdvisoryFeed(value), value);
});

test("validates explicit provenance and rejects synthetic canonical CVEs", () => {
  const nvdBacked = nvdAdvisory({
    authoritative_nvd_affected: ["openclaw@<2026.9.1"],
    synthesized_from_ghsa: false,
    patched: ["openclaw@2026.9.1"],
    authoritative_canonical_patched: ["openclaw@2026.9.1"],
    authoritative_ghsa_patched: [],
    cwe_ids: ["CWE-94"],
    authoritative_canonical_cwe_ids: ["CWE-94"],
    authoritative_ghsa_cwe_ids: [],
    authoritative_canonical_platforms: ["openclaw"],
    authoritative_ghsa_platforms: [],
  });
  const ghsaSynthesized = advisory({
    id: "CVE-2026-2000",
    cve_id: "CVE-2026-2000",
    ghsa_id: "GHSA-syn1-1111-2222",
    aliases: ["CVE-2026-2000", "GHSA-syn1-1111-2222"],
    affected: ["openclaw@<2.0.0"],
    authoritative_nvd_affected: [],
    authoritative_ghsa_affected: ["openclaw@<2.0.0"],
    synthesized_from_ghsa: true,
    patched: ["openclaw@2.0.0"],
    authoritative_canonical_patched: [],
    authoritative_ghsa_patched: ["openclaw@2.0.0"],
    cwe_ids: ["CWE-79"],
    authoritative_canonical_cwe_ids: [],
    authoritative_ghsa_cwe_ids: ["CWE-79"],
    authoritative_canonical_platforms: [],
    authoritative_ghsa_platforms: ["openclaw"],
  });

  assert.equal(validateAdvisoryFeed(feed([nvdBacked])).advisories.length, 1);
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ id: "CVE-2026-3000" })])),
    /canonical CVEs require explicit NVD provenance/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([ghsaSynthesized])),
    /GHSA-synthesized canonical CVEs must not be published/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      nvdAdvisory({
        authoritative_nvd_affected: ["openclaw@*"],
        synthesized_from_ghsa: false,
      }),
    ])),
    /authoritative NVD scope must contain an explicit version range/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      nvdAdvisory({
        authoritative_nvd_affected: ["openclaw@<2.0.0"],
        synthesized_from_ghsa: false,
      }),
    ])),
    /authoritative NVD scope must remain in affected selectors/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({
        ghsa_id: "GHSA-scp1-1111-2222",
        aliases: ["GHSA-scp1-1111-2222"],
        authoritative_ghsa_affected: ["nanoclaw@<2.0.0"],
      }),
    ])),
    /authoritative GHSA scope must remain in affected selectors/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      {
        ...nvdBacked,
        patched: [],
      },
    ])),
    /authoritative patch provenance must remain in patched selectors/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      {
        ...nvdBacked,
        platforms: ["openclaw"],
        authoritative_ghsa_platforms: ["openshell"],
        ghsa_id: "GHSA-meta-1111-2222",
        aliases: ["GHSA-meta-1111-2222"],
      },
    ])),
    /authoritative platform provenance must remain in platforms/,
  );
});

test("rejects empty, duplicate, and unscoped feeds", () => {
  assert.throws(() => validateAdvisoryFeed(feed([])), /at least one advisory/);
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory(), advisory()])),
    /Duplicate advisory id/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ affected: [] })])),
    /explicit product and version scope/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ affected: ["openclaw"] })])),
    /invalid affected selector/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ affected: ["openclaw@banana"] })])),
    /unsupported affected version scope/,
  );
});

test("rejects unknown infrastructure, ClawHub, and alias collisions", () => {
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ platforms: ["unknown-agent"] })])),
    /unsupported protected component/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ affected: ["clawhub@<2.0.0"] })])),
    /distribution channel/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
        nvdAdvisory({ id: "CVE-2026-1000", aliases: ["GHSA-dupe-1111-2222"] }),
        nvdAdvisory({ id: "CVE-2026-2000", aliases: ["GHSA-dupe-1111-2222"] }),
      ])),
    /belongs to both|cve_id must also appear/,
  );
});

test("rejects structurally incomplete advisories before signing", () => {
  assert.throws(() => validateAdvisoryFeed({ advisories: [advisory()] }), /version/);
  assert.throws(() => validateAdvisoryFeed(feed([advisory({ severity: "unknown" })])), /severity/);
  assert.throws(() => validateAdvisoryFeed(feed([advisory({ title: "" })])), /title/);
  assert.throws(() => validateAdvisoryFeed(feed([advisory({ published: "not-a-date" })])), /valid date/);
  assert.throws(() => validateAdvisoryFeed(feed([advisory({ updated: "" })])), /updated/);
  assert.throws(() => validateAdvisoryFeed(feed([advisory({ updated: "not-a-date" })])), /valid date/);
});

test("rejects inferred wildcards and unprotected or unversioned CPEs", () => {
  assert.throws(
    () => validateAdvisoryFeed(feed([advisory({ affected: ["openclaw@*"] })])),
    /wildcard affected scope is only valid.*GHSA/,
  );
  assert.equal(
    validateAdvisoryFeed(feed([
      advisory({
        id: "GHSA-wild-1111-2222",
        aliases: ["GHSA-wild-1111-2222"],
        affected: ["openclaw@*"],
      }),
    ])).advisories.length,
    1,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({
        affected: ["openclaw@*"],
        authoritative_ghsa_affected: ["openclaw@*"],
      }),
    ])),
    /authoritative_ghsa_affected requires a tied, valid GHSA stable identifier/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({
        ghsa_id: "GHSA-not-valid",
        aliases: ["GHSA-not-valid"],
        affected: ["openclaw@*"],
        authoritative_ghsa_affected: ["openclaw@*"],
      }),
    ])),
    /ghsa_id must be a valid GHSA identifier/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({
        ghsa_id: "GHSA-auth-1111-2222",
        aliases: ["GHSA-auth-1111-2222"],
        authoritative_ghsa_affected: ["openclaw@banana"],
      }),
    ])),
    /unsupported authoritative GHSA version scope/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({
        ghsa_id: "GHSA-othr-1111-2222",
        aliases: ["GHSA-othr-1111-2222"],
        affected: ["openclaw@*", "@openclaw/plugin@<2.0.0"],
        authoritative_ghsa_affected: ["@openclaw/plugin@<2.0.0"],
      }),
    ])),
    /wildcard affected scope is only valid.*GHSA/,
  );
  assert.equal(
    validateAdvisoryFeed(feed([
      advisory({
        ghsa_id: "GHSA-auth-1111-2222",
        aliases: ["GHSA-auth-1111-2222"],
        affected: ["openclaw@*"],
        authoritative_ghsa_affected: ["openclaw@*"],
      }),
    ])).advisories.length,
    1,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({ affected: ["cpe:2.3:a:openclaw:clawhub:1.0.0:*:*:*:*:*:*:*"] }),
    ])),
    /allowlisted protected application/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({ affected: ["cpe:2.3:a:openclaw:clawdbot:2026.1.24:*:*:*:*:*:*:*"] }),
    ])),
    /allowlisted protected application/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({ affected: ["cpe:2.3:a:software-metadata.pub:hermes:0.9.0:*:*:*:*:python:*:*"] }),
    ])),
    /allowlisted protected application/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({ affected: ["cpe:2.3:a:nousresearch:hermes_agent:0.18.2:*:*:*:*:*:*:*"] }),
    ])),
    /allowlisted protected application/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({ affected: ["cpe:2.3:a:qwibitai:nanoclaw:1.2.0:*:*:*:*:*:*:*"] }),
    ])),
    /allowlisted protected application/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({ affected: ["cpe:2.3:a:picoclaw:picoclaw:1.2.0:*:*:*:*:*:*:*"] }),
    ])),
    /allowlisted protected application/,
  );
  assert.throws(
    () => validateAdvisoryFeed(feed([
      advisory({ affected: ["cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:*:*:*"] }),
    ])),
    /explicit version/,
  );
});

test("rejects canonical and alias identity collisions", () => {
  assert.throws(
    () => validateAdvisoryFeed(feed([
      nvdAdvisory({
        id: "CVE-2026-1000",
        cve_id: "CVE-2026-1000",
        ghsa_id: "GHSA-dupe-1111-2222",
        aliases: ["CVE-2026-1000", "GHSA-dupe-1111-2222"],
      }),
      advisory({
        id: "GHSA-dupe-1111-2222",
        aliases: ["GHSA-dupe-1111-2222"],
      }),
    ])),
    /Stable identifier GHSA-dupe-1111-2222 belongs to both/,
  );
});

test("accepts reviewed global Hermes package provenance", () => {
  const value = ghsaSourceFeed({ advisories: [hermesGlobalGhsaSourceAdvisory()] });
  assert.equal(validateAdvisoryFeed(value), value);
});

test("keeps provisional Hermes repository advisories alongside the reviewed global source", () => {
  const id = "GHSA-hrm2-1111-2222";
  const githubAdvisoryUrl =
    `https://github.com/nousresearch/hermes-agent/security/advisories/${id}`;
  const advisory = ghsaSourceAdvisory({
    id,
    ghsa_id: id,
    affected: ["hermes-agent@<0.20.0"],
    patched: ["hermes-agent@0.20.0"],
    platforms: ["hermes"],
    repository: "nousresearch/hermes-agent",
    github_advisory_url: githubAdvisoryUrl,
    references: [githubAdvisoryUrl],
  });
  const value = ghsaSourceFeed({ advisories: [advisory] });
  assert.equal(validateAdvisoryFeed(value), value);
});

test("rejects forged or unscoped reviewed global Hermes package provenance", () => {
  const validate = (entry) => validateAdvisoryFeed(ghsaSourceFeed({ advisories: [entry] }));
  const valid = hermesGlobalGhsaSourceAdvisory();

  for (const [entry, expected] of [
    [{ ...valid, ghsa_source_kind: undefined }, /must come from the reviewed global package source/],
    [{ ...valid, ghsa_source_kind: "repository" }, /must come from the reviewed global package source/],
    [{ ...valid, ghsa_source_ecosystem: "npm" }, /source ecosystem must be pip/],
    [{ ...valid, ghsa_source_package: "hermes" }, /source package must be hermes-agent/],
    [{ ...valid, github_reviewed_at: null }, /github_reviewed_at must be a valid date/],
    [{ ...valid, withdrawn_at: "2026-07-01T00:00:00Z" }, /must not be withdrawn/],
    [{
      ...valid,
      github_advisory_url: `https://github.com/nousresearch/hermes-agent/security/advisories/${valid.id}`,
      references: [
        `https://github.com/nousresearch/hermes-agent/security/advisories/${valid.id}`,
        `https://nvd.nist.gov/vuln/detail/${valid.cve_id}`,
      ],
    }, /must use its global GitHub advisory URL/],
    [{ ...valid, affected: [] }, /must contain (?:explicit package scope|an explicit product and version scope)/],
    [{ ...valid, affected: ["hermes@<0.16.0"] }, /affected scope must identify hermes-agent/],
    [{ ...valid, patched: ["hermes@0.16.0"] }, /patched scope must identify hermes-agent/],
  ]) {
    assert.throws(() => validate(entry), expected);
  }
});

test("rejects global reviewed-package metadata on non-Hermes repository advisories", () => {
  const value = ghsaSourceAdvisory({
    ghsa_source_kind: "global_reviewed_package",
    ghsa_source_ecosystem: "npm",
    ghsa_source_package: "openclaw",
    github_reviewed_at: "2026-09-01T00:00:00Z",
  });
  assert.throws(
    () => validateAdvisoryFeed(ghsaSourceFeed({ advisories: [value] })),
    /reviewed global package provenance is only allowlisted for Hermes/,
  );
});

test("validates GHSA source enrichment without requiring publishable scope", () => {
  const cveId = "CVE-2026-5151";
  const first = ghsaSourceAdvisory({
    id: "GHSA-enr1-1111-2222",
    ghsa_id: "GHSA-enr1-1111-2222",
    cve_id: cveId,
    affected: [],
    patched: [],
    platforms: [],
    aliases: ["GHSA-enr1-1111-2222", cveId],
  });
  const second = ghsaSourceAdvisory({
    id: "GHSA-enr2-1111-2222",
    ghsa_id: "GHSA-enr2-1111-2222",
    cve_id: cveId,
    affected: [],
    patched: [],
    aliases: ["GHSA-enr2-1111-2222", cveId],
  });
  const value = ghsaSourceFeed({
    enrichmentAdvisories: [first, second],
    excludedIds: [first.id, second.id],
  });

  assert.equal(validateAdvisoryFeed(value), value);
});

test("validates GHSA source collection identity relationships", () => {
  const published = ghsaSourceAdvisory();
  const enrichment = ghsaSourceAdvisory({
    id: "GHSA-enr3-1111-2222",
    ghsa_id: "GHSA-enr3-1111-2222",
    cve_id: "CVE-2026-5252",
    affected: [],
    patched: [],
    aliases: ["GHSA-enr3-1111-2222", "CVE-2026-5252"],
  });

  assert.throws(
    () => validateAdvisoryFeed({
      ...ghsaSourceFeed({ advisories: [published] }),
      enrichment_advisories: undefined,
    }),
    /enrichment_advisories must be an array/,
  );
  assert.throws(
    () => validateAdvisoryFeed({
      ...feed([advisory()]),
      excluded_advisory_ids: [],
    }),
    /record both enrichment_advisories and excluded_advisory_ids/,
  );
  assert.throws(
    () => {
      const overlap = ghsaSourceAdvisory({
        id: published.id,
        ghsa_id: published.id,
        cve_id: "CVE-2026-5454",
        aliases: [published.id, "CVE-2026-5454"],
      });
      return validateAdvisoryFeed(ghsaSourceFeed({
        advisories: [overlap],
        enrichmentAdvisories: [{ ...overlap, affected: [], patched: [] }],
        excludedIds: [overlap.id],
      }));
    },
    /both directly publishable and enrichment-only|directly publishable GHSA cannot also be excluded/,
  );
  assert.throws(
    () => validateAdvisoryFeed(ghsaSourceFeed({
      advisories: [published],
      excludedIds: [published.id],
    })),
    /directly publishable GHSA cannot also be excluded/,
  );
  assert.throws(
    () => validateAdvisoryFeed(ghsaSourceFeed({
      enrichmentAdvisories: [enrichment],
    })),
    /enrichment advisory must also appear in excluded_advisory_ids/,
  );
  assert.throws(
    () => validateAdvisoryFeed(ghsaSourceFeed({
      enrichmentAdvisories: [enrichment, { ...enrichment }],
      excludedIds: [enrichment.id],
    })),
    /Duplicate GHSA enrichment identity/,
  );
  assert.throws(
    () => validateAdvisoryFeed(ghsaSourceFeed({
      excludedIds: [enrichment.id, enrichment.id.toLowerCase()],
    })),
    /Duplicate excluded GHSA identity/,
  );
});

test("rejects malformed GHSA enrichment provenance before signing", () => {
  const id = "GHSA-enr4-1111-2222";
  const cveId = "CVE-2026-5353";
  const valid = ghsaSourceAdvisory({
    id,
    ghsa_id: id,
    cve_id: cveId,
    affected: [],
    patched: [],
    aliases: [id, cveId],
  });
  const validateEnrichment = (entry) => validateAdvisoryFeed(ghsaSourceFeed({
    enrichmentAdvisories: [entry],
    excludedIds: [id],
  }));

  for (const [entry, expected] of [
    [{ ...valid, cve_id: null, aliases: [id] }, /must have a valid CVE alias/],
    [{ ...valid, ghsa_id: "GHSA-othr-1111-2222" }, /id and ghsa_id must identify the same/],
    [{ ...valid, aliases: [id, "CVE-2026-9999"] }, /cve_id must also appear in aliases/],
    [{ ...valid, status: "active" }, /status must be matured/],
    [{ ...valid, source: "untrusted" }, /source provenance/],
    [{ ...valid, repository: "not-a-repository" }, /owner\/name syntax/],
    [{
      ...valid,
      repository: "softwarepub/hermes",
      github_advisory_url: `https://github.com/softwarepub/hermes/security/advisories/${id}`,
      references: [
        `https://github.com/softwarepub/hermes/security/advisories/${id}`,
        `https://nvd.nist.gov/vuln/detail/${cveId}`,
      ],
    }, /not an allowlisted protected GHSA source/],
    [{ ...valid, github_advisory_url: "https://example.com/advisory" }, /GitHub URL for this GHSA/],
    [{ ...valid, affected: ["openclaw@<2026.9.1"] }, /must not contain directly publishable scope/],
    [{ ...valid, authoritative_nvd_affected: [] }, /must not claim canonical NVD provenance/],
  ]) {
    assert.throws(() => validateEnrichment(entry), expected);
  }
});
