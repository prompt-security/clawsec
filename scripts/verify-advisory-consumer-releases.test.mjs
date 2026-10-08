import assert from "node:assert/strict";
import test from "node:test";

import {
  REQUIRED_ADVISORY_CONSUMER_RELEASES,
  findExactDateBuildSelectors,
  validateRequiredConsumerRelease,
  verifyAdvisoryConsumerReleases,
} from "./ci/verify_advisory_consumer_releases.mjs";

function feed(...affected) {
  return {
    advisories: [{ id: "CVE-2026-1000", affected }],
  };
}

function nextPatch(version) {
  const [major, minor, patch] = version.split(".").map(Number);
  return `${major}.${minor}.${patch + 1}`;
}

function compatibleRelease(requirement, { version = requirement.minimumVersion, ...overrides } = {}) {
  const tag = `${requirement.skill}-v${version}`;
  return {
    tag_name: tag,
    draft: false,
    prerelease: false,
    published_at: "2026-10-08T00:00:00Z",
    assets: ["skill.json", `${tag}.zip`].map((name) => ({ name, state: "uploaded", size: 512 })),
    ...overrides,
  };
}

function releaseFetch(pages = [REQUIRED_ADVISORY_CONSUMER_RELEASES.map((requirement) => (
  compatibleRelease(requirement)
))]) {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    const page = Number(new URL(url).searchParams.get("page"));
    const result = pages[page - 1] ?? [];
    if (result?.response) return result.response;
    return {
      ok: true,
      status: 200,
      json: async () => result,
    };
  };
  return { fetchImpl, requests };
}

test("pins the minimum compatible version for every direct advisory consumer", () => {
  assert.deepEqual(
    REQUIRED_ADVISORY_CONSUMER_RELEASES.map(({ skill, minimumVersion, minimumTag }) => ({
      skill,
      minimumVersion,
      minimumTag,
    })),
    [
      {
        skill: "clawsec-suite",
        minimumVersion: "0.1.17",
        minimumTag: "clawsec-suite-v0.1.17",
      },
      {
        skill: "hermes-attestation-guardian",
        minimumVersion: "0.1.8",
        minimumTag: "hermes-attestation-guardian-v0.1.8",
      },
      {
        skill: "clawsec-nanoclaw",
        minimumVersion: "0.0.11",
        minimumTag: "clawsec-nanoclaw-v0.0.11",
      },
    ],
  );
});

test("detects every validator-supported exact date-build package selector", () => {
  const selectors = [
    "hermes-agent@2026.5.29.2",
    "HERMES @ v2024.2.29.0",
    "Hermes-Agent@=V2000.2.29.11",
    " openclaw @ = 1900.2.28.1 ",
  ];
  assert.deepEqual(
    findExactDateBuildSelectors(feed(...selectors)),
    selectors.map((selector, index) => ({
      advisoryId: "CVE-2026-1000",
      selector,
      dateBuild: ["2026.5.29.2", "2024.2.29.0", "2000.2.29.11", "1900.2.28.1"][index],
    })),
  );
});

test("does not gate ordinary SemVer, ranges, or impossible dates", () => {
  assert.deepEqual(
    findExactDateBuildSelectors(feed(
      "hermes-agent@<0.16.0",
      "other-package@1.2.3",
      "hermes-agent@<2026.5.29.2",
      "hermes-agent@2026.2.29.1",
      "hermes-agent@2026.4.31.1",
    )),
    [],
  );
});

test("SemVer-only feeds do not need repository credentials or API calls", async () => {
  let called = false;
  const result = await verifyAdvisoryConsumerReleases(feed("hermes-agent@<0.16.0"), {
    fetchImpl: async () => {
      called = true;
      throw new Error("unexpected fetch");
    },
  });
  assert.equal(result.required, false);
  assert.equal(called, false);
});

test("exact date-build selectors require all three published consumer releases", async () => {
  const { fetchImpl, requests } = releaseFetch();
  const result = await verifyAdvisoryConsumerReleases(feed("Hermes @ = v2026.5.29.2"), {
    apiUrl: "https://github.example/api/v3/",
    fetchImpl,
    repository: "prompt-security/clawsec",
    token: "test-token",
  });

  assert.equal(result.required, true);
  assert.equal(result.releases.length, 3);
  assert.equal(requests.length, 1);
  assert.equal(
    requests[0].url,
    "https://github.example/api/v3/repos/prompt-security/clawsec/releases?per_page=100&page=1",
  );
  for (const { options } of requests) {
    assert.equal(options.headers.Authorization, "Bearer test-token");
    assert.equal(options.headers["X-GitHub-Api-Version"], "2022-11-28");
  }
});

test("newer compatible releases survive cleanup of the minimum release tags", async () => {
  const newerReleases = REQUIRED_ADVISORY_CONSUMER_RELEASES.map((requirement, index) => (
    compatibleRelease(requirement, {
      version: nextPatch(requirement.minimumVersion),
      published_at: `2026-10-0${index + 1}T00:00:00Z`,
    })
  ));
  const { fetchImpl } = releaseFetch([newerReleases]);
  const result = await verifyAdvisoryConsumerReleases(feed("openclaw@2026.5.29.2"), {
    fetchImpl,
    repository: "prompt-security/clawsec",
    token: "test-token",
  });

  assert.deepEqual(
    result.releases.map(({ tag_name: tag }) => tag),
    REQUIRED_ADVISORY_CONSUMER_RELEASES.map(
      (requirement) => `${requirement.skill}-v${nextPatch(requirement.minimumVersion)}`,
    ),
  );
});

test("retained stable floors keep the next stable release gate live beside newer prereleases", async () => {
  const releases = REQUIRED_ADVISORY_CONSUMER_RELEASES.flatMap((requirement) => [
    compatibleRelease(requirement, { published_at: "2026-10-01T00:00:00Z" }),
    compatibleRelease(requirement, {
      version: `${nextPatch(requirement.minimumVersion)}-rc.1`,
      prerelease: true,
      published_at: "2026-10-08T00:00:00Z",
    }),
  ]);
  const { fetchImpl } = releaseFetch([releases]);

  const result = await verifyAdvisoryConsumerReleases(feed("openshell@2026.5.29.2"), {
    fetchImpl,
    repository: "prompt-security/clawsec",
    token: "test-token",
  });

  assert.deepEqual(
    result.releases.map(({ tag_name: tag }) => tag),
    REQUIRED_ADVISORY_CONSUMER_RELEASES.map(({ minimumTag }) => minimumTag),
    "the prerelease must not displace the retained stable floor used before publishing its stable successor",
  );
});

test("release discovery follows pagination before selecting compatible releases", async () => {
  const unrelatedPage = Array.from({ length: 100 }, (_, index) => ({
    tag_name: `unrelated-v1.0.${index}`,
    draft: false,
    prerelease: false,
    published_at: "2026-10-08T00:00:00Z",
    assets: [],
  }));
  const compatiblePage = REQUIRED_ADVISORY_CONSUMER_RELEASES.map((requirement) => (
    compatibleRelease(requirement, { version: nextPatch(requirement.minimumVersion) })
  ));
  const { fetchImpl, requests } = releaseFetch([unrelatedPage, compatiblePage]);

  const result = await verifyAdvisoryConsumerReleases(feed("nanoclaw@2026.5.29.2"), {
    fetchImpl,
    repository: "prompt-security/clawsec",
    token: "test-token",
  });
  assert.equal(result.releases.length, 3);
  assert.deepEqual(
    requests.map(({ url }) => new URL(url).searchParams.get("page")),
    ["1", "2"],
  );
});

test("release verification fails closed when a required skill has no compatible release", async () => {
  const missingRequirement = REQUIRED_ADVISORY_CONSUMER_RELEASES[1];
  const releases = REQUIRED_ADVISORY_CONSUMER_RELEASES
    .filter((requirement) => requirement !== missingRequirement)
    .map((requirement) => compatibleRelease(requirement));
  const { fetchImpl } = releaseFetch([releases]);

  await assert.rejects(
    verifyAdvisoryConsumerReleases(feed("hermes-agent@2026.5.29.2"), {
      fetchImpl,
      repository: "prompt-security/clawsec",
      token: "test-token",
    }),
    new RegExp(`No published, non-draft, non-prerelease ${missingRequirement.skill} release has SemVer >= ${missingRequirement.minimumVersion}`),
  );
});

test("release verification rejects below-minimum and prerelease-only candidates", async () => {
  const requirement = REQUIRED_ADVISORY_CONSUMER_RELEASES[0];
  const [major, minor, patch] = requirement.minimumVersion.split(".").map(Number);
  const belowMinimum = `${major}.${minor}.${patch - 1}`;
  const otherReleases = REQUIRED_ADVISORY_CONSUMER_RELEASES.slice(1).map((candidate) => (
    compatibleRelease(candidate)
  ));

  for (const release of [
    compatibleRelease(requirement, { version: belowMinimum }),
    compatibleRelease(requirement, {
      version: nextPatch(requirement.minimumVersion),
      tag_name: `${requirement.skill}-v${nextPatch(requirement.minimumVersion)}-rc.1`,
      prerelease: true,
    }),
  ]) {
    const { fetchImpl } = releaseFetch([[release, ...otherReleases]]);
    await assert.rejects(
      verifyAdvisoryConsumerReleases(feed("picoclaw@2026.5.29.2"), {
        fetchImpl,
        repository: "prompt-security/clawsec",
        token: "test-token",
      }),
      new RegExp(`No published, non-draft, non-prerelease ${requirement.skill} release has SemVer >= ${requirement.minimumVersion}`),
    );
  }
});

test("release verification fails closed on transport, HTTP, and malformed list responses", async () => {
  const selectorFeed = feed("hermes-agent@2026.5.29.2");
  const options = {
    repository: "prompt-security/clawsec",
    token: "test-token",
  };

  await assert.rejects(
    verifyAdvisoryConsumerReleases(selectorFeed, {
      ...options,
      fetchImpl: async () => {
        throw new Error("connection reset");
      },
    }),
    /Could not list advisory consumer releases \(page 1\): connection reset/,
  );

  const { fetchImpl: httpFailure } = releaseFetch([{ response: { ok: false, status: 503 } }]);
  await assert.rejects(
    verifyAdvisoryConsumerReleases(selectorFeed, { ...options, fetchImpl: httpFailure }),
    /Could not list advisory consumer releases \(page 1\): HTTP 503/,
  );

  await assert.rejects(
    verifyAdvisoryConsumerReleases(selectorFeed, {
      ...options,
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError("unexpected token");
        },
      }),
    }),
    /release list page 1 returned invalid JSON: unexpected token/,
  );

  await assert.rejects(
    verifyAdvisoryConsumerReleases(selectorFeed, {
      ...options,
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({}) }),
    }),
    /release list page 1 is not a JSON array/,
  );
});

test("release verification rejects wrong, below-minimum, and invalid publication states", () => {
  const requirement = REQUIRED_ADVISORY_CONSUMER_RELEASES[0];
  const [major, minor, patch] = requirement.minimumVersion.split(".").map(Number);
  const invalidReleases = [
    [compatibleRelease(requirement, { tag_name: "different-skill-v9.9.9" }), /tag must match/],
    [compatibleRelease(requirement, { version: `${major}.${minor}.${patch - 1}` }), /below minimum/],
    [compatibleRelease(requirement, { draft: true }), /release is a draft/],
    [compatibleRelease(requirement, { prerelease: true }), /release is a prerelease/],
    [compatibleRelease(requirement, { published_at: null }), /no valid publication timestamp/],
    [compatibleRelease(requirement, { published_at: "" }), /no valid publication timestamp/],
    [compatibleRelease(requirement, { published_at: "0" }), /no valid publication timestamp/],
    [compatibleRelease(requirement, { published_at: "not-a-timestamp" }), /no valid publication timestamp/],
  ];

  for (const [release, expected] of invalidReleases) {
    assert.throws(() => validateRequiredConsumerRelease(release, requirement), expected);
  }
});

test("release verification audits each required asset for presence, size, and upload state", () => {
  for (const requirement of REQUIRED_ADVISORY_CONSUMER_RELEASES) {
    const version = nextPatch(requirement.minimumVersion);
    const validRelease = compatibleRelease(requirement, { version });
    for (const assetName of ["skill.json", `${requirement.skill}-v${version}.zip`]) {
      const escapedAssetName = assetName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const expected = new RegExp(`${escapedAssetName} is missing, empty, or not uploaded`);

      const missingAsset = compatibleRelease(requirement, {
        version,
        assets: validRelease.assets.filter(({ name }) => name !== assetName),
      });
      assert.throws(() => validateRequiredConsumerRelease(missingAsset, requirement), expected);

      const zeroByteAsset = compatibleRelease(requirement, {
        version,
        assets: validRelease.assets.map((asset) => (
          asset.name === assetName ? { ...asset, size: 0 } : asset
        )),
      });
      assert.throws(() => validateRequiredConsumerRelease(zeroByteAsset, requirement), expected);

      const unavailableAsset = compatibleRelease(requirement, {
        version,
        assets: validRelease.assets.map((asset) => (
          asset.name === assetName ? { ...asset, state: "new" } : asset
        )),
      });
      assert.throws(() => validateRequiredConsumerRelease(unavailableAsset, requirement), expected);
    }
  }
});

test("exact date-build release checks require repository and token context", async () => {
  let networkCalls = 0;
  const rejectNetwork = async () => {
    networkCalls += 1;
    throw new Error("credential validation must finish before network access");
  };

  await assert.rejects(
    verifyAdvisoryConsumerReleases(feed("hermes-agent@2026.5.29.2"), {
      // Empty strings deliberately override any GitHub Actions ambient values;
      // `undefined` would activate the production environment fallback.
      repository: "",
      token: "test-token",
      fetchImpl: rejectNetwork,
    }),
    /GITHUB_REPOSITORY/,
  );
  await assert.rejects(
    verifyAdvisoryConsumerReleases(feed("hermes-agent@2026.5.29.2"), {
      repository: "prompt-security/clawsec",
      token: "",
      fetchImpl: rejectNetwork,
    }),
    /GH_TOKEN or GITHUB_TOKEN/,
  );
  assert.equal(networkCalls, 0, "missing context must fail before any GitHub API request");
});
