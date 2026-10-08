#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import {
  compareSemver,
  isExactDateBuildVersion,
  parseAffectedSpecifier,
} from "../../skills/hermes-attestation-guardian/lib/semver.mjs";

const GITHUB_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const STABLE_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const RELEASES_PER_PAGE = 100;
const MAX_RELEASE_PAGES = 1_000;

function consumerRelease(skill, minimumVersion) {
  return Object.freeze({
    skill,
    minimumVersion,
    minimumTag: `${skill}-v${minimumVersion}`,
  });
}

// These are the first releases whose advisory matchers understand exact
// four-component date-build identities. Publishing such selectors is unsafe
// until every direct consumer has a downloadable release at or above its
// compatibility floor. The exact floor release may later be deleted by the
// normal same-major release retention policy, so the gate deliberately accepts
// newer compatible releases.
export const REQUIRED_ADVISORY_CONSUMER_RELEASES = Object.freeze([
  consumerRelease("clawsec-suite", "0.1.17"),
  consumerRelease("hermes-attestation-guardian", "0.1.8"),
  consumerRelease("clawsec-nanoclaw", "0.0.11"),
]);

function exactDateBuildFromVersionSpec(versionSpec) {
  const normalized = String(versionSpec || "").trim();
  const candidate = normalized.startsWith("=")
    ? normalized.slice(1).trim()
    : normalized;
  return isExactDateBuildVersion(candidate) ? candidate.replace(/^v/i, "") : null;
}

export function findExactDateBuildSelectors(feed) {
  if (!feed || typeof feed !== "object" || Array.isArray(feed)) {
    throw new Error("Advisory feed must be a JSON object");
  }
  if (!Array.isArray(feed.advisories)) {
    throw new Error("Advisory feed must contain an advisories array");
  }

  const matches = [];
  for (const [advisoryIndex, advisory] of feed.advisories.entries()) {
    if (!advisory || typeof advisory !== "object" || Array.isArray(advisory)) {
      throw new Error(`Advisory at index ${advisoryIndex} must be a JSON object`);
    }
    if (!Array.isArray(advisory.affected)) {
      throw new Error(`Advisory at index ${advisoryIndex} must contain an affected array`);
    }

    for (const selector of advisory.affected) {
      if (typeof selector !== "string") {
        throw new Error(`Advisory at index ${advisoryIndex} has a non-string affected selector`);
      }
      const parsed = parseAffectedSpecifier(selector);
      if (!parsed) continue;

      const dateBuild = exactDateBuildFromVersionSpec(parsed.versionSpec);
      if (dateBuild) {
        matches.push({
          advisoryId: typeof advisory.id === "string" ? advisory.id : null,
          selector,
          dateBuild,
        });
      }
    }
  }

  return matches;
}

function publishedAtTimestamp(value) {
  if (
    typeof value !== "string"
    || value.trim().length === 0
    || !GITHUB_TIMESTAMP.test(value)
  ) {
    return null;
  }
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function releaseVersion(release, requirement) {
  if (typeof release?.tag_name !== "string") return null;
  const prefix = `${requirement.skill}-v`;
  if (!release.tag_name.startsWith(prefix)) return null;
  const version = release.tag_name.slice(prefix.length);
  return STABLE_SEMVER.test(version) ? version : null;
}

function expectedReleaseAssets(release) {
  return ["skill.json", `${release.tag_name}.zip`];
}

function requiredReleaseProblems(release, requirement) {
  const problems = [];
  if (!release || typeof release !== "object" || Array.isArray(release)) {
    return ["API response is not a release object"];
  }
  const version = releaseVersion(release, requirement);
  if (!version) {
    problems.push(`tag must match ${requirement.skill}-v<stable-semver>`);
  } else if (compareSemver(version, requirement.minimumVersion) < 0) {
    problems.push(`version ${version} is below minimum ${requirement.minimumVersion}`);
  }
  if (release.draft !== false) problems.push("release is a draft");
  if (release.prerelease !== false) problems.push("release is a prerelease");
  if (publishedAtTimestamp(release.published_at) === null) {
    problems.push("release has no valid publication timestamp");
  }

  const assets = Array.isArray(release.assets) ? release.assets : [];
  for (const expectedAsset of expectedReleaseAssets(release)) {
    const assetIsReady = assets.some((candidate) => (
      candidate?.name === expectedAsset
      && candidate.state === "uploaded"
      && Number.isFinite(candidate.size)
      && candidate.size > 0
    ));
    if (!assetIsReady) {
      problems.push(`${expectedAsset} is missing, empty, or not uploaded`);
    }
  }
  return problems;
}

export function validateRequiredConsumerRelease(release, requirement) {
  const problems = requiredReleaseProblems(release, requirement);
  if (problems.length > 0) {
    throw new Error(
      `Published advisory consumer release ${release?.tag_name || requirement.minimumTag} is not compatible: ${problems.join("; ")}`,
    );
  }
  return release;
}

function selectNewestCompatibleRelease(releases, requirement) {
  const eligible = releases
    .map((release) => ({
      release,
      version: releaseVersion(release, requirement),
      publishedAt: publishedAtTimestamp(release?.published_at),
    }))
    .filter(({ release, version, publishedAt }) => (
      version !== null
      && compareSemver(version, requirement.minimumVersion) >= 0
      && release.draft === false
      && release.prerelease === false
      && publishedAt !== null
    ))
    .sort((left, right) => (
      right.publishedAt - left.publishedAt
      || compareSemver(right.version, left.version)
      || right.release.tag_name.localeCompare(left.release.tag_name)
    ));

  if (eligible.length === 0) {
    throw new Error(
      `No published, non-draft, non-prerelease ${requirement.skill} release has SemVer >= ${requirement.minimumVersion}`,
    );
  }
  return validateRequiredConsumerRelease(eligible[0].release, requirement);
}

async function fetchPublishedReleases({
  apiUrl,
  fetchImpl,
  repository,
  token,
}) {
  const [owner, repositoryName] = repository.split("/");
  const releaseEndpoint = `${apiUrl.replace(/\/$/, "")}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repositoryName)}/releases`;
  const releases = [];

  for (let page = 1; page <= MAX_RELEASE_PAGES; page += 1) {
    const releaseUrl = `${releaseEndpoint}?per_page=${RELEASES_PER_PAGE}&page=${page}`;
    let response;
    try {
      response = await fetchImpl(releaseUrl, {
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "User-Agent": "clawsec-advisory-consumer-release-gate",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      });
    } catch (error) {
      throw new Error(`Could not list advisory consumer releases (page ${page}): ${error.message}`);
    }

    if (!response?.ok) {
      const status = Number.isInteger(response?.status) ? `HTTP ${response.status}` : "unknown HTTP error";
      throw new Error(`Could not list advisory consumer releases (page ${page}): ${status}`);
    }

    let pageReleases;
    try {
      pageReleases = await response.json();
    } catch (error) {
      throw new Error(`Advisory consumer release list page ${page} returned invalid JSON: ${error.message}`);
    }
    if (!Array.isArray(pageReleases)) {
      throw new Error(`Advisory consumer release list page ${page} is not a JSON array`);
    }
    releases.push(...pageReleases);
    if (pageReleases.length < RELEASES_PER_PAGE) return releases;
  }

  throw new Error(`Advisory consumer release pagination exceeded ${MAX_RELEASE_PAGES} pages`);
}

export async function verifyAdvisoryConsumerReleases(feed, {
  apiUrl = process.env.GITHUB_API_URL || "https://api.github.com",
  fetchImpl = globalThis.fetch,
  repository = process.env.GITHUB_REPOSITORY,
  token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN,
} = {}) {
  const selectors = findExactDateBuildSelectors(feed);
  if (selectors.length === 0) {
    return { required: false, selectors, releases: [] };
  }

  if (typeof repository !== "string" || !/^[^/\s]+\/[^/\s]+$/.test(repository)) {
    throw new Error("GITHUB_REPOSITORY must identify one owner/repository");
  }
  if (typeof token !== "string" || token.trim().length === 0) {
    throw new Error("GH_TOKEN or GITHUB_TOKEN is required to verify advisory consumer releases");
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("A Fetch-compatible implementation is required to verify advisory consumer releases");
  }

  const publishedReleases = await fetchPublishedReleases({
    apiUrl,
    fetchImpl,
    repository,
    token,
  });
  const releases = REQUIRED_ADVISORY_CONSUMER_RELEASES.map((requirement) => (
    selectNewestCompatibleRelease(publishedReleases, requirement)
  ));
  return { required: true, selectors, releases };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    const feedPath = process.argv[2];
    if (!feedPath) {
      throw new Error("Usage: verify_advisory_consumer_releases.mjs <feed.json>");
    }
    const feed = JSON.parse(await readFile(feedPath, "utf8"));
    const result = await verifyAdvisoryConsumerReleases(feed);
    if (!result.required) {
      process.stdout.write("No exact four-component date-build selectors; consumer release gate not required.\n");
    } else {
      const tags = result.releases.map(({ tag_name: tag }) => tag).join(", ");
      process.stdout.write(
        `Verified ${tags} for ${result.selectors.length} exact four-component date-build selector(s).\n`,
      );
    }
  } catch (error) {
    console.error(`Advisory consumer release verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}
