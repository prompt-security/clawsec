#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const inventoryPath = fileURLToPath(
  new URL("../contracts/release-policy/legacy-prereleases-v1.json", import.meta.url),
);
const rawInventory = await readFile(inventoryPath, "utf8");
const inventoryDigest = createHash("sha256").update(rawInventory).digest("hex");

assert.equal(
  inventoryDigest,
  "f688f138685126e6bb234151f7fa5d737096b525191922ad06d2cfaa49ba1720",
  "the reviewed legacy-prerelease snapshot is immutable policy evidence",
);

const inventory = JSON.parse(rawInventory);

assert.equal(inventory.schema, "clawsec.legacy-prerelease-inventory/v1");
assert.deepEqual(inventory.repository, {
  slug: "prompt-security/clawsec",
  git_remote: "https://github.com/prompt-security/clawsec.git",
});
assert.deepEqual(inventory.observation, {
  observed_at: "2026-07-22T23:32:35Z",
  github_releases_api: "https://api.github.com/repos/prompt-security/clawsec/releases?per_page=100",
  github_release_objects_observed: 16,
  release_pagination: "one_complete_page_16_of_100",
  tag_scope: "refs/tags/*-beta*",
  tag_advertisement_method: "git_ls_remote_tags_with_peeled_refs",
  tag_object_method: "fetched_remote_refs_plus_git_for_each_ref_object_type",
  asset_method: "downloaded_bytes_sha256_matched_github_digest",
});
assert.deepEqual(inventory.policy, {
  classification: "frozen_legacy_public_prerelease_history",
  retention: "fetchable_history",
  historical_fetch_only: true,
  authorization_granted: false,
  public_write_authorized: false,
  tag_creation_permitted: false,
  github_release_creation_permitted: false,
  store_publication_permitted: false,
  catalog_activation_permitted: false,
  active_resolution: false,
  discovery_publication_permitted: false,
  republish_permitted: false,
  ref_or_asset_mutation_permitted: false,
});

const expectedRefs = new Map(
  Object.entries({
    "hermes-traffic-guardian-v0.0.1-beta1": [
      "annotated",
      "2763b8214c19ce18c8a1fd8fce7530b0bfeec917",
      "369745821f74f1dc3b196d9df22b643781112052",
    ],
    "hermes-traffic-guardian-v0.0.1-beta2": [
      "annotated",
      "7b21b2d90ba771c6a4ffeeda880df7df99c50828",
      "1e48a955ccf7f9a4b5d4aaedfbb9f47779348595",
    ],
    "hermes-traffic-guardian-v0.0.1-beta3": [
      "lightweight",
      "1b676fd42cf8683db1677a10f25d697cfd3862cb",
      "1b676fd42cf8683db1677a10f25d697cfd3862cb",
    ],
    "hermes-traffic-guardian-v0.0.1-beta5": [
      "annotated",
      "772ab8bad5959c9106357f25417e2efbf70ea162",
      "6573ee9ecfeaacf4b46692d8be02496dcc53af5a",
    ],
    "nanoclaw-traffic-guardian-v0.0.1-beta1": [
      "annotated",
      "cc889f55f45fd7f45be914d847acd1f5c53a5d9b",
      "369745821f74f1dc3b196d9df22b643781112052",
    ],
    "nanoclaw-traffic-guardian-v0.0.1-beta2": [
      "annotated",
      "0f65f85a383a6c82d52551295ab50443ab81fd38",
      "1e48a955ccf7f9a4b5d4aaedfbb9f47779348595",
    ],
    "nanoclaw-traffic-guardian-v0.0.1-beta5": [
      "annotated",
      "e0fdc5c284d1170a6047ef807e2ec6c74a76c49a",
      "6573ee9ecfeaacf4b46692d8be02496dcc53af5a",
    ],
    "openclaw-traffic-guardian-v0.0.1-beta1": [
      "lightweight",
      "369745821f74f1dc3b196d9df22b643781112052",
      "369745821f74f1dc3b196d9df22b643781112052",
    ],
    "openclaw-traffic-guardian-v0.0.1-beta2": [
      "annotated",
      "8d09bbff74aa9ecb16bc034f76f4a0d252930ce7",
      "1e48a955ccf7f9a4b5d4aaedfbb9f47779348595",
    ],
    "openclaw-traffic-guardian-v0.0.1-beta3": [
      "lightweight",
      "c1d1824f862ef673829463e67254593cad362937",
      "c1d1824f862ef673829463e67254593cad362937",
    ],
    "openclaw-traffic-guardian-v0.0.1-beta5": [
      "annotated",
      "f7280af9066be22766f221bb9551c4ca8ee6707b",
      "6573ee9ecfeaacf4b46692d8be02496dcc53af5a",
    ],
    "picoclaw-traffic-guardian-v0.0.1-beta1": [
      "lightweight",
      "369745821f74f1dc3b196d9df22b643781112052",
      "369745821f74f1dc3b196d9df22b643781112052",
    ],
    "picoclaw-traffic-guardian-v0.0.1-beta2": [
      "annotated",
      "f5cf15c697729237834002f1698830f84ce68c4a",
      "1e48a955ccf7f9a4b5d4aaedfbb9f47779348595",
    ],
    "picoclaw-traffic-guardian-v0.0.1-beta3": [
      "lightweight",
      "1b676fd42cf8683db1677a10f25d697cfd3862cb",
      "1b676fd42cf8683db1677a10f25d697cfd3862cb",
    ],
    "picoclaw-traffic-guardian-v0.0.1-beta5": [
      "annotated",
      "515bde4587dea5f9144257eaf25b6f40374ba9e8",
      "6573ee9ecfeaacf4b46692d8be02496dcc53af5a",
    ],
  }),
);

const expectedReleases = new Map(
  Object.entries({
    "hermes-traffic-guardian-v0.0.1-beta5": [343366161, "2026-06-23T08:32:34Z"],
    "nanoclaw-traffic-guardian-v0.0.1-beta5": [343366965, "2026-06-23T08:34:13Z"],
    "openclaw-traffic-guardian-v0.0.1-beta5": [343368509, "2026-06-23T08:37:30Z"],
    "picoclaw-traffic-guardian-v0.0.1-beta5": [343400870, "2026-06-23T09:35:29Z"],
  }),
);

assert.equal(inventory.tags.length, expectedRefs.size);
assert.deepEqual(
  inventory.tags.map(({ name }) => name),
  [...expectedRefs.keys()].sort(),
  "the inventory must remain sorted and contain only the reviewed refs",
);

const allAssetIds = new Set();
let releaseCount = 0;
let assetCount = 0;

for (const tag of inventory.tags) {
  assert.deepEqual(
    Object.keys(tag).sort(),
    ["name", "peeled_commit_oid", "ref_oid", "ref_type", "release"],
  );

  const expectedRef = expectedRefs.get(tag.name);
  assert.ok(expectedRef, `unexpected prerelease ref: ${tag.name}`);
  assert.deepEqual(
    [tag.ref_type, tag.ref_oid, tag.peeled_commit_oid],
    expectedRef,
    `ref identity drifted for ${tag.name}`,
  );
  assert.match(tag.ref_oid, /^[0-9a-f]{40}$/);
  assert.match(tag.peeled_commit_oid, /^[0-9a-f]{40}$/);
  if (tag.ref_type === "lightweight") {
    assert.equal(tag.ref_oid, tag.peeled_commit_oid);
  } else {
    assert.notEqual(tag.ref_oid, tag.peeled_commit_oid);
  }

  const expectedRelease = expectedReleases.get(tag.name);
  if (!expectedRelease) {
    assert.equal(tag.release, null, `${tag.name} must remain tag-only history`);
    continue;
  }

  releaseCount += 1;
  assert.equal(tag.release.id, expectedRelease[0]);
  assert.equal(tag.release.published_at, expectedRelease[1]);
  assert.equal(tag.release.draft, false);
  assert.equal(tag.release.prerelease, true);
  assert.equal(tag.release.immutable, false);
  assert.equal(tag.release.classification, "legacy_mutable");

  const expectedAssetNames = [
    "README.md",
    "SKILL.md",
    "checksums.json",
    "checksums.sig",
    "install.md",
    "permissions.json",
    "signing-public.pem",
    "skill-card.md",
    "skill.json",
    "skillspector-report.md",
    `${tag.name}.zip`,
  ].sort();
  assert.deepEqual(
    tag.release.assets.map(({ name }) => name).sort(),
    expectedAssetNames,
    `asset set drifted for ${tag.name}`,
  );

  const assetNames = new Set();
  for (const asset of tag.release.assets) {
    assetCount += 1;
    assert.deepEqual(Object.keys(asset).sort(), ["id", "name", "sha256", "size"]);
    assert.ok(Number.isSafeInteger(asset.id) && asset.id > 0);
    assert.ok(!allAssetIds.has(asset.id), `duplicate GitHub asset ID ${asset.id}`);
    allAssetIds.add(asset.id);
    assert.match(asset.name, /^[A-Za-z0-9._-]+$/);
    assert.ok(!assetNames.has(asset.name), `duplicate asset ${asset.name} for ${tag.name}`);
    assetNames.add(asset.name);
    assert.ok(Number.isSafeInteger(asset.size) && asset.size >= 0);
    assert.match(asset.sha256, /^[0-9a-f]{64}$/);
  }
}

assert.equal(releaseCount, expectedReleases.size);
assert.equal(assetCount, 44);
assert.deepEqual(inventory.counts, {
  tags: expectedRefs.size,
  releases: releaseCount,
  assets: assetCount,
});

console.log(
  `legacy prerelease inventory: ${inventory.counts.tags} tags, ` +
    `${inventory.counts.releases} releases, ${inventory.counts.assets} assets verified`,
);
