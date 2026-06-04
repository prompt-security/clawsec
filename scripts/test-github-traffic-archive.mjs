import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  buildTrafficSummary,
  fetchGitHubTraffic,
  mergeTrafficArchive,
  writeJson,
} from './archive-github-traffic.mjs';

const TEST_REPOSITORY = 'prompt-security/clawsec';
const TEST_CAPTURE_DATE = Date.UTC(2026, 5, 3);

const utcDay = (offsetFromCaptureDate = 0) => {
  const date = new Date(TEST_CAPTURE_DATE);
  date.setUTCDate(date.getUTCDate() + offsetFromCaptureDate);
  return `${date.toISOString().slice(0, 10)}T00:00:00Z`;
};

const captureAt = ({
  offsetFromCaptureDate = 0,
  hour = 3,
  minute = 17,
} = {}) => {
  const date = new Date(TEST_CAPTURE_DATE);
  date.setUTCDate(date.getUTCDate() + offsetFromCaptureDate);
  date.setUTCHours(hour, minute, 0, 0);
  return date.toISOString();
};

const capturedAt = captureAt();

test('fetchGitHubTraffic requests the daily GitHub traffic endpoints with auth', async () => {
  const calls = [];
  const responses = {
    [`/repos/${TEST_REPOSITORY}/traffic/views?per=day`]: {
      count: 30,
      uniques: 18,
      views: [{ timestamp: utcDay(-1), count: 30, uniques: 18 }],
    },
    [`/repos/${TEST_REPOSITORY}/traffic/clones?per=day`]: {
      count: 7,
      uniques: 5,
      clones: [{ timestamp: utcDay(-1), count: 7, uniques: 5 }],
    },
    [`/repos/${TEST_REPOSITORY}/traffic/popular/referrers`]: [
      { referrer: 'github.com', count: 12, uniques: 9 },
    ],
    [`/repos/${TEST_REPOSITORY}/traffic/popular/paths`]: [
      { path: `/${TEST_REPOSITORY}`, title: TEST_REPOSITORY, count: 16, uniques: 10 },
    ],
  };

  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), headers: options.headers });
    const pathname = new URL(url).pathname;
    const search = new URL(url).search;
    const payload = responses[`${pathname}${search}`];
    assert.ok(payload, `unexpected traffic endpoint: ${pathname}${search}`);
    return new globalThis.Response(JSON.stringify(payload), { status: 200 });
  };

  const snapshot = await fetchGitHubTraffic({
    repo: TEST_REPOSITORY,
    token: 'test-token',
    capturedAt,
    fetchImpl,
  });

  assert.equal(calls.length, 4);
  assert.ok(calls.every((call) => call.headers.Authorization === 'Bearer test-token'));
  assert.deepEqual(snapshot.views.views, responses[`/repos/${TEST_REPOSITORY}/traffic/views?per=day`].views);
  assert.deepEqual(snapshot.clones.clones, responses[`/repos/${TEST_REPOSITORY}/traffic/clones?per=day`].clones);
});

test('mergeTrafficArchive upserts daily views and clones without double-counting overlapping windows', () => {
  const archive = mergeTrafficArchive(
    {
      version: 1,
      repository: TEST_REPOSITORY,
      updated_at: captureAt({ offsetFromCaptureDate: -1 }),
      daily: {
        views: [
          { timestamp: utcDay(-2), count: 10, uniques: 6 },
          { timestamp: utcDay(-1), count: 20, uniques: 12 },
        ],
        clones: [
          { timestamp: utcDay(-2), count: 2, uniques: 1 },
        ],
      },
      snapshots: {
        referrers: [],
        paths: [],
      },
      captures: [],
    },
    {
      repository: TEST_REPOSITORY,
      captured_at: capturedAt,
      views: {
        views: [
          { timestamp: utcDay(-1), count: 25, uniques: 14 },
          { timestamp: utcDay(), count: 35, uniques: 21 },
        ],
      },
      clones: {
        clones: [
          { timestamp: utcDay(-1), count: 3, uniques: 2 },
          { timestamp: utcDay(), count: 5, uniques: 4 },
        ],
      },
      referrers: [{ referrer: 'github.com', count: 12, uniques: 9 }],
      paths: [{ path: `/${TEST_REPOSITORY}`, title: TEST_REPOSITORY, count: 16, uniques: 10 }],
    },
  );

  assert.deepEqual(archive.daily.views, [
    { timestamp: utcDay(-2), count: 10, uniques: 6 },
    { timestamp: utcDay(-1), count: 25, uniques: 14 },
    { timestamp: utcDay(), count: 35, uniques: 21 },
  ]);
  assert.deepEqual(archive.daily.clones, [
    { timestamp: utcDay(-2), count: 2, uniques: 1 },
    { timestamp: utcDay(-1), count: 3, uniques: 2 },
    { timestamp: utcDay(), count: 5, uniques: 4 },
  ]);
});

test('mergeTrafficArchive keeps one referrer/path snapshot per capture date', () => {
  const first = mergeTrafficArchive(undefined, {
    repository: TEST_REPOSITORY,
    captured_at: capturedAt,
    views: { views: [] },
    clones: { clones: [] },
    referrers: [{ referrer: 'github.com', count: 12, uniques: 9 }],
    paths: [{ path: `/${TEST_REPOSITORY}`, title: TEST_REPOSITORY, count: 16, uniques: 10 }],
  });

  const second = mergeTrafficArchive(first, {
    repository: TEST_REPOSITORY,
    captured_at: captureAt({ hour: 4, minute: 0 }),
    views: { views: [] },
    clones: { clones: [] },
    referrers: [{ referrer: 'google.com', count: 8, uniques: 6 }],
    paths: [{ path: `/${TEST_REPOSITORY}/wiki`, title: 'Wiki', count: 11, uniques: 7 }],
  });

  assert.equal(second.snapshots.referrers.length, 1);
  assert.equal(second.snapshots.paths.length, 1);
  assert.deepEqual(second.snapshots.referrers[0].entries, [
    { referrer: 'google.com', count: 8, uniques: 6 },
  ]);
  assert.deepEqual(second.snapshots.paths[0].entries, [
    { path: `/${TEST_REPOSITORY}/wiki`, title: 'Wiki', count: 11, uniques: 7 },
  ]);
});

test('mergeTrafficArchive rejects blank referrer and path fields instead of archiving empty strings', () => {
  assert.throws(
    () => mergeTrafficArchive(undefined, {
      repository: TEST_REPOSITORY,
      captured_at: capturedAt,
      views: { views: [] },
      clones: { clones: [] },
      referrers: [{ count: 12, uniques: 9 }],
      paths: [],
    }),
    /referrers\.referrer must be a non-empty string/,
  );

  assert.throws(
    () => mergeTrafficArchive(undefined, {
      repository: TEST_REPOSITORY,
      captured_at: capturedAt,
      views: { views: [] },
      clones: { clones: [] },
      referrers: [],
      paths: [{ path: `/${TEST_REPOSITORY}`, title: ' ', count: 16, uniques: 10 }],
    }),
    /paths\.title must be a non-empty string/,
  );
});

test('writeJson replaces JSON through a same-directory temporary file', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'clawsec-traffic-json-'));
  const file = path.join(dir, 'summary.json');

  await writeJson(file, { version: 1, count: 1 });
  await writeJson(file, { version: 1, count: 2 });

  assert.equal(await readFile(file, 'utf8'), '{\n  "version": 1,\n  "count": 2\n}\n');
  assert.deepEqual(await readdir(dir), ['summary.json']);
});

test('buildTrafficSummary reports count totals and labels summed daily uniques accurately', () => {
  const archive = mergeTrafficArchive(undefined, {
    repository: TEST_REPOSITORY,
    captured_at: capturedAt,
    views: {
      views: [
        { timestamp: utcDay(-33), count: 100, uniques: 80 },
        { timestamp: utcDay(-1), count: 30, uniques: 18 },
        { timestamp: utcDay(), count: 40, uniques: 22 },
      ],
    },
    clones: {
      clones: [
        { timestamp: utcDay(-1), count: 7, uniques: 5 },
        { timestamp: utcDay(), count: 9, uniques: 6 },
      ],
    },
    referrers: [],
    paths: [],
  });

  const summary = buildTrafficSummary(archive, { now: captureAt({ hour: 12, minute: 0 }) });

  assert.equal(summary.metrics.views.last_30_days.count, 70);
  assert.equal(summary.metrics.views.last_30_days.sum_daily_uniques, 40);
  assert.equal(summary.metrics.views.last_30_days.unique_semantics, 'sum_of_daily_uniques');
  assert.equal(summary.metrics.views.all_time.count, 170);
  assert.equal(summary.metrics.clones.last_30_days.count, 16);
  assert.equal(summary.daily.views.length, 3);
});

test('traffic archive workflow uses a daily schedule and a dedicated archive branch', async () => {
  const workflowPath = new URL('../.github/workflows/archive-traffic.yml', import.meta.url);
  const workflow = await readFile(workflowPath, 'utf8');

  assert.match(workflow, /cron:\s+'17 3 \* \* \*'/);
  assert.match(workflow, /TRAFFIC_ARCHIVE_BRANCH:\s+traffic-archive/);
  assert.match(workflow, /TRAFFIC_ARCHIVE_TOKEN/);
  assert.match(workflow, /node scripts\/archive-github-traffic\.mjs/);
  assert.match(workflow, /git add traffic\/archive\.json traffic\/summary\.json/);
  assert.match(workflow, /git rm --ignore-unmatch traffic\/README\.md/);
  assert.doesNotMatch(workflow, /git add .*traffic\/README\.md/);
  assert.match(workflow, /git push origin HEAD:\$\{TRAFFIC_ARCHIVE_BRANCH\}/);
});
