#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const API_ROOT = 'https://api.github.com';
const GITHUB_API_VERSION = '2022-11-28';
const ARCHIVE_VERSION = 1;
const DAY_MS = 24 * 60 * 60 * 1000;

const SUMMARY_WINDOWS = [
  ['last_14_days', 14],
  ['last_30_days', 30],
  ['last_90_days', 90],
  ['last_365_days', 365],
];

const toIsoString = (value, label) => {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return date.toISOString();
};

const toDailyTimestamp = (value) => `${toIsoString(value, 'traffic timestamp').slice(0, 10)}T00:00:00Z`;
const toDateKey = (value) => toIsoString(value, 'capture timestamp').slice(0, 10);

const toNonNegativeInteger = (value, label) => {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return Math.trunc(number);
};

const toRequiredString = (value, label) => {
  if (typeof value !== 'string') {
    throw new Error(`${label} must be a non-empty string`);
  }

  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`${label} must be a non-empty string`);
  }

  return trimmed;
};

const normalizeRepository = (repo) => {
  const normalized = String(repo || '').trim();
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(normalized)) {
    throw new Error(`Repository must be in owner/name form, received: ${repo || '(empty)'}`);
  }
  return normalized;
};

const normalizeDailyEntries = (entries, label) => {
  if (!Array.isArray(entries)) {
    throw new Error(`${label} must be an array`);
  }

  return entries
    .map((entry) => ({
      timestamp: toDailyTimestamp(entry.timestamp),
      count: toNonNegativeInteger(entry.count, `${label}.count`),
      uniques: toNonNegativeInteger(entry.uniques, `${label}.uniques`),
    }))
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
};

const normalizeReferrers = (entries) => {
  if (!Array.isArray(entries)) {
    throw new Error('referrers must be an array');
  }

  return entries.map((entry) => ({
    referrer: toRequiredString(entry.referrer, 'referrers.referrer'),
    count: toNonNegativeInteger(entry.count, 'referrers.count'),
    uniques: toNonNegativeInteger(entry.uniques, 'referrers.uniques'),
  }));
};

const normalizePaths = (entries) => {
  if (!Array.isArray(entries)) {
    throw new Error('paths must be an array');
  }

  return entries.map((entry) => ({
    path: toRequiredString(entry.path, 'paths.path'),
    title: toRequiredString(entry.title, 'paths.title'),
    count: toNonNegativeInteger(entry.count, 'paths.count'),
    uniques: toNonNegativeInteger(entry.uniques, 'paths.uniques'),
  }));
};

const upsertByKey = (existing, incoming, key) => {
  const entriesByKey = new Map();

  for (const entry of existing || []) {
    entriesByKey.set(entry[key], entry);
  }
  for (const entry of incoming || []) {
    entriesByKey.set(entry[key], entry);
  }

  return [...entriesByKey.values()].sort((a, b) => String(a[key]).localeCompare(String(b[key])));
};

const latestEntry = (entries) => {
  if (!entries?.length) {
    return null;
  }
  return entries[entries.length - 1];
};

const sumSeries = (entries) => entries.reduce(
  (totals, entry) => ({
    count: totals.count + entry.count,
    sum_daily_uniques: totals.sum_daily_uniques + entry.uniques,
  }),
  { count: 0, sum_daily_uniques: 0 },
);

const startOfUtcDay = (date) => Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());

const summarizeWindow = (entries, days, now) => {
  const cutoff = new Date(startOfUtcDay(now) - ((days - 1) * DAY_MS));
  const filtered = entries.filter((entry) => new Date(entry.timestamp) >= cutoff);
  const totals = sumSeries(filtered);

  return {
    days,
    count: totals.count,
    sum_daily_uniques: totals.sum_daily_uniques,
    unique_semantics: 'sum_of_daily_uniques',
    first_date: filtered[0]?.timestamp.slice(0, 10) ?? null,
    last_date: filtered.at(-1)?.timestamp.slice(0, 10) ?? null,
  };
};

const summarizeAllTime = (entries) => {
  const totals = sumSeries(entries);

  return {
    count: totals.count,
    sum_daily_uniques: totals.sum_daily_uniques,
    unique_semantics: 'sum_of_daily_uniques',
    first_date: entries[0]?.timestamp.slice(0, 10) ?? null,
    last_date: entries.at(-1)?.timestamp.slice(0, 10) ?? null,
  };
};

const normalizeExistingArchive = (archive, repository, capturedAt) => {
  if (!archive) {
    return {
      version: ARCHIVE_VERSION,
      repository,
      archive_started_at: capturedAt,
      updated_at: capturedAt,
      daily: {
        views: [],
        clones: [],
      },
      snapshots: {
        referrers: [],
        paths: [],
      },
      captures: [],
    };
  }

  if (archive.repository && archive.repository !== repository) {
    throw new Error(`Archive repository mismatch: ${archive.repository} != ${repository}`);
  }

  return {
    version: ARCHIVE_VERSION,
    repository,
    archive_started_at: archive.archive_started_at || capturedAt,
    updated_at: archive.updated_at || capturedAt,
    daily: {
      views: normalizeDailyEntries(archive.daily?.views || [], 'daily.views'),
      clones: normalizeDailyEntries(archive.daily?.clones || [], 'daily.clones'),
    },
    snapshots: {
      referrers: (archive.snapshots?.referrers || []).map((snapshot) => ({
        captured_at: toIsoString(snapshot.captured_at, 'referrer snapshot timestamp'),
        date: snapshot.date || toDateKey(snapshot.captured_at),
        entries: normalizeReferrers(snapshot.entries || []),
      })),
      paths: (archive.snapshots?.paths || []).map((snapshot) => ({
        captured_at: toIsoString(snapshot.captured_at, 'path snapshot timestamp'),
        date: snapshot.date || toDateKey(snapshot.captured_at),
        entries: normalizePaths(snapshot.entries || []),
      })),
    },
    captures: (archive.captures || []).map((capture) => ({
      captured_at: toIsoString(capture.captured_at, 'capture timestamp'),
      date: capture.date || toDateKey(capture.captured_at),
      views_window: {
        count: toNonNegativeInteger(capture.views_window?.count || 0, 'captures.views_window.count'),
        uniques: toNonNegativeInteger(capture.views_window?.uniques || 0, 'captures.views_window.uniques'),
      },
      clones_window: {
        count: toNonNegativeInteger(capture.clones_window?.count || 0, 'captures.clones_window.count'),
        uniques: toNonNegativeInteger(capture.clones_window?.uniques || 0, 'captures.clones_window.uniques'),
      },
    })),
  };
};

export const mergeTrafficArchive = (existingArchive, snapshot) => {
  const repository = normalizeRepository(snapshot.repository);
  const capturedAt = toIsoString(snapshot.captured_at, 'capture timestamp');
  const captureDate = toDateKey(capturedAt);
  const archive = normalizeExistingArchive(existingArchive, repository, capturedAt);

  const views = normalizeDailyEntries(snapshot.views?.views || [], 'views');
  const clones = normalizeDailyEntries(snapshot.clones?.clones || [], 'clones');
  const referrerSnapshot = {
    captured_at: capturedAt,
    date: captureDate,
    entries: normalizeReferrers(snapshot.referrers || []),
  };
  const pathSnapshot = {
    captured_at: capturedAt,
    date: captureDate,
    entries: normalizePaths(snapshot.paths || []),
  };
  const capture = {
    captured_at: capturedAt,
    date: captureDate,
    views_window: {
      count: toNonNegativeInteger(snapshot.views?.count ?? sumSeries(views).count, 'views.count'),
      uniques: toNonNegativeInteger(snapshot.views?.uniques ?? sumSeries(views).sum_daily_uniques, 'views.uniques'),
    },
    clones_window: {
      count: toNonNegativeInteger(snapshot.clones?.count ?? sumSeries(clones).count, 'clones.count'),
      uniques: toNonNegativeInteger(snapshot.clones?.uniques ?? sumSeries(clones).sum_daily_uniques, 'clones.uniques'),
    },
  };

  return {
    ...archive,
    updated_at: capturedAt,
    daily: {
      views: upsertByKey(archive.daily.views, views, 'timestamp'),
      clones: upsertByKey(archive.daily.clones, clones, 'timestamp'),
    },
    snapshots: {
      referrers: upsertByKey(archive.snapshots.referrers, [referrerSnapshot], 'date'),
      paths: upsertByKey(archive.snapshots.paths, [pathSnapshot], 'date'),
    },
    captures: upsertByKey(archive.captures, [capture], 'date'),
  };
};

export const buildTrafficSummary = (archive, options = {}) => {
  const now = new Date(options.now || new Date().toISOString());
  if (Number.isNaN(now.getTime())) {
    throw new Error(`Invalid summary date: ${options.now}`);
  }

  const views = archive.daily?.views || [];
  const clones = archive.daily?.clones || [];
  const buildMetrics = (entries) => {
    const metrics = Object.fromEntries(SUMMARY_WINDOWS.map(([key, days]) => [
      key,
      summarizeWindow(entries, days, now),
    ]));
    metrics.all_time = summarizeAllTime(entries);
    return metrics;
  };

  return {
    version: ARCHIVE_VERSION,
    repository: archive.repository,
    generated_at: now.toISOString(),
    archive_started_at: archive.archive_started_at || null,
    updated_at: archive.updated_at || null,
    source: {
      api: 'GitHub REST repository traffic endpoints',
      retention_limit: 'GitHub exposes roughly the last 14 days; this archive keeps daily snapshots long term.',
      unique_semantics: 'GitHub daily unique values are retained as sum_daily_uniques for longer windows, not deduplicated visitors.',
    },
    metrics: {
      views: buildMetrics(views),
      clones: buildMetrics(clones),
    },
    daily: {
      views,
      clones,
    },
    latest_snapshots: {
      referrers: latestEntry(archive.snapshots?.referrers || []),
      paths: latestEntry(archive.snapshots?.paths || []),
    },
    snapshot_counts: {
      referrers: archive.snapshots?.referrers?.length || 0,
      paths: archive.snapshots?.paths?.length || 0,
      captures: archive.captures?.length || 0,
    },
  };
};

const fetchJson = async ({ repo, token, pathname, fetchImpl }) => {
  const url = new URL(pathname, API_ROOT);
  const response = await fetchImpl(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'User-Agent': 'clawsec-traffic-archive',
      'X-GitHub-Api-Version': GITHUB_API_VERSION,
    },
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    const suffix = body ? ` ${body.slice(0, 500)}` : '';
    throw new Error(`GitHub traffic API request failed for ${repo}: ${url.pathname}${url.search} returned ${response.status}.${suffix}`);
  }

  return response.json();
};

export const fetchGitHubTraffic = async ({
  repo,
  token,
  capturedAt = new Date().toISOString(),
  fetchImpl = globalThis.fetch,
}) => {
  const repository = normalizeRepository(repo);
  if (!token) {
    throw new Error('A GitHub token is required to read repository traffic.');
  }
  if (typeof fetchImpl !== 'function') {
    throw new Error('fetch is not available in this Node runtime.');
  }

  const encodedRepo = repository.split('/').map(encodeURIComponent).join('/');
  const request = (pathname) => fetchJson({
    repo: repository,
    token,
    pathname: `/repos/${encodedRepo}${pathname}`,
    fetchImpl,
  });

  const [views, clones, referrers, paths] = await Promise.all([
    request('/traffic/views?per=day'),
    request('/traffic/clones?per=day'),
    request('/traffic/popular/referrers'),
    request('/traffic/popular/paths'),
  ]);

  return {
    repository,
    captured_at: toIsoString(capturedAt, 'capture timestamp'),
    views,
    clones,
    referrers,
    paths,
  };
};

const readJsonIfPresent = async (file) => {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return undefined;
    }
    throw error;
  }
};

const writeTextAtomic = async (file, content) => {
  const dir = path.dirname(file);
  const tempFile = path.join(dir, `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  let handle;

  await fs.mkdir(dir, { recursive: true });

  try {
    handle = await fs.open(tempFile, 'w');
    await handle.writeFile(content, 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await fs.rename(tempFile, file);
  } catch (error) {
    if (handle) {
      await handle.close().catch(() => {});
    }
    await fs.unlink(tempFile).catch(() => {});
    throw error;
  }
};

export const writeJson = async (file, value) => {
  await writeTextAtomic(file, `${JSON.stringify(value, null, 2)}\n`);
};

const parseArgs = (args) => {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--archive-dir') {
      options.archiveDir = args[index + 1];
      index += 1;
    } else if (arg === '--repo') {
      options.repo = args[index + 1];
      index += 1;
    } else if (arg === '--captured-at') {
      options.capturedAt = args[index + 1];
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
};

const printHelp = () => {
  console.log(`Usage: node scripts/archive-github-traffic.mjs [options]

Options:
  --archive-dir <dir>   Directory that will receive archive.json and summary.json.
  --repo <owner/repo>   Repository to archive. Defaults to GITHUB_REPOSITORY.
  --captured-at <iso>   Override capture time for tests or backfills.
`);
};

const main = async () => {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    printHelp();
    return;
  }

  const archiveDir = path.resolve(
    REPO_ROOT,
    options.archiveDir || process.env.TRAFFIC_ARCHIVE_DIR || 'traffic',
  );
  const archiveFile = path.join(archiveDir, 'archive.json');
  const summaryFile = path.join(archiveDir, 'summary.json');
  const repository = normalizeRepository(options.repo || process.env.GITHUB_REPOSITORY);
  const token = process.env.GH_TRAFFIC_TOKEN
    || process.env.TRAFFIC_ARCHIVE_TOKEN
    || process.env.GITHUB_TOKEN
    || process.env.GH_TOKEN;
  const capturedAt = options.capturedAt || new Date().toISOString();

  const snapshot = await fetchGitHubTraffic({
    repo: repository,
    token,
    capturedAt,
  });
  const existingArchive = await readJsonIfPresent(archiveFile);
  const archive = mergeTrafficArchive(existingArchive, snapshot);
  const summary = buildTrafficSummary(archive, { now: archive.updated_at });

  await writeJson(archiveFile, archive);
  await writeJson(summaryFile, summary);

  console.log(`Archived GitHub traffic for ${repository} at ${archive.updated_at}`);
  console.log(`Daily views retained: ${archive.daily.views.length}`);
  console.log(`Daily clones retained: ${archive.daily.clones.length}`);
  console.log(`Referrer snapshots retained: ${archive.snapshots.referrers.length}`);
  console.log(`Path snapshots retained: ${archive.snapshots.paths.length}`);
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await main();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Failed to archive GitHub traffic: ${message}`);
    process.exit(1);
  }
}
