import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CalendarDays,
  Download,
  ExternalLink,
  Eye,
  Loader2,
  Users,
} from 'lucide-react';
import { Footer } from '../components/Footer';
import {
  TRAFFIC_ARCHIVE_BRANCH_URL,
  TRAFFIC_ARCHIVE_SUMMARY_URL,
} from '../constants';
import {
  TrafficDailyEntry,
  TrafficMetricWindow,
  TrafficPathEntry,
  TrafficReferrerEntry,
  TrafficSummary,
} from '../types';
import { formatUtcDateTime, formatUtcShortDate } from '../utils/dateFormatters';

type TrafficMode = 'views' | 'clones';

const WINDOW_LABELS: Array<[keyof TrafficSummary['metrics']['views'], string]> = [
  ['last_14_days', '14 days'],
  ['last_30_days', '30 days'],
  ['last_90_days', '90 days'],
  ['last_365_days', '365 days'],
  ['all_time', 'All time'],
];

const formatNumber = new Intl.NumberFormat('en-US');

const MetricCard = ({
  label,
  metric,
}: {
  label: string;
  metric: TrafficMetricWindow;
}) => (
  <div className="rounded-lg border border-clawd-700 bg-clawd-900/85 p-5">
    <div className="flex items-center justify-between gap-3">
      <p className="text-sm font-semibold text-gray-300">{label}</p>
      <CalendarDays className="h-4 w-4 text-clawd-accent" />
    </div>
    <div className="mt-4 grid grid-cols-2 gap-4">
      <div>
        <p className="text-2xl font-bold text-white">{formatNumber.format(metric.count)}</p>
        <p className="text-xs uppercase text-gray-500">events</p>
      </div>
      <div>
        <p className="text-2xl font-bold text-clawd-accent">
          {formatNumber.format(metric.sum_daily_uniques)}
        </p>
        <p className="text-xs uppercase text-gray-500">daily uniques</p>
      </div>
    </div>
    <p className="mt-4 text-xs text-gray-500">
      {formatUtcShortDate(metric.first_date)} - {formatUtcShortDate(metric.last_date)}
    </p>
  </div>
);

const DailyChart = ({
  entries,
  mode,
}: {
  entries: TrafficDailyEntry[];
  mode: TrafficMode;
}) => {
  const chartEntries = entries.slice(-90);
  const maxCount = Math.max(...chartEntries.map((entry) => entry.count), 1);
  const barClass = mode === 'views' ? 'bg-clawd-accent' : 'bg-emerald-300';

  if (chartEntries.length === 0) {
    return (
      <div className="flex h-72 items-center justify-center rounded-lg border border-dashed border-clawd-700 bg-clawd-900/50 text-sm text-gray-400">
        No daily traffic data has been archived yet.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-clawd-700 bg-clawd-900/70 p-5">
      <div className="mb-5 flex items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white">Daily {mode}</h2>
          <p className="text-xs text-gray-500">Latest {chartEntries.length} archived days</p>
        </div>
        <BarChart3 className="h-5 w-5 text-clawd-accent" />
      </div>
      <div className="flex h-64 items-end gap-1 overflow-hidden">
        {chartEntries.map((entry) => {
          const height = Math.max(4, Math.round((entry.count / maxCount) * 100));
          return (
            <div
              key={entry.timestamp}
              className="group flex min-w-0 flex-1 items-end"
              title={`${formatUtcShortDate(entry.timestamp)}: ${formatNumber.format(entry.count)} ${mode}, ${formatNumber.format(entry.uniques)} daily uniques`}
            >
              <div
                className={`w-full rounded-t-sm ${barClass} opacity-70 transition-opacity group-hover:opacity-100`}
                style={{ height: `${height}%` }}
              />
            </div>
          );
        })}
      </div>
      <div className="mt-3 flex items-center justify-between text-xs text-gray-500">
        <span>{formatUtcShortDate(chartEntries[0].timestamp)}</span>
        <span>{formatUtcShortDate(chartEntries.at(-1)?.timestamp)}</span>
      </div>
    </div>
  );
};

const SnapshotList = ({
  title,
  capturedAt,
  entries,
  type,
}: {
  title: string;
  capturedAt?: string | null;
  entries: Array<TrafficReferrerEntry | TrafficPathEntry>;
  type: 'referrer' | 'path';
}) => (
  <section className="rounded-lg border border-clawd-700 bg-clawd-900/80 p-5">
    <div className="mb-5 flex items-center justify-between gap-4">
      <div>
        <h2 className="text-lg font-bold text-white">{title}</h2>
        <p className="text-xs text-gray-500">Captured {formatUtcDateTime(capturedAt)}</p>
      </div>
      <Activity className="h-5 w-5 text-clawd-accent" />
    </div>
    {entries.length === 0 ? (
      <p className="text-sm text-gray-400">No snapshot data has been archived yet.</p>
    ) : (
      <div className="space-y-3">
        {entries.slice(0, 10).map((entry) => {
          const label = type === 'path'
            ? ((entry as TrafficPathEntry).title || (entry as TrafficPathEntry).path)
            : (entry as TrafficReferrerEntry).referrer;
          const href = type === 'path'
            ? `https://github.com${(entry as TrafficPathEntry).path}`
            : null;

          return (
            <div key={`${type}-${label}`} className="flex items-center justify-between gap-4">
              <div className="min-w-0">
                {href ? (
                  <a
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block truncate text-sm font-semibold text-white hover:text-clawd-accent"
                  >
                    {label}
                  </a>
                ) : (
                  <p className="truncate text-sm font-semibold text-white">{label}</p>
                )}
                {'path' in entry && (
                  <p className="truncate text-xs text-gray-500">{entry.path}</p>
                )}
              </div>
              <div className="shrink-0 text-right">
                <p className="text-sm font-bold text-clawd-accent">{formatNumber.format(entry.count)}</p>
                <p className="text-xs text-gray-500">{formatNumber.format(entry.uniques)} uniques</p>
              </div>
            </div>
          );
        })}
      </div>
    )}
  </section>
);

export const TrafficAnalytics: React.FC = () => {
  const [summary, setSummary] = useState<TrafficSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<TrafficMode>('views');

  useEffect(() => {
    let active = true;

    const fetchSummary = async () => {
      setLoading(true);
      setError(null);

      try {
        const response = await fetch(TRAFFIC_ARCHIVE_SUMMARY_URL, { cache: 'no-store' });
        if (!response.ok) {
          throw new Error(`Archive returned ${response.status}`);
        }
        const payload: TrafficSummary = await response.json();
        if (active) {
          setSummary(payload);
        }
      } catch (err) {
        console.error('Failed to load traffic archive:', err);
        if (active) {
          setError('Traffic archive data is not available yet.');
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    fetchSummary();

    return () => {
      active = false;
    };
  }, []);

  const selectedMetrics = summary?.metrics[mode];
  const selectedDaily = useMemo(() => summary?.daily[mode] || [], [summary, mode]);

  return (
    <div className="max-w-6xl mx-auto pt-[52px] space-y-10">
      <section className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
        <div className="max-w-3xl space-y-4">
          <div className="inline-flex items-center gap-2 rounded-lg border border-clawd-700 bg-clawd-900/70 px-3 py-1 text-xs font-semibold uppercase text-clawd-accent">
            <Activity className="h-4 w-4" />
            GitHub traffic archive
          </div>
          <h1 className="text-3xl md:text-4xl text-white">Repository Traffic</h1>
          <p className="text-gray-400">
            Daily retained views, clones, referrers, and popular paths for prompt-security/clawsec.
          </p>
        </div>
        <a
          href={TRAFFIC_ARCHIVE_BRANCH_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center justify-center gap-2 rounded-lg bg-clawd-accent px-4 py-2 font-semibold text-[#27125d] transition-colors hover:bg-clawd-accentHover"
        >
          <ExternalLink size={17} />
          Open archive
        </a>
      </section>

      {loading ? (
        <section className="flex items-center justify-center rounded-lg border border-clawd-700 bg-clawd-900/80 py-16">
          <Loader2 className="h-7 w-7 animate-spin text-clawd-accent" />
          <span className="ml-3 text-gray-400">Loading traffic archive...</span>
        </section>
      ) : error || !summary || !selectedMetrics ? (
        <section className="rounded-lg border border-orange-500/30 bg-orange-950/20 p-6">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-1 h-5 w-5 shrink-0 text-orange-300" />
            <div>
              <h2 className="font-bold text-orange-200">Archive unavailable</h2>
              <p className="mt-1 text-sm text-gray-300">{error || 'Traffic archive data is missing.'}</p>
              <a
                href={TRAFFIC_ARCHIVE_BRANCH_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-4 inline-flex items-center gap-2 text-sm font-semibold text-clawd-accent hover:text-clawd-accentHover"
              >
                Check archive branch
                <ExternalLink size={15} />
              </a>
            </div>
          </div>
        </section>
      ) : (
        <>
          <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
            {WINDOW_LABELS.map(([key, label]) => (
              <MetricCard key={key} label={label} metric={selectedMetrics[key]} />
            ))}
          </section>

          <section className="flex flex-col gap-4 rounded-lg border border-clawd-700 bg-clawd-900/70 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3 text-sm text-gray-400">
              <Users className="h-5 w-5 text-clawd-accent" />
              <span>Updated {formatUtcDateTime(summary.updated_at)}</span>
            </div>
            <div className="inline-flex rounded-lg bg-clawd-800 p-1">
              <button
                type="button"
                onClick={() => setMode('views')}
                aria-pressed={mode === 'views'}
                className={`inline-flex items-center gap-2 rounded-md px-4 py-2 text-sm font-semibold transition-colors ${
                  mode === 'views' ? 'bg-white text-clawd-900' : 'text-gray-400 hover:text-white'
                }`}
              >
                <Eye size={16} />
                Views
              </button>
              <button
                type="button"
                onClick={() => setMode('clones')}
                aria-pressed={mode === 'clones'}
                className={`inline-flex items-center gap-2 rounded-md px-4 py-2 text-sm font-semibold transition-colors ${
                  mode === 'clones' ? 'bg-white text-clawd-900' : 'text-gray-400 hover:text-white'
                }`}
              >
                <Download size={16} />
                Clones
              </button>
            </div>
          </section>

          <DailyChart entries={selectedDaily} mode={mode} />

          <section className="grid gap-5 lg:grid-cols-2">
            <SnapshotList
              title="Latest referrers"
              capturedAt={summary.latest_snapshots.referrers?.captured_at}
              entries={summary.latest_snapshots.referrers?.entries || []}
              type="referrer"
            />
            <SnapshotList
              title="Latest popular paths"
              capturedAt={summary.latest_snapshots.paths?.captured_at}
              entries={summary.latest_snapshots.paths?.entries || []}
              type="path"
            />
          </section>
        </>
      )}

      <Footer />
    </div>
  );
};
