# Repository Traffic Archive

## Summary

ClawSec retains GitHub repository traffic with a daily scheduled workflow. GitHub only exposes a short rolling traffic window, so the workflow captures the API every day and writes normalized history to the `traffic-archive` branch.

## Data Flow

- `.github/workflows/archive-traffic.yml` runs daily at `03:17 UTC` and on manual dispatch.
- `scripts/archive-github-traffic.mjs` calls the GitHub traffic API for views, clones, referrers, and popular paths.
- The workflow writes `traffic/archive.json`, `traffic/summary.json`, and `traffic/README.md` to the `traffic-archive` branch.
- The `/traffic` page reads `traffic/summary.json` from the archive branch and renders long-term views.

## Token

Set `TRAFFIC_ARCHIVE_TOKEN` when the default workflow token cannot read repository traffic.

For a fine-grained token, grant read access to repository administration metadata for `prompt-security/clawsec`. The workflow uses `GITHUB_TOKEN` with `contents: write` to push the archive branch.

## Retention Semantics

- Views and clones are upserted by daily timestamp.
- Overlapping GitHub 14-day windows do not get appended as totals.
- Referrers and popular paths are retained as dated snapshots.
- `sum_daily_uniques` is the sum of GitHub daily unique values. It is not deduplicated monthly or yearly visitors.

## Files

- `scripts/archive-github-traffic.mjs`
- `scripts/test-github-traffic-archive.mjs`
- `.github/workflows/archive-traffic.yml`
- `pages/TrafficAnalytics.tsx`
- `traffic-archive:traffic/archive.json`
- `traffic-archive:traffic/summary.json`
