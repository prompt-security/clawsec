const formatWithFallback = (
  dateStr: string | null | undefined,
  formatter: (date: Date) => string,
  emptyFallback: string,
) => {
  if (!dateStr) {
    return emptyFallback;
  }

  try {
    return formatter(new Date(dateStr));
  } catch {
    return dateStr;
  }
};

export const formatShortDate = (dateStr: string) => formatWithFallback(
  dateStr,
  (date) => date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  }),
  dateStr,
);

export const formatLongDateTime = (dateStr: string) => formatWithFallback(
  dateStr,
  (date) => date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }),
  dateStr,
);

export const formatUtcShortDate = (dateStr?: string | null) => formatWithFallback(
  dateStr,
  (date) => date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    timeZone: 'UTC',
  }),
  'n/a',
);

export const formatUtcDateTime = (dateStr?: string | null) => formatWithFallback(
  dateStr,
  (date) => date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: 'UTC',
    timeZoneName: 'short',
  }),
  'n/a',
);
