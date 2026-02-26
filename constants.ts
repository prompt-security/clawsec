
// Canonical hosted feed endpoint for fetching live advisories
export const ADVISORY_FEED_URL = 'https://clawsec.prompt.security/advisories/feed.json';

// Compatibility mirror for legacy clients; keep as last-resort fallback only
export const LEGACY_ADVISORY_FEED_URL = 'https://clawsec.prompt.security/releases/latest/download/feed.json';

// Local feed path for development
export const LOCAL_FEED_PATH = '/advisories/feed.json';
