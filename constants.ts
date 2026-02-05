// ClawSec Suite SKILL.md URL - injected at build time, with hardcoded fallback
export const SKILL_URL = import.meta.env.VITE_CLAWSEC_SUITE_URL || 
  'https://clawsec.prompt.security/releases/download/clawsec-suite-v0.0.5/clawsec-suite.skill';

// Feed URL for fetching live advisories
export const ADVISORY_FEED_URL = 'https://clawsec.prompt.security/releases/latest/download/feed.json';

// Local feed path for development
export const LOCAL_FEED_PATH = '/advisories/feed.json';

