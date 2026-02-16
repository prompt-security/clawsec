# PR Notes for ClawSec ClawHub Checker

## Important Limitation Notice

This skill currently catches **VirusTotal Code Insight flags** but cannot access **OpenClaw internal check results** because:

1. **VirusTotal flags** are exposed via `clawhub install` command output (we parse stderr)
2. **OpenClaw internal checks** are only shown on the ClawHub website, not exposed via API

## Example from `clawsec-suite` page:
- ✅ **VirusTotal**: "Benign" 
- ⚠️ **OpenClaw internal check**: "The package is internally consistent with a feed-monitoring / advisory-guardian purpose, but a few operational details and optional bypasses deserve attention before installing."

## Recommendation for ClawHub
Expose internal check results via:
- `clawhub inspect --json` endpoint
- Additional API field for security tools
- Or at minimum, include in `clawhub install` warning output

## Current Workaround
Our heuristic checks (skill age, author reputation, downloads, updates) provide similar risk assessment but miss specific operational warnings about bypasses, missing signatures, etc.

## PR Should Include
1. This skill as defense-in-depth layer
2. Feature request to ClawHub for exposing internal check data
3. Documentation about the limitation