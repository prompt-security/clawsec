# Configuration

## Scope
- Configuration spans frontend build settings, runtime feed paths, workflow triggers, and skill metadata contracts.
- Most runtime-sensitive controls are environment variables prefixed with `CLAWSEC_` or `OPENCLAW_`.
- Path normalization is security-sensitive and intentionally rejects unresolved home-token literals.

## Core Runtime Variables
| Variable | Default | Used By |
| --- | --- | --- |
| `CLAWSEC_FEED_URL` | Hosted advisory URL | Suite hook and guarded installer feed loading. |
| `CLAWSEC_FEED_SIG_URL` | `<feed>.sig` | Detached signature source. |
| `CLAWSEC_FEED_CHECKSUMS_URL` | `checksums.json` near feed URL | Optional checksum-manifest source. |
| `CLAWSEC_FEED_PUBLIC_KEY` | Suite-local PEM file | Feed signature verification. |
| `CLAWSEC_ALLOW_UNSIGNED_FEED` | `0` | Temporary migration bypass flag. |
| `CLAWSEC_VERIFY_CHECKSUM_MANIFEST` | `1` | Enables checksum-manifest verification. |
| `CLAWSEC_HOOK_INTERVAL_SECONDS` | `300` | Advisory hook scan throttle. |

## Path Resolution Rules
| Rule | Behavior | Enforcement Location |
| --- | --- | --- |
| `~` expansion | Resolved to detected home directory | Shared path utility functions in suite/watchdog scripts. |
| `$HOME` / `${HOME}` expansion | Resolved when unescaped | Same utilities. |
| Windows home tokens | `%USERPROFILE%`, `$env:USERPROFILE` normalized | Same utilities. |
| Escaped tokens (`\$HOME`) | Rejected with explicit error | Prevents accidental literal directory creation. |
| Invalid explicit path | Can fallback to default path with warning | `resolveConfiguredPath` helpers. |

## Frontend and Build Configuration
- `vite.config.ts` defines port (`3000`), host (`0.0.0.0`), and path alias (`@`).
- `index.html` provides Tailwind runtime config, custom fonts, and base color tokens.
- `tsconfig.json` uses bundler module resolution, `noEmit`, and JSX runtime configuration.
- `eslint.config.js` applies TS, React, hooks, and script-specific lint rules.

## Skill Metadata Configuration
| Field Group | Location | Function |
| --- | --- | --- |
| Core skill identity | `skills/*/skill.json` | Name/version/author/license/description metadata. |
| SBOM file list | `skill.json -> sbom.files` | Declares release-required artifacts. |
| Platform metadata | `openclaw` or `nanoclaw` blocks | CLI requirements, triggers, platform capability hints. |
| Suite catalog metadata | `skills/clawsec-suite/skill.json -> catalog` | Integrated/default/consent behavior for suite members. |

## Workflow Configuration
- Schedule configuration exists in workflow `cron` entries (`poll-nvd-cves`, `codeql`, `scorecard`).
- Release workflow expects tag naming pattern `<skill>-v<semver>`.
- Deployment workflow is triggered by successful CI/release `workflow_run` events and manual dispatch.
- Composite signing action requires private key inputs and verifies signatures immediately after signing.

## Example Snippets
```bash
# run guarded install with explicit local signed feed paths
CLAWSEC_LOCAL_FEED="$HOME/.openclaw/skills/clawsec-suite/advisories/feed.json" \
CLAWSEC_LOCAL_FEED_SIG="$HOME/.openclaw/skills/clawsec-suite/advisories/feed.json.sig" \
CLAWSEC_FEED_PUBLIC_KEY="$HOME/.openclaw/skills/clawsec-suite/advisories/feed-signing-public.pem" \
node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill clawtributor --dry-run
```

```json
{
  "name": "example-skill",
  "version": "1.2.3",
  "sbom": {
    "files": [
      { "path": "SKILL.md", "required": true, "description": "Install docs" }
    ]
  }
}
```

## Operational Notes
- Keep signing keys outside the repository and inject via GitHub Secrets only.
- Prefer absolute paths or unescaped home expressions in local environment variable overrides.
- Treat unsigned feed mode as temporary migration support, not normal operation.
- Re-run release-link validation when editing `SKILL.md` URLs to avoid broken artifact references.

## Source References
- vite.config.ts
- index.html
- tsconfig.json
- eslint.config.js
- skills/clawsec-suite/skill.json
- skills/clawsec-nanoclaw/skill.json
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/utils.mjs
- skills/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- skills/clawsec-suite/scripts/guarded_skill_install.mjs
- scripts/validate-release-links.sh
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/skill-release.yml
- .github/actions/sign-and-verify/action.yml
