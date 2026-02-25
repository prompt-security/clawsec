# Dependencies

## Build and Runtime
| Layer | Primary Dependencies | Why It Exists |
| --- | --- | --- |
| Frontend runtime | `react`, `react-dom`, `react-router-dom`, `lucide-react` | UI rendering, routing, iconography. |
| Markdown rendering | `react-markdown`, `remark-gfm` | Render skill docs/readmes in detail pages. |
| Build tooling | `vite`, `@vitejs/plugin-react`, `typescript` | Fast TS/TSX bundling and production builds. |
| Python utilities | stdlib + `ruff`/`bandit` policy from `pyproject.toml` | Validate/package skills and run static checks. |
| Shell automation | `bash`, `jq`, `curl`, `openssl`, `sha256sum`/`shasum` | Feed polling, signing, checksum generation, release checks. |

## Dependency Details
| Package | Version Constraint | Scope |
| --- | --- | --- |
| `react` / `react-dom` | `^19.2.4` | Frontend runtime |
| `react-router-dom` | `^7.13.1` | Frontend routing |
| `lucide-react` | `^0.575.0` | UI icon set |
| `vite` | `^7.3.1` | Dev server + build |
| `typescript` | `~5.8.2` | Type checking |
| `eslint` | `^9.39.2` | JS/TS linting |
| `@typescript-eslint/*` | `^8.55.0` / `^8.56.0` | TS lint parser/rules |
| `fast-check` | `^4.5.3` | Property/fuzz style tests |

| Override | Pinned Version | Rationale |
| --- | --- | --- |
| `ajv` | `6.14.0` | Security and compatibility stabilization. |
| `balanced-match` | `4.0.3` | Transitive vulnerability control. |
| `brace-expansion` | `5.0.2` | Transitive dependency hardening. |
| `minimatch` | `10.2.1` | Deterministic dependency behavior. |

## External Services
| Service | Used By | Function |
| --- | --- | --- |
| NVD API (`services.nvd.nist.gov`) | `poll-nvd-cves` workflow + local feed script | Pull CVEs by keyword/date window. |
| GitHub API | Deploy/release workflows | Discover releases, download assets, publish outputs. |
| GitHub Pages | Deploy workflow | Serve static site and mirrored artifacts. |
| ClawHub CLI/registry | Install scripts + optional publish jobs | Install and publish skills. |
| Optional local SMTP/sendmail | `openclaw-audit-watchdog` scripts | Deliver audit reports by email. |

## Development Tools
| Tool | Invocation | Coverage |
| --- | --- | --- |
| ESLint | `npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0` | Frontend and script linting. |
| TypeScript | `npx tsc --noEmit` | Compile-time TS contract checks. |
| Ruff | `ruff check utils/` | Python style and bug pattern checks. |
| Bandit | `bandit -r utils/ -ll` | Python security checks. |
| Trivy | Workflow + optional local run | FS/config vulnerability scans. |
| Gitleaks | Workflow + optional local run | Secret leak detection. |

## Example Snippets
```json
{
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^19.2.4",
    "react-router-dom": "^7.13.1"
  }
}
```

```toml
[tool.ruff]
target-version = "py310"
line-length = 120

[tool.bandit]
exclude_dirs = ["__pycache__", ".venv"]
skips = ["B101"]
```

## Compatibility Notes
- Local scripts account for macOS vs Linux differences in `date` and `stat` usage.
- Some workflows/scripts require OpenSSL features used with Ed25519 and `pkeyutl -rawin`.
- Windows support is strongest for Node-based tooling; POSIX shell paths may require WSL/Git Bash.
- Feed consumers include compatibility bypasses for migration phases, but signed mode is the intended steady state.

## Versioning Notes
- Skill release tags follow `<skill>-v<semver>` and are parsed by CI/deploy automation.
- PR validation enforces version parity between `skill.json` and `SKILL.md` frontmatter for bumped skills.
- The public skills index keeps latest discovered version per skill for UI display.
- Signed artifact manifests (`checksums.json`) are versioned per release and include file hashes and URLs.

## Source References
- package.json
- package-lock.json
- pyproject.toml
- eslint.config.js
- tsconfig.json
- scripts/prepare-to-push.sh
- scripts/populate-local-feed.sh
- scripts/populate-local-skills.sh
- .github/workflows/ci.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/skill-release.yml
