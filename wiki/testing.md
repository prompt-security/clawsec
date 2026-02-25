# Testing

## Testing Strategy
- The repository uses layered verification rather than a single root `npm test` command.
- Core confidence comes from lint/type/build gates plus skill-local Node test suites.
- Python and shell tooling are validated through dedicated lint/security checks.
- Workflow pipelines run the same command classes used in local pre-push automation.

## Verification Layers
| Layer | Commands | Scope |
| --- | --- | --- |
| Frontend/static checks | ESLint + `tsc --noEmit` + `npm run build` | TS/TSX correctness and build viability. |
| Skill unit tests | `node skills/<skill>/test/*.test.mjs` | Signature, matching, suppression, installer contracts. |
| Python quality | `ruff check utils/`, `bandit -r utils/ -ll` | Utility correctness and security patterns. |
| Shell/script quality | ShellCheck + manual script smoke runs | Script hygiene and command robustness. |
| CI security scans | Trivy, npm audit, gitleaks, CodeQL, Scorecard | Dependency, config, and supply-chain security posture. |

## Skill Test Matrix
| Skill | Test Files | Primary Focus |
| --- | --- | --- |
| `clawsec-suite` | `feed_verification`, `guarded_install`, `path_resolution`, fuzz tests | Signature checks, advisory gating, path safety, matching robustness. |
| `openclaw-audit-watchdog` | suppression config and render tests | Config parsing, suppression behavior, report formatting. |
| `clawsec-clawhub-checker` | `reputation_check.test.mjs` | Input validation and reputation gating behavior. |

## CI Workflow Coverage
| Workflow | Trigger | Key Assertions |
| --- | --- | --- |
| `ci.yml` | PR/push to `main` | Lint/type/build, Python checks, security scans, skill tests. |
| `codeql.yml` | PR/push/schedule | JS/TS static security analysis. |
| `scorecard.yml` | schedule/push | Supply-chain posture reporting and SARIF upload. |
| `skill-release.yml` | tags + PRs | Version parity and release artifact verification. |

## Local Testing Commands
```bash
# baseline frontend + config checks
npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0
npx tsc --noEmit
npm run build
```

```bash
# representative skill tests
node skills/clawsec-suite/test/feed_verification.test.mjs
node skills/clawsec-suite/test/guarded_install.test.mjs
node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
```

## Failure Patterns to Watch
- Signature/test fixtures can fail from key/payload mismatch when expected files are regenerated inconsistently.
- Path-resolution tests intentionally fail on escaped home tokens; this behavior is expected and security-relevant.
- Local scripts relying on `openclaw` or `clawhub` binaries may fail in environments where those CLIs are absent.
- Deploy/release logic can pass locally while failing in CI if signing secrets or workflow permissions differ.

## Suggested Test Order
1. Run `./scripts/prepare-to-push.sh` for a full local gate.
2. Run directly impacted skill-local tests.
3. For feed/signing changes, run suite verification tests first (`feed_verification`, `guarded_install`).
4. For workflow or release changes, also run `scripts/validate-release-links.sh` and key consistency script.

## Source References
- AGENTS.md
- scripts/prepare-to-push.sh
- scripts/validate-release-links.sh
- .github/workflows/ci.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/workflows/skill-release.yml
- skills/clawsec-suite/test/feed_verification.test.mjs
- skills/clawsec-suite/test/guarded_install.test.mjs
- skills/clawsec-suite/test/path_resolution.test.mjs
- skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
- skills/clawsec-clawhub-checker/test/reputation_check.test.mjs
- docs/PLATFORM_VERIFICATION.md
