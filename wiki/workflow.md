# Workflow

## End-to-End Lifecycle
- Development starts with local coding + local data population for realistic UI preview.
- PR CI validates quality/security and skill test suites.
- Tag-driven release workflow packages and signs skill artifacts.
- Pages deploy workflow mirrors release/advisory artifacts and publishes the static site.
- Scheduled workflows continuously enrich advisory feed and supply-chain visibility.

## Primary Workflow Map
| Workflow | Trigger | Main Steps |
| --- | --- | --- |
| CI | PR/push to `main` | Lint, typecheck, build, Python checks, security scans, skill tests. |
| Poll NVD CVEs | Daily cron + manual dispatch | Fetch CVEs, transform/dedupe, update feed, sign artifacts, PR changes. |
| Process Community Advisory | Issue label `advisory-approved` | Parse issue form, create advisory, sign feed, open PR, comment issue. |
| Skill Release | Tag `<skill>-v*` | Validate versions, package SBOM files, sign checksums, publish release. |
| Deploy Pages | Successful CI/Release or manual dispatch | Discover releases, mirror assets, sign public advisories/checksums, deploy site. |

## Local Operator Workflow
| Step | Command | Outcome |
| --- | --- | --- |
| Install deps | `npm install` | Ready local environment. |
| Populate local catalog | `./scripts/populate-local-skills.sh` | `public/skills/index.json` and file checksums. |
| Populate local feed | `./scripts/populate-local-feed.sh --days 120` | Updated local advisory feed copy. |
| Run local gate | `./scripts/prepare-to-push.sh` | CI-like pass/fail signal. |
| Start dev UI | `npm run dev` | Browser preview at local Vite endpoint. |

## Release Workflow Details
- Version bump and docs parity are enforced for PR/tag paths.
- Skill packaging includes SBOM-declared files and integrity manifests.
- `checksums.json` is signed and immediately verified in workflow execution.
- Optional publish-to-ClawHub job runs after successful GitHub release when configured.
- Older releases within same major line can be superseded/deleted by automation.

## Advisory Workflow Details
- NVD workflow determines incremental window from previous feed `updated` timestamp.
- Transform phase maps CVE metrics to severity/type and normalizes affected targets.
- Community advisory workflow creates deterministic IDs (`CLAW-YYYY-NNNN`) from issue metadata.
- Both advisory workflows update skill feed copies and signature companions.

## Example Snippets
```bash
# manual release prep for a skill
./scripts/release-skill.sh clawsec-feed 0.0.5
# then push tag if running in release branch mode
```

```yaml
# pages deploy depends on successful upstream workflow run
on:
  workflow_run:
    workflows: ["CI", "Skill Release"]
    types: [completed]
```

## Operational Risks
- Workflow permissions and secret scope misconfiguration can block signing/publishing.
- NVD/API transient failures may delay advisory freshness.
- Invalid tag naming or version mismatches halt release automation.
- Local scripts and CI can diverge if operator machine lacks expected binaries (`jq`, `openssl`, `clawhub`).

## Source References
- scripts/release-skill.sh
- scripts/prepare-to-push.sh
- scripts/populate-local-feed.sh
- scripts/populate-local-skills.sh
- .github/workflows/ci.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/actions/sign-and-verify/action.yml
