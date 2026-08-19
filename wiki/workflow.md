# Workflow

## End-to-End Lifecycle
- Development starts with local coding + local data population for realistic UI preview.
- PR CI validates quality/security and skill test suites.
- PR Pages-verify validates production build/signing behavior without publishing.
- Tag-driven release workflow packages and signs skill artifacts.
- Pages deploy workflow mirrors release/advisory artifacts and publishes the static site.
- Wiki-sync workflow publishes repo `wiki/` docs to GitHub Wiki on `main`.
- Scheduled workflows continuously enrich advisory feed and supply-chain visibility.

## Primary Workflow Map
| Workflow | Trigger | Main Steps |
| --- | --- | --- |
| CI | PRs to `main` + manual dispatch | Lint, typecheck, build, Python checks, security scans, skill tests. |
| Pages Verify | PRs to `main` | Build Pages artifact and validate signing outputs (no publish). |
| Poll NVD CVEs | Daily cron + manual dispatch | Fetch CVEs, transform/dedupe, update feed, sign artifacts, PR changes. |
| Process Community Advisory | Issue label `advisory-approved` | Parse issue form, create advisory, sign feed, open PR, comment issue. |
| Skill Release | Skill tags + metadata PR changes | PR: version-parity + dry-run checks; tags: package/sign/publish release assets. |
| Deploy Pages | Push to `main` + successful non-PR Skill Release + manual dispatch | Discover releases, mirror assets, sign public advisories/checksums, deploy site. |
| Sync Wiki | Pushes to `main` touching `wiki/**` + manual dispatch | Sync `wiki/` into `<repo>.wiki.git` and generate `Home.md` from `INDEX.md`. |

## Pages Validation Layers

Pages advisory validation runs at three different stages:

| Layer | Trigger | Validation scope |
| --- | --- | --- |
| Deploy Pages Advisory Checksums Tests | Every CI run for a PR to `main`, or a manual CI dispatch | Runs `scripts/test-deploy-pages-checksums.mjs` against local fixtures and generated artifacts. It covers artifact contracts, workflow wiring, retry timing, backoff, and final error reporting without contacting production. |
| Pages Verify | Every PR to `main` | Uses an ephemeral signing key to build the production-shaped Pages artifact, verifies copied files and aliases, and smoke-tests the built endpoints locally. It does not publish or contact the production site. |
| Verify Production Advisory Endpoints | After every successful Pages deployment | Requests the real custom-domain endpoints and verifies that root files, advisory aliases, signatures, signing keys, and the available release mirror agree. |

The production check runs after deployments triggered by a push to `main`, a successful non-PR Skill Release, or a manual dispatch. It is not limited by changed paths because every Pages deployment can temporarily expose mixed artifacts while GitHub Pages or its CDN propagates the new deployment.

Production verification makes up to 12 attempts. The first attempt is immediate; the first retry waits 10 seconds, later waits use a 1.5 exponential backoff factor, and each wait is capped at 60 seconds. A persistent mismatch fails with the final observed endpoint error and guidance to rerun after Pages or CDN propagation completes.

## Local Operator Workflow
| Step | Command | Outcome |
| --- | --- | --- |
| Install deps | `npm install` | Ready local environment. |
| Populate local catalog | `./scripts/populate-local-skills.sh` | `public/skills/index.json` and file checksums. |
| Populate local feed | `./scripts/populate-local-feed.sh --days 120` | Updated local advisory feed copy. |
| Generate wiki llms exports | `npm run gen:wiki-llms` | Updates `public/wiki/llms.txt` and per-page exports. |
| Run local gate | `./scripts/prepare-to-push.sh` | CI-like pass/fail signal. |
| Start dev UI | `npm run dev` | Browser preview at local Vite endpoint. |

## Release Workflow Details
- Version bump and docs parity are enforced for PR/tag paths.
- PR runs validate changed skill packages with a dry-run build before anything is published.
- Tag pushes matching `<skill>-v<semver>` build the real release payload, sign `checksums.json`, verify the signature, and publish GitHub Release assets.
- Skill packaging includes SBOM-declared files, release trust packet files, install instructions, security scan evidence, and integrity manifests.
- `checksums.json` is signed and immediately verified in workflow execution.
- Configured ClawHub publication runs as a blocking job after the GitHub release, uploads the verified signed-release payload, and checks exact registry file parity.
- Older releases within same major line can be superseded/deleted by automation.

## SkillSpector Release Evidence
Detailed SkillSpector release behavior lives in [Automation and Release Pipelines](modules/automation-release.md). Keep the detailed scanner command, staged-payload rules, PR comment behavior, and release-asset list there so scanner changes have one primary documentation owner.

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
- scripts/generate-wiki-llms.mjs
- .github/workflows/ci.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml
- https://github.com/NVIDIA/SkillSpector
- .github/workflows/deploy-pages.yml
- .github/workflows/pages-verify.yml
- .github/workflows/wiki-sync.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/actions/sign-and-verify/action.yml
