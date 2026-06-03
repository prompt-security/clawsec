# Wiki Index

## Summary
- Purpose: Document ClawSec as a combined web catalog, signed advisory channel, and multi-skill security distribution system.
- Tech stack: React 19 + Vite + TypeScript frontend, Node/ESM scripts, Python utilities, Bash automation, GitHub Actions pipelines.
- Entry points: `index.tsx`, `App.tsx`, `scripts/prepare-to-push.sh`, `scripts/populate-local-feed.sh`, `scripts/populate-local-skills.sh`, workflow files under `.github/workflows/`.
- Where to start: Read [Overview](overview.md), then [Architecture](architecture.md), then module pages for the area you are editing.
- How to navigate: Use Guides for cross-cutting concerns, Operations for runbooks and migration plans, Modules for implementation boundaries, and Source References at the end of each page to jump into code.

## Start Here
- [Overview](overview.md)
- [Architecture](architecture.md)

## Translations
- [Español](es/INDEX.md)
- [한국어](ko/INDEX.md)
- [Français (draft scaffold)](fr/INDEX.md)
- [Deutsch (draft scaffold)](de/INDEX.md)
- [日本語 (draft scaffold)](ja/INDEX.md)

## Guides
- [Localization Workflow](localization.md)
- [Dependencies](dependencies.md)
- [Data Flow](data-flow.md)
- [Configuration](configuration.md)
- [Testing](testing.md)
- [Workflow](workflow.md)
- [Security](security.md)

## Operations
- [Security Signing Runbook](security-signing-runbook.md)
- [Signed Feed Migration Plan](migration-signed-feed.md)
- [Platform Verification Checklist](platform-verification.md)
- [Cross-Platform Remediation Plan](remediation-plan.md)

## Modules
- [Frontend Web App](modules/frontend-web.md)
- [ClawSec Suite Core](modules/clawsec-suite.md)
- [ClawSec Scanner](modules/clawsec-scanner.md)
- [Hermes Attestation Guardian](modules/hermes-attestation-guardian.md)
- [Hermes Attestation Guardian Draft History (Archived)](modules/hermes-attestation-guardian-draft-history.md)
- [NanoClaw Integration](modules/nanoclaw-integration.md)
- [Picoclaw Security Guardian](modules/picoclaw-security-guardian.md)
- [Picoclaw Self Pen Testing](modules/picoclaw-self-pen-testing.md)
- [Runtime Traffic Guardian Baseline](modules/runtime-traffic-guardian-baseline.md)
- [Automation and Release Pipelines](modules/automation-release.md)
- [Local Validation and Packaging Tools](modules/local-tooling.md)

## Glossary
- [Glossary](glossary.md)

## Generation Metadata
- [Generation Metadata](GENERATION.md)

## Update Notes
- 2026-05-04: Added runtime traffic guardian baseline module and platform-specific skill scaffolds for OpenClaw, Hermes, NanoClaw, and Picoclaw.
- 2026-04-26: Split Picoclaw self-pen-testing into standalone `picoclaw-self-pen-testing`; updated Picoclaw module docs and references.
- 2026-04-25: Added Picoclaw Security Guardian module for advisory awareness, config drift detection, and chain-of-supply verification.
- 2026-04-19: Moved NanoClaw platform-support and CI/CD pipeline detail sections out of `README.md` into module pages (`modules/nanoclaw-integration.md`, `modules/automation-release.md`) and left README pointers.
- 2026-04-16: Added install-guard compatibility note for Hermes Attestation Guardian (community-source install now SAFE without `--force`; behavior unchanged).
- 2026-04-15: Expanded Hermes Attestation Guardian module page into full narrative, claim-by-claim operator guidance (no claim tables), and added archived draft-history module page.
- 2026-03-10: Added ClawSec Scanner module documentation and linked it under Modules.
- 2026-02-26: Added Operations pages and updated navigation guidance after migrating root docs into wiki pages.

## Source References
- README.md
- App.tsx
- package.json
- scripts/prepare-to-push.sh
- scripts/populate-local-feed.sh
- scripts/populate-local-skills.sh
- skills/clawsec-suite/skill.json
- skills/clawsec-scanner/skill.json
- skills/hermes-attestation-guardian/skill.json
- skills/hermes-traffic-guardian/skill.json
- skills/nanoclaw-traffic-guardian/skill.json
- skills/openclaw-traffic-guardian/skill.json
- skills/picoclaw-security-guardian/skill.json
- skills/picoclaw-self-pen-testing/skill.json
- skills/picoclaw-traffic-guardian/skill.json
- wiki/modules/clawsec-scanner.md
- wiki/modules/hermes-attestation-guardian.md
- wiki/modules/hermes-attestation-guardian-draft-history.md
- wiki/modules/picoclaw-security-guardian.md
- wiki/modules/picoclaw-self-pen-testing.md
- wiki/modules/runtime-traffic-guardian-baseline.md
- .github/workflows/ci.yml
