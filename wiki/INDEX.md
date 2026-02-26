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

## Guides
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
- [Cross-Platform Compatibility Report](compatibility-report.md)

## Modules
- [Frontend Web App](modules/frontend-web.md)
- [ClawSec Suite Core](modules/clawsec-suite.md)
- [NanoClaw Integration](modules/nanoclaw-integration.md)
- [Automation and Release Pipelines](modules/automation-release.md)
- [Local Validation and Packaging Tools](modules/local-tooling.md)

## Glossary
- [Glossary](glossary.md)

## Generation Metadata
- [Generation Metadata](GENERATION.md)

## Update Notes
- 2026-02-26: Added Operations pages and updated navigation guidance after migrating root docs into wiki pages.

## Source References
- README.md
- App.tsx
- package.json
- scripts/prepare-to-push.sh
- scripts/populate-local-feed.sh
- scripts/populate-local-skills.sh
- skills/clawsec-suite/skill.json
- .github/workflows/ci.yml
