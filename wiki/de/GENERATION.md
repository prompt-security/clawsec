<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (de)
Source: ../GENERATION.md
Review status: draft
-->

# Wiki Generation Metadata

- Commit hash: `c3983a100581a9f27eb8cc3b5baa4f585e6c45e4`
- Branch name: `codex/clawsec-scanner-0.0.2-dast-harness`
- Generation timestamp (local): `2026-03-10T19:06:29+0200`
- Generation mode: `update`
- Output language: `English`
- Assets copied into `wiki/assets/`:
  - `overview_img_01_prompt-security-logo.png` (from `img/Black+Color.png`)
  - `overview_img_02_clawsec-mascot.png` (from `public/img/mascot.png`)
  - `architecture_img_01_prompt-line.svg` (from `public/img/prompt_line.svg`)

## Notes
- Migrated root documentation pages from `docs/` into dedicated `wiki/` operation pages.
- Updated index and cross-links to use `wiki/` as the documentation source of truth.
- Added a dedicated module page for `clawsec-scanner` and linked it from `wiki/INDEX.md`.
- Future updates should preserve existing headings and append `Update Notes` sections when making deltas.
- 2026-05-04: Added `wiki/modules/runtime-traffic-guardian-baseline.md` and platform-specific runtime traffic guardian skill scaffolds for OpenClaw, Hermes, NanoClaw, and Picoclaw.
- 2026-04-15: Expanded `wiki/modules/hermes-attestation-guardian.md` into full narrative claim breakdowns (people-speak + wiring + verification + scenario) and moved draft-plan context into `wiki/modules/hermes-attestation-guardian-draft-history.md`.
- 2026-04-26: Split Picoclaw self-pen-testing into dedicated `wiki/modules/picoclaw-self-pen-testing.md`, and updated `wiki/modules/picoclaw-security-guardian.md` to cover advisory/drift/supply-chain scope only.
- 2026-04-25: Added DeepWiki-friendly `wiki/modules/picoclaw-security-guardian.md` with support-matrix claims, threat model, default safety posture, frontend/advisory-board wiring, verification commands, and source references. Regenerated `public/wiki/**/llms.txt` exports with `npm run gen:wiki-llms`.

## Source References
- README.md
- package.json
- AGENTS.md
- wiki/overview.md
- wiki/architecture.md
- wiki/modules/clawsec-scanner.md
- wiki/modules/runtime-traffic-guardian-baseline.md
- wiki/modules/picoclaw-security-guardian.md
- wiki/modules/picoclaw-self-pen-testing.md
- wiki/dependencies.md
- wiki/data-flow.md
- wiki/glossary.md
- wiki/security-signing-runbook.md
- wiki/migration-signed-feed.md
- wiki/platform-verification.md
- wiki/remediation-plan.md
