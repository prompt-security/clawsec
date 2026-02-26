# Migration Record: Unsigned Feed → Signed Feed (Completed)

## 1) Objective and Status

Document how ClawSec advisory distribution moved from unsigned `feed.json` delivery to detached-signature verification, with compatibility preserved for legacy clients.

Current status on `main`:
- Signed feed publishing is active in advisory workflows and deploy workflow.
- Suite and NanoClaw consumers default to signed feed endpoints.
- Unsigned behavior exists only as explicit compatibility bypass (`CLAWSEC_ALLOW_UNSIGNED_FEED=1`).

## 2) Baseline (today, post-migration)

Current feed paths in active use:
- Source of truth: `advisories/feed.json`
- Source signature: `advisories/feed.json.sig`
- Skill copy: `skills/clawsec-feed/advisories/feed.json`
- Skill copy signature: `skills/clawsec-feed/advisories/feed.json.sig`
- Pages copy: `public/advisories/feed.json`
- Pages signature: `public/advisories/feed.json.sig`
- Latest mirror copy: `public/releases/latest/download/advisories/feed.json` (+ `.sig`)

Current consumer defaults:
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`
- `skills/clawsec-nanoclaw/lib/advisories.ts`
- default URL: `https://clawsec.prompt.security/advisories/feed.json`

## 3) Migration principles

- **Dual-publish first**: publish signatures before enforcing verification.
- **Fail-open only during transition**: temporary compatibility period is explicit and time-bounded.
- **Measured rollout**: enforce verification after telemetry confirms stable signed publishing.
- **Fast rollback**: preserve a path back to unsigned behavior while root cause is investigated.

## 4) Phased timeline (historical)

### Phase 0 — Preparation (Completed)

Deliverables:
- signing keys generated and fingerprints recorded
- GitHub secrets created
- public key(s) added in repo
- runbooks approved (`security-signing-runbook.md`, this file)

Exit criteria:
- key fingerprints verified by reviewer
- protected branch/workflow controls enabled

### Phase 1 — CI signing enabled, no client enforcement (Completed)

Implement:
- add feed signing step/workflow to produce `advisories/feed.json.sig`
- optionally produce `advisories/checksums.json` + `.sig`
- ensure CI verifies signatures before publishing artifacts

Also update deployment:
- copy `.sig` artifacts to `public/advisories/`
- mirror `.sig` in `public/releases/latest/download/advisories/`

Exit criteria:
- signatures generated successfully for all feed update paths
- deploy artifacts contain both payload and signature companions

### Phase 2 — Consumer dual-read/dual-verify support (Completed)

Implement in consumers:
- read `feed.json` and `feed.json.sig`
- verify with pinned public key
- keep controlled temporary unsigned fallback during migration window

Validation:
- test remote signed path
- test local signed fallback path
- test invalid signature rejection

Exit criteria:
- verification logic released and tested
- no false-positive verification failures in soak period

### Phase 3 — Enforcement (Completed)

Actions:
- disable temporary unsigned fallback behavior in default paths
- add CI/publish gates that fail when `.sig` is missing
- announce enforcement date in release notes and docs

Exit criteria:
- all production clients verify signatures by default
- no unsigned feed dependency in standard installation flow

### Phase 4 — Stabilization (Ongoing)

Actions:
- run first key rotation tabletop drill
- run rollback tabletop drill
- close migration with post-implementation review

## 5) Rollback plan

### Rollback triggers

Initiate rollback if any of the following occur:
- sustained signature verification failures across clients
- signing workflow cannot produce valid signatures
- key compromise suspected but replacement key is not yet deployed
- deployment path publishes mismatched payload/signature pairs

### Rollback levels

### Level 1 (preferred): Verification bypass window, keep signed publishing

Use when: signing is healthy, client-side verifier has a defect.

Actions:
1. Re-enable temporary unsigned-acceptance behavior in client release branch.
2. Ship patch release with explicit expiry date for bypass.
3. Keep signing pipeline active to avoid authenticity gap.

Recovery target: restore strict verification within 24–48h.

### Level 2: Signed pipeline paused, unsigned feed temporarily authoritative

Use when: signing pipeline is unstable or producing inconsistent artifacts.

Actions:
1. Disable signing workflow or signing step.
2. Continue publishing unsigned `advisories/feed.json` via existing workflows.
3. Revert deploy gates that require `.sig` artifacts.
4. Open incident record and track time in unsigned mode.

Recovery target: restore signed publishing ASAP, ideally <72h.

### Level 3: Full release freeze

Use when: compromise or integrity of repository/workflows is in doubt.

Actions:
1. Pause feed mutation and deployment workflows.
2. Restore known-good commit for advisory files/workflows.
3. Rotate keys and credentials.
4. Resume pipeline only after security review sign-off.

### Roll-forward after rollback

- identify root cause
- add regression tests/gates
- redeploy signed artifacts
- publish incident + remediation summary

## 6) Communication plan

For enforcement and rollback events, communicate:
- what changed
- expected operator/client action
- duration of temporary compatibility mode (if any)
- verification commands for users

Recommended channels:
- GitHub release notes
- repository README/docs updates
- issue/incident report in repository

## 7) Go/No-Go checklist

Go only if all are true:
- signing workflow success rate is stable
- signatures are mirrored to all documented feed endpoints
- consumer verification path tested for remote + local fallback
- rollback owner is assigned and reachable
- key rotation procedure has been dry-run at least once

## Source References
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts
- skills/clawsec-suite/scripts/guarded_skill_install.mjs
- advisories/feed.json
- wiki/security-signing-runbook.md
