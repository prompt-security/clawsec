# Agent-Harness Automated Testing Pipeline (Design)

Design/RFC for an automated pipeline that installs the supported agent runtimes
on CI workers and, when a skill changes, drives those agents to install the skill
non-mutatively and verify it does what it claims. This page is a **design document
only** — no pipeline code exists yet. It is the blueprint that implementing agents
follow, in the sequenced roadmap below.

## Context

ClawSec ships security skills for four external agent runtimes — OpenClaw,
NanoClaw, Hermes, and Picoclaw — plus a signed advisory feed and a guarded
installer. Today a skill change is validated by **deterministic** checks only:
lint, structural `utils/validate_skill.py`, the standalone `*.test.mjs` unit
suites, and two agent-specific sandbox regressions
(`skills/picoclaw-security-guardian/test/picoclaw_security_guardian_sandbox_regression.sh`
and `skills/hermes-attestation-guardian/test/hermes_attestation_sandbox_regression.sh`)
that install a skill into a real agent runtime but run with
`model_name="sandbox-model"` — i.e. **no LLM in the loop**.

Two gaps follow:

1. Nothing checks that a changed skill actually *does what it claims* when a real
   agent, driven by real inference, installs and uses it.
2. Nothing checks — after a release — that the **install + verification pipeline
   itself** works end-to-end against the published, signed artifacts.

This pipeline closes both, in two phases, while treating cost and abuse of the
inference credentials as a first-class constraint.

## Goals and non-goals

**Goals**

- Pre-merge (Phase A): install a changed skill non-mutatively into each agent it
  declares support for, and verify the skill is capable of what it claims.
- Post-release (Phase B): verify the install + verification pipeline works
  end-to-end against the real published, signed release.
- Run agent harnesses on GitHub-hosted runners with **keyless** Bedrock access
  (GitHub OIDC → a tightly-scoped IAM role), such that untrusted fork code can
  never reach the credentials and cost is bounded.
- Reuse existing ClawSec machinery (sandbox regressions, `skill_platforms.mjs`,
  signing composite action, guarded-install exit codes, trust-packet generator)
  rather than reinventing it.

**Non-goals**

- Replacing the deterministic unit suites or `validate_skill.py` (this augments
  them).
- Testing agent-runtime internals beyond skill install/verify behavior.
- Guaranteeing LLM-behavioral verification on every PR — that tier is gated and
  advisory (see honest scoping below).

## Status and honest scoping

This deliverable is the design doc. Explicitly out of scope for now: writing any
workflow, composite action, adapter, or manifest; provisioning any AWS resource;
onboarding agents beyond documenting the interface.

**Scope the pre-merge promise honestly.** The default pre-merge tier is
deterministic and credential-free — it verifies supply-chain and *claims*
conformance (install succeeds, loader sees the skill, exit-code contracts hold,
observed behavior is a subset of declared permissions). True LLM-behavioral
capability is a **maintainer-gated, advisory-first** add-on, because GitHub does
not expose secrets to fork PRs and inference costs money. The doc must not oversell
the mock tier as full behavioral verification.

## Terminology

- **Agent / harness** — one of the four runtimes (OpenClaw, NanoClaw, Hermes,
  Picoclaw) a skill can target, obtained by CI and driven to install/run a skill.
- **Oracle** — a deterministic assertion about a run (exit code, schema
  conformance, declared-vs-observed permissions). Preferred over LLM judgment.
- **Tier** — the trust level of a run: *mock* (no secrets, deterministic,
  every PR) or *Bedrock* (real inference, gated behind human approval).
- **Conformance spec** — `skills/<name>/harness-test.json`, the per-skill scenario
  file mapping a prompt to expected activation and declared behavior.

## Step 0 — Picoclaw feasibility spike (mandatory gate)

The single biggest risk is **feasibility, not security**. Before any general
framework is built, prove the core assumptions end-to-end on the one agent whose
source URL is known (`github.com/sipeed/picoclaw`). Answer, for Picoclaw:

1. **Headless drive** — is there a non-interactive run mode that executes a
   scripted scenario to completion?
2. **Inference override** — can the inference endpoint + model be redirected via
   env/config to (a) a loopback mock and (b) a Bedrock-backed endpoint?
3. **Bedrock auth shape** — *this decides the whole isolation model*: does the
   agent speak a configurable HTTP/OpenAI-style base-URL (a broker can inject
   SigV4; creds never enter the agent container), or does it sign requests
   client-side with the AWS SDK (creds must be inside the container → the broker
   model is void; use the fallback isolation model)?
4. **Deterministic mock tool-calls** — can a scripted mock make the agent actually
   invoke the skill's scripts/tools?
5. **Activation signal** — does the agent emit a machine-readable skill-selection
   log/event, so "the skill activated" is a deterministic oracle rather than an
   LLM-judged inference?

The spike selects the credential-isolation model and sets the template every other
agent follows. Only Picoclaw is realizable now; the other three are manifest stubs
(`enabled:false`) pending their URLs, pinned commit SHAs, and build/run/install
commands.

## Architecture

### Generalize the two sandbox regressions into one data-driven adapter

The existing Picoclaw and Hermes sandbox regressions are already ~90% of a
per-agent test adapter: obtain source → build → isolated `HOME` → local
ClawHub-compatible registry → install with the agent's own install path → verify
the loader sees the skill → run the skill's scripts. They differ only in five
things: source fetch, build command, install transport, loader probe, and
headless-run command. Encode those five in a **per-agent manifest**; keep the
orchestration identical.

### Directory layout

A new top-level `harness/` directory (sibling to `skills/` and `scripts/`). It is
runtime infra, **not** a shippable skill, so it must never appear in a skill SBOM
or release archive.

```
harness/
  lib/           adapter.mjs · manifest.mjs · registry.mjs · sandbox.mjs
                 mock_provider.mjs · bedrock_provider.mjs · oracles.mjs
                 judge.mjs · transcript.mjs
  manifests/     picoclaw.harness.json (populated)
                 hermes.harness.json · openclaw.harness.json · nanoclaw.harness.json (stubs)
  adapters/picoclaw/probes/   picoclaw_install.go · picoclaw_loader_probe.go
  scenarios/schema/harness-test.schema.json
  run_conformance.mjs         run_release_e2e.mjs
  test/          adapter_contract.test.mjs · registry.test.mjs
                 mock_provider.test.mjs · oracles.test.mjs
skills/<name>/harness-test.json   # per-skill conformance spec (opt-in initially)
```

### The `AgentAdapter` interface

`obtain()` (git clone `--filter=blob:none`, checkout the pinned SHA, **assert
`git rev-parse HEAD` === the full 40-char SHA** — reject moving tags/short SHAs) →
`build()` → `sandbox()` (isolated `HOME`) → `installSkill()` → `verifyInstall()`
→ `driveScenario(provider)` → `collectTranscript()`. Only agent-specific steps
come from the manifest plus checked-in probe files (the Picoclaw Go harness moves
out of its current bash heredoc into `harness/adapters/picoclaw/probes/`).

### Install transports

Two transports, both already implemented in the existing scripts:

- `clawhub-http` — Picoclaw's `NewClawHubRegistry` / `install_skill` tool (a local
  HTTP registry serving `/api/v1/search`, `/api/v1/skills/<slug>`,
  `/api/v1/download`).
- `well-known-dir` — Hermes `hermes skills install well-known:...` (a static
  `/.well-known/skills/<slug>/` tree).

`harness/lib/registry.mjs` serves both from one server bound to `127.0.0.1`.
NanoClaw and OpenClaw map to one of the two once their manifests are known.

### Provider shim (one code path, two backends)

- `mock_provider.mjs` — a deterministic scripted-tool-call inference stub on
  loopback, no secrets (generalizes `model_name="sandbox-model"`). This is the
  fork/default-tier backend.
- `bedrock_provider.mjs` — the real Bedrock backend (gated tier).

They are interchangeable by swapping two manifest env vars (endpoint, model), so
fork and gated tiers share one code path.

### Oracles — deterministic first; LLM-judge is a last resort

In strict priority order:

1. **Activation** — the agent's own loader/selection signal vs `skill.json`
   `triggers[]`.
2. **Fail-closed exit codes** — guarded-install `42` (confirm-required), `43`
   (reputation), non-zero drift — reusing the existing contracts verbatim
   (`skills/clawsec-suite/scripts/guarded_skill_install.mjs`).
3. **Findings schema conformance** — the `SPEC.md` finding schema and "Minimum
   Detection Set" where a skill ships one.
4. **Declared-vs-observed permissions** — observed egress/persistence/binaries
   must be a **subset** of the declared `permissions.json` (generated by
   `scripts/ci/generate_skill_release_trust_packet.mjs`). This makes "does what
   it claims" literal and cheap.
5. **LLM-as-judge** — only for natural-language guidance quality no oracle can
   cover. Robustness: N-vote quorum (default 5 votes / quorum 4), adversarial
   rubric paraphrases, a **claim-blinded** transcript-only view, a separate
   secret-leak/injection judge, and **fail-closed** on ties or quorum-miss. Judged
   scenarios are **skipped (not silently passed)** in the mock tier.

### Per-skill conformance spec

`skills/<name>/harness-test.json` declares scenarios mapping a prompt → expected
activation + declared behavior + oracle/judge config + `mock_script[]` for the
fork tier. It is schema-validated (`harness/scenarios/schema/harness-test.schema.json`)
in the no-secrets PR job. **Opt-in initially**, with a documented target of one
activation + one fail-closed scenario per skill before it becomes required.

## Credential and abuse-prevention model

### Fork-credentialing — the reconciled rule

GitHub **never mints an OIDC id-token for a fork's `pull_request` run**, regardless
of labels or `environment:`. Therefore:

- **Same-repo (maintainer) PRs** may reach the Bedrock tier via the label
  `agent-harness-approved` + protected environment (they *can* obtain an id-token).
- **Fork PRs** reach the Bedrock tier **only** via maintainer-initiated
  `workflow_dispatch(pr_number, head_sha)` — the maintainer reads the diff, then
  dispatches against the base-repo workflow with an explicit pinned head SHA. **Do
  not use `pull_request_target`**; this avoids the re-checkout-of-untrusted-head
  footgun entirely. Forks otherwise stay on the free, no-secret mock tier.

### OIDC → scoped IAM role (no long-lived keys)

A dedicated protected environment `agent-harness-bedrock` (required reviewers,
deployment branch = `main`) is the only context from which the role is assumed.

**Trust policy — `StringEquals` only, never wildcards.** Pin the subject to the
environment (environment subs carry no ref, forcing every assume-role through
environment protection) and pin `job_workflow_ref` to the exact workflow file at
`main`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::<ACCT>:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:<owner>/clawsec:environment:agent-harness-bedrock",
        "token.actions.githubusercontent.com:job_workflow_ref": "<owner>/clawsec/.github/workflows/agent-harness-bedrock.yml@refs/heads/main"
      }
    }
  }]
}
```

> `aud` is shared by every GitHub repository worldwide, so `sub` is the only tenant
> control. Require **no OIDC subject-claim customization** at org/repo level (it
> would silently change the sub the policy matches) and a **dedicated AWS account**
> for this role.

**Permission policy — one model, nothing else:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeOneModelOnly",
      "Effect": "Allow",
      "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
      "Resource": [
        "arn:aws:bedrock:<region>::foundation-model/<model-id>",
        "arn:aws:bedrock:<region>:<ACCT>:inference-profile/<inference-profile-id>"
      ]
    },
    {
      "Sid": "DenyAllElse",
      "Effect": "Deny",
      "NotAction": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
      "Resource": "*"
    }
  ]
}
```

Include both the inference-profile ARN and each backing regional foundation-model
ARN if cross-region inference profiles are used. Set `MaxSessionDuration` ≤ 3600 so
a stolen token expires within the hour and only against one cheap model.

### Runtime isolation — pick per the spike

- **Broker model** (agent uses a configurable HTTP base-URL): a SigV4 broker
  container holds the creds on a NAT'd `egress` network; the agent + skill run in a
  separate container on a `docker --internal` network (no default route, no
  internet DNS) whose only reachable host is the broker. The agent container is
  launched with **no** `AWS_*` env, **no** `$AWS_WEB_IDENTITY_TOKEN_FILE`, and
  **no** `~/.aws` mount. The broker **hardcodes** the destination
  `bedrock-runtime.<region>.amazonaws.com`, ignores all client-supplied
  host/URL/model fields (SSRF defense — the single highest-value internal→egress
  target; needs its own fuzz/regression test), and enforces per-run invocation and
  token caps with a hard kill.
- **Fallback model** (agent signs client-side with the AWS SDK): inject the
  short-lived scoped creds into a hardened container (non-root, read-only rootfs,
  dropped capabilities, pids/memory limits, **no `/var/run/docker.sock` mount, no
  `--network host`**) behind a forward egress proxy that allowlists only the
  Bedrock host.

### Defense-in-depth requirements

| Area | Requirement |
|---|---|
| Cache poisoning | A credential-free run must **never** feed the build cache a credentialed run restores. Use a trust-tagged cache key an untrusted run cannot produce, or rebuild-from-source + verify a content digest in the credentialed job. |
| Supply chain | Pin each agent to an immutable commit SHA; run clone+build credential-free, before any token is minted; lockfile-pin agent build deps (Go `go.sum` / pinned pip); pin the install CLI (not `npx clawhub@latest`). |
| Cost backstop | App-level broker caps are the only real-time limit → add an AWS-side hard ceiling (per-model on-demand Service Quota or provisioned-throughput cap), plus Bedrock model-invocation logging + an AWS Budgets alarm. |
| Two-person rule | The environment reviewer must differ from the labeler/dispatcher — enforced by policy or a bot check (GitHub environment settings alone don't enforce this). |
| Transcript egress | Even with no live creds reachable, the uploaded transcript is an exfil channel → extract `sanitizeReportForComment` into `scripts/ci/sanitize_transcript.mjs`; post only a short pass/fail summary to PRs; put the full (redacted) transcript in a short-retention artifact with a defined access scope. |
| Governance | First-ever `CODEOWNERS` gating `harness/manifests/**`, `.github/workflows/agent-harness-*.yml`, `.github/actions/assume-bedrock-role/**`; branch protection making the mock tier a required check and requiring CODEOWNER review + up-to-date branches; a CI lint failing on wildcard OIDC subs and on `id-token`/`secrets.`/`environment:` tokens in the mock-tier workflow file. |

### Threat model

| Attack | Stopped by | Residual gap |
|---|---|---|
| Fork edits `agent-harness-*.yml` to add an exfil step | Fork `pull_request` runs get no secrets; the Bedrock workflow runs the base-ref workflow file; `job_workflow_ref` pinned to `@refs/heads/main` | Composite actions/scripts are read from the checkout — pin their execution to base-ref copies, never the PR checkout |
| Label-then-push TOCTOU | Label-guard removes the label on `synchronize`; credentialed run pins to the reviewed SHA and aborts if HEAD moved; environment reviewer pauses before token mint | Ordering race means "abort if HEAD moved" (not label removal) is the real backstop; reviewer must verify against the pinned SHA |
| Cache poisoning: untrusted run seeds the build cache a credentialed run restores | — (must be designed in) | Trust-tag the cache key or rebuild+verify in the credentialed job (see requirements) |
| Agent reads OIDC token / `AWS_*` from a sibling container | Broker isolation: creds only in the broker on a separate network; agent has no AWS env/file | Forbid `docker.sock` mount and `--network host`; run broker in a separate user namespace |
| OIDC sub widening (wildcard, or customized claim mapping) | `StringEquals` on the exact environment sub + `job_workflow_ref`; CI wildcard lint | Assert no org/repo OIDC subject-claim customization; dedicated account; `aud` is globally shared |
| Malicious skill exfiltrates via the transcript artifact | `sanitize_transcript.mjs` redacts known secret shapes; no live creds reachable | Arbitrary attacker-chosen data still passes; bound by artifact retention/access scope |
| Broker SSRF (attacker-controlled host/model) | Broker hardcodes the Bedrock host + rejects non-pinned model | Only as strong as broker input validation → dedicated SSRF fuzz test |
| Cost / DoS | One cheap model in IAM; broker per-run caps + hard kill; job timeout; concurrency cancel-in-progress; 1h session; human environment approval | Broker caps are app-level → add an AWS-side hard quota; Budgets alerts lag hours |
| Phase B triggered indirectly by a fork via the release PR-validation run | `workflow_run` guard `event != 'pull_request' && conclusion == 'success' && name == 'Skill Release'` (proven in `deploy-pages.yml`) | Guard depends on the exact upstream workflow name; pin by workflow path/id where possible |
| Compromised upstream agent repo/build | Pin full commit SHA + assert; credential-free build; CODEOWNER-gated manifests | SHA pinning doesn't pin transitive build deps → lockfile-pin / vendor builds |

## The two phases

### Phase A — pre-merge, default/mock tier — `agent-harness-verify.yml`

`on: pull_request [paths: skills/**, harness/**]`; `permissions: read-all`; **no
secrets, no `id-token`, no `environment:`** anywhere in the file. Jobs:

- `detect` — runs `scripts/ci/select_agent_harness_matrix.mjs` over `base...head`
  → changed skills → `collectDeclaredPlatforms` → agents with an enabled manifest.
  A missing/disabled manifest is a **neutral skip + annotation**, never a failure.
- `mock-verify` — matrix over `{skill, agent}`, `fail-fast: false`,
  `timeout-minutes: 20`, deterministic oracles against the loopback mock. **This
  is the required, hard-fail check.**
- `report` — aggregate conclusion (`if: always()`).

Non-mutation is structural: `permissions: contents: read` (no write token), install
through a local ClawHub-compatible mock registry (no real publish), skill source
mounted read-only, ephemeral `HOME`/`<AGENT>_HOME` under `mktemp`, no tags/commits
pushed.

### Phase A — pre-merge, gated/real tier — `agent-harness-bedrock.yml`

`on: pull_request [types: labeled]` (same-repo only:
`if: label == 'agent-harness-approved' && head.repo.full_name == github.repository`)
**and** `workflow_dispatch(pr_number, head_sha)` (the fork path).
`environment: agent-harness-bedrock`; `permissions: id-token: write, contents: read`.
Checkout the pinned/reviewed head SHA and **abort if HEAD moved**; a companion
`pull_request_target: [synchronize]` label-guard removes the label on any new push.
Run deterministic oracles **first (blocking)**, then the LLM-behavioral scenario
(**advisory/non-blocking** until a flake baseline exists; bounded retries; pinned
model; low temperature). The job **never executes PR-provided workflow/script
content with creds** — untrusted code runs only inside the isolated agent
container, and composite actions/scripts run from the base-ref copy.

### Phase B — post-release — `agent-harness-release-verify.yml`

`on: workflow_run ["Skill Release"] completed`, guarded exactly like
`deploy-pages.yml` (`conclusion == 'success' && workflow_run.event != 'pull_request'`),
plus `release: published` / `workflow_dispatch(tag)`.
`environment: agent-harness-bedrock`, OIDC. It **downloads the published signed
release assets**, verifies the detached Ed25519 signature and asserts the
`signing-public.pem` fingerprint equals the canonical `clawsec-signing-public.pem`
(reusing the deploy-pages verify snippet + `skills/*/scripts/verify_supply_chain.mjs`)
**before** install, installs via the **real documented install command**, and
asserts the guarded two-stage flow (`42` → `--confirm-advisory` → `0`, and
reputation `43`), advisory fail-closed, and loader-sees-skill. Hard-fail on any
pipeline invariant; open an issue on failure. This validates the **pipeline**, not
just the skill.

### Composite actions

Two composite actions in the `.github/actions/sign-and-verify/action.yml` hardening
style (`set -euo pipefail`, `umask 077`, `mktemp` + `trap` cleanup, never echo
secrets):

- `.github/actions/provision-agent-harness` — clone @ pinned SHA + assert +
  build, with a trust-scoped cache key.
- `.github/actions/assume-bedrock-role` — wraps `aws-actions/configure-aws-credentials`
  (pinned by SHA) for OIDC, `::add-mask::`s creds, asserts the caller identity and
  the pinned model. Called only inside the `agent-harness-bedrock` environment.

## Reused existing assets (do not reinvent)

| Existing asset | How reused |
|---|---|
| `skills/picoclaw-security-guardian/test/picoclaw_security_guardian_sandbox_regression.sh` + Hermes twin | Generalized into `harness/lib/*` + probe files — the reference bodies of the Picoclaw/Hermes adapters |
| `scripts/ci/skill_platforms.mjs` | `collectDeclaredPlatforms` / `installAgentForSkill` (+ `hermes → hermes-agent` alias) drive the changed-skill × agent matrix |
| `.github/actions/sign-and-verify/action.yml` | Hardening-style template for both new composite actions; its OpenSSL Ed25519 verify reused in Phase B |
| `.github/workflows/community-advisory.yml` | Label-gate template (`if: github.event.label.name == '...'`) for same-repo promotion |
| `.github/workflows/deploy-pages.yml` | `workflow_run` PR-refusal guard + download→verify→then-use + canonical-fingerprint compare for Phase B |
| `.github/workflows/ci.yml` | `read-all` + `pull_request`-only + no-secrets posture = the exact mock-tier baseline; standalone `*.test.mjs` runner convention |
| `scripts/ci/simulate_skill_tag_release.mjs` + `scripts/ci/generate_skill_release_trust_packet.mjs` | Build a hermetic signed artifact + emit `permissions.json` (the claims oracle) in one command (Phase A, ephemeral key) |
| `skills/clawsec-suite/scripts/guarded_skill_install.mjs` (+ enhanced `43`) | Exit-code contracts asserted deterministically by the exit-code oracle |
| `skills/clawsec-suite/test/lib/test_harness.mjs` | `pass/fail/report`, `generateEd25519KeyPair`, `signPayload`, `createTempDir`, `withEnv`, `http.createServer` mocks for `harness/test/*.test.mjs` |
| `sanitizeReportForComment()` in `skill-release.yml` | Extracted to `scripts/ci/sanitize_transcript.mjs`; applied to every transcript before it leaves the runner |
| `skills/*/SPEC.md` (e.g. `openclaw-traffic-guardian`) | Finding schema + "Minimum Detection Set" feed the findings-schema oracle |
| `utils/validate_skill.py` | Structural pre-gate reused as-is in the mock tier |

## Files to be created

- `wiki/agent-harness-testing.md` (this doc).
- `harness/lib/{adapter,manifest,registry,sandbox,mock_provider,bedrock_provider,oracles,judge,transcript}.mjs`
- `harness/manifests/{picoclaw,hermes,openclaw,nanoclaw}.harness.json`
- `harness/adapters/picoclaw/probes/{picoclaw_install,picoclaw_loader_probe}.go`
- `harness/scenarios/schema/harness-test.schema.json`
- `harness/{run_conformance,run_release_e2e}.mjs`
- `harness/test/{adapter_contract,registry,mock_provider,oracles}.test.mjs`
- `scripts/ci/{select_agent_harness_matrix,sanitize_transcript}.mjs` (+ standalone tests)
- `.github/actions/{provision-agent-harness,assume-bedrock-role}/action.yml`
- `.github/workflows/{agent-harness-verify,agent-harness-bedrock,agent-harness-release-verify}.yml`
- `.github/CODEOWNERS`
- `skills/<name>/harness-test.json` (per testable skill, opt-in)

## Implementation roadmap (sequenced)

1. **M0 — Picoclaw feasibility spike** (Step 0). Gate: answers to the five
   questions; selects the isolation model. *No further work until this passes.*
2. **M1 — deterministic core, mock tier, Picoclaw only.** `harness/lib/*`,
   `picoclaw.harness.json`, probes, `select_agent_harness_matrix.mjs`,
   `sanitize_transcript.mjs`, `agent-harness-verify.yml`, `harness/test/*.test.mjs`,
   the file-per-trust-level CI lint. Fully useful with zero AWS/secret surface.
3. **M2 — AWS/OIDC foundation.** Dedicated account, OIDC provider, scoped role,
   Budgets/quota, `agent-harness-bedrock` environment + reviewers,
   `assume-bedrock-role` action, broker (or fallback) with an SSRF fuzz test.
4. **M3 — Bedrock behavioral tier (advisory).** `bedrock_provider.mjs`,
   `judge.mjs`, `agent-harness-bedrock.yml` + label-guard + `workflow_dispatch`
   fork path. Measure the LLM flake baseline before considering it blocking.
5. **M4 — Phase B.** `run_release_e2e.mjs` + `agent-harness-release-verify.yml`.
6. **M5 — onboard remaining agents** as URLs/SHAs land: fill each manifest, add
   probes, validate against the Picoclaw template. `enabled:false` until ready.

## Open questions

- Repo URLs + pinnable commit SHAs + build/run/install commands for OpenClaw,
  NanoClaw, and Hermes (only `picoclaw = github.com/sipeed/picoclaw` is known).
- Exact Bedrock model id + region; whether cross-region inference profiles are used
  (drives the IAM `Resource` list); the dedicated AWS account id.
- Per-run token/invocation caps + monthly budget ceiling (placeholders: 50
  invocations / 200k tokens per run).
- Canonical install verb per agent (`npx clawhub@latest install` vs
  `npx skills add … -a <agent>`) to pin in each manifest.
- Reviewer ≠ labeler enforcement mechanism (policy vs bot).
- Transcript artifact retention period + who may download it.
- Whether `harness-test.json` is required for every `skills/**` PR (hard-fail if
  missing) or opt-in with a coverage bar.

## Verification

**Of this design (now):** confirm every reused-asset path exists and the described
contract matches (spot-check `scripts/ci/skill_platforms.mjs`, the two sandbox
scripts, the `deploy-pages.yml` guard, the `community-advisory.yml` label gate — all
verified during planning); a security-owner review of the OIDC trust/permission
JSON and the fork-credentialing rule; and confirmation that the threat-model table
maps each attack to a named control + residual gap.

**Of the pipeline (once built, per milestone):**

- **M1** — open a PR touching a `skills/**` file → `agent-harness-verify.yml` runs
  the mock tier and deterministic oracles pass; open a PR with a deliberately
  mis-declared `permissions.json` → the declared-vs-observed oracle **fails**. Run
  `harness/test/*.test.mjs` locally with the repo `node <file>.test.mjs`
  convention.
- **CI lint** — add `id-token:` / `secrets.` to the mock-tier workflow in a scratch
  branch → the lint fails.
- **M2/M3** — maintainer `workflow_dispatch` on a test PR → the environment pauses
  for a reviewer → the role is assumed → a single-model invocation succeeds; assert
  a fork `pull_request` run gets **no** id-token; the broker SSRF fuzz test rejects
  attacker-controlled hosts; exceeding the cap → the broker hard-kills.
- **M4** — push a real skill tag → `Skill Release` completes → Phase B downloads
  the published assets, signature + fingerprint verify, the real install command
  runs, and the guarded two-stage `42`/`43` + advisory fail-closed are asserted.

## Update Notes

- 2026-07-12: Initial design. Two-phase pipeline (pre-merge claims verification +
  post-release pipeline verification), tiered mock/Bedrock inference, keyless OIDC →
  scoped IAM role, Picoclaw feasibility spike as the mandatory Step 0. Execution
  deferred; this page is the blueprint.

## Source References

- README.md
- scripts/ci/skill_platforms.mjs
- scripts/ci/simulate_skill_tag_release.mjs
- scripts/ci/generate_skill_release_trust_packet.mjs
- skills/clawsec-suite/scripts/guarded_skill_install.mjs
- skills/clawsec-suite/test/lib/test_harness.mjs
- skills/picoclaw-security-guardian/test/picoclaw_security_guardian_sandbox_regression.sh
- skills/hermes-attestation-guardian/test/hermes_attestation_sandbox_regression.sh
- utils/validate_skill.py
- .github/actions/sign-and-verify/action.yml
- .github/workflows/ci.yml
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/skill-release.yml
- wiki/testing.md
- wiki/platform-verification.md
- wiki/security-signing-runbook.md
