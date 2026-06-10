# hermes-attestation-guardian

Hermes-only attestation, advisory verification, and guarded verification workflow.

Status: implemented (v0.1.0), Hermes-only.

## Vercel Skills Installation

Install with the Vercel Skills CLI for this harness:

```bash
npx skills add prompt-security/clawsec --skill hermes-attestation-guardian -a hermes-agent -y
```

## Capabilities

This skill now covers the full Hermes-side capability set expected from the clawsec-suite parity workstream:

- Deterministic runtime posture attestation generation.
- Fail-closed attestation verification (schema + canonical digest).
- Optional detached signature verification for attestation artifacts.
- Authenticated baseline diffing with stable severity classification.
- Scoped output-path enforcement under `$HERMES_HOME`.
- Signed advisory feed verification (Ed25519) with optional checksum-manifest verification.
- Fail-closed advisory verification state persistence under `$HERMES_HOME/security/advisories`.
- Advisory-aware guarded skill verification with explicit `--confirm-advisory` override.
- Optional recurring scheduler helpers for attestation and advisory checks (print-only by default, explicit apply mode).
- Sandboxed end-to-end regression harness for install + verify + advisory gates.

## Quickstart

Canonical release verification and trust-policy guidance lives in `SKILL.md`:
- `Mandatory release verification gate (before install)`
- `Hermes guard trust policy note`

After running that gate, use:

```bash
node scripts/generate_attestation.mjs
node scripts/verify_attestation.mjs --input ~/.hermes/security/attestations/current.json
node scripts/refresh_advisory_feed.mjs
node scripts/check_advisories.mjs
node scripts/guarded_skill_verify.mjs --skill some-skill --version 1.2.3
node scripts/setup_attestation_cron.mjs --every 6h --print-only
node scripts/setup_advisory_check_cron.mjs --every 6h --skill some-skill --print-only
```

Scheduler safety warning: never leave `--allow-unsigned` enabled in recurring advisory check jobs except during short emergency recovery windows.

## Runtime requirements

Required:
- `node`

Optional tooling (for local verification workflows):
- `openssl`, `bash`, `docker`

## Tests

```bash
node test/attestation_schema.test.mjs
node test/attestation_diff.test.mjs
node test/attestation_cli.test.mjs
node test/setup_attestation_cron.test.mjs
node test/setup_advisory_check_cron.test.mjs
node test/feed_verification.test.mjs
node test/guarded_skill_verify.test.mjs
bash test/hermes_attestation_sandbox_regression.sh
```
