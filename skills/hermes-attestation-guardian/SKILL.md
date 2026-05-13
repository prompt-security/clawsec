---
name: hermes-attestation-guardian
version: 0.1.1
description: Hermes-only runtime security attestation and drift detection skill for operator-managed Hermes infrastructure.
homepage: https://clawsec.prompt.security
hermes:
  emoji: "🛡️"
  requires:
    bins: [node]
---

# Hermes Attestation Guardian

IMPORTANT SCOPE:
- This skill targets Hermes infrastructure only (CLI/Gateway/profile-managed deployments).
- This skill is not an OpenClaw runtime hook package.

## Goal

Generate deterministic Hermes posture attestations, verify them with fail-closed integrity checks, and compare baseline drift using stable severity mapping.

## Mandatory release verification gate (before install)

Before treating any release install instructions as valid, verify all three inputs:

1) `checksums.json`
2) `checksums.sig`
3) pinned signing public-key fingerprint

```bash
BASE="https://github.com/prompt-security/clawsec/releases/download/hermes-attestation-guardian-v0.1.0"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$BASE/checksums.json" -o "$TMP/checksums.json"
curl -fsSL "$BASE/checksums.sig" -o "$TMP/checksums.sig"
curl -fsSL "$BASE/signing-public.pem" -o "$TMP/signing-public.pem"

[ -s "$TMP/checksums.json" ] || { echo "ERROR: missing checksums.json" >&2; exit 1; }
[ -s "$TMP/checksums.sig" ] || { echo "ERROR: missing checksums.sig" >&2; exit 1; }

EXPECTED_PUBKEY_SHA256="711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8"
ACTUAL_PUBKEY_SHA256="$(openssl pkey -pubin -in "$TMP/signing-public.pem" -outform DER | sha256sum | awk '{print $1}')"
[ "$ACTUAL_PUBKEY_SHA256" = "$EXPECTED_PUBKEY_SHA256" ] || {
  echo "ERROR: signing-public.pem fingerprint mismatch" >&2
  exit 1
}

openssl base64 -d -A -in "$TMP/checksums.sig" -out "$TMP/checksums.sig.bin"
openssl pkeyutl -verify -rawin -pubin -inkey "$TMP/signing-public.pem" \
  -sigfile "$TMP/checksums.sig.bin" -in "$TMP/checksums.json" >/dev/null
```

## Hermes guard trust policy note

When installing from community sources, configure Hermes guard to use signature-aware trust (trusted signer fingerprint allowlist) rather than source-name-only trust. Unknown signer fingerprints should stay on community policy, and invalid signatures must remain blocked.

## Commands

```bash
# Generate attestation (default output: ~/.hermes/security/attestations/current.json)
node scripts/generate_attestation.mjs

# Generate with explicit policy + deterministic timestamp
node scripts/generate_attestation.mjs \
  --policy ~/.hermes/security/attestation-policy.json \
  --generated-at 2026-04-15T18:00:00.000Z \
  --write-sha256

# Verify schema + canonical digest
node scripts/verify_attestation.mjs --input ~/.hermes/security/attestations/current.json

# Verify with baseline diff (baseline must be authenticated)
node scripts/verify_attestation.mjs \
  --input ~/.hermes/security/attestations/current.json \
  --baseline ~/.hermes/security/attestations/baseline.json \
  --baseline-expected-sha256 <trusted-baseline-sha256> \
  --fail-on-severity high

# Optional detached signature verification
node scripts/verify_attestation.mjs \
  --input ~/.hermes/security/attestations/current.json \
  --signature ~/.hermes/security/attestations/current.json.sig \
  --public-key ~/.hermes/security/keys/attestation-public.pem

# Refresh advisory feed verification state (fail-closed by default)
node scripts/refresh_advisory_feed.mjs

# Check advisory feed verification + feed summary
node scripts/check_advisories.mjs

# Guarded advisory-aware skill verification gate (returns 42 on advisory match without explicit confirm)
node scripts/guarded_skill_verify.mjs --skill some-skill --version 1.2.3

# Explicit operator acknowledgement path for advisory matches
node scripts/guarded_skill_verify.mjs --skill some-skill --version 1.2.3 --confirm-advisory

# Optional temporary unsigned bypass (dangerous; emergency-only)
HERMES_ADVISORY_ALLOW_UNSIGNED_FEED=1 node scripts/refresh_advisory_feed.mjs --allow-unsigned

# Preview scheduler config without mutating user schedule state
node scripts/setup_attestation_cron.mjs --every 6h --print-only

# Apply managed scheduler block
node scripts/setup_attestation_cron.mjs --every 6h --apply

# Preview advisory check scheduler config (guarded flow, print-only default)
node scripts/setup_advisory_check_cron.mjs --every 6h --skill some-skill --print-only

# Apply advisory check scheduler block (uses guarded_skill_verify flow)
node scripts/setup_advisory_check_cron.mjs --every 6h --skill some-skill --version 1.2.3 --apply

# Emergency-only: unsigned bypass for scheduled advisory checks (do not keep enabled)
node scripts/setup_advisory_check_cron.mjs --every 6h --skill some-skill --allow-unsigned --apply
```

WARNING: `--allow-unsigned` in scheduled commands is incident-response only. Remove it immediately after recovery and restore signed advisory verification.

## Attestation payload (implemented)

The generator emits:
- schema_version, platform, generated_at
- generator metadata (skill + node version)
- host metadata (hostname/platform/arch)
- posture.runtime (gateway enabled flags + risky toggles)
- posture.feed_verification status (verified|unverified|unknown) sourced from `$HERMES_HOME/security/advisories/feed-verification-state.json`
- posture.integrity watched_files and trust_anchors (existence + sha256)
- digests.canonical_sha256 over a stable canonical JSON representation

## Fail-closed behavior

Verifier exits non-zero when:
- schema validation fails
- canonical digest algorithm is unsupported or digest binding mismatches
- expected file sha256 mismatches (if configured)
- detached signature verification fails (if configured)
- baseline is provided without authenticated trust binding (`--baseline-expected-sha256` and/or baseline signature + public key)
- baseline authenticity or baseline schema/digest validation fails
- baseline diff highest severity is at/above `--fail-on-severity` (default: critical)

Severity messages are emitted as INFO / WARNING / CRITICAL style lines.

## Side effects

- `generate_attestation.mjs` writes one JSON file (and optional `.sha256`) under `$HERMES_HOME/security/attestations`.
- `verify_attestation.mjs` is read-only.
- `refresh_advisory_feed.mjs` writes verified feed cache + verification state under `$HERMES_HOME/security/advisories`.
- `check_advisories.mjs` is read-only.
- `guarded_skill_verify.mjs` re-runs feed refresh/verification (same advisory cache + state side effects) and then performs advisory-aware gate checks.
- `setup_attestation_cron.mjs` is read-only unless `--apply` is provided.
- `setup_attestation_cron.mjs --apply` rewrites only the current user managed schedule block delimited by:
  - `# >>> hermes-attestation-guardian >>>`
  - `# <<< hermes-attestation-guardian <<<`
- `setup_advisory_check_cron.mjs` is read-only unless `--apply` is provided.
- `setup_advisory_check_cron.mjs --apply` rewrites only the current user advisory-check managed schedule block delimited by:
  - `# >>> hermes-attestation-guardian-advisory-check >>>`
  - `# <<< hermes-attestation-guardian-advisory-check <<<`
  - generated command path uses `guarded_skill_verify.mjs` (advisory-aware gate), not raw `check_advisories.mjs`

## Advisory feed override knobs

- Source selection: `HERMES_ADVISORY_FEED_SOURCE=auto|remote|local`
- Remote artifacts: `HERMES_ADVISORY_FEED_URL`, `HERMES_ADVISORY_FEED_SIG_URL`, `HERMES_ADVISORY_FEED_CHECKSUMS_URL`, `HERMES_ADVISORY_FEED_CHECKSUMS_SIG_URL`
- Local artifacts: `HERMES_LOCAL_ADVISORY_FEED`, `HERMES_LOCAL_ADVISORY_FEED_SIG`, `HERMES_LOCAL_ADVISORY_FEED_CHECKSUMS`, `HERMES_LOCAL_ADVISORY_FEED_CHECKSUMS_SIG`
- Pinned key override: `HERMES_ADVISORY_FEED_PUBLIC_KEY` (default is built-in pinned key)
- Optional checksum toggle: `HERMES_ADVISORY_VERIFY_CHECKSUM_MANIFEST` (default: enabled)
- UNSAFE emergency bypass only: `HERMES_ADVISORY_ALLOW_UNSIGNED_FEED=1`

## Notes

- Hermes scan + test context is `.mjs`-based by design:
  - runtime scripts: `scripts/*.mjs`
  - shared libraries: `lib/*.mjs`
  - regression tests: `test/*.test.mjs`
- Keep `.mjs` paths/extensions stable so scanner scope, SBOM wiring, and test harness references stay valid.
- Default output root is `~/.hermes/security/attestations/`.
- No destructive remediation actions (delete/restore/quarantine) are implemented.
- Advisory feed remote URL allowlisting is not implemented in v0.0.2; operators must explicitly trust configured feed/checksum endpoints.
- Guarded advisory version matching currently uses a lightweight comparator parser (`>=`, `<=`, `>`, `<`, `=`, `^`, `~`, wildcard `*`) and does not implement full npm semver range grammar (for example, OR ranges and complex comparator sets).
- Operator policy file is optional JSON with:
  - `watch_files`: list of file paths
  - `trust_anchor_files`: list of file paths
