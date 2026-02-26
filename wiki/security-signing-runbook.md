# ClawSec Signing Operations Runbook

## 1) Purpose

This runbook defines operational procedures for introducing and running cryptographic signing in the ClawSec repository.

It covers:
- key generation
- GitHub secret management
- signing workflow integration
- key rotation and revocation
- incident response

## 2) Current operating state (important)

On `main`, advisory and release channels are signed and verified by default:

- Feed writers:
  - `.github/workflows/poll-nvd-cves.yml` updates `advisories/feed.json` and signs `advisories/feed.json.sig`
  - `.github/workflows/community-advisory.yml` does the same for approved issue reports
  - both sync signed feed artifacts into `skills/clawsec-feed/advisories/`
- Feed publish path:
  - `.github/workflows/deploy-pages.yml` publishes `public/advisories/feed.json` + `.sig`
  - generates and signs `public/checksums.json` + `public/checksums.sig`
  - publishes canonical key as `public/signing-public.pem` and `public/advisories/feed-signing-public.pem`
  - mirrors compatibility artifacts under `public/releases/latest/download/` (including `feed.json`, `feed.json.sig`, `checksums.json`, `checksums.sig`, `signing-public.pem`)
- Feed consumers:
  - `skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`
  - `skills/clawsec-suite/scripts/guarded_skill_install.mjs`
  - `skills/clawsec-nanoclaw/lib/advisories.ts`
  - default feed URL is `https://clawsec.prompt.security/advisories/feed.json`

Unsigned mode remains an explicit compatibility bypass (`CLAWSEC_ALLOW_UNSIGNED_FEED=1`) and is not the steady-state operating model.

## 3) Target signed artifacts

### Advisory feed channel
- `advisories/feed.json` (payload)
- `advisories/feed.json.sig` (detached Ed25519 signature; base64)
- `advisories/feed-signing-public.pem` (pinned public key)

### Release artifact channel
- `<release>/checksums.json`
- `<release>/checksums.sig`
- `<release>/signing-public.pem`

## 4) Key roles and custody

- **Security owner**: approves key lifecycle changes and incident actions.
- **Platform owner**: maintains workflows and GitHub secrets.
- **Reviewer**: validates fingerprints in PRs/releases.

Policy:
- private keys are never committed
- public keys are committed and code-reviewed
- key generation occurs on trusted operator workstation or HSM-backed environment

## 5) Key generation (Ed25519)

> Run from a secure workstation. Do not run on shared CI runners.

```bash
# Feed signing keypair
openssl genpkey -algorithm Ed25519 -out feed-signing-private.pem
openssl pkey -in feed-signing-private.pem -pubout -out feed-signing-public.pem

# Release checksums signing keypair (optional separate key)
openssl genpkey -algorithm Ed25519 -out release-signing-private.pem
openssl pkey -in release-signing-private.pem -pubout -out release-signing-public.pem
```

Generate fingerprints (store in ticket/change record):

```bash
openssl pkey -pubin -in feed-signing-public.pem -outform DER | shasum -a 256
openssl pkey -pubin -in release-signing-public.pem -outform DER | shasum -a 256
```

Optional test-sign before publishing:

```bash
echo '{"probe":"ok"}' > /tmp/probe.json
openssl pkeyutl -sign -rawin -inkey feed-signing-private.pem -in /tmp/probe.json -out /tmp/probe.sig.bin
openssl base64 -A -in /tmp/probe.sig.bin -out /tmp/probe.sig
openssl base64 -d -A -in /tmp/probe.sig -out /tmp/probe.sig.bin
openssl pkeyutl -verify -rawin -pubin -inkey feed-signing-public.pem -in /tmp/probe.json -sigfile /tmp/probe.sig.bin
```

## 6) GitHub secrets setup

### Required secrets

- `CLAWSEC_SIGNING_PRIVATE_KEY` — PEM-encoded Ed25519 private key (used for both feed and release signing)
- `CLAWSEC_SIGNING_PRIVATE_KEY_PASSPHRASE` — (optional) passphrase if the private key is encrypted

### Procedure

1. Go to **Repo Settings → Secrets and variables → Actions → New repository secret**.
2. Paste full PEM including header/footer.
3. Prefer GitHub **Environment secrets** (with required reviewers) for workflow scoping when possible.
4. Record change ticket with:
   - secret name
   - creator
   - creation time
   - key fingerprint

### Recommended environment protections

- Require manual approval for workflows that can use signing secrets.
- Restrict who can edit protected workflows.
- Enable branch protection for `main` and require review for workflow changes.

## 7) Workflow integration points

This repo enforces signing as a post-mutation, pre-publish control.

### Feed pipeline

Current feed mutation points:
- `.github/workflows/poll-nvd-cves.yml`
- `.github/workflows/community-advisory.yml`

Current behavior:
- workflow step signs `advisories/feed.json` into `advisories/feed.json.sig`
- signing action verifies generated signatures during workflow execution
- signed artifacts are committed via PR automation

### Pages pipeline

Current publisher:
- `.github/workflows/deploy-pages.yml`

Current behavior:
- copies payload/signature to `public/advisories/`
- generates + signs `public/checksums.json` and `public/checksums.sig`
- publishes signing key to `public/signing-public.pem` and `public/advisories/feed-signing-public.pem`
- mirrors advisory + signature/checksum/key companions into `public/releases/latest/download/` compatibility paths

### Skill release pipeline (recommended hardening)

Current release generator:
- `.github/workflows/skill-release.yml`

Current behavior:
- creates `checksums.json`, signs it as `checksums.sig`, and verifies signature before publish
- includes `signing-public.pem` in release assets
- validates generated public-key fingerprint against canonical key material

## 8) Rotation policy and runbook

### Rotation cadence
- Routine: every 90 days (or stricter org policy).
- Immediate: on suspected exposure, unauthorized workflow change, or unexplained signature mismatch.

### Routine rotation steps

1. Generate new keypair(s).
2. Open PR that updates public key file(s) and fingerprints documentation.
3. Add new private key(s) as GitHub secret(s).
4. Merge workflow changes that use new key(s).
5. Re-sign latest feed/release manifests.
6. Validate verification in CI and in one external client.
7. Remove old private key secret(s).
8. Keep old public key reference only as long as required for historical verification.

### Revocation steps

1. Disable workflows using compromised key.
2. Remove compromised GitHub secret(s).
3. Commit revocation note and new public key.
4. Re-sign latest artifacts with replacement key.
5. Publish incident advisory with timestamp and impacted window.

## 9) Incident response playbook (signing-specific)

### Triggers
- signature verification fails for newly published feed/release
- unknown commits/workflow edits touching signing paths
- leaked key material, accidental logging, or suspicious secret access

### Severity guide
- **SEV-1**: key exfiltration confirmed or maliciously signed payload published
- **SEV-2**: verification failures with unknown cause
- **SEV-3**: procedural non-compliance, no active compromise

### Response phases

1. **Containment**
   - pause signing/publish workflows
   - block further feed merges if authenticity is uncertain
2. **Investigation**
   - review workflow run logs
   - review commits affecting `.github/workflows/`, `advisories/`, and key files
   - determine first-bad timestamp and affected artifacts
3. **Eradication**
   - rotate/revoke compromised key(s)
   - restore trusted artifacts from known-good commit
4. **Recovery**
   - re-sign artifacts
   - redeploy pages/releases
   - verify via independent client check
5. **Post-incident**
   - publish timeline and remediation summary
   - tighten controls (review gates, protected environments, secret scope)

## 10) Audit evidence checklist

For each release cycle or feed-signing run, retain:
- workflow run URL and commit SHA
- signer key fingerprint in use
- verification result logs
- operator/reviewer approvals
- any exception or bypass rationale

## 11) Minimum acceptance criteria before stricter policy changes

Before tightening policy further (for example, removing compatibility bypass paths):
- signed artifacts are produced consistently for at least 2 weeks
- deploy pipeline mirrors signature companions
- one rollback drill and one key rotation drill completed successfully
- incident response on-call owner identified and documented

## Source References
- advisories/feed.json
- advisories/feed.json.sig
- advisories/feed-signing-public.pem
- clawsec-signing-public.pem
- .github/actions/sign-and-verify/action.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/skill-release.yml
- scripts/ci/verify_signing_key_consistency.sh
- wiki/migration-signed-feed.md
