---
name: picoclaw-security-guardian
version: 0.0.3
description: Picoclaw security posture skill with advisory awareness, configuration drift detection, and supply-chain verification guidance.
homepage: https://clawsec.prompt.security
author: prompt-security
license: AGPL-3.0-or-later
picoclaw:
  emoji: "🦐"
  category: "security"
  requires:
    bins: [node]
  test_requires:
    bins: [bash, docker, python3, node, openssl, zip]
---

# Picoclaw Security Guardian

Detailed architecture/operator docs: `wiki/modules/picoclaw-security-guardian.md`.


## Release Artifact Verification

For standalone installs, verify the signed release manifest before trusting `SKILL.md`, `skill.json`, or the archive. The `skill.json` file is the package metadata/SBOM source, and the release pipeline signs `checksums.json` with the ClawSec release key.

```bash
set -euo pipefail

SKILL_NAME="picoclaw-security-guardian"
VERSION="0.0.3"
REPO="prompt-security/clawsec"
TAG="${SKILL_NAME}-v${VERSION}"
BASE="https://github.com/${REPO}/releases/download/${TAG}"
ZIP_NAME="${SKILL_NAME}-v${VERSION}.zip"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

RELEASE_PUBKEY_SHA256="711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8"

curl -fsSL "$BASE/checksums.json" -o "$TMP_DIR/checksums.json"
curl -fsSL "$BASE/checksums.sig" -o "$TMP_DIR/checksums.sig"
curl -fsSL "$BASE/signing-public.pem" -o "$TMP_DIR/signing-public.pem"
curl -fsSL "$BASE/$ZIP_NAME" -o "$TMP_DIR/$ZIP_NAME"
curl -fsSL "$BASE/SKILL.md" -o "$TMP_DIR/SKILL.md"
curl -fsSL "$BASE/skill.json" -o "$TMP_DIR/skill.json"

ACTUAL_PUBKEY_SHA256="$(openssl pkey -pubin -in "$TMP_DIR/signing-public.pem" -outform DER | shasum -a 256 | awk '{print $1}')"
if [ "$ACTUAL_PUBKEY_SHA256" != "$RELEASE_PUBKEY_SHA256" ]; then
  echo "ERROR: signing-public.pem fingerprint mismatch" >&2
  exit 1
fi

openssl base64 -d -A -in "$TMP_DIR/checksums.sig" -out "$TMP_DIR/checksums.sig.bin"
openssl pkeyutl -verify -rawin -pubin \
  -inkey "$TMP_DIR/signing-public.pem" \
  -sigfile "$TMP_DIR/checksums.sig.bin" \
  -in "$TMP_DIR/checksums.json" >/dev/null

hash_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

verify_manifest_file() {
  asset="$1"
  path="$2"
  expected="$(jq -r --arg asset "$asset" '.files[$asset].sha256 // empty' "$TMP_DIR/checksums.json")"
  if [ -z "$expected" ]; then
    echo "ERROR: checksums.json missing $asset" >&2
    exit 1
  fi
  actual="$(hash_file "$path")"
  if [ "$actual" != "$expected" ]; then
    echo "ERROR: checksum mismatch for $asset" >&2
    exit 1
  fi
}

expected_archive="$(jq -r '.archive.sha256 // empty' "$TMP_DIR/checksums.json")"
if [ -z "$expected_archive" ]; then
  echo "ERROR: checksums.json missing archive.sha256" >&2
  exit 1
fi
actual_archive="$(hash_file "$TMP_DIR/$ZIP_NAME")"
if [ "$actual_archive" != "$expected_archive" ]; then
  echo "ERROR: archive checksum mismatch" >&2
  exit 1
fi

verify_manifest_file "SKILL.md" "$TMP_DIR/SKILL.md"
verify_manifest_file "skill.json" "$TMP_DIR/skill.json"

echo "Signed release manifest, archive, SKILL.md, and skill.json verified."
```

Only install or extract the archive after this verification succeeds.

## Goal

Provide Picoclaw with the same support-matrix security capabilities ClawSec tracks for mature platform modules:

| Skill name | supported platform | security feed | config drift | agent posture-review lane | chain of supply verification |
|---|---|---|---|---|---|
| picoclaw-security-guardian | Picoclaw | Yes | Yes | Separate package | Yes |

## Threat model

Picoclaw is a lightweight AI gateway that can expose chat channels, a Web UI, tool execution, MCP servers, credentials, schedulers, and embedded/router deployments. This skill focuses on the trust boundaries where those features become security-sensitive.

## Default safety posture

- Read-only by default.
- No scheduler creation in v0.0.1.
- No outbound network by default.
- Writes only explicit report/profile outputs under `$PICOCLAW_HOME/security/clawsec/` unless the operator supplies test-local temporary paths.
- Advisory checks fail closed when verification state is not verified unless the operator passes `--allow-unsigned` for a documented emergency/offline window.

## Security advisory awareness

Use `scripts/check_advisories.mjs` with a local feed/cache and verification state:

```bash
node scripts/check_advisories.mjs   --feed ~/.picoclaw/security/clawsec/feed.json   --state ~/.picoclaw/security/clawsec/feed-verification-state.json
```

The script filters advisories for `picoclaw`, `ai-gateway`, empty/all-platform advisories, or affected package entries containing `picoclaw`.
The expected feed input is the consolidated signed ClawSec advisory feed, so it can contain NVD CVEs, approved community advisories, and provisional GHSA-without-CVE records.

## Drift protection

Generate a deterministic profile:

```bash
node scripts/generate_profile.mjs   --output ~/.picoclaw/security/clawsec/current-profile.json
```

Compare against an approved baseline:

```bash
node scripts/check_drift.mjs   --baseline ~/.picoclaw/security/clawsec/baseline-profile.json   --current ~/.picoclaw/security/clawsec/current-profile.json   --fail-on critical
```

Critical drift includes public Web UI enablement, Web UI auth disablement, workspace restriction disablement, unsigned/insecure verification mode, verified-feed regression, and watched-file/release-artifact fingerprint changes.

## Chain-of-supply verification

Verify a Picoclaw release artifact against a checksum manifest plus detached signature. Signed manifest verification is required for a passing supply-chain verdict:

```bash
node scripts/verify_supply_chain.mjs \
  --artifact ./picoclaw \
  --checksums ./checksums.json \
  --signature ./checksums.json.sig \
  --public-key ./feed-signing-public.pem
```

Checksum-only mode is integrity-only, not provenance. Use `--allow-unsigned-checksums` only for short, documented offline triage windows; it should not satisfy production install verification.

## Operator review notes

- Treat public UI binding (`0.0.0.0`, `-public`) as a critical review item until auth and network allowlists are proven.
- Treat MCP servers as separate trust boundaries; review each server's filesystem, network, and credential access.
- Treat third-party OpenWrt/LuCI wrappers as separate supply-chain artifacts. Verify provenance before installing them on routers.
- Never leave unsigned advisory mode enabled in recurring or production checks.

## Validation

```bash
python utils/validate_skill.py skills/picoclaw-security-guardian
node skills/picoclaw-security-guardian/test/profile.test.mjs
node skills/picoclaw-security-guardian/test/drift.test.mjs
node skills/picoclaw-security-guardian/test/supply_chain.test.mjs
bash -n skills/picoclaw-security-guardian/test/picoclaw_security_guardian_sandbox_regression.sh
```

## Pre-release install regression

Before publishing v0.0.1 release artifacts, run the isolated install lane from the repo root:

```bash
skills/picoclaw-security-guardian/test/picoclaw_security_guardian_sandbox_regression.sh
```

The regression installs the skill through Picoclaw's own `find_skills` / `install_skill` path from a local ClawHub-compatible registry into an isolated Docker-hosted Picoclaw workspace with isolated `HOME`, `PICOCLAW_HOME`, and `PICOCLAW_WORKSPACE`. It verifies signed release-artifact preflight inputs, confirms Picoclaw's skill loader can list/load the installed skill, then runs the installed copy's profile, drift, advisory fail-closed, advisory filtering, and supply-chain verification paths against Picoclaw-style `config.json` and `launcher-config.json` files.
