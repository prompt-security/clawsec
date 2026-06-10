---
name: openclaw-traffic-guardian
version: 0.0.1-beta3
description: OpenClaw runtime traffic monitoring baseline for opt-in HTTP/HTTPS proxy inspection, egress detection, inbound injection detection, and social-account policy review.
homepage: https://clawsec.prompt.security
author: prompt-security
license: AGPL-3.0-or-later
clawdis:
  emoji: "TG"
  requires:
    bins: [node, python3]
---

# OpenClaw Traffic Guardian

This is a baseline specification skill. It intentionally does not ship a proxy or runtime implementation yet.

## Vercel Skills Installation

Install with the Vercel Skills CLI for this harness:

```bash
npx skills add prompt-security/clawsec --skill openclaw-traffic-guardian -a openclaw -y
```

## Release Artifact Verification

For standalone installs, verify the signed release manifest before trusting `SKILL.md`, `skill.json`, or the archive. The `skill.json` file is the package metadata/SBOM source, and the release pipeline signs `checksums.json` with the ClawSec release key.

```bash
set -euo pipefail

SKILL_NAME="openclaw-traffic-guardian"
VERSION="0.0.1-beta3"
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

## Scope

Builders should use this skill as the OpenClaw landing zone for runtime traffic monitoring:

- operator-scoped HTTP proxy inspection
- optional HTTPS inspection with per-process CA trust
- outbound exfiltration detection
- inbound injection detection
- approval-sensitive social-account mutation review
- redacted local threat logs
- optional OpenClaw hook/status integration

Do not merge this capability into `clawsec-scanner`, `openclaw-audit-watchdog`, or `soul-guardian`. Those skills have different trust boundaries and safety contracts.

## Safety Contract

- Opt-in only.
- Detect-and-log by default.
- No automatic system CA installation.
- No global `HTTP_PROXY` or `HTTPS_PROXY` changes.
- No blocking in the first implementation.
- Redact secrets before logs or conversation alerts.
- Keep all state under `OPENCLAW_TRAFFIC_GUARDIAN_HOME` or `~/.openclaw/security/clawsec/traffic-guardian`.

## Builder Entry Points

Read `SPEC.md` before implementing. Use the placeholder folders as follows:

| Path | Intended use |
|---|---|
| `lib/` | Detector rules, redaction, event schema, report formatting |
| `scripts/` | Start, stop, status, config validation, log query helpers |
| `hooks/openclaw-traffic-guardian-hook/` | Optional OpenClaw hook/status integration |
| `test/` | Unit tests, proxy fixture tests, redaction tests, process-scope tests |

## Required First Implementation Behavior

1. Validate config without starting the proxy.
2. Start monitor in foreground or explicit background mode.
3. Scope proxy environment variables to the target OpenClaw process.
4. Inspect HTTP request/response text up to a bounded byte limit.
5. Support optional HTTPS MITM only when the operator supplies per-process trust configuration.
6. Flag requests matching `SPEC.md`'s Outbound POLICY_REVIEW cases as operator-review findings, including TweetClaw or other X/Twitter automation writes and scheduler/background-runner repeats without a fresh operator-approval marker.
7. Detect repeat/background-runner context from bounded request metadata such as paths, headers, user-agent, client context, tool invocation metadata, or scheduler identifiers.
8. Emit JSONL findings with redacted snippets plus source type, mutation category, approval-marker presence, and direct-operator versus background-runner context.
9. Provide a `status` command that reports mode, listener, CA fingerprint if present, and last findings.

## Out of Scope for v0.0.1 Implementation

- automatic system trust-store mutation
- transparent network interception
- default blocking
- sending traffic to external services
- collecting full request/response bodies
