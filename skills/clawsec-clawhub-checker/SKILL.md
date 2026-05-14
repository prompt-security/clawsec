---
name: clawsec-clawhub-checker
version: 0.0.4
description: ClawHub reputation checker for clawsec-suite. Adds a standalone reputation gate before guarded skill installation.
homepage: https://clawsec.prompt.security
clawdis:
  emoji: "🛡️"
  requires:
    bins: [node, clawhub, openclaw]
  depends_on: [clawsec-suite]
---

# ClawSec ClawHub Checker

Adds a reputation gate on top of the `clawsec-suite` guarded installer.

## Operational Notes

- Required runtime: `node`, `clawhub`, `openclaw`
- Depends on: installed `clawsec-suite`
- Side effects: none on other skills; this package does not rewrite installed suite files
- Advisory-hook wiring is optional and manual in this release
- Network behavior: reputation checks call ClawHub inspect/search endpoints
- Trust model: scores are heuristic and confirmation-gated

## What It Does

1. Reads skill metadata from ClawHub (`inspect --json`)
2. Evaluates scanner status (including VirusTotal summary when present)
3. Applies additional reputation heuristics (age, updates, author history, downloads)
4. Requires explicit `--confirm-reputation` when score is below threshold

## Installation

Install after `clawsec-suite`:

```bash
npx clawhub@latest install clawsec-suite
npx clawhub@latest install clawsec-clawhub-checker
```

Optional preflight check (validates local paths and prints recommended command):

```bash
node ~/.openclaw/skills/clawsec-clawhub-checker/scripts/setup_reputation_hook.mjs
```


## Release Artifact Verification

For standalone installs, verify the signed release manifest before trusting `SKILL.md`, `skill.json`, or the archive. The `skill.json` file is the package metadata/SBOM source, and the release pipeline signs `checksums.json` with the ClawSec release key.

```bash
set -euo pipefail

SKILL_NAME="clawsec-clawhub-checker"
VERSION="0.0.4"
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

## Usage

Run the enhanced installer directly from this skill:

```bash
node ~/.openclaw/skills/clawsec-clawhub-checker/scripts/enhanced_guarded_install.mjs \
  --skill some-skill \
  --version 1.0.0
```

If a skill is below threshold, rerun only with explicit approval:

```bash
node ~/.openclaw/skills/clawsec-clawhub-checker/scripts/enhanced_guarded_install.mjs \
  --skill some-skill \
  --version 1.0.0 \
  --confirm-reputation
```

## Optional Advisory-Hook Wiring (Manual)

This release does not auto-patch `clawsec-suite` hook files.  
If you rely on advisory alerts that include `reputationWarning` / `reputationWarnings`, wire the checker module manually:

- Source module: `~/.openclaw/skills/clawsec-clawhub-checker/hooks/clawsec-advisory-guardian/lib/reputation.mjs`
- Target hook file: `~/.openclaw/skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`

Treat that wiring as a deliberate local customization and review it before enabling.

## Exit Codes

- `0` safe to install
- `42` advisory confirmation required (from clawsec-suite)
- `43` reputation confirmation required
- `1` error

## Configuration

Environment variables:

- `CLAWHUB_REPUTATION_THRESHOLD` - Minimum score (0-100, default: 70)

## Safety Notes

- This is defense-in-depth, not a replacement for advisory matching
- Scanner outputs can produce false positives and false negatives
- Always review skill code before overriding warnings

## Development

Key files:

- `scripts/enhanced_guarded_install.mjs`
- `scripts/check_clawhub_reputation.mjs`
- `scripts/setup_reputation_hook.mjs`
- `hooks/clawsec-advisory-guardian/lib/reputation.mjs`

## License

GNU AGPL v3.0 or later - Part of the ClawSec security suite
