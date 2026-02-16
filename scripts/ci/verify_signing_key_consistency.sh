#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

SKILL_MD="skills/clawsec-suite/SKILL.md"
CANONICAL_KEYS=(
  "clawsec-signing-public.pem"
  "advisories/feed-signing-public.pem"
  "skills/clawsec-suite/advisories/feed-signing-public.pem"
)

fingerprint_for_pem() {
  local pem_file="$1"
  openssl pkey -pubin -in "$pem_file" -outform DER | shasum -a 256 | awk '{print $1}'
}

if [[ ! -f "$SKILL_MD" ]]; then
  echo "ERROR: missing $SKILL_MD" >&2
  exit 1
fi

DOC_EXPECTED_FPR="$(awk -F'"' '/RELEASE_PUBKEY_SHA256=/{print $2; exit}' "$SKILL_MD")"
if [[ -z "$DOC_EXPECTED_FPR" ]]; then
  echo "ERROR: could not parse RELEASE_PUBKEY_SHA256 from $SKILL_MD" >&2
  exit 1
fi

TMP_DOC_KEY="$(mktemp)"
trap 'rm -f "$TMP_DOC_KEY"' EXIT
awk '
  /-----BEGIN PUBLIC KEY-----/ {in_key=1}
  in_key {print}
  /-----END PUBLIC KEY-----/ {exit}
' "$SKILL_MD" > "$TMP_DOC_KEY"

if ! grep -q "BEGIN PUBLIC KEY" "$TMP_DOC_KEY"; then
  echo "ERROR: could not extract inline public key from $SKILL_MD" >&2
  exit 1
fi

DOC_INLINE_FPR="$(fingerprint_for_pem "$TMP_DOC_KEY")"

if [[ "$DOC_INLINE_FPR" != "$DOC_EXPECTED_FPR" ]]; then
  echo "ERROR: SKILL.md mismatch: inline key fingerprint ($DOC_INLINE_FPR) != RELEASE_PUBKEY_SHA256 ($DOC_EXPECTED_FPR)" >&2
  exit 1
fi

echo "SKILL.md inline key fingerprint matches RELEASE_PUBKEY_SHA256: $DOC_EXPECTED_FPR"

CANONICAL_FPR=""
for key_file in "${CANONICAL_KEYS[@]}"; do
  if [[ ! -f "$key_file" ]]; then
    echo "ERROR: missing canonical key file: $key_file" >&2
    exit 1
  fi
  fpr="$(fingerprint_for_pem "$key_file")"
  echo "$key_file -> $fpr"
  if [[ -z "$CANONICAL_FPR" ]]; then
    CANONICAL_FPR="$fpr"
  elif [[ "$fpr" != "$CANONICAL_FPR" ]]; then
    echo "ERROR: key fingerprint mismatch among canonical pem files" >&2
    exit 1
  fi
done

if [[ "$CANONICAL_FPR" != "$DOC_EXPECTED_FPR" ]]; then
  echo "ERROR: canonical pem fingerprint ($CANONICAL_FPR) != SKILL.md RELEASE_PUBKEY_SHA256 ($DOC_EXPECTED_FPR)" >&2
  exit 1
fi

echo "All signing key references are consistent: $CANONICAL_FPR"
