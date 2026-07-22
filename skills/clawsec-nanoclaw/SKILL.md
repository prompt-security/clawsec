---
name: clawsec-nanoclaw
version: 0.0.11
description: Use only with legacy NanoClaw >=0.1.0 <2.0.0 to check ClawSec advisories, package signatures, and the bundled v1 integrity adapter; NanoClaw v2 is incompatible and requires a separate adapter
---

# ClawSec for NanoClaw v1 (Legacy)

Legacy advisory, package-signature, and integrity tooling for compatible pre-v2 NanoClaw deployments.

## Compatibility Gate

- Supported NanoClaw range: `>=0.1.0 <2.0.0`.
- NanoClaw v2 (`>=2.0.0`): **incompatible; do not install or activate this adapter**.
- NanoClaw v2 uses different host, container, SQLite IPC, and extension surfaces. It requires a separate ClawSec adapter.
- The v1 integration paths in this package are retained for legacy users and migration evidence only. They are not NanoClaw v2 instructions.

Stop if the target version is unknown or is NanoClaw v2. Do not reinterpret the v1 IPC examples as a generic installation recipe.

## Overview

The bundled v1 MCP tools check installed skills against a curated feed of security advisories, include exploitability context for triage, and report issues in existing packages. They return advisory decisions; they do not own or enforce the host installer.

**Core principle:** Check before you install. Monitor what's running.

## When to Use

Use ClawSec tools when:
- Installing a new skill (check safety first)
- User asks "are my skills secure?"
- Investigating suspicious behavior
- Regular security audits
- After receiving security notifications

Do NOT use for:
- Code review (use other tools)
- Performance issues (different concern)
- General debugging

## MCP Tools Available

### Pre-Installation Check

```typescript
// Before installing any skill
const safety = await tools.clawsec_check_skill_safety({
  skillName: 'new-skill',
  skillVersion: '1.0.0'  // optional
});

if (!safety.safe) {
  // Show user the risks before proceeding
  console.warn(`Security issues: ${safety.advisories.map(a => a.id)}`);
}
```

### Security Audit

```typescript
// Check all installed skills (defaults to ~/.claude/skills in the container)
const result = await tools.clawsec_check_advisories({
  installRoot: '/home/node/.claude/skills'  // optional
});

if (result.matches.some((m) =>
  m.advisory.severity === 'critical' || m.advisory.exploitability_score === 'high'
)) {
  // Alert user immediately
  console.error('Urgent advisories found!');
}
```

### Browse Advisories

```typescript
// List advisories with filters
const advisories = await tools.clawsec_list_advisories({
  severity: 'high',               // optional
  exploitabilityScore: 'high'     // optional
});
```

## Quick Reference

| Task | Tool | Key Parameter |
|------|------|---------------|
| Pre-install check | `clawsec_check_skill_safety` | `skillName` |
| Audit all skills | `clawsec_check_advisories` | `installRoot` (optional) |
| Browse feed | `clawsec_list_advisories` | `severity`, `type`, `exploitabilityScore` (optional) |
| Verify package signature | `clawsec_verify_skill_package` | `packagePath` |
| Refresh advisory cache | `clawsec_refresh_cache` | (none) |
| Check file integrity | `clawsec_check_integrity` | `mode`, `autoRestore` (optional) |
| Approve file change | `clawsec_approve_change` | `path` |
| View baseline status | `clawsec_integrity_status` | `path` (optional) |
| Verify audit log | `clawsec_verify_audit` | (none) |

## Common Patterns

### Pattern 1: Pre-Installation Advisory Review

```typescript
// ALWAYS check before installing
const safety = await tools.clawsec_check_skill_safety({
  skillName: userRequestedSkill
});

if (!safety.safe) {
  // Return the advisory evidence to the host installer or operator.
  await showSecurityWarning(safety.advisories);
  return { recommendation: 'do-not-install', safety };
}

// Advisory output is one input, not installation authorization.
return {
  recommendation: 'continue-review',
  safety,
  requiresSignatureVerification: true,
  requiresCodeReview: true,
  requiresOperatorApproval: true
};
```

### Pattern 2: Legacy v1 Host Scheduling

Scheduling is deployment-owned. This package does not register a NanoClaw v2 task or scheduler integration. A compatible v1 operator may wire an advisory check through the v1 host's reviewed scheduling surface after completing the manual integration in [INSTALL.md](./INSTALL.md).

### Pattern 3: User Security Query

```
User: "Are my skills secure?"

You: I'll check installed skills for known vulnerabilities.
[Use clawsec_check_advisories]

Response:
✅ No urgent issues found.
- 2 low-severity/low-exploitability advisories
- All skills up to date
```

## Common Mistakes

### ❌ Installing without checking
```typescript
// DON'T
await installSkill('untrusted-skill');
```

```typescript
// DO
const safety = await tools.clawsec_check_skill_safety({
  skillName: 'untrusted-skill'
});
if (!safety.safe) return { recommendation: 'do-not-install', safety };
return {
  recommendation: 'continue-review',
  requiresSignatureVerification: true,
  requiresCodeReview: true,
  requiresOperatorApproval: true
};
```

### ❌ Ignoring exploitability context
```typescript
// DON'T: Use severity only
if (advisory.severity === 'high') {
  notifyNow(advisory);
}
```

```typescript
// DO: Use exploitability + severity
if (
  advisory.exploitability_score === 'high' ||
  advisory.severity === 'critical'
) {
  notifyNow(advisory);
}
```

### ❌ Skipping critical severity
```typescript
// DON'T: Ignore high exploitability in medium severity advisories
if (advisory.severity === 'critical') alert();
```

```typescript
// DO: Prioritize exploitability and severity together
if (advisory.exploitability_score === 'high' || advisory.severity === 'critical') {
  // Alert immediately
}
```

## Implementation Details

**Feed Source**: https://clawsec.prompt.security/advisories/feed.json

This signed feed is consolidated. NanoClaw receives NVD CVEs, approved community advisories, and provisional GHSA-without-CVE advisories through the same default URL.

**Legacy v1 example cadence**: Every 6 hours after explicit host wiring; the skill does not install a scheduler.

**Signature Verification**: Ed25519 signed feeds
**Package Verification Policy**: pinned key only, bounded package/signature paths

**Legacy v1 cache location**: `/workspace/project/data/clawsec-advisory-cache.json`

See [INSTALL.md](./INSTALL.md) for setup and [docs/](./docs/) for advanced usage.

## Real-World Impact

- Helps operators identify skills with known RCE vulnerabilities before installation
- Alerts to supply chain attacks in dependencies
- Provides actionable remediation steps
- Uses a curated feed while preserving severity and exploitability context for operator review

## Release Artifact Verification

For standalone installs, verify the signed release manifest before trusting `SKILL.md`, `skill.json`, or the archive. The `skill.json` file is the package metadata/SBOM source, and the release pipeline signs `checksums.json` with the ClawSec release key.

```bash
set -euo pipefail

SKILL_NAME="clawsec-nanoclaw"
VERSION="0.0.11"
REPO="prompt-security/clawsec"
TAG="${SKILL_NAME}-v${VERSION}"
BASE="https://github.com/${REPO}/releases/download/${TAG}"
ZIP_NAME="${SKILL_NAME}-v${VERSION}.zip"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ClawSec GitHub Release signing trust anchor. This is not a NanoClaw v2
# integration key and is distinct from the v1 embedded feed-verification path.
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
