# Skill Package Signing and Verification for NanoClaw v1 (Legacy)

> **Compatibility boundary:** This document describes the bundled NanoClaw v1 adapter for `>=0.1.0 <2.0.0`. It is incompatible with NanoClaw v2 and is not a v2 installation, publisher, or key-management contract.

The bundled v1 verifier checks one detached `.sig` file with its configured pinned ClawSec public key. It does not accept caller-selected publisher keys, unsigned packages, or a dual-signature rotation format.

---

## Table of Contents

1. [Overview](#overview)
2. [Publisher Workflow Is Out of Scope](#publisher-workflow-is-out-of-scope)
3. [For Legacy NanoClaw v1 Agents](#for-legacy-nanoclaw-v1-agents)
4. [Security Properties](#security-properties)
5. [Key Management](#key-management)
6. [Troubleshooting](#troubleshooting)

---

## Overview

The legacy verifier can detect whether a staged package matches a detached signature made by the pinned ClawSec key. Verification is one input to an operator decision; the tool does not install a package and does not make arbitrary third-party packages trusted.

### Why Signature Verification?

Without signature verification, an attacker could:
- **Replace** a legitimate skill package with a malicious one during download
- **Modify** package contents to inject backdoors or steal data
- **Distribute** trojan skills that appear legitimate but contain malware

Signature verification ensures:
- ✅ **Authenticity**: Signature matches the configured pinned ClawSec key
- ✅ **Integrity**: Package hasn't been modified since signing
- ✅ **Non-repudiation**: Signer can't deny signing the package

---

## Publisher Workflow Is Out of Scope

This legacy package does not define a supported publisher key-generation or arbitrary-package signing workflow. The bundled verifier accepts only the key configured by the v1 host service; callers cannot supply a different key or request unsigned acceptance.

Use the ClawSec release pipeline and its signed release manifest for official ClawSec package publication. Do not generate a local key and expect this adapter to trust it.

---

## For Legacy NanoClaw v1 Agents

### Quick Start

```typescript
// Verify a downloaded skill package before installation
const verification = await tools.clawsec_verify_skill_package({
  packagePath: '/tmp/my-skill-1.0.0.tar.gz'
  // signaturePath auto-detected as /tmp/my-skill-1.0.0.tar.gz.sig
});

const result = JSON.parse(verification.content[0].text);

if (!result.valid) {
  console.log('⚠️ SIGNATURE VERIFICATION FAILED!');
  console.log(`Reason: ${result.reason || result.error}`);
  console.log('DO NOT install this package.');
  return;
}

console.log(`✓ Signature valid (signer: ${result.signer})`);
console.log(`Package hash: ${result.packageInfo.sha256}`);
console.log('Signature matches the pinned key; continue required advisory review and operator approval.');
```

### MCP Tool: `clawsec_verify_skill_package`

**Parameters:**
- `packagePath` (required): Absolute path to skill package (`.tar.gz`, `.tar`, `.tgz`, or `.zip`)
- `signaturePath` (optional): Path to signature file (auto-detects `.sig` if omitted)

Path policy:
- Files must be under one of: `/tmp`, `/var/tmp`, `/workspace/ipc`, `/workspace/project/data`, `/workspace/project/tmp`, `/workspace/project/downloads`
- Symlinks are rejected
- Signatures must use `.sig`

**Returns:**
```typescript
{
  success: boolean,           // Operation completed without errors
  valid: boolean,             // Signature is cryptographically valid
  recommendation: string,     // "install" | "block"
  signer: string,             // "clawsec"
  algorithm: "Ed25519",       // Signature algorithm
  verifiedAt: string,         // ISO timestamp
  packageInfo: {
    size: number,             // Package file size in bytes
    sha256: string            // SHA-256 hash of package
  },
  error?: string              // Error message if failed
}
```

### Usage Patterns

#### Pattern 1: Basic Signature Review

```typescript
async function reviewSkillSignature(packagePath: string) {
  // Verify signature first
  const verification = await tools.clawsec_verify_skill_package({ packagePath });
  const result = JSON.parse(verification.content[0].text);

  if (!result.success || !result.valid || result.recommendation === 'block') {
    throw new Error(`Signature review failed: ${result.reason || result.error}`);
  }

  return {
    packagePath,
    verification: result,
    nextStep: 'Complete advisory and code review, then request operator approval.'
  };
}
```

#### Pattern 2: Combined Security Checks

```typescript
async function buildInstallReview(packagePath: string, skillName: string) {
  // Step 1: Verify signature
  const sigVerify = await tools.clawsec_verify_skill_package({ packagePath });
  const sigResult = JSON.parse(sigVerify.content[0].text);

  if (!sigResult.valid) {
    throw new Error(`Signature invalid: ${sigResult.reason}`);
  }

  // Step 2: Check advisories
  const advisory = await tools.clawsec_check_skill_safety({ skillName });
  const advResult = JSON.parse(advisory.content[0].text);

  if (!advResult.safe) {
    throw new Error(`Known vulnerabilities: ${advResult.advisories.map(a => a.id).join(', ')}`);
  }

  // These checks produce evidence; they do not authorize or perform installation.
  return {
    packagePath,
    signature: sigResult,
    advisories: advResult,
    requiresCodeReview: true,
    requiresOperatorApproval: true
  };
}
```

#### Pattern 3: Download and Verify Workflow

```typescript
async function downloadAndVerifySkill(url: string) {
  const packagePath = `/tmp/${Date.now()}-skill.tar.gz`;
  const signaturePath = `${packagePath}.sig`;

  // Download package
  await fetch(url).then(r => r.arrayBuffer()).then(buf => {
    fs.writeFileSync(packagePath, Buffer.from(buf));
  });

  // Download signature
  await fetch(`${url}.sig`).then(r => r.text()).then(sig => {
    fs.writeFileSync(signaturePath, sig);
  });

  // Verify before installation
  const verification = await tools.clawsec_verify_skill_package({
    packagePath,
    signaturePath
  });

  const result = JSON.parse(verification.content[0].text);

  if (!result.valid) {
    fs.unlinkSync(packagePath);     // Delete tampered file
    fs.unlinkSync(signaturePath);
    throw new Error('Signature verification failed');
  }

  // Preserve the staged files for advisory/code review and operator approval.
  // The host installer must separately enforce the final decision.
  return { packagePath, signaturePath, verification: result };
}
```

### Error Handling

```typescript
const verification = await tools.clawsec_verify_skill_package({ packagePath });
const result = JSON.parse(verification.content[0].text);

// Check result.success first (operation completed)
if (!result.success) {
  console.error('Verification operation failed:', result.error);
  // Reasons: file not found, service unavailable, timeout
  return;
}

// Then check result.valid (signature cryptographically valid)
if (!result.valid) {
  console.error('Invalid signature:', result.reason);
  // Reasons: signature mismatch, tampered package, invalid format
  return;
}

// Finally check recommendation
switch (result.recommendation) {
  case 'install':
    console.log('✓ Signature recommendation permits continued review; operator approval is still required');
    break;
  case 'block':
    console.error('⛔ Signature recommendation is block; the host installer or operator must enforce it');
    break;
}
```

---

## Security Properties

### What Signature Verification Detects

✅ **Detects:**
- **Tampering**: Detecting if package contents were modified after signing
- **MITM attacks**: Detecting if package was swapped during download
- **Malicious mirrors**: Ensuring package comes from trusted source
- **Accidental corruption**: Detecting file corruption during transfer

### What Signature Verification Does NOT Prevent

❌ **Does Not Prevent:**
- **Malicious signed packages**: If the publisher's key is compromised
- **Zero-day vulnerabilities**: Bugs unknown to the publisher
- **Social engineering**: Convincing users to trust malicious publishers
- **Time-of-check-to-time-of-use**: Package modified after verification

**Defense in Depth**: Combine signature verification with:
1. **Advisory checking** (`clawsec_check_skill_safety`)
2. **Code review** (manual inspection of skill code)
3. **Sandboxing** (run skills in isolated containers)
4. **Monitoring** (detect suspicious behavior at runtime)

### Trust Model

Signature verification relies on **trust in the public key**:

```
┌─────────────────────────────────────────────────┐
│ You trust ClawSec's public key                  │
│          ↓                                      │
│ ClawSec signs package with private key          │
│          ↓                                      │
│ You verify signature with ClawSec's public key  │
│          ↓                                      │
│ Signature valid → Bytes match the pinned key   │
└─────────────────────────────────────────────────┘
```

**Key Question**: How do you establish trust in the public key?
- **Pinned in repository**: Public key committed to ClawSec repo (trust GitHub)
- **HTTPS website**: Download from `https://clawsec.prompt.security/` (trust TLS/CA)
- **Out-of-band verification**: Compare key fingerprint via phone, Signal, etc.
- **Web of Trust**: Multiple trusted sources publish the same key

---

## Key Management

### ClawSec's Pinned Public Key

**Location**: `/workspace/project/skills/clawsec-nanoclaw/advisories/feed-signing-public.pem`

The legacy v1 package-verifier handler reads the embedded advisory feed-verification key by default. That coupling is limited to this frozen adapter. It is not the ClawSec GitHub Release manifest trust anchor and is not a NanoClaw v2 trust contract.

**Key Fingerprint** (for manual verification):
```bash
# Compute fingerprint of pinned key
openssl pkey -pubin -in feed-signing-public.pem -outform DER | \
  openssl dgst -sha256 -binary | base64
# Expected: <will be filled in after key generation>
```

### Public Key Policy

The verifier always uses the pinned ClawSec public key from this skill package.
Runtime public-key overrides are intentionally not supported.

### Key Rotation

The bundled v1 verifier has no dual-key or dual-signature rotation protocol. It accepts one configured public key and one `.sig` path. A key change requires a reviewed package update and explicit operator migration; do not invent a `.sig2` fallback or accept caller-selected keys.

---

## Troubleshooting

### Error: "Signature file not found"

**Cause**: Missing `.sig` file or incorrect path.

**Solution**:
```bash
# Check if signature exists
ls -l /tmp/skill.tar.gz.sig

# If missing, download signature
curl -o /tmp/skill.tar.gz.sig https://example.com/skill.tar.gz.sig

# Or specify explicit path
clawsec_verify_skill_package({
  packagePath: '/tmp/skill.tar.gz',
  signaturePath: '/tmp/custom-signature.sig'
})
```

### Error: "Signature verification failed"

**Cause**: Package was tampered with, or signature doesn't match package.

**Solution**:
```bash
# Re-download package and signature
curl -o /tmp/skill.tar.gz https://example.com/skill.tar.gz
curl -o /tmp/skill.tar.gz.sig https://example.com/skill.tar.gz.sig

# Verify manually with OpenSSL
openssl dgst -sha512 -verify clawsec-signing-public.pem \
  -signature /tmp/skill.tar.gz.sig /tmp/skill.tar.gz
# Should output: "Verified OK"
```

### Error: "Invalid PEM format"

**Cause**: Public key file is corrupted or not in PEM format.

**Solution**:
```bash
# Check public key format
head -1 /path/to/public-key.pem
# Should output: "-----BEGIN PUBLIC KEY-----"

# Re-download public key
curl -o clawsec-signing-public.pem \
  https://clawsec.prompt.security/clawsec-signing-public.pem
```

### Error: "Package file not found"

**Cause**: Incorrect path or file doesn't exist.

**Solution**:
```bash
# Use absolute paths (required)
clawsec_verify_skill_package({
  packagePath: '/tmp/skill.tar.gz'  // ✓ Absolute
  // packagePath: './skill.tar.gz' // ✗ Relative (won't work)
})

# Verify file exists
stat /tmp/skill.tar.gz
```

### Verification Times Out (>5s)

**Cause**: Large package (>50MB) or slow disk I/O.

**Solution**:
```bash
# Check package size
ls -lh /tmp/skill.tar.gz

# For very large packages, verification can take time
# Consider splitting into smaller skill modules
```

---

## Appendix: Signature File Format

ClawSec uses **Ed25519 detached signatures** in raw binary format, base64-encoded.

**File Structure**:
```
my-skill-1.0.0.tar.gz.sig:
  Line 1: base64-encoded signature (88 characters)
```

**Example**:
```
MEQCIDxyz...ABC123==
```

**Properties**:
- Algorithm: Ed25519 (EdDSA with Curve25519)
- Signature size: 64 bytes (88 characters base64)
- Hash function: SHA-512 (internal to Ed25519)
- Format: Raw binary, base64-encoded

**Verification Algorithm**:
1. Decode base64 signature → 64-byte binary
2. Hash package with SHA-512
3. Verify Ed25519 signature(hash, publicKey) → boolean

---

## References

- [Ed25519 Specification (RFC 8032)](https://tools.ietf.org/html/rfc8032)
- [OpenSSL Ed25519 Documentation](https://www.openssl.org/docs/man3.0/man7/Ed25519.html)
- [ClawSec Security Architecture](https://clawsec.prompt.security/docs/architecture)
- [Supply Chain Attack Prevention](https://owasp.org/www-community/attacks/Supply_Chain_Attack)

---

**Document Version**: 0.0.11 legacy adapter
**Last Updated**: 2026-07-22
**Maintainer**: ClawSec Security Team
