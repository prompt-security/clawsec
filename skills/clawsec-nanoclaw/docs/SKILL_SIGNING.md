# Skill Package Signing and Verification

This document explains how ClawSec signs skill packages and how NanoClaw agents verify signatures before installation.

---

## Table of Contents

1. [Overview](#overview)
2. [For Skill Publishers: How to Sign Packages](#for-skill-publishers-how-to-sign-packages)
3. [For NanoClaw Agents: How to Verify Signatures](#for-nanoclaw-agents-how-to-verify-signatures)
4. [Security Properties](#security-properties)
5. [Key Management](#key-management)
6. [Troubleshooting](#troubleshooting)

---

## Overview

Skill signature verification prevents **supply chain attacks** by ensuring skill packages haven't been tampered with during distribution. ClawSec uses **Ed25519 digital signatures** to sign skill packages, and NanoClaw agents verify these signatures before installation.

### Why Signature Verification?

Without signature verification, an attacker could:
- **Replace** a legitimate skill package with a malicious one during download
- **Modify** package contents to inject backdoors or steal data
- **Distribute** trojan skills that appear legitimate but contain malware

Signature verification ensures:
- ✅ **Authenticity**: Package comes from ClawSec (or trusted publisher)
- ✅ **Integrity**: Package hasn't been modified since signing
- ✅ **Non-repudiation**: Signer can't deny signing the package

---

## For Skill Publishers: How to Sign Packages

### Prerequisites

- OpenSSL 1.1.1+ (for Ed25519 support)
- Private Ed25519 signing key (generate once, keep secure)
- Skill package ready for distribution

### Step 1: Generate Ed25519 Keypair (One-Time Setup)

```bash
# Generate private key (KEEP THIS SECRET!)
openssl genpkey -algorithm ED25519 -out clawsec-signing-private.pem

# Extract public key (share this with users)
openssl pkey -in clawsec-signing-private.pem -pubout -out clawsec-signing-public.pem

# Secure the private key
chmod 600 clawsec-signing-private.pem
```

**⚠️ CRITICAL**: Never commit the private key to version control! Store it securely:
- Local machine: `~/.ssh/clawsec-signing-private.pem` with `chmod 600`
- CI/CD: GitHub Secrets, AWS Secrets Manager, or similar
- Team: 1Password, Vault, or hardware security module (HSM)

### Step 2: Package Your Skill

```bash
# Create skill package (tarball or zip)
tar -czf my-skill-1.0.0.tar.gz -C skills/my-skill .

# Or as a zip file
zip -r my-skill-1.0.0.zip skills/my-skill/
```

### Step 3: Sign the Package

```bash
# Create detached Ed25519 signature
openssl dgst -sha512 -sign clawsec-signing-private.pem \
  -out my-skill-1.0.0.tar.gz.sig \
  my-skill-1.0.0.tar.gz

# Verify the signature was created
ls -lh my-skill-1.0.0.tar.gz.sig
# Should show a ~64-byte file
```

**Signature Format**: Detached Ed25519 signature, base64-encoded, stored in `.sig` file.

### Step 4: Distribute Package + Signature

Distribute **both** files together:
- `my-skill-1.0.0.tar.gz` (the skill package)
- `my-skill-1.0.0.tar.gz.sig` (the signature)

Users will verify the signature against your public key before installation.

### Step 5: Publish Public Key

Share your public key with users via:
- **Pinned in repository**: Commit `clawsec-signing-public.pem` to your repo
- **Website**: Host at `https://yoursite.com/clawsec-signing-public.pem`
- **DNS TXT record**: Publish as base64-encoded TXT record
- **Skill metadata**: Embed in `skill.json`

---

## For NanoClaw Agents: How to Verify Signatures

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
console.log('Safe to proceed with installation.');
```

### MCP Tool: `clawsec_verify_skill_package`

**Parameters:**
- `packagePath` (required): Absolute path to skill package (`.tar.gz` or `.zip`)
- `signaturePath` (optional): Path to signature file (auto-detects `.sig` if omitted)

**Returns:**
```typescript
{
  success: boolean,           // Operation completed without errors
  valid: boolean,             // Signature is cryptographically valid
  recommendation: string,     // "install" | "block" | "review"
  signer: string,             // "clawsec" or custom signer
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

#### Pattern 1: Basic Pre-Installation Check

```typescript
async function installSkill(packagePath: string) {
  // Verify signature first
  const verification = await tools.clawsec_verify_skill_package({ packagePath });
  const result = JSON.parse(verification.content[0].text);

  if (result.recommendation === 'block') {
    throw new Error(`Cannot install: ${result.reason || result.error}`);
  }

  // Signature valid - proceed with extraction
  extractPackage(packagePath, '/workspace/project/skills/');
}
```

#### Pattern 2: Combined Security Checks

```typescript
async function installSkillSafely(packagePath: string, skillName: string) {
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

  // Both checks passed - safe to install
  extractPackage(packagePath, '/workspace/project/skills/');
  console.log(`✓ Installed ${skillName} (verified + no advisories)`);
}
```

#### Pattern 3: Download and Verify Workflow

```typescript
async function downloadAndInstallSkill(url: string) {
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

  // Install verified package
  extractPackage(packagePath, '/workspace/project/skills/');

  // Cleanup
  fs.unlinkSync(packagePath);
  fs.unlinkSync(signaturePath);
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
    console.log('✓ Safe to install');
    break;
  case 'block':
    console.error('⛔ Installation blocked');
    break;
  case 'review':
    console.warn('⚠️ Manual review recommended');
    break;
}
```

---

## Security Properties

### What Signature Verification Prevents

✅ **Prevents:**
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
│ Signature valid → Package is authentic         │
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

This is the **same key** used for advisory feed verification, providing a single trust anchor for all ClawSec security operations.

**Key Fingerprint** (for manual verification):
```bash
# Compute fingerprint of pinned key
openssl pkey -pubin -in feed-signing-public.pem -outform DER | \
  openssl dgst -sha256 -binary | base64
# Expected: <will be filled in after key generation>
```

### Using Custom Public Keys

For organizational deployments with custom skill publishers:

```typescript
// Load custom public key
const customPublicKey = fs.readFileSync('/path/to/org-public.pem', 'utf8');

// Verify with custom key (not pinned ClawSec key)
const verification = await tools.clawsec_verify_skill_package({
  packagePath: '/tmp/org-skill.tar.gz',
  publicKeyPath: '/path/to/org-public.pem'  // Custom key
});
```

**Note**: The MCP tool currently uses the pinned key. Custom key support via `publicKeyPem` parameter requires host-side implementation.

### Key Rotation

If ClawSec's signing key is compromised or needs rotation:

1. **Generate new keypair** (keep private key secure)
2. **Sign all packages** with new key
3. **Publish new public key** to all distribution channels
4. **Update pinned key** in `/workspace/project/skills/clawsec-nanoclaw/advisories/`
5. **Deprecate old key** after transition period (e.g., 90 days)

During transition, support **dual signatures**:
- `package.tar.gz.sig` (old key)
- `package.tar.gz.sig2` (new key)

Agents can verify with either key during the overlap period.

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

**Document Version**: 1.0.0
**Last Updated**: 2026-02-25
**Maintainer**: ClawSec Security Team
