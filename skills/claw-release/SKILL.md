---
name: claw-release
version: 0.0.3
description: Release automation for Claw skills and website. Guides through version bumping, tagging, and release verification.
homepage: https://clawsec.prompt.security
metadata: {"openclaw":{"emoji":"🚀","category":"utility","internal":true}}
clawdis:
  emoji: "🚀"
  requires:
    bins: [bash, git, jq, gh]
---

# Claw Release

Internal tool for releasing skills and managing the ClawSec catalog.

**An internal tool by [Prompt Security](https://prompt.security)**

---

## Operational Notes

- Internal maintainer workflow only.
- Required runtime: `bash`, `git`, `jq`, `gh`
- Required credentials: authenticated GitHub CLI with permission to create releases
- Side effects: creates commits, tags, pushes to remote, and publishes GitHub Releases
- Trust model: run only from a trusted checkout with a clean working tree and maintainer approval


## Release Artifact Verification

For standalone installs, verify the signed release manifest before trusting `SKILL.md`, `skill.json`, or the archive. The `skill.json` file is the package metadata/SBOM source, and the release pipeline signs `checksums.json` with the ClawSec release key.

```bash
set -euo pipefail

SKILL_NAME="claw-release"
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

## Quick Reference

| Release Type | Command | Tag Format |
|-------------|---------|------------|
| Skill release | `./scripts/release-skill.sh <name> <version>` | `<name>-v<version>` |
| Pre-release | `./scripts/release-skill.sh <name> 1.0.0-beta1` | `<name>-v1.0.0-beta1` |

---

## Release Workflow

### Step 1: Determine Version Type

Ask what changed:
- **Bug fixes only** → Patch (1.0.0 → 1.0.1)
- **New features, backward compatible** → Minor (1.0.0 → 1.1.0)
- **Breaking changes** → Major (1.0.0 → 2.0.0)
- **Testing/unstable** → Pre-release (1.0.0-beta1, 1.0.0-rc1)

### Step 2: Pre-flight Checks

```bash
# Check for uncommitted changes
git status

# Verify skill directory exists
ls skills/<skill-name>/skill.json

# Get current version
jq -r '.version' skills/<skill-name>/skill.json
```

### Step 3: Run Release Script

```bash
./scripts/release-skill.sh <skill-name> <new-version>
```

The script will:
1. Validate version format (semver)
2. Check tag doesn't already exist
3. Update skill.json version
4. Update SKILL.md frontmatter version (if file exists)
5. Update hardcoded version URLs (feed_url)
6. Commit changes
7. Create annotated git tag

### Step 4: Push Release

```bash
git push && git push origin <skill-name>-v<version>
```

### Step 5: Verify Release

After pushing, the CI/CD pipeline will:
1. Validate skill exists
2. Verify version matches skill.json
3. Verify version matches SKILL.md frontmatter (if exists)
4. Generate checksums from SBOM
5. Create .skill package (ZIP)
6. Create GitHub Release
7. Trigger website rebuild (for non-internal skills)

Verify at:
- **GitHub Releases:** `https://github.com/prompt-security/clawsec/releases/tag/<skill-name>-v<version>`
- **GitHub Actions:** Check workflow run status

---

## Undo a Release (Before Push)

If you need to undo before pushing:

```bash
git tag -d <skill-name>-v<version>
git reset --soft HEAD~1
```

`git reset --soft` preserves the release changes in your working tree so you can inspect or amend them without discarding data.

---

## Pre-release Versions

For beta, alpha, or release candidates:

```bash
./scripts/release-skill.sh <skill-name> 1.2.0-beta1
./scripts/release-skill.sh <skill-name> 1.2.0-alpha1
./scripts/release-skill.sh <skill-name> 1.2.0-rc1
```

Pre-releases are automatically marked in GitHub Releases.

---

## Common Issues

| Error | Solution |
|-------|----------|
| `Tag already exists` | Choose a different version number |
| `Version mismatch in CI` | Ensure you used the release script (not manual tagging) |
| `SKILL.md version mismatch` | Ensure you used the release script which updates both skill.json and SKILL.md |
| `Uncommitted changes` | Commit or stash first: `git stash` or `git add . && git commit` |
| `skill.json not found` | Verify skill directory path is correct |

---

## Internal Skills

Skills with `"internal": true` in their `openclaw` section:
- Are released normally via GitHub Releases
- Are NOT shown in the public skills catalog website
- Can still be downloaded directly from release URLs

This skill (`claw-release`) is an internal skill.

---

## Existing Skills

| Skill | Category | Internal |
|-------|----------|----------|
| clawsec-feed | security | No |
| clawtributor | security | No |
| openclaw-audit-watchdog | security | No |
| soul-guardian | security | No |
| claw-release | utility | Yes |

---

## Verification Checklist

After release, confirm:
- [ ] GitHub Release exists with correct tag
- [ ] Release has: skill.json, SKILL.md, checksums.json, .skill package
- [ ] Release is marked as pre-release if applicable
- [ ] GitHub Actions workflow completed successfully
- [ ] Website updated (for non-internal skills only)

---

## License

GNU AGPL v3.0 or later - See repository for details.

Built by the [Prompt Security](https://prompt.security) team.
