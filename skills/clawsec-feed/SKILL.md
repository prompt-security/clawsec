---
name: clawsec-feed
version: 0.0.12
description: Security advisory feed package for OpenClaw-related threats and vulnerabilities. The upstream feed is updated daily; local automation is handled by clawsec-suite or the operator.
homepage: https://clawsec.prompt.security
metadata: {"openclaw":{"emoji":"📡","category":"security"}}
clawdis:
  emoji: "📡"
  requires:
    bins: [bash, curl, jq, openssl, shasum, unzip]
---

# ClawSec Feed 📡

Security advisory feed monitoring for AI agents. Subscribe to community-driven threat intelligence and stay informed about emerging threats.

The default `feed.json` is the consolidated agent feed. It includes NVD CVEs, approved community advisories, and GitHub Security Advisories. When a GHSA matures into a CVE, the CVE becomes canonical and the GHSA remains in `aliases`; treat either identifier as the same advisory. A stale GHSA remains enforceable: `stale` describes identifier age, not risk expiration.

## Vercel Skills Installation

Install with the Vercel Skills CLI for this harness:

```bash
npx skills add prompt-security/clawsec --skill clawsec-feed -a openclaw -y
```

## Operational Notes

- Required runtime for standalone installation: `bash`, `curl`, `jq`, `openssl`, `shasum`, `unzip`
- Side effects: standalone install only writes local skill files
- Network behavior: downloads release metadata/artifacts and, if you choose to poll manually, fetches the advisory feed
- Trust model: this package does not itself create cron jobs or submit data externally; automation is delegated to `clawsec-suite` or your own scheduler

**An open source project by [Prompt Security](https://prompt.security)**

---

## Installation Options

You can get clawsec-feed in two ways:

### Option A: Bundled with ClawSec Suite (Recommended)

**If you've installed clawsec-suite, you may already have this!**

ClawSec-feed is bundled alongside ClawSec Suite to provide crucial CVE and threat intelligence information. When you install the suite, if you don't already have the feed installed, it will be deployed from the bundled copy.

**Advantages:**
- Convenient - no separate download needed
- Standard location - installed to `~/.openclaw/skills/clawsec-feed/`
- Preserved - if you already have feed installed, it won't be overwritten
- Single verification - integrity checked as part of suite package

### Option B: Standalone Installation (This Page)

Install clawsec-feed independently without the full suite.

**When to use standalone:**
- You only need the advisory feed (not other suite components)
- You want to install before installing the suite
- You prefer explicit control over feed installation

**Advantages:**
- Lighter weight installation
- Independent from suite
- Direct control over installation process

Continue below for standalone installation instructions.

Standalone installation is a network download workflow. Verify the release source and the provided checksums before installing it on production hosts.

---

Installation Steps:
Agents should review scripts before execution!

```bash
# Get latest clawsec-feed release tag
LATEST_TAG=$(curl -sSL https://api.github.com/repos/prompt-security/ClawSec/releases | \
  jq -r '[.[] | select(.tag_name | startswith("clawsec-feed-v"))][0].tag_name')

# Download SKILL.md from latest release
SKILL_URL="https://github.com/prompt-security/clawsec/releases/download/$LATEST_TAG/SKILL.md"
curl -sSL --fail --show-error "$SKILL_URL"
```

Once you have this skill file, proceed to **[Deploy ClawSec Feed](#deploy-clawsec-feed)** below.

---

## Release Artifact Verification

For standalone installs, verify the signed release manifest before trusting `SKILL.md`, `skill.json`, or the archive. The `skill.json` file is the package metadata/SBOM source, and the release pipeline signs `checksums.json` with the ClawSec release key.

```bash
set -euo pipefail

SKILL_NAME="clawsec-feed"
VERSION="0.0.12"
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

## Deploy ClawSec Feed

Installation steps:

### Step 1: Create skill directory and save this file

```bash
mkdir -p ~/.openclaw/skills/clawsec-feed
# Save this SKILL.md as SKILL.md in the directory above
```

### Step 2: Install skill files

```bash
# Get latest release tag with retry logic
LATEST_TAG=$(curl -sSL --retry 3 --retry-delay 1 \
  https://api.github.com/repos/prompt-security/ClawSec/releases | \
  jq -r '[.[] | select(.tag_name | startswith("clawsec-feed-v"))][0].tag_name')

BASE_URL="https://github.com/prompt-security/clawsec/releases/download/$LATEST_TAG"
INSTALL_DIR="${CLAWSEC_INSTALL_DIR:-$HOME/.openclaw/skills/clawsec-feed}"
TEMP_DIR=$(mktemp -d)
trap "rm -rf '$TEMP_DIR'" EXIT

# Download checksums.json (REQUIRED for integrity verification)
echo "Downloading checksums..."
if ! curl -sSL --fail --show-error --retry 3 --retry-delay 1 \
     "$BASE_URL/checksums.json" -o "$TEMP_DIR/checksums.json"; then
  echo "ERROR: Failed to download checksums.json"
  exit 1
fi

# Validate checksums.json structure
if ! jq -e '.skill and .version and .files' "$TEMP_DIR/checksums.json" >/dev/null 2>&1; then
  echo "ERROR: Invalid checksums.json structure"
  exit 1
fi

# PRIMARY: Try .skill artifact
echo "Attempting .skill artifact installation..."
if curl -sSL --fail --show-error --retry 3 --retry-delay 1 \
   "$BASE_URL/clawsec-feed.skill" -o "$TEMP_DIR/clawsec-feed.skill" 2>/dev/null; then

  # Security: Check artifact size (prevent DoS)
  ARTIFACT_SIZE=$(stat -c%s "$TEMP_DIR/clawsec-feed.skill" 2>/dev/null || stat -f%z "$TEMP_DIR/clawsec-feed.skill")
  MAX_SIZE=$((50 * 1024 * 1024))  # 50MB

  if [ "$ARTIFACT_SIZE" -gt "$MAX_SIZE" ]; then
    echo "WARNING: Artifact too large ($(( ARTIFACT_SIZE / 1024 / 1024 ))MB), falling back to individual files"
  else
    echo "Extracting artifact ($(( ARTIFACT_SIZE / 1024 ))KB)..."

    # Security: Check for path traversal before extraction
    if unzip -l "$TEMP_DIR/clawsec-feed.skill" | grep -qE '\.\./|^/|~/'; then
      echo "ERROR: Path traversal detected in artifact - possible security issue!"
      exit 1
    fi

    # Security: Check file count (prevent zip bomb)
    FILE_COUNT=$(unzip -l "$TEMP_DIR/clawsec-feed.skill" | grep -c "^[[:space:]]*[0-9]" || echo 0)
    if [ "$FILE_COUNT" -gt 100 ]; then
      echo "ERROR: Artifact contains too many files ($FILE_COUNT) - possible zip bomb"
      exit 1
    fi

    # Extract to temp directory
    unzip -q "$TEMP_DIR/clawsec-feed.skill" -d "$TEMP_DIR/extracted"

    # Verify skill.json exists
    if [ ! -f "$TEMP_DIR/extracted/clawsec-feed/skill.json" ]; then
      echo "ERROR: skill.json not found in artifact"
      exit 1
    fi

    # Verify checksums for all extracted files
    echo "Verifying checksums..."
    CHECKSUM_FAILED=0
    for file in $(jq -r '.files | keys[]' "$TEMP_DIR/checksums.json"); do
      EXPECTED=$(jq -r --arg f "$file" '.files[$f].sha256' "$TEMP_DIR/checksums.json")
      FILE_PATH=$(jq -r --arg f "$file" '.files[$f].path' "$TEMP_DIR/checksums.json")

      # Try nested path first, then flat filename
      if [ -f "$TEMP_DIR/extracted/clawsec-feed/$FILE_PATH" ]; then
        ACTUAL=$(shasum -a 256 "$TEMP_DIR/extracted/clawsec-feed/$FILE_PATH" | cut -d' ' -f1)
      elif [ -f "$TEMP_DIR/extracted/clawsec-feed/$file" ]; then
        ACTUAL=$(shasum -a 256 "$TEMP_DIR/extracted/clawsec-feed/$file" | cut -d' ' -f1)
      else
        echo "  ✗ $file (not found in artifact)"
        CHECKSUM_FAILED=1
        continue
      fi

      if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "  ✗ $file (checksum mismatch)"
        CHECKSUM_FAILED=1
      else
        echo "  ✓ $file"
      fi
    done

    if [ "$CHECKSUM_FAILED" -eq 0 ]; then
      # Validate feed.json structure (skill-specific)
      if [ -f "$TEMP_DIR/extracted/clawsec-feed/advisories/feed.json" ]; then
        FEED_FILE="$TEMP_DIR/extracted/clawsec-feed/advisories/feed.json"
      elif [ -f "$TEMP_DIR/extracted/clawsec-feed/feed.json" ]; then
        FEED_FILE="$TEMP_DIR/extracted/clawsec-feed/feed.json"
      else
        echo "ERROR: feed.json not found in artifact"
        exit 1
      fi

      if ! jq -e '.version and .advisories' "$FEED_FILE" >/dev/null 2>&1; then
        echo "ERROR: feed.json missing required fields (version, advisories)"
        exit 1
      fi

      # SUCCESS: Install from artifact
      echo "Installing from artifact..."
      mkdir -p "$INSTALL_DIR"
      cp -r "$TEMP_DIR/extracted/clawsec-feed"/* "$INSTALL_DIR/"
      chmod 600 "$INSTALL_DIR/skill.json"
      find "$INSTALL_DIR" -type f ! -name "skill.json" -exec chmod 644 {} \;
      echo "SUCCESS: Skill installed from .skill artifact"
      exit 0
    else
      echo "WARNING: Checksum verification failed, falling back to individual files"
    fi
  fi
fi

# FALLBACK: Download individual files
echo "Downloading individual files from checksums.json manifest..."
mkdir -p "$TEMP_DIR/downloads"

DOWNLOAD_FAILED=0
for file in $(jq -r '.files | keys[]' "$TEMP_DIR/checksums.json"); do
  FILE_URL=$(jq -r --arg f "$file" '.files[$f].url' "$TEMP_DIR/checksums.json")
  EXPECTED=$(jq -r --arg f "$file" '.files[$f].sha256' "$TEMP_DIR/checksums.json")

  echo "Downloading: $file"
  if ! curl -sSL --fail --show-error --retry 3 --retry-delay 1 \
       "$FILE_URL" -o "$TEMP_DIR/downloads/$file"; then
    echo "ERROR: Failed to download $file"
    DOWNLOAD_FAILED=1
    continue
  fi

  # Verify checksum immediately
  ACTUAL=$(shasum -a 256 "$TEMP_DIR/downloads/$file" | cut -d' ' -f1)
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "ERROR: Checksum mismatch for $file"
    DOWNLOAD_FAILED=1
  else
    echo "  ✓ Verified: $file"
  fi
done

if [ "$DOWNLOAD_FAILED" -eq 1 ]; then
  echo "ERROR: Individual file download failed"
  exit 1
fi

# Validate JSON files structure
if ! jq -e '.name and .version' "$TEMP_DIR/downloads/skill.json" >/dev/null 2>&1; then
  echo "ERROR: skill.json missing required fields (name, version)"
  exit 1
fi

if ! jq -e '.version and .advisories' "$TEMP_DIR/downloads/feed.json" >/dev/null 2>&1; then
  echo "ERROR: feed.json missing required fields (version, advisories)"
  exit 1
fi

# Install files
echo "Installing from individual files..."
mkdir -p "$INSTALL_DIR"
cp "$TEMP_DIR/downloads"/* "$INSTALL_DIR/"
chmod 600 "$INSTALL_DIR/skill.json"
find "$INSTALL_DIR" -type f ! -name "skill.json" -exec chmod 644 {} \;
echo "SUCCESS: Skill installed from individual files"
```

### Step 3: Add to your heartbeat

Add ClawSec Feed to your heartbeat routine:

```markdown
## ClawSec Feed (every heartbeat)
1. Verify and check the advisory feed for new security alerts.
2. Inventory installed skill versions and protected runtime/infrastructure versions: OpenClaw, NanoClaw, Hermes, Picoclaw, OpenShell, and NemoClaw.
3. Match the exact installed product and version against each `affected` selector.
4. Report matches, and report an installed product with an unknown version as indeterminate instead of safe.
5. Notify the user if action or version confirmation is required.
```

### Step 4: Confirm deployment

Tell your user:
```
ClawSec Feed deployed successfully. I will now:
- Monitor the community advisory feed for threats
- Alert you to any security issues affecting your environment
- Keep you informed of emerging attack patterns
```

---

## What ClawSec Feed Does

### Advisory Feed Monitoring

Subscribes to the community advisory feed for:

- **Known malicious skills/plugins** - Skills that have been identified as harmful
- **Prompt injection patterns** - Attack patterns observed in the wild
- **Vulnerable skill versions** - Skills with known security flaws
- **Vulnerable runtimes and infrastructure** - Agent runtimes, OpenShell sandboxes, and NemoClaw stacks with known security flaws
- **Security best practice updates** - New recommendations for agent safety

When a relevant advisory is published, your agent will notify you.

---

## Checking the Advisory Feed

```bash
# Download, authenticate, validate, and print the current feed.
# CLAWSEC_FEED_URL and CLAWSEC_FEED_SIG_URL may override the default endpoints;
# the signer must still match the pinned key shipped with this skill.
./scripts/fetch_verified_feed.sh
```

**Feed structure:**

```json
{
  "version": "1.0",
  "updated": "2026-02-02T12:00:00Z",
  "advisories": [
    {
      "id": "GA-2026-001",
      "severity": "critical",
      "type": "malicious_skill",
      "title": "Malicious data exfiltration in skill 'helper-plus'",
      "description": "Skill sends user data to external server",
      "affected": ["helper-plus@1.0.0", "helper-plus@1.0.1"],
      "action": "Remove immediately",
      "published": "2026-02-01T10:00:00Z",
      "exploitability_score": "critical",
      "exploitability_rationale": "Trivially exploitable through normal skill usage; no special conditions required. Active exploitation observed in the wild."
    }
  ]
}
```

---

## Parsing the Feed

### Get advisory count

```bash
TEMP_FEED=$(mktemp)
trap "rm -f '$TEMP_FEED'" EXIT

if ! ./scripts/fetch_verified_feed.sh > "$TEMP_FEED"; then
  echo "Error: Failed to fetch and verify advisory feed"
  exit 1
fi

# Validate JSON before parsing
if ! jq empty "$TEMP_FEED" 2>/dev/null; then
  echo "Error: Invalid JSON in feed"
  exit 1
fi

FEED=$(cat "$TEMP_FEED")

# Get advisory count with error handling
COUNT=$(echo "$FEED" | jq '.advisories | length')
if [ $? -ne 0 ]; then
  echo "Error: Failed to parse advisories"
  exit 1
fi
echo "Advisory count: $COUNT"
```

### Get critical advisories

```bash
# Parse critical advisories with jq error handling
CRITICAL=$(echo "$FEED" | jq '.advisories[] | select(.severity == "critical")')
if [ $? -ne 0 ]; then
  echo "Error: Failed to filter critical advisories"
  exit 1
fi
echo "$CRITICAL"
```

### Get advisories from the last 7 days

```bash
# Use UTC timezone for consistent date handling
WEEK_AGO=$(TZ=UTC date -v-7d +%Y-%m-%dT00:00:00Z 2>/dev/null || TZ=UTC date -d '7 days ago' +%Y-%m-%dT00:00:00Z)
RECENT=$(echo "$FEED" | jq --arg since "$WEEK_AGO" '.advisories[] | select(.published > $since)')
if [ $? -ne 0 ]; then
  echo "Error: Failed to filter recent advisories"
  exit 1
fi
echo "$RECENT"
```

### Filter by exploitability score

Shared exploitability prioritization guidance is maintained in:

- [`wiki/exploitability-scoring.md`](../../wiki/exploitability-scoring.md)
- [`skills/clawsec-suite/SKILL.md`](../clawsec-suite/SKILL.md) ("Quick feed check")

### Get exploitability context for an advisory

```bash
# Show exploitability details by canonical CVE or GHSA alias
ADVISORY_ID="CVE-2026-27488"
echo "$FEED" | jq --arg identifier "$ADVISORY_ID" '
  .advisories[]
  | select(
      ([.id, .cve_id, .ghsa_id] + (.ghsa_ids // []) + (.aliases // []))
      | map(select(type == "string") | ascii_upcase)
      | index($identifier | ascii_upcase)
    )
  | {
  id: .id,
  aliases: (.aliases // []),
  severity: .severity,
  exploitability_score: .exploitability_score,
  exploitability_rationale: .exploitability_rationale,
  title: .title
  }'
```

### Prioritize advisories by exploitability

```bash
# Sort advisories by exploitability (critical → high → medium → low)
# This helps agents focus on the most immediately actionable threats
echo "$FEED" | jq '[.advisories[] | select(.exploitability_score != null)] |
  sort_by(
    if .exploitability_score == "critical" then 0
    elif .exploitability_score == "high" then 1
    elif .exploitability_score == "medium" then 2
    elif .exploitability_score == "low" then 3
    else 4 end
  )'
```

---

## Decide Whether This Environment Is Affected

Use a read-only environment inventory before making an impact claim.

1. Inventory installed skill/package versions and the versions of OpenClaw, NanoClaw, Hermes, Picoclaw, OpenShell, and NemoClaw. Use trustworthy local evidence such as package manifests, lockfiles, deployment configuration, image labels/digests, or the component's own version command.
2. Read `affected` as exact `product@version-scope` selectors. Split on the final `@` so scoped package names remain intact. `platforms` routes an advisory to a protected component family; it is not proof that the component is installed.
3. Report **affected** only when the exact product is present and its version matches the selector. Report **not affected** when the product is absent or its known version is outside every selector.
4. If the product is present but its version cannot be established, report **indeterminate / possibly affected** and ask the user for the missing deployment detail. Never silently treat an unknown version as safe.
5. Treat `id`, `cve_id`, `ghsa_id`, `ghsa_ids`, and `aliases` as one stable advisory identity for state, suppression, links, and notifications. Do not re-alert solely because a GHSA became a CVE.
6. Keep stale GHSA records enforceable. ClawHub is a distribution channel, not a protected runtime or infrastructure component.

The standalone package cannot reliably discover every container, remote host, or custom installation. When the local inventory is incomplete, surface that limitation to the user instead of guessing.

## Cross-Reference Installed Skills

Check if any of your installed skills are affected by advisories:

```bash
# List your installed skills (adjust path for your platform)
INSTALL_DIR="${CLAWSEC_INSTALL_DIR:-$HOME/.openclaw/skills}"

TEMP_FEED=$(mktemp)
trap "rm -f '$TEMP_FEED'" EXIT

if ! ./scripts/fetch_verified_feed.sh > "$TEMP_FEED"; then
  echo "Error: Failed to fetch and verify advisory feed"
  exit 1
fi

# Validate and parse feed
if ! jq empty "$TEMP_FEED" 2>/dev/null; then
  echo "Error: Invalid JSON in feed"
  exit 1
fi

FEED=$(cat "$TEMP_FEED")
AFFECTED=$(echo "$FEED" | jq -r '
  .advisories[].affected[]?
  | select(type == "string")
  | (rindex("@") // -1) as $separator
  | if $separator > 0 then .[0:$separator] else . end
' 2>/dev/null | sort -u)
if [ $? -ne 0 ]; then
  echo "Error: Failed to parse affected skills from feed"
  exit 1
fi

# Safely validate all installed skills before processing
# This prevents shell injection via malicious filenames
VALIDATED_SKILLS=()
while IFS= read -r -d '' skill_path; do
  skill=$(basename "$skill_path")

  # Validate skill name BEFORE adding to array (prevents injection)
  if [[ "$skill" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    VALIDATED_SKILLS+=("$skill")
  else
    echo "Warning: Skipping invalid skill name: $skill" >&2
  fi
done < <(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)

# Candidate-name scan only. Resolve the installed version and evaluate the
# advisory's version scope before declaring the skill affected.
# Use exact fixed-string matching (prevents regex injection and substring collisions)
for skill in "${VALIDATED_SKILLS[@]}"; do
  # At this point, $skill is guaranteed to match ^[a-zA-Z0-9_-]+$
  if echo "$AFFECTED" | grep -qxF "$skill"; then
    echo "REVIEW: Installed skill '$skill' is named by an advisory; evaluate its version scope."
    # Get candidate advisory details for this skill
    echo "$FEED" | jq --arg s "$skill" '
      .advisories[]
      | select(any(.affected[]?;
          (rindex("@") // -1) as $separator
          | (if $separator > 0 then .[0:$separator] else . end) == $s
        ))
    '
  fi
done
```

**If you find candidate skills:**
1. Resolve the installed version and evaluate the advisory range.
2. Check the advisory details and severity.
3. Notify your user immediately for confirmed critical/high matches.
4. Include the recommended action from the advisory.

---

## Advisory Types

| Type | Description |
|------|-------------|
| `malicious_skill` | Skill identified as intentionally harmful |
| `vulnerable_skill` | Skill with security vulnerabilities |
| `prompt_injection` | Known prompt injection pattern |
| `attack_pattern` | Observed attack technique |
| `best_practice` | Security recommendation |

---

## Severity Levels

| Severity | Action Required |
|----------|-----------------|
| `critical` | Notify user immediately, take action |
| `high` | Notify user soon, plan remediation |
| `medium` | Notify at next interaction |
| `low` | Log for reference |

---

## Prioritizing High-Exploitability Threats

**IMPORTANT:** When reviewing advisories, always prioritize by **exploitability score** in addition to severity. The exploitability score indicates how easily a vulnerability can be exploited in practice, helping you focus on the most actionable threats.

### Exploitability Priority Levels

| Exploitability | Meaning | Action Priority |
|----------------|---------|-----------------|
| `high` | Trivially or easily exploitable with public tooling | **Immediate notification** |
| `medium` | Exploitable but requires specific conditions | **Standard notification** |
| `low` | Difficult to exploit or theoretical | **Low priority notification** |

### How to Use Exploitability in Notifications

1. **Filter for high-exploitability first:**
   ```bash
   # Get high exploitability advisories
   echo "$FEED" | jq '.advisories[] | select(.exploitability_score == "high")'
   ```

2. **Include exploitability in notifications:**
   ```
   📡 ClawSec Feed: High-exploitability alert

   CRITICAL - CVE-2026-27488 (Exploitability: HIGH)
     → Trivially exploitable RCE in skill-loader v2.1.0
     → Public exploit code available
     → Recommended action: Immediate removal or upgrade to v2.1.1
   ```

3. **Prioritize by both severity AND exploitability:**
   - A HIGH severity + HIGH exploitability CVE is more urgent than a CRITICAL severity + LOW exploitability CVE
   - Focus user attention on threats that are both severe and easily exploitable
   - Include the exploitability rationale to help users understand the risk context

### Example Notification Priority Order

When multiple advisories exist, present them in this order:
1. **Critical severity + High exploitability** - most urgent
2. **High severity + High exploitability**
3. **Critical severity + Medium/Low exploitability**
4. **High severity + Medium/Low exploitability**
5. **Medium/Low severity** (any exploitability)

This ensures you alert users to the most actionable, immediately dangerous threats first.

---

## When to Notify Your User

**Notify Immediately (Critical):**
- New critical advisory affecting an installed skill
- Active exploitation detected
- **High exploitability score** (regardless of severity)

**Notify Soon (High):**
- New high-severity advisory affecting installed skills
- Failed to fetch advisory feed (network issue?)
- Medium exploitability with high severity

**Notify at Next Interaction (Medium):**
- New medium-severity advisories
- General security updates
- Low exploitability advisories

**Log Only (Low/Info):**
- Low-severity advisories (mention if user asks)
- Feed checked, no new advisories
- Theoretical vulnerabilities (low exploitability, low severity)

---

## Response Format

### If there are new advisories:

```
📡 ClawSec Feed: 2 new advisories since last check

CRITICAL - GA-2026-015: Malicious prompt pattern "ignore-all" (Exploitability: HIGH)
  → Detected prompt injection technique. Update your system prompt defenses.
  → Exploitability: Easily exploitable with publicly documented techniques.

HIGH - GA-2026-016: Vulnerable skill "data-helper" v1.2.0 (Exploitability: MEDIUM)
  → You have this installed! Recommended action: Update to v1.2.1 or remove.
  → Exploitability: Requires specific configuration; not trivially exploitable.
```

### If nothing new:

```
FEED_OK - Advisory feed checked, no new alerts. 📡
```

---

## State Tracking

Track the last feed check to identify new advisories:

For each advisory, store every stable identifier from `id`, `cve_id`, `ghsa_id`, `ghsa_ids`, and `aliases`. Consider the advisory already known when any identifier is known, then backfill the rest. This prevents a GHSA-to-CVE transition from creating a duplicate alert.

```json
{
  "schema_version": "1.0",
  "last_feed_check": "2026-02-02T15:00:00Z",
  "last_feed_updated": "2026-02-02T12:00:00Z",
  "known_advisories": ["GA-2026-001", "GA-2026-002"]
}
```

Save to: `~/.openclaw/clawsec-feed-state.json`

### State File Operations

```bash
STATE_FILE="$HOME/.openclaw/clawsec-feed-state.json"

# Create state file with secure permissions if it doesn't exist
if [ ! -f "$STATE_FILE" ]; then
  echo '{"schema_version":"1.0","last_feed_check":null,"last_feed_updated":null,"known_advisories":[]}' > "$STATE_FILE"
  chmod 600 "$STATE_FILE"
fi

# Validate state file before reading
if ! jq -e '.schema_version' "$STATE_FILE" >/dev/null 2>&1; then
  echo "Warning: State file corrupted or invalid schema. Creating backup and resetting."
  cp "$STATE_FILE" "${STATE_FILE}.bak.$(TZ=UTC date +%Y%m%d%H%M%S)"
  echo '{"schema_version":"1.0","last_feed_check":null,"last_feed_updated":null,"known_advisories":[]}' > "$STATE_FILE"
  chmod 600 "$STATE_FILE"
fi

# Check for major version compatibility
SCHEMA_VER=$(jq -r '.schema_version // "0"' "$STATE_FILE")
if [[ "${SCHEMA_VER%%.*}" != "1" ]]; then
  echo "Warning: State file schema version $SCHEMA_VER may not be compatible with this version"
fi

# Update last check time (always use UTC)
TEMP_STATE=$(mktemp)
if jq --arg t "$(TZ=UTC date +%Y-%m-%dT%H:%M:%SZ)" '.last_feed_check = $t' "$STATE_FILE" > "$TEMP_STATE"; then
  mv "$TEMP_STATE" "$STATE_FILE"
  chmod 600 "$STATE_FILE"
else
  echo "Error: Failed to update state file"
  rm -f "$TEMP_STATE"
fi
```

---

## Rate Limiting

**Important:** To avoid excessive requests to the feed server, follow these guidelines:

| Check Type | Recommended Interval | Minimum Interval |
|------------|---------------------|------------------|
| Heartbeat check | Every 15-30 minutes | 5 minutes |
| Full feed refresh | Every 1-4 hours | 30 minutes |
| Cross-reference scan | Once per session | 5 minutes |

```bash
# Check if enough time has passed since last check
STATE_FILE="$HOME/.openclaw/clawsec-feed-state.json"
MIN_INTERVAL_SECONDS=300  # 5 minutes

LAST_CHECK=$(jq -r '.last_feed_check // "1970-01-01T00:00:00Z"' "$STATE_FILE" 2>/dev/null)
LAST_EPOCH=$(TZ=UTC date -j -f "%Y-%m-%dT%H:%M:%SZ" "$LAST_CHECK" +%s 2>/dev/null || date -d "$LAST_CHECK" +%s 2>/dev/null || echo 0)
NOW_EPOCH=$(TZ=UTC date +%s)

if [ $((NOW_EPOCH - LAST_EPOCH)) -lt $MIN_INTERVAL_SECONDS ]; then
  echo "Rate limit: Last check was less than 5 minutes ago. Skipping."
  exit 0
fi
```

---

## Environment Variables (Optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `CLAWSEC_FEED_URL` | Custom advisory feed URL | Consolidated signed feed |
| `CLAWSEC_INSTALL_DIR` | Installation directory | `~/.openclaw/skills/clawsec-feed` |

---

## Updating ClawSec Feed

Check for and install newer versions:

```bash
# Check current installed version
INSTALL_DIR="${CLAWSEC_INSTALL_DIR:-$HOME/.openclaw/skills/clawsec-feed}"
CURRENT_VERSION=$(jq -r '.version' "$INSTALL_DIR/skill.json" 2>/dev/null || echo "unknown")
echo "Installed version: $CURRENT_VERSION"

# Check latest available version
LATEST_URL="https://api.github.com/repos/prompt-security/ClawSec/releases"
LATEST_VERSION=$(curl -sSL --fail --show-error --retry 3 --retry-delay 1 "$LATEST_URL" 2>/dev/null | \
  jq -r '[.[] | select(.tag_name | startswith("clawsec-feed-v"))][0].tag_name // empty' | \
  sed 's/clawsec-feed-v//')

if [ -z "$LATEST_VERSION" ]; then
  echo "Warning: Could not determine latest version"
else
  echo "Latest version: $LATEST_VERSION"

  if [ "$CURRENT_VERSION" != "$LATEST_VERSION" ]; then
    echo "Update available! Run the deployment steps with the new version."
  else
    echo "You are running the latest version."
  fi
fi
```

---

## Initial Download Integrity

**Bootstrap Trust Problem:** The initial download of this skill cannot be verified by the skill itself. To establish trust:

1. **Verify the source URL** - Ensure you are downloading from `https://clawsec.prompt.security`
2. **Check release signatures** - GitHub signs our releases; verify the release is from the checksums.
3. **Compare checksums** - After download, compare the SHA-256 hash against the published `checksums.json`:

```bash
# After downloading SKILL.md, verify its integrity
EXPECTED_HASH="<hash-from-checksums.json>"
ACTUAL_HASH=$(shasum -a 256 SKILL.md | cut -d' ' -f1)

if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
  echo "ERROR: Skill file integrity check failed!"
  echo "This file may have been tampered with. Do not proceed."
  exit 1
fi
```

**Note:** For maximum security, verify checksums.json via a separate trusted channel (e.g., direct from GitHub release page UI, not via curl).

---

## Related Skills

- **openclaw-audit-watchdog** - Automated daily security audits
- **clawtributor** - Report vulnerabilities to the community

---

## License

GNU AGPL v3.0 or later - See repository for details.

Built with 📡 by the [Prompt Security](https://prompt.security) team and the agent community.
