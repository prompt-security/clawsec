---
name: clawsec-feed
version: 0.0.5
description: Security advisory feed with automated NVD CVE polling for OpenClaw-related vulnerabilities. Use when checking for security advisories, looking up CVEs, monitoring vulnerability feeds, or verifying whether installed skills have known security issues.
homepage: https://clawsec.prompt.security
metadata: {"openclaw":{"emoji":"📡","category":"security"}}
clawdis:
  emoji: "📡"
  requires:
    bins: [curl, jq]
---

# ClawSec Feed 📡

Security advisory feed monitoring for AI agents. Subscribe to community-driven threat intelligence and stay informed about emerging threats.

This feed is automatically updated daily with CVEs related to OpenClaw, clawdbot, and Moltbot from the NIST National Vulnerability Database (NVD).

**An open source project by [Prompt Security](https://prompt.security)**

---

## Installation

**Bundled with ClawSec Suite:** If you installed clawsec-suite, clawsec-feed is already included at `~/.openclaw/skills/clawsec-feed/`.

**Standalone installation:** Follow the steps below if you only need the advisory feed.

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
1. Check advisory feed for new security alerts
2. Cross-reference with installed skills
3. Notify user if action is required
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

## Checking the Advisory Feed

```bash
# Use environment variable if set, otherwise use raw GitHub feed (always up-to-date)
DEFAULT_FEED_URL="https://raw.githubusercontent.com/prompt-security/ClawSec/main/advisories/feed.json"
FEED_URL="${CLAWSEC_FEED_URL:-$DEFAULT_FEED_URL}"

# Fetch with error handling and retry logic
curl -sSL --fail --show-error --retry 3 --retry-delay 1 "$FEED_URL"
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

All examples below assume `$FEED` contains the fetched JSON (see "Checking the Advisory Feed" above).

```bash
# Advisory count
echo "$FEED" | jq '.advisories | length'

# Critical advisories only
echo "$FEED" | jq '.advisories[] | select(.severity == "critical")'

# Advisories from the last 7 days
WEEK_AGO=$(TZ=UTC date -v-7d +%Y-%m-%dT00:00:00Z 2>/dev/null || TZ=UTC date -d '7 days ago' +%Y-%m-%dT00:00:00Z)
echo "$FEED" | jq --arg since "$WEEK_AGO" '.advisories[] | select(.published > $since)'
```

### Filter by exploitability score

Shared exploitability prioritization guidance is maintained in:

- [`wiki/exploitability-scoring.md`](../../wiki/exploitability-scoring.md)
- [`skills/clawsec-suite/SKILL.md`](../clawsec-suite/SKILL.md) ("Quick feed check")

### Get exploitability context for an advisory

```bash
# Show exploitability details for a specific CVE
CVE_ID="CVE-2026-27488"
echo "$FEED" | jq --arg cve "$CVE_ID" '.advisories[] | select(.id == $cve) | {
  id: .id,
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

## Cross-Reference Installed Skills

Check if any of your installed skills are affected by advisories:

Assumes `$FEED` is already fetched (see "Checking the Advisory Feed").

```bash
INSTALL_DIR="${CLAWSEC_INSTALL_DIR:-$HOME/.openclaw/skills}"
AFFECTED=$(echo "$FEED" | jq -r '.advisories[].affected[]?' 2>/dev/null | sort -u)

# Validate skill names to prevent shell injection
while IFS= read -r -d '' skill_path; do
  skill=$(basename "$skill_path")
  [[ "$skill" =~ ^[a-zA-Z0-9_-]+$ ]] || continue
  if echo "$AFFECTED" | grep -qF "$skill"; then
    echo "WARNING: Installed skill '$skill' has a security advisory!"
    echo "$FEED" | jq --arg s "$skill" '.advisories[] | select(.affected[] | contains($s))'
  fi
done < <(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
```

If affected skills are found, notify the user immediately for critical/high severity and include the recommended action.

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

## Severity and Exploitability

| Severity | Action | | Exploitability | Meaning |
|----------|--------|-|----------------|---------|
| `critical` | Notify immediately, take action | | `high` | Trivially exploitable with public tooling |
| `high` | Notify soon, plan remediation | | `medium` | Requires specific conditions |
| `medium` | Notify at next interaction | | `low` | Difficult to exploit or theoretical |
| `low` | Log for reference | | | |

Always prioritize by **both** severity and exploitability. A HIGH severity + HIGH exploitability CVE is more urgent than CRITICAL + LOW exploitability.

```bash
# Sort advisories by exploitability (critical → high → medium → low)
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

## Response Format

```
📡 ClawSec Feed: 2 new advisories since last check

CRITICAL - GA-2026-015: Malicious prompt pattern "ignore-all" (Exploitability: HIGH)
  → Action: Update your system prompt defenses.

HIGH - GA-2026-016: Vulnerable skill "data-helper" v1.2.0 (Exploitability: MEDIUM)
  → Action: Update to v1.2.1 or remove.
```

If nothing new: `FEED_OK - Advisory feed checked, no new alerts. 📡`

---

## State Tracking

Track the last feed check to identify new advisories:

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
DEFAULT_STATE='{"schema_version":"1.0","last_feed_check":null,"last_feed_updated":null,"known_advisories":[]}'

# Initialize if missing or corrupted
if [ ! -f "$STATE_FILE" ] || ! jq -e '.schema_version' "$STATE_FILE" >/dev/null 2>&1; then
  [ -f "$STATE_FILE" ] && cp "$STATE_FILE" "${STATE_FILE}.bak.$(TZ=UTC date +%Y%m%d%H%M%S)"
  echo "$DEFAULT_STATE" > "$STATE_FILE"
  chmod 600 "$STATE_FILE"
fi

# Update last check time (always use UTC)
jq --arg t "$(TZ=UTC date +%Y-%m-%dT%H:%M:%SZ)" '.last_feed_check = $t' "$STATE_FILE" | \
  sponge "$STATE_FILE" || echo "Error: Failed to update state file"
```

---

## Rate Limiting

To avoid excessive requests to the feed server, respect these minimum intervals:

| Check Type | Recommended Interval | Minimum Interval |
|------------|---------------------|------------------|
| Heartbeat check | Every 15-30 minutes | 5 minutes |
| Full feed refresh | Every 1-4 hours | 30 minutes |
| Cross-reference scan | Once per session | 5 minutes |

Compare `last_feed_check` from the state file against the current time before fetching.

---

## Environment Variables (Optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `CLAWSEC_FEED_URL` | Custom advisory feed URL | Raw GitHub (`main` branch) |
| `CLAWSEC_INSTALL_DIR` | Installation directory | `~/.openclaw/skills/clawsec-feed` |

---

## Updating ClawSec Feed

```bash
INSTALL_DIR="${CLAWSEC_INSTALL_DIR:-$HOME/.openclaw/skills/clawsec-feed}"
CURRENT=$(jq -r '.version' "$INSTALL_DIR/skill.json" 2>/dev/null || echo "unknown")
LATEST=$(curl -sSL https://api.github.com/repos/prompt-security/ClawSec/releases | \
  jq -r '[.[] | select(.tag_name | startswith("clawsec-feed-v"))][0].tag_name // empty' | \
  sed 's/clawsec-feed-v//')
echo "Installed: $CURRENT | Latest: $LATEST"
[ "$CURRENT" != "$LATEST" ] && echo "Update available! Re-run deployment steps."
```

---

## Related Skills

- **openclaw-audit-watchdog** - Automated daily security audits
- **clawtributor** - Report vulnerabilities to the community

---

## License

GNU AGPL v3.0 or later - See repository for details.

Built with 📡 by the [Prompt Security](https://prompt.security) team and the agent community.
