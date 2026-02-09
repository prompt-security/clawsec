---
name: clawsec-suite
version: 0.0.9
description: ClawSec suite manager with embedded advisory-feed monitoring, approval-gated malicious-skill response, and guided setup for additional security skills.
homepage: https://clawsec.prompt.security
clawdis:
  emoji: "📦"
  requires:
    bins: [curl, jq, shasum]
---

# ClawSec Suite

This means `clawsec-suite` can:
- monitor the ClawSec advisory feed,
- track which advisories are new since last check,
- cross-reference advisories against locally installed skills,
- recommend removal for malicious-skill advisories and require explicit user approval first,
- and still act as the setup/management entrypoint for other ClawSec protections.

## Included vs Optional Protections

### Built into clawsec-suite
- Embedded feed seed file: `advisories/feed.json`
- Portable heartbeat workflow in `HEARTBEAT.md`
- Advisory polling + state tracking + affected-skill checks
- OpenClaw advisory guardian hook package: `hooks/clawsec-advisory-guardian/`
- Setup scripts for hook and optional cron scheduling: `scripts/`
- Guarded installer: `scripts/guarded_skill_install.mjs`

### installed separately
- `openclaw-audit-watchdog`
- `soul-guardian`
- `clawtributor` (explicit opt-in)

## Installation

### Option A: Via clawhub (recommended)

```bash
npx clawhub@latest install clawsec-suite
```

### Option B: Manual download with verification

```bash
set -euo pipefail

VERSION="${SKILL_VERSION:?Set SKILL_VERSION (e.g. 0.0.8)}"
INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.openclaw/skills}"
DEST="$INSTALL_ROOT/clawsec-suite"
BASE="https://github.com/prompt-security/clawsec/releases/download/clawsec-suite-v${VERSION}"

TEMP_DIR="$(mktemp -d)"
DOWNLOAD_DIR="$TEMP_DIR/downloads"
trap 'rm -rf "$TEMP_DIR"' EXIT
mkdir -p "$DOWNLOAD_DIR"

# 1) Download checksums manifest
curl -fsSL "$BASE/checksums.json" -o "$TEMP_DIR/checksums.json"
if ! jq -e '.skill and .version and .files' "$TEMP_DIR/checksums.json" >/dev/null 2>&1; then
  echo "ERROR: Invalid checksums.json format" >&2
  exit 1
fi

# 2) Download every file listed in checksums and verify immediately
DOWNLOAD_FAILED=0
for file in $(jq -r '.files | keys[]' "$TEMP_DIR/checksums.json"); do
  FILE_URL="$(jq -r --arg f "$file" '.files[$f].url' "$TEMP_DIR/checksums.json")"
  EXPECTED="$(jq -r --arg f "$file" '.files[$f].sha256' "$TEMP_DIR/checksums.json")"

  if ! curl -fsSL "$FILE_URL" -o "$DOWNLOAD_DIR/$file"; then
    echo "ERROR: Download failed for $file" >&2
    DOWNLOAD_FAILED=1
    continue
  fi

  if command -v shasum >/dev/null 2>&1; then
    ACTUAL="$(shasum -a 256 "$DOWNLOAD_DIR/$file" | awk '{print $1}')"
  else
    ACTUAL="$(sha256sum "$DOWNLOAD_DIR/$file" | awk '{print $1}')"
  fi

  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "ERROR: Checksum mismatch for $file" >&2
    DOWNLOAD_FAILED=1
  else
    echo "Verified: $file"
  fi
done

if [ "$DOWNLOAD_FAILED" -eq 1 ]; then
  echo "ERROR: One or more files failed verification" >&2
  exit 1
fi

# 3) Install files using paths from checksums.json
while IFS= read -r file; do
  [ -z "$file" ] && continue
  REL_PATH="$(jq -r --arg f "$file" '.files[$f].path // $f' "$TEMP_DIR/checksums.json")"
  SRC_PATH="$DOWNLOAD_DIR/$file"
  DST_PATH="$DEST/$REL_PATH"

  mkdir -p "$(dirname "$DST_PATH")"
  cp "$SRC_PATH" "$DST_PATH"
done < <(jq -r '.files | keys[]' "$TEMP_DIR/checksums.json")

chmod 600 "$DEST/skill.json"
find "$DEST" -type f ! -name "skill.json" -exec chmod 644 {} \;

echo "Installed clawsec-suite v${VERSION} to: $DEST"
echo "Next step (OpenClaw): node \"$DEST/scripts/setup_advisory_hook.mjs\""
```

## OpenClaw Automation (Hook + Optional Cron)

After installing the suite, enable the advisory guardian hook:

```bash
SUITE_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-suite"
node "$SUITE_DIR/scripts/setup_advisory_hook.mjs"
```

Optional: create/update a periodic cron nudge (default every `6h`) that triggers a main-session advisory scan:

```bash
SUITE_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-suite"
node "$SUITE_DIR/scripts/setup_advisory_cron.mjs"
```

What this adds:
- scan on `agent:bootstrap` and `/new` (`command:new`),
- compare advisory `affected` entries against installed skills,
- notify when new matches appear,
- and ask for explicit user approval before any removal flow.

Restart the OpenClaw gateway after enabling the hook. Then run `/new` once to force an immediate scan in the next session context.

## Guarded Skill Install Flow (Double Confirmation)

When the user asks to install a skill, treat that as the first request and run a guarded install check:

```bash
SUITE_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-suite"
node "$SUITE_DIR/scripts/guarded_skill_install.mjs" --skill helper-plus --version 1.0.1
```

Behavior:
- If no advisory match is found, install proceeds.
- If advisory match is found, the script prints advisory context and exits with code `42`.
- Then require an explicit second confirmation from the user and rerun with `--confirm-advisory`:

```bash
node "$SUITE_DIR/scripts/guarded_skill_install.mjs" --skill helper-plus --version 1.0.1 --confirm-advisory
```

This enforces:
1. First confirmation: user asked to install.
2. Second confirmation: user explicitly approves install after seeing advisory details.

## Embedded Advisory Feed Behavior

The embedded feed logic uses these defaults:

- Remote feed URL: `https://raw.githubusercontent.com/prompt-security/clawsec/main/advisories/feed.json`
- Local seed fallback: `~/.openclaw/skills/clawsec-suite/advisories/feed.json`
- State file: `~/.openclaw/clawsec-suite-feed-state.json`
- Hook rate-limit env (OpenClaw hook): `CLAWSEC_HOOK_INTERVAL_SECONDS` (default `300`)

### Quick feed check

```bash
FEED_URL="${CLAWSEC_FEED_URL:-https://raw.githubusercontent.com/prompt-security/clawsec/main/advisories/feed.json}"
STATE_FILE="${CLAWSEC_SUITE_STATE_FILE:-$HOME/.openclaw/clawsec-suite-feed-state.json}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! curl -fsSLo "$TMP/feed.json" "$FEED_URL"; then
  echo "ERROR: Failed to fetch advisory feed"
  exit 1
fi

if ! jq -e '.version and (.advisories | type == "array")' "$TMP/feed.json" >/dev/null; then
  echo "ERROR: Invalid advisory feed format"
  exit 1
fi

mkdir -p "$(dirname "$STATE_FILE")"
if [ ! -f "$STATE_FILE" ]; then
  echo '{"schema_version":"1.0","known_advisories":[],"last_feed_check":null,"last_feed_updated":null}' > "$STATE_FILE"
  chmod 600 "$STATE_FILE"
fi

NEW_IDS_FILE="$TMP/new_ids.txt"
jq -r --argfile state "$STATE_FILE" '($state.known_advisories // []) as $known | [.advisories[]?.id | select(. != null and ($known | index(.) | not))] | .[]?' "$TMP/feed.json" > "$NEW_IDS_FILE"

if [ -s "$NEW_IDS_FILE" ]; then
  echo "New advisories detected:"
  while IFS= read -r id; do
    [ -z "$id" ] && continue
    jq -r --arg id "$id" '.advisories[] | select(.id == $id) | "- [\(.severity | ascii_upcase)] \(.id): \(.title)"' "$TMP/feed.json"
  done < "$NEW_IDS_FILE"
else
  echo "FEED_OK - no new advisories"
fi
```

## Heartbeat Integration

Use the suite heartbeat script as the single periodic security check entrypoint:

- `skills/clawsec-suite/HEARTBEAT.md`

It handles:
- suite update checks,
- feed polling,
- new-advisory detection,
- affected-skill cross-referencing,
- approval-gated response guidance for malicious/removal advisories,
- and persistent state updates.

## Approval-Gated Response Contract

If an advisory indicates a malicious or removal-recommended skill and that skill is installed:

1. Notify the user immediately with advisory details and severity.
2. Recommend removing or disabling the affected skill.
3. Treat the original install request as first intent only.
4. Ask for explicit second confirmation before deletion/disable action (or before proceeding with risky install).
5. Only proceed after that second confirmation.

The suite hook and heartbeat guidance are intentionally non-destructive by default.

## Optional Skill Installation

Install additional protections as needed:

```bash
npx clawhub@latest install openclaw-audit-watchdog
npx clawhub@latest install soul-guardian
# opt-in only:
npx clawhub@latest install clawtributor
```

## Security Notes

- Always verify checksums before installing files manually.
- Keep advisory polling rate-limited (at least 5 minutes between checks).
- Treat `critical` and `high` advisories affecting installed skills as immediate action items.
- If you migrate off standalone `clawsec-feed`, keep one canonical state file to avoid duplicate notifications.
