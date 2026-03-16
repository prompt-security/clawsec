---
name: clawsec-suite
version: 0.1.4
description: ClawSec suite manager with embedded advisory-feed monitoring and guided setup for security skills. Use when setting up agent security, checking advisory feeds, installing security skills, verifying skill signatures, or managing the ClawSec security suite.
homepage: https://clawsec.prompt.security
clawdis:
  emoji: "📦"
  requires:
    bins: [curl, jq, shasum, openssl]
---

# ClawSec Suite

ClawSec Suite is the central management entrypoint for ClawSec security protections. It monitors the ClawSec advisory feed, tracks new advisories, cross-references them against locally installed skills, recommends removal for malicious-skill advisories (with explicit user approval), and provides guided setup for additional security skills.

## Included vs Optional Protections

### Built into clawsec-suite
- Embedded feed seed file: `advisories/feed.json`
- Portable heartbeat workflow in `HEARTBEAT.md`
- Advisory polling + state tracking + affected-skill checks
- OpenClaw advisory guardian hook package: `hooks/clawsec-advisory-guardian/`
- Setup scripts for hook and optional cron scheduling: `scripts/`
- Guarded installer: `scripts/guarded_skill_install.mjs`
- Dynamic catalog discovery for installable skills: `scripts/discover_skill_catalog.mjs`

### Installed separately (dynamic catalog)
`clawsec-suite` does not hard-code add-on skill names in this document.

Discover the current catalog from the authoritative index (`https://clawsec.prompt.security/skills/index.json`) at runtime:

```bash
SUITE_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-suite"
node "$SUITE_DIR/scripts/discover_skill_catalog.mjs"
```

Fallback behavior:
- If the remote catalog index is reachable and valid, the suite uses it.
- If the remote index is unavailable or malformed, the script falls back to suite-local catalog metadata in `skill.json`.

## Installation

### Cross-shell path note

- In `bash`/`zsh`, keep path variables expandable (for example, `INSTALL_ROOT="$HOME/.openclaw/skills"`).
- Do not single-quote home-variable paths (avoid `'$HOME/.openclaw/skills'`).
- In PowerShell, set an explicit path:
  - `$env:INSTALL_ROOT = Join-Path $HOME ".openclaw\\skills"`
- If a path is passed with unresolved tokens (like `\$HOME/...`), suite scripts now fail fast with a clear error.

### Option A: Via clawhub (recommended)

```bash
npx clawhub@latest install clawsec-suite
```

### Option B: Manual download with signature + checksum verification

For manual installation, download the release archive from GitHub Releases and verify integrity before installing:

1. Set `SKILL_VERSION` and download `clawsec-suite-v${VERSION}.zip`, `checksums.json`, and `checksums.sig` from the release URL.
2. Verify the Ed25519 signature on `checksums.json` using the pinned release-signing public key (fingerprint: `711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8`).
3. Verify the archive SHA-256 hash matches `checksums.json`.
4. Extract to `$INSTALL_ROOT/clawsec-suite` and set permissions (`chmod 600 skill.json`).

See the [clawsec-scanner SKILL.md](../clawsec-scanner/SKILL.md) for a full verification script example using the same signing key.

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
- consider advisories with `application: "openclaw"` (and legacy entries without `application` for backward compatibility),
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
- If `--version` is omitted, matching is conservative: any advisory that references the skill name is treated as a match.
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

- Remote feed URL: `https://clawsec.prompt.security/advisories/feed.json`
- Remote feed signature URL: `${CLAWSEC_FEED_URL}.sig` (override with `CLAWSEC_FEED_SIG_URL`)
- Remote checksums manifest URL: sibling `checksums.json` (override with `CLAWSEC_FEED_CHECKSUMS_URL`)
- Local seed fallback: `~/.openclaw/skills/clawsec-suite/advisories/feed.json`
- Local feed signature: `${CLAWSEC_LOCAL_FEED}.sig` (override with `CLAWSEC_LOCAL_FEED_SIG`)
- Local checksums manifest: `~/.openclaw/skills/clawsec-suite/advisories/checksums.json`
- Pinned feed signing key: `~/.openclaw/skills/clawsec-suite/advisories/feed-signing-public.pem` (override with `CLAWSEC_FEED_PUBLIC_KEY`)
- State file: `~/.openclaw/clawsec-suite-feed-state.json`
- Hook rate-limit env (OpenClaw hook): `CLAWSEC_HOOK_INTERVAL_SECONDS` (default `300`)

**Fail-closed verification:** Feed signatures are required by default. Checksum manifests are verified when companion checksum artifacts are available. Set `CLAWSEC_ALLOW_UNSIGNED_FEED=1` only as a temporary migration bypass when adopting this version before signed feed artifacts are available upstream.

### Quick feed check

```bash
FEED_URL="${CLAWSEC_FEED_URL:-https://clawsec.prompt.security/advisories/feed.json}"
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
    jq -r --arg id "$id" '.advisories[] | select(.id == $id) | "  Exploitability: \(.exploitability_score // "unknown" | ascii_upcase)"' "$TMP/feed.json"
  done < "$NEW_IDS_FILE"
else
  echo "FEED_OK - no new advisories"
fi
```

## Exploitability Context

Advisories in the feed can include `exploitability_score` and `exploitability_rationale` fields to help agents prioritize real-world threats:

- **Exploitability scores**: `high`, `medium`, `low`, or `unknown`
- **Context-aware assessment**: Considers attack vector, authentication requirements, and AI agent deployment patterns
- **Exploit availability**: Detects public exploits and weaponization status

When processing advisories, prioritize by exploitability in addition to severity. A HIGH severity + HIGH exploitability CVE is more urgent than a CRITICAL severity + LOW exploitability CVE.

For detailed methodology, see the [exploitability scoring documentation](../../wiki/exploitability-scoring.md).

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

## Advisory Suppression / Allowlist

The advisory guardian pipeline supports opt-in suppression for advisories that have been reviewed and accepted by your security team. This is useful for first-party tooling or advisories that do not apply to your deployment.

### Activation

Advisory suppression requires a single gate: the configuration file must contain `"enabledFor"` with `"advisory"` in the array. No CLI flag is needed -- the sentinel in the config file IS the opt-in gate.

If the `enabledFor` array is missing, empty, or does not include `"advisory"`, all advisories are reported normally.

### Config File Resolution (4-tier)

The advisory guardian resolves the suppression config using the same priority order as the audit pipeline:

1. Explicit `--config <path>` argument
2. `OPENCLAW_AUDIT_CONFIG` environment variable
3. `~/.openclaw/security-audit.json`
4. `.clawsec/allowlist.json`

### Config Format

```json
{
  "enabledFor": ["advisory"],
  "suppressions": [
    {
      "checkId": "CVE-2026-25593",
      "skill": "clawsec-suite",
      "reason": "First-party security tooling — reviewed by security team",
      "suppressedAt": "2026-02-15"
    },
    {
      "checkId": "CLAW-2026-0001",
      "skill": "example-skill",
      "reason": "Advisory does not apply to our deployment configuration",
      "suppressedAt": "2026-02-16"
    }
  ]
}
```

### Sentinel Semantics

- `"enabledFor": ["advisory"]` -- only advisory suppression active
- `"enabledFor": ["audit"]` -- only audit suppression active (no effect on advisory pipeline)
- `"enabledFor": ["audit", "advisory"]` -- both pipelines honor suppressions
- Missing or empty `enabledFor` -- no suppression active (safe default)

### Matching Rules

- **checkId:** exact match against the advisory ID (e.g., `CVE-2026-25593` or `CLAW-2026-0001`)
- **skill:** case-insensitive match against the affected skill name from the advisory
- Both fields must match for an advisory to be suppressed

### Required Fields per Suppression Entry

| Field | Description | Example |
|-------|-------------|---------|
| `checkId` | Advisory ID to suppress | `CVE-2026-25593` |
| `skill` | Affected skill name | `clawsec-suite` |
| `reason` | Justification for audit trail (required) | `First-party tooling, reviewed by security team` |
| `suppressedAt` | ISO 8601 date (YYYY-MM-DD) | `2026-02-15` |

### Shared Config with Audit Pipeline

The advisory and audit pipelines share the same config file. Use the `enabledFor` array to control which pipelines honor the suppression list. Audit entries (with check identifiers like `skills.code_safety`) are only matched by the audit pipeline. Advisory entries (with advisory IDs like `CVE-2026-25593` or `CLAW-2026-0001`) are only matched by the advisory pipeline.

## Optional Skill Installation

Discover currently available installable skills dynamically, then install the ones you want:

```bash
SUITE_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-suite"
node "$SUITE_DIR/scripts/discover_skill_catalog.mjs"

# then install any discovered skill by name
npx clawhub@latest install <skill-name>
```

Machine-readable output is also available for automation:

```bash
node "$SUITE_DIR/scripts/discover_skill_catalog.mjs" --json
```

## Security Notes

- Always verify `checksums.json` signature before trusting its file URLs/hashes, then verify each file checksum.
- Verify advisory feed detached signatures; do not enable `CLAWSEC_ALLOW_UNSIGNED_FEED` outside temporary migration windows.
- Keep advisory polling rate-limited (at least 5 minutes between checks).
- Treat `critical` and `high` advisories affecting installed skills as immediate action items.
- If you migrate off standalone `clawsec-feed`, keep one canonical state file to avoid duplicate notifications.
- Pin and verify public key fingerprints out-of-band before first use.
