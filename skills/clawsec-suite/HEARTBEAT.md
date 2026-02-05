# ClawSec Suite — Cron Check

Run this on a schedule (cron/systemd/CI/agent scheduler). It is written to be portable: it assumes only POSIX shell + curl + a SHA tool.

## Goals

1) Check whether ClawSec Suite has an update available
2) Verify integrity of the installed suite package

> Design note: Uses the **checksums.json** file from the latest release, which contains version info and SHA256 hashes. Avoids reliance on a separate catalog manifest.

---

## Configuration

```bash
INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.openclaw/skills}"
SUITE_DIR="$INSTALL_ROOT/clawsec-suite"
CHECKSUMS_URL="${CHECKSUMS_URL:-https://clawsec.prompt.security/releases/latest/download/checksums.json}"
```

---

## Step 0 — Basic sanity

```bash
set -euo pipefail

test -d "$SUITE_DIR"
test -f "$SUITE_DIR/skill.json"

echo "=== ClawSec update Check ==="
echo "When: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Where: $SUITE_DIR"
```

---

## Step 1 — Verify the currently installed suite files (local integrity)

This step is only meaningful if you ship a checksums file *inside* the suite directory (recommended).

If present, verify it:

```bash
if [ -f "$SUITE_DIR/checksums.txt" ]; then
  echo "Verifying local checksums.txt"
  cd "$SUITE_DIR"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c checksums.txt
  else
    sha256sum -c checksums.txt
  fi
else
  echo "NOTE: No local checksums.txt shipped; skipping local integrity verification"
fi
```

---

## Step 1.5 — Verify Bundled Components

Check that bundled security skills are properly deployed:

```bash
INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.openclaw/skills}"
SUITE_DIR="$INSTALL_ROOT/clawsec-suite"

# Function to check bundled skill
check_bundled_skill() {
  local skill_name="$1"
  local skill_dir="$INSTALL_ROOT/$skill_name"
  local bundled_dir="$SUITE_DIR/bundled/$skill_name"

  if [ -d "$skill_dir" ] && [ -f "$skill_dir/skill.json" ]; then
    SKILL_VERSION=$(jq -r '.version' "$skill_dir/skill.json")
    echo "✓ $skill_name v${SKILL_VERSION} is installed"
  elif [ -d "$bundled_dir" ] && [ -f "$bundled_dir/skill.json" ]; then
    echo "⚠ $skill_name bundled but not deployed"
    echo "  Deploy with: cp -r '$bundled_dir' '$skill_dir'"
  else
    echo "✗ $skill_name not found"
  fi
}

echo "=== Bundled Skills Status ==="
check_bundled_skill "clawsec-feed"
check_bundled_skill "openclaw-audit-watchdog"
check_bundled_skill "soul-guardian"
```

---

## Step 2 — Check for updates (using checksums.json)

Fetch the latest checksums.json from the release mirror. This file contains version info and SHA256 hashes for all release assets.

```bash
TMP="$(mktemp -d)"
cd "$TMP"

curl -fsSLo checksums.json "$CHECKSUMS_URL"


INSTALLED_VER="$(jq -r '.version // ""' "$SUITE_DIR/skill.json" 2>/dev/null || true)"
LATEST_VER="$(jq -r '.version // ""' checksums.json 2>/dev/null || true)"

echo "Installed suite: ${INSTALLED_VER:-unknown}"
echo "Latest suite:    ${LATEST_VER:-unknown}"

if [ -n "$LATEST_VER" ] && [ "$LATEST_VER" != "$INSTALLED_VER" ]; then
  echo "UPDATE AVAILABLE: clawsec-suite ${INSTALLED_VER:-unknown} -> $LATEST_VER"
  echo "(Implement your runtime-specific update action here.)"
else
  echo "Suite appears up to date."
fi
```

If your runtime does not have `jq`, you can parse the version line with grep/sed, or we can publish a simpler `latest.txt` endpoint.

---

## Output

This heartbeat should print a short report suitable for being copied into an alert message:

- suite version status
- integrity status