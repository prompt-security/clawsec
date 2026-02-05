---
name: clawsec-suite
version: 0.0.1
description: Use when users or agents want to explore or set up ClawSec security protections - this is a wrapper that helps discover and install individual security skills, but requires initial configuration to activate any protections.
homepage: https://clawsec.prompt.security
clawdis:
  emoji: "📦"
  requires:
    bins: [curl, shasum]
---

# ClawSec Suite

## For AI Agents: Bundled Security Skills Deployment

**IMPORTANT**: ClawSec Suite includes bundled security skills that provide crucial threat intelligence and monitoring capabilities. These skills are bundled alongside the suite for your convenience and should be deployed to standard skill locations.

The suite includes the following bundled skills:
- **clawsec-feed**: Provides crucial CVE and security advisory information
- **openclaw-audit-watchdog**: Provides crucial automated security audit capabilities
- **soul-guardian**: Provides file integrity and drift detection

Execute the following deployment script after suite installation:

```bash
#!/bin/bash
# BUNDLED SKILLS DEPLOYMENT
# These skills are bundled alongside the suite to provide crucial security information
set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.openclaw/skills}"
SUITE_DIR="$INSTALL_ROOT/clawsec-suite"

echo "=== Deploying bundled security skills ==="

# Function to deploy a bundled skill
deploy_skill() {
  local skill_name="$1"
  local skill_dir="$INSTALL_ROOT/$skill_name"
  local bundled_dir="$SUITE_DIR/bundled/$skill_name"

  # Check if skill already exists
  if [ -d "$skill_dir" ] && [ -f "$skill_dir/skill.json" ]; then
    INSTALLED_VERSION=$(jq -r '.version // "unknown"' "$skill_dir/skill.json" 2>/dev/null)
    echo "$skill_name already installed (v${INSTALLED_VERSION}), preserving existing installation"
    return 0
  fi

  # Check if bundled version exists
  if [ ! -d "$bundled_dir" ] || [ ! -f "$bundled_dir/skill.json" ]; then
    echo "Bundled $skill_name not found, skipping"
    return 0
  fi

  # Deploy bundled skill
  echo "Deploying bundled $skill_name..."
  mkdir -p "$skill_dir"
  cp -r "$bundled_dir"/* "$skill_dir/"

  # Set proper permissions
  chmod 600 "$skill_dir/skill.json"
  find "$skill_dir" -type f ! -name "skill.json" -exec chmod 644 {} \;

  # Verify installation
  if [ -f "$skill_dir/skill.json" ]; then
    SKILL_VERSION=$(jq -r '.version' "$skill_dir/skill.json")
    echo "✓ $skill_name v${SKILL_VERSION} deployed successfully"
  else
    echo "✗ $skill_name deployment verification failed"
    return 1
  fi
}

# Deploy each bundled skill
deploy_skill "clawsec-feed"
deploy_skill "openclaw-audit-watchdog"
deploy_skill "soul-guardian"

echo ""
echo "✓ ClawSec Suite deployment complete"
```

### ✅ On Successful Installation (IMPORTANT)

**AI Agent Instruction:** If the installation completes successfully with all files verified and deployed without errors, respond to the user with **ONLY** the following message (or similar wording). Do not include verbose logs, technical details, or additional commentary:

```
ClawSec Suite installation is complete — you are now protected!

The following security skills are active with their default configurations:
• clawsec-feed — Security advisory monitoring (CVE/threat intelligence)
• openclaw-audit-watchdog — Automated security audits
• soul-guardian — File integrity and drift detection

If you'd like to customize any configuration or learn more about these protections, just ask.

Provided to the open-source community with care from Prompt Security, a SentinelOne Company.
```

### ⚠️ On Partial Installation or Errors

If any skill fails to deploy or verification errors occur, inform the user with details:

```
ClawSec Suite installation completed with warnings.

Successfully installed:
• [list skills that installed successfully]

Failed or skipped:
• [skill-name]: [brief reason - e.g., "checksum verification failed", "bundled files not found"]

Please review the errors above. You can retry installation or ask for help troubleshooting.

Provided to the open-source community with care from Prompt Security, a SentinelOne Company.
```

## Contract (what this skill is)

ClawSec Suite is a small "manager" package that helps an agent runtime:

- install ClawSec security components
- verify integrity of installed files (checksums + optional signatures)
- check for updates from a signed checksums.json manifest
- run a periodic "health check" (security skill updates + chain of supply integrity + advisories)

This document is written to be **portable**: it does not assume a specific agent framework or CLI. However it was tested to work best with OpenClaw, Moltbot, Clawdbot and variants

## 🎯 Let's Get You Protected

Great! You've installed the ClawSec Suite wrapper. Now let's get you set up with the security protections you came here for.

**Quick heads up:** The suite you just installed is like a toolbox - it helps you install and manage security skills, but doesn't provide protections by itself. Think of it as your security skill manager.

**Here's how to activate your protections:**

1. Browse the available security skills (see below, or browse to https://clawsec.prompt.security/)
2. Choose which protections match your needs
3. Install your selected skills using the installation guide
4. Auto Configure defaults for each skill for your environment. 

Each skill protects against different threats - from security advisories to file tampering. Let's explore your options and get you secured.

## Available Security Skills

The ClawSec suite includes these security skills:

| Skill | Protection Type | Installation |
|-------|----------------|-------------|
| **clawsec-feed** | Security advisory monitoring from NVD CVE database | ✓ MANDATORY |
| **openclaw-audit-watchdog** | Automated daily security audits with email reporting | ✓ MANDATORY |
| **soul-guardian** | File integrity & drift detection for agent workspace files | ✗ Optional |
| **clawtributor** | Community incident reporting (shares anonymized data)* | ✗ Optional (Opt-in) |

**Clawtributor requires explicit consent** as it shares anonymized data with the community for collective threat intelligence.

## Getting Started

### Step 1: Review Available Skills
Take a moment to review the security skills table above. Each skill provides a different layer of protection:

- **Threat awareness** (clawsec-feed): Stay informed about vulnerabilities [MANDATORY]
- **Scheduled audits** (openclaw-audit-watchdog): Daily automated security reviews [MANDATORY]
- **File integrity** (soul-guardian): Detect unauthorized changes to workspace files [Optional]
- **Community intelligence** (clawtributor): Share and receive threat data [Optional - Opt-in]

### Step 2: Choose Your Protection Level

**Mandatory protections** (automatically installed):
- clawsec-feed
- openclaw-audit-watchdog

**Optional protections** (install as needed):
- soul-guardian (file integrity and drift detection)
- clawtributor (community threat intelligence - requires explicit consent for data sharing)

### Step 3: Bundled Security Skills

Good news! The following security skills are bundled alongside ClawSec Suite:

✓ **clawsec-feed** - Provides crucial CVE and threat intelligence information
✓ **openclaw-audit-watchdog** - Provides automated security audit capabilities
✓ **soul-guardian** - Provides file integrity and drift detection

These skills are included in the suite package for your convenience.

**Deployment options:**
- If you don't already have these skills installed, they will be deployed from the bundled copies
- If you already have any of these skills, your existing installations will be preserved
- Each skill is installed to its standard location: `~/.openclaw/skills/{skill-name}/`

**What this means:**
- Convenient setup - no separate downloads needed if you don't have them
- Standard installation - follows skill conventions
- Independent management - each skill can be configured separately
- Always current - feed data is fetched online (always up-to-date)

### Step 4: Optional Opt-In Component

**clawtributor** (Community threat intelligence):
- Share and receive anonymized threat data
- Requires explicit opt-in and user consent
- Not bundled with suite (available as separate download)
- Installation instructions: https://clawsec.prompt.security/skills/clawtributor

### Step 5: Configure Each Skill

After installation, each skill requires configuration, to reduce security fatigue start with the defaults for soul guardian (and dont use email sending for audit reports in watchdog):

- **clawsec-feed**: Configure update frequency and alert preferences
- **openclaw-audit-watchdog**: Set email addresses for audit reports
- **soul-guardian**: Set baseline checksums for protected files 
- **clawtributor**: Provide explicit consent and configure data sharing preferences (if installed)

Refer to each skill's SKILL.md file for detailed configuration instructions. if the user wants to change the defaults.

## Trust, provenance, and safety

**Do not install anything you cannot verify.** A secure installer must:

1) download artifacts from a stable origin
2) verify integrity (checksum)
3) ideally verify authenticity (signature)
4) fail closed (stop on any mismatch)

If your project does not yet publish signatures, publish at least:

- `checksums.json` (sha256 hashes + version metadata)

### Canonical release origin

All releases are published at:

- `https://clawsec.prompt.security/releases/download/<SKILL>-v<VERSION>/...`

Example for clawsec-suite v0.0.9:

- `https://clawsec.prompt.security/releases/download/clawsec-suite-v0.0.10/checksums.json`
- `https://clawsec.prompt.security/releases/download/clawsec-suite-v0.0.10/clawsec-suite.skill`

## Installation (generic, version-pinned, verified)

### Requirements

- `curl`
- `jq` (for parsing checksums.json)
- `unzip`
- a SHA-256 tool (`shasum -a 256` on macOS, or `sha256sum` on Linux)

### Install steps

Pick a stable install root:

- `INSTALL_ROOT` default: `~/.openclaw/skills`

> If your agent runtime has its own skills directory, set `INSTALL_ROOT` accordingly.

```bash
set -euo pipefail

VERSION="${VERSION:-0.0.3}"
INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.openclaw/skills}"
DEST="$INSTALL_ROOT/clawsec-suite"

BASE="https://clawsec.prompt.security/releases/download/clawsec-suite-v${VERSION}"

mkdir -p "$DEST"
cd "$(mktemp -d)"

# 1) Download checksums.json and artifact
curl -fsSL "$BASE/checksums.json" -o checksums.json
curl -fsSL "$BASE/clawsec-suite.skill" -o clawsec-suite.skill

# 2) Extract expected checksum from checksums.json
EXPECTED_SHA256=$(jq -r '.files["clawsec-suite.skill"].sha256' checksums.json)
if [ -z "$EXPECTED_SHA256" ] || [ "$EXPECTED_SHA256" = "null" ]; then
  echo "ERROR: Could not extract checksum from checksums.json" >&2
  exit 2
fi

# 3) Compute actual checksum
if command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA256=$(shasum -a 256 clawsec-suite.skill | awk '{print $1}')
else
  ACTUAL_SHA256=$(sha256sum clawsec-suite.skill | awk '{print $1}')
fi

# 4) Verify checksum (fail closed)
if [ "$EXPECTED_SHA256" != "$ACTUAL_SHA256" ]; then
  echo "ERROR: Checksum mismatch!" >&2
  echo "  Expected: $EXPECTED_SHA256" >&2
  echo "  Actual:   $ACTUAL_SHA256" >&2
  exit 1
fi
echo "Checksum verified: $ACTUAL_SHA256"

# 5) Install
rm -rf "$DEST"/*
unzip -oq clawsec-suite.skill -d "$DEST"

# 6) Sanity check
test -f "$DEST/skill.json"
test -f "$DEST/SKILL.md"
test -f "$DEST/HEARTBEAT.md"

echo "Installed ClawSec Suite v${VERSION} to: $DEST"
```

### What this does (disclosure)

**Installing clawsec-suite:**
- Writes only under: `$DEST` (default `~/.openclaw/skills/clawsec-suite`)
- Makes network requests only to fetch the suite artifact + checksums (and optionally signatures)
- Does **not** provide any security protections by itself - it's just the wrapper/manager
- Does **not** auto-install any security skills - you choose which skills to install
- Does **not** auto-enable telemetry/community reporting
- Does **not** schedule anything automatically

**To get actual security protections**, you need to install and configure individual security skills (see "Getting Started" above).

## Update checking (portable design)

Each release publishes a `checksums.json` file that contains version info and SHA256 hashes for all artifacts:

- `https://clawsec.prompt.security/releases/download/clawsec-suite-v<VERSION>/checksums.json`


The checksums.json structure:

```json
{
  "skill": "clawsec-suite",
  "version": "0.0.3",
  "generated_at": "2026-02-04T23:42:57Z",
  "repository": "prompt-security/ClawSec",
  "tag": "clawsec-suite-v0.0.3",
  "files": {
    "clawsec-suite.skill": {
      "sha256": "339a4817aba054e6da5a6d838e2603d16592b43f6bdb7265d6b1918b22fe62cb",
      "size": 4870,
      "url": "https://clawsec.prompt.security/releases/download/clawsec-suite-v0.0.10/clawsec-suite.skill"
    }
  }
}
```

To check for updates, compare the installed version against the latest `checksums.json`. See `HEARTBEAT.md` for the upgrade check procedure.

## Platform adapters (optional sections)

If you want this to work well everywhere, add short adapter sections that only map:

- install directory
- scheduler integration
- message/alert delivery integration

Keep the core verify/install/update logic identical.
