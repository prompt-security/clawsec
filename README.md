<h1 align="center">
  <img src="./img/prompt-icon.svg" alt="prompt-icon" width="40">
  ClawSec: Security Skill Suite for AI Agents
  <img src="./img/prompt-icon.svg" alt="prompt-icon" width="40">
</h1>

<div align="center">

## Secure Your OpenClaw and NanoClaw Agents with a Complete Security Skill Suite

<h4>Brought to you by <a href="https://prompt.security">Prompt Security</a>, the Platform for AI Security</h4>

</div>

<div align="center">

![Prompt Security Logo](./img/Black+Color.png)
<img src="./public/img/mascot.png" alt="clawsec mascot" width="200" />

</div>
<div align="center">

🌐 **Live at: [https://clawsec.prompt.security](https://clawsec.prompt.security) [https://prompt.security/clawsec](https://prompt.security/clawsec)**

[![CI](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml)
[![Deploy Pages](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml)
[![Poll NVD CVEs](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml)


</div>

---

## 🦞 What is ClawSec?

ClawSec is a **complete security skill suite for AI agent platforms**. It provides unified security monitoring, integrity verification, and threat intelligence-protecting your agent's cognitive architecture against prompt injection, drift, and malicious instructions.

### Supported Platforms

- **OpenClaw** (MoltBot, Clawdbot, and clones) - Full suite with skill installer, file integrity protection, and security audits
- **NanoClaw** - Containerized WhatsApp bot security with MCP tools for advisory monitoring, signature verification, and file integrity

### Core Capabilities

- **📦 Suite Installer** - One-command installation of all security skills with integrity verification
- **🛡️ File Integrity Protection** - Drift detection and auto-restore for critical agent files (SOUL.md, IDENTITY.md, etc.)
- **📡 Live Security Advisories** - Automated NVD CVE polling and community threat intelligence
- **🔍 Security Audits** - Self-check scripts to detect prompt injection markers and vulnerabilities
- **🔐 Checksum Verification** - SHA256 checksums for all skill artifacts
- **Health Checks** - Automated updates and integrity verification for all installed skills

---

## 🎬 Product Demos

Animated previews below are GIFs (no audio). Click any preview to open the full MP4 with audio.

### Install Demo (`clawsec-suite`)

[![Install demo animated preview](public/video/install-demo-preview.gif)](public/video/install-demo.mp4)

Direct link: [install-demo.mp4](public/video/install-demo.mp4)

### Drift Detection Demo (`soul-guardian`)

[![Drift detection animated preview](public/video/soul-guardian-demo-preview.gif)](public/video/soul-guardian-demo.mp4)

Direct link: [soul-guardian-demo.mp4](public/video/soul-guardian-demo.mp4)

---

## 🚀 Quick Start

### For AI Agents

```bash
# Install the ClawSec security suite
npx clawhub@latest install clawsec-suite
```

After install, the suite can:
1. Discover installable protections from the published skills catalog
2. Verify release integrity using signed checksums
3. Set up advisory monitoring and hook-based protection flows
4. Add optional scheduled checks

Manual/source-first option:

> Read https://github.com/prompt-security/clawsec/releases/latest/download/SKILL.md and follow the installation instructions.

### For Humans

Copy this instruction to your AI agent:

> Install ClawSec with `npx clawhub@latest install clawsec-suite`, then complete the setup steps from the generated instructions.

### Shell and OS Notes

ClawSec scripts are split between:
- Cross-platform Node/Python tooling (`npm run build`, hook/setup `.mjs`, `utils/*.py`)
- POSIX shell workflows (`*.sh`, most manual install snippets)

For Linux/macOS (`bash`/`zsh`):
- Use unquoted or double-quoted home vars: `export INSTALL_ROOT="$HOME/.openclaw/skills"`
- Do **not** single-quote expandable vars (for example, avoid `'$HOME/.openclaw/skills'`)

For Windows (PowerShell):
- Prefer explicit path building:
  - `$env:INSTALL_ROOT = Join-Path $HOME ".openclaw\\skills"`
  - `node "$env:INSTALL_ROOT\\clawsec-suite\\scripts\\setup_advisory_hook.mjs"`
- POSIX `.sh` scripts require WSL or Git Bash.

Troubleshooting: if you see directories such as `~/.openclaw/workspace/$HOME/...`, a home variable was passed literally. Re-run using an absolute path or an unquoted home expression.

---

## 📱 NanoClaw Platform Support

ClawSec now supports **NanoClaw**, a containerized WhatsApp bot powered by Claude agents.

### clawsec-nanoclaw Skill

**Location**: `skills/clawsec-nanoclaw/`

A complete security suite adapted for NanoClaw's containerized architecture:

- **9 MCP Tools** for agents to check vulnerabilities
  - Advisory checking and browsing
  - Pre-installation safety checks
  - Skill package signature verification (Ed25519)
  - File integrity monitoring
- **Automatic Advisory Feed** - Fetches and caches advisories every 6 hours
- **Platform Filtering** - Shows only NanoClaw-relevant advisories
- **IPC-Based** - Container-safe host communication
- **Full Documentation** - Installation guide, usage examples, troubleshooting

### Advisory Feed for NanoClaw

The feed now monitors NanoClaw-specific keywords:
- `NanoClaw` - Direct product name
- `WhatsApp-bot` - Core functionality
- `baileys` - WhatsApp client library dependency

Advisories can specify `platforms: ["nanoclaw"]` for platform-specific issues.

### Quick Start for NanoClaw

See [`skills/clawsec-nanoclaw/INSTALL.md`](skills/clawsec-nanoclaw/INSTALL.md) for detailed setup instructions.

**Quick integration:**
1. Copy skill to NanoClaw deployment
2. Integrate MCP tools in container
3. Add IPC handlers and cache service on host
4. Restart NanoClaw

---

## 📦 ClawSec Suite (OpenClaw)

The **clawsec-suite** is a skill-of-skills manager that installs, verifies, and maintains security skills from the ClawSec catalog.

### Skills in the Suite

| Skill | Description | Installation | Compatibility |
|-------|-------------|--------------|---------------|
| 📡 **clawsec-feed** | Security advisory feed monitoring with live CVE updates | ✅ Included by default | All agents |
| 🔭 **openclaw-audit-watchdog** | Automated daily audits with email reporting | ⚙️ Optional (install separately) | OpenClaw/MoltBot/Clawdbot |
| 👻 **soul-guardian** | Drift detection and file integrity guard with auto-restore | ⚙️ Optional | All agents |
| 🤝 **clawtributor** | Community incident reporting | ❌ Optional (Explicit request) | All agents |

> ⚠️ **clawtributor** is not installed by default as it may share anonymized incident data. Install only on explicit user request.

> ⚠️ **openclaw-audit-watchdog** is tailored for the OpenClaw/MoltBot/Clawdbot agent family. Other agents receive the universal skill set.

### Suite Features

- **Integrity Verification** - Every skill package includes `checksums.json` with SHA256 hashes
- **Updates** - Automatic checks for new skill versions 
- **Self-Healing** - Failed integrity checks trigger automatic re-download from trusted releases
- **Advisory Cross-Reference** - Installed skills are checked against the security advisory feed

---

## 📡 Security Advisory Feed

ClawSec maintains a continuously updated security advisory feed, automatically populated from NIST's National Vulnerability Database (NVD).

### Feed URL

```bash
# Fetch latest advisories
curl -s https://clawsec.prompt.security/advisories/feed.json | jq '.advisories[] | select(.severity == "critical" or .severity == "high")'
```

Canonical endpoint: `https://clawsec.prompt.security/advisories/feed.json`  
Compatibility mirror (legacy): `https://clawsec.prompt.security/releases/latest/download/feed.json`

### Monitored Keywords

The feed polls CVEs related to:
- **OpenClaw Platform**: `OpenClaw`, `clawdbot`, `Moltbot`
- **NanoClaw Platform**: `NanoClaw`, `WhatsApp-bot`, `baileys`
- Prompt injection patterns
- Agent security vulnerabilities

### Exploitability Context

ClawSec enriches CVE advisories with **exploitability context** to help agents assess real-world risk beyond raw CVSS scores. Newly analyzed advisories can include:

- **Exploit Evidence**: Whether public exploits exist in the wild
- **Weaponization Status**: If exploits are integrated into common attack frameworks
- **Attack Requirements**: Prerequisites needed for successful exploitation (network access, authentication, user interaction)
- **Risk Assessment**: Contextualized risk level combining technical severity with exploitability

This feature helps agents prioritize vulnerabilities that pose immediate threats versus theoretical risks, enabling smarter security decisions.

### Advisory Schema

**NVD CVE Advisory:**
```json
{
  "id": "CVE-2026-XXXXX",
  "severity": "critical|high|medium|low",
  "type": "vulnerable_skill",
  "platforms": ["openclaw", "nanoclaw"],
  "title": "Short description",
  "description": "Full CVE description from NVD",
  "published": "2026-02-01T00:00:00Z",
  "cvss_score": 8.8,
  "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX",
  "exploitability_score": "high|medium|low|unknown",
  "exploitability_rationale": "Why this CVE is or is not likely exploitable in agent deployments",
  "references": ["..."],
  "action": "Recommended remediation"
}
```

**Community Advisory:**
```json
{
  "id": "CLAW-2026-0042",
  "severity": "high",
  "type": "prompt_injection|vulnerable_skill|tampering_attempt",
  "platforms": ["nanoclaw"],
  "title": "Short description",
  "description": "Detailed description from issue",
  "published": "2026-02-01T00:00:00Z",
  "affected": ["skill-name@1.0.0"],
  "source": "Community Report",
  "github_issue_url": "https://github.com/.../issues/42",
  "action": "Recommended remediation"
}
```

**Platform values:**
- `"openclaw"` - OpenClaw/Clawdbot/MoltBot only
- `"nanoclaw"` - NanoClaw only
- `["openclaw", "nanoclaw"]` - Both platforms
- (empty/missing) - All platforms (backward compatible)

---

## 🔄 CI/CD Pipelines

ClawSec uses automated pipelines for continuous security updates and skill distribution.

### Automated Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| **ci.yml** | PRs to `main`, pushes to `main` | Lint/type/build + skill test suites |
| **pages-verify.yml** | PRs to `main` | Verifies Pages build and signing outputs without publishing |
| **poll-nvd-cves.yml** | Daily cron (06:00 UTC) | Polls NVD for new CVEs, updates feed |
| **community-advisory.yml** | Issue labeled `advisory-approved` | Processes community reports into advisories |
| **skill-release.yml** | Skill tags + metadata PR changes | Validates version parity in PRs and publishes signed skill releases on tags |
| **deploy-pages.yml** | `workflow_run` after successful trusted CI/release or manual dispatch | Builds and deploys the web interface to GitHub Pages |
| **wiki-sync.yml** | Pushes to `main` touching `wiki/**` | Syncs `wiki/` to the GitHub Wiki mirror |

### Skill Release Pipeline

When a skill is tagged (e.g., `soul-guardian-v1.0.0`), the pipeline:

1. **Validates** - Checks `skill.json` version matches tag
2. **Enforces key consistency** - Verifies pinned release key references are consistent across repo PEMs and `skills/clawsec-suite/SKILL.md`
3. **Generates Checksums** - Creates `checksums.json` with SHA256 hashes for all SBOM files
4. **Signs + verifies** - Signs `checksums.json` and validates the generated `signing-public.pem` fingerprint against canonical repo key material
5. **Releases** - Publishes to GitHub Releases with all artifacts
6. **Supersedes Old Releases** - Deletes older versions within the same major line (tags remain)
7. **Triggers Pages Update** - Refreshes the skills catalog on the website

### Signing Key Consistency Guardrails

To prevent supply-chain drift, CI now fails fast when signing key references diverge.

Guardrail script:
- `scripts/ci/verify_signing_key_consistency.sh`

What it checks:
- `skills/clawsec-suite/SKILL.md` inline public key fingerprint matches `RELEASE_PUBKEY_SHA256`
- Canonical PEM files all match the same fingerprint:
  - `clawsec-signing-public.pem`
  - `advisories/feed-signing-public.pem`
  - `skills/clawsec-suite/advisories/feed-signing-public.pem`
- Generated public key in workflows matches canonical key:
  - `release-assets/signing-public.pem` (release workflow)
  - `public/signing-public.pem` (pages workflow)

Where enforced:
- `.github/workflows/skill-release.yml`
- `.github/workflows/deploy-pages.yml`

### Release Versioning & Superseding

ClawSec follows [semantic versioning](https://semver.org/). When a new version is released:

| Scenario | Behavior |
|----------|----------|
| New patch/minor (e.g., 1.0.1, 1.1.0) | Previous releases with same major version are **deleted** |
| New major (e.g., 2.0.0) | Previous major version (1.x.x) remains for backwards compatibility |

**Why do old releases disappear?**

When you release `skill-v0.0.2`, the previous `skill-v0.0.1` release is automatically deleted to keep the releases page clean. Only the latest version within each major version is retained.

- **Git tags are preserved** - You can always recreate a release from an existing tag if needed
- **Major versions coexist** - Both `skill-v1.x.x` and `skill-v2.x.x` latest releases remain available for backwards compatibility

### Release Artifacts

Each skill release includes:
- `checksums.json` - SHA256 hashes for integrity verification
- `skill.json` - Skill metadata
- `SKILL.md` - Main skill documentation
- Additional files from SBOM (scripts, configs, etc.)

### Signing Operations Documentation

For feed/release signing rollout and operations guidance:
- [`wiki/security-signing-runbook.md`](wiki/security-signing-runbook.md) - key generation, GitHub secrets, rotation/revocation, incident response
- [`wiki/migration-signed-feed.md`](wiki/migration-signed-feed.md) - phased migration from unsigned feed, enforcement gates, rollback plan

---

## 🛠️ Offline Tools

ClawSec includes Python utilities for local skill development and validation.

### Skill Validator

Validates a skill folder against the required schema:

```bash
python utils/validate_skill.py skills/clawsec-feed
```

Checks:
- `skill.json` exists and is valid JSON
- Required fields present (name, version, description, author, license)
- SBOM files exist and are readable
- OpenClaw metadata is properly structured

### Skill Checksums Generator

Generates `checksums.json` with SHA256 hashes for a skill:

```bash
python utils/package_skill.py skills/clawsec-feed ./dist
```

Outputs:
- `checksums.json` - SHA256 hashes for verification

---

## 🛠️ Local Development

### Prerequisites

- Node.js 20+
- Python 3.10+ (for offline tools)
- npm

### Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

### Populate Local Data

```bash
# Populate skills catalog from local skills/ directory
./scripts/populate-local-skills.sh

# Populate advisory feed with real NVD CVE data
./scripts/populate-local-feed.sh --days 120

# Generate wiki llms exports from wiki/ (for local preview)
./scripts/populate-local-wiki.sh

# Direct generator entrypoint (used by predev/prebuild)
npm run gen:wiki-llms
```

Notes:
- `npm run dev` and `npm run build` automatically regenerate wiki `llms.txt` exports (`predev`/`prebuild` hooks).
- `public/wiki/` is generated output (local + CI) and is intentionally gitignored.

### Build

```bash
npm run build
```

---

## 📁 Project Structure

```
├── advisories/
│   └── feed.json              # Main advisory feed (auto-updated from NVD)
├── components/                 # React components
├── pages/                      # Page components
├── wiki/                       # Source-of-truth docs (synced to GitHub Wiki)
├── scripts/
│   ├── generate-wiki-llms.mjs # wiki/*.md -> public/wiki/**/llms.txt
│   ├── populate-local-feed.sh # Local CVE feed populator
│   ├── populate-local-skills.sh # Local skills catalog populator
│   ├── populate-local-wiki.sh # Local wiki llms export populator
│   └── release-skill.sh       # Manual skill release helper
├── skills/
│   ├── clawsec-suite/       # 📦 Suite installer (skill-of-skills)
│   ├── clawsec-feed/        # 📡 Advisory feed skill
│   ├── clawsec-nanoclaw/    # 📱 NanoClaw platform security suite
│   ├── clawsec-clawhub-checker/ # 🧪 ClawHub reputation checks
│   ├── clawtributor/           # 🤝 Community reporting skill
│   ├── openclaw-audit-watchdog/ # 🔭 Automated audit skill
│   ├── prompt-agent/          # 🧠 Prompt-focused protection workflows
│   └── soul-guardian/         # 👻 File integrity skill
├── utils/
│   ├── package_skill.py       # Skill packager utility
│   └── validate_skill.py      # Skill validator utility
├── .github/workflows/
│   ├── ci.yml                 # Cross-platform lint/type/build + tests
│   ├── pages-verify.yml       # PR-only pages build verification
│   ├── poll-nvd-cves.yml      # CVE polling pipeline
│   ├── community-advisory.yml # Approved issue -> advisory PR
│   ├── skill-release.yml      # Skill release pipeline
│   ├── wiki-sync.yml          # Sync repo wiki/ to GitHub Wiki
│   └── deploy-pages.yml       # Pages deployment
└── public/                     # Static assets + generated publish artifacts
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Submitting Security Advisories

Found a prompt injection vector, malicious skill, or security vulnerability? Report it via GitHub Issues:

1. Open a new issue using the **Security Incident Report** template
2. Fill out the required fields (severity, type, description, affected skills)
3. A maintainer will review and add the `advisory-approved` label
4. The advisory is automatically published to the feed as `CLAW-{YEAR}-{ISSUE#}`

See [CONTRIBUTING.md](CONTRIBUTING.md#submitting-security-advisories) for detailed guidelines.

### Adding New Skills

1. Create a skill folder under `skills/`
2. Add `skill.json` with required metadata and SBOM
3. Add `SKILL.md` with agent-readable instructions
4. Validate with `python utils/validate_skill.py skills/your-skill`
5. Submit a PR for review

## 📚 Documentation Source of Truth

For all wiki content, edit files under `wiki/` in this repository. The GitHub Wiki (`<repo>.wiki.git`) is synced from `wiki/` by `.github/workflows/wiki-sync.yml` when `wiki/**` changes on `main`.

LLM exports are generated from `wiki/` into `public/wiki/`:
- `/wiki/llms.txt` is the LLM-ready export for `wiki/INDEX.md` (or a generated fallback index if `INDEX.md` is missing).
- `/wiki/<page>/llms.txt` is the LLM-ready export for that single wiki page.

---

## 📄 License

- Source code: GNU AGPL v3.0 or later - See [LICENSE](LICENSE) for details.
- Fonts in `font/`: Licensed separately - See [`font/README.md`](font/README.md).

---

<div align="center">

**ClawSec** · Prompt Security, SentinelOne

🦞 Hardening agentic workflows, one skill at a time.

</div>
