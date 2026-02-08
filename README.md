<h1 align="center">
  <img src="./img/prompt-icon.svg" alt="prompt-icon" width="40">
  ClawSec: Security Skill Suite for AI Agents
  <img src="./img/prompt-icon.svg" alt="prompt-icon" width="40">
</h1>

<div align="center">

## Secure Your OpenClaw Bots with a Complete Security Skill Suite

<h4>Brought to you by <a href="https://prompt.security">Prompt Security</a>, the Platform for AI Security</h4>

</div>

<div align="center">

![Prompt Security Logo](./img/Black+Color.png)

</div>

<div align="center">

🌐 **Live at: [https://clawsec.prompt.security](https://clawsec.prompt.security)**

[![CI](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml)
[![Deploy Pages](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml)
[![Poll NVD CVEs](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml)
[![Skill Release](https://github.com/prompt-security/clawsec/actions/workflows/skill-release.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/skill-release.yml)

</div>

---

## 🦞 What is ClawSec?

ClawSec is a **complete security skill suite for the OpenClaw family of agents (Moltbot, Clawdbot, some clones)**. It provides a unified installer that deploys, verifies, and maintains security skills-protecting your agent's cognitive architecture against prompt injection, drift, and malicious instructions.

### Core Capabilities

- **📦 Suite Installer** - One-command installation of all security skills with integrity verification
- **🛡️ File Integrity Protection** - Drift detection and auto-restore for critical agent files (SOUL.md, IDENTITY.md, etc.)
- **📡 Live Security Advisories** - Automated NVD CVE polling and community threat intelligence
- **🔍 Security Audits** - Self-check scripts to detect prompt injection markers and vulnerabilities
- **🔐 Checksum Verification** - SHA256 checksums for all skill artifacts via `.skill` packages
- **Health Checks** - Automated updates and integrity verification for all installed skills

---

## 🚀 Quick Start

### For AI Agents

```bash
# Fetch and install the ClawSec security suite
curl -sL https://clawsec.prompt.security/releases/latest/download/SKILL.md
```

The skill file contains deployment instructions. Your agent will:
1. Detect its agent family (OpenClaw/MoltBot/ClawdBot or other)
2. Install appropriate skills from the catalog
3. Verify integrity using checksums
4. Set up cron update checks

### For Humans

Copy this instruction to your AI agent:

> Read https://clawsec.prompt.security/releases/latest/download/SKILL.md and follow the instructions to install the protection skill suite.

---

## 📦 ClawSec Suite

The **clawsec-suite** is a skill-of-skills manager that installs, verifies, and maintains security skills from the ClawSec catalog.

### Skills in the Suite

| Skill | Description | Installation | Compatibility |
|-------|-------------|--------------|---------------|
| 📡 **clawsec-feed** | Security advisory feed monitoring with live CVE updates | ✅ Included by default | All agents |
| 🔭 **openclaw-audit-watchdog** | Automated daily audits with email reporting | ✅ Included by default | OpenClaw/MoltBot/ClawdBot |
| 👻 **soul-guardian** | Drift detection and file integrity guard with auto-restore | ⚙️ Optional | All agents |
| 🤝 **clawtributor** | Community incident reporting | ❌ Optional (Explicit request) | All agents |

> ⚠️ **clawtributor** is not installed by default as it may share anonymized incident data. Install only on explicit user request.

> ⚠️ **openclaw-audit-watchdog** is tailored for the OpenClaw/MoltBot/ClawdBot agent family. Other agents receive the universal skill set.

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

### Monitored Keywords

The feed polls CVEs related to:
- `OpenClaw`
- `clawdbot`  
- `Moltbot`
- Prompt injection patterns
- Agent security vulnerabilities

### Advisory Schema

**NVD CVE Advisory:**
```json
{
  "id": "CVE-2026-XXXXX",
  "severity": "critical|high|medium|low",
  "type": "vulnerable_skill",
  "title": "Short description",
  "description": "Full CVE description from NVD",
  "published": "2026-02-01T00:00:00Z",
  "cvss_score": 8.8,
  "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX",
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
  "title": "Short description",
  "description": "Detailed description from issue",
  "published": "2026-02-01T00:00:00Z",
  "affected": ["skill-name@1.0.0"],
  "source": "Community Report",
  "github_issue_url": "https://github.com/.../issues/42",
  "action": "Recommended remediation"
}
```

---

## 🔄 CI/CD Pipelines

ClawSec uses automated pipelines for continuous security updates and skill distribution.

### Automated Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| **poll-nvd-cves.yml** | Daily cron (06:00 UTC) | Polls NVD for new CVEs, updates feed |
| **community-advisory.yml** | Issue labeled `advisory-approved` | Processes community reports into advisories |
| **skill-release.yml** | `<skill>-v*.*.*` tags | Packages individual skills with checksums to GitHub Releases |
| **deploy-pages.yml** | Push to main | Builds and deploys the web interface to GitHub Pages |

### Skill Release Pipeline

When a skill is tagged (e.g., `soul-guardian-v1.0.0`), the pipeline:

1. **Validates** - Checks `skill.json` version matches tag
2. **Generates Checksums** - Creates `checksums.json` with SHA256 hashes for all SBOM files
3. **Packages** - Creates `.skill` zip file with all required files
4. **Releases** - Publishes to GitHub Releases with all artifacts
5. **Supersedes Old Releases** - Marks older versions (same major) as pre-releases
6. **Triggers Pages Update** - Refreshes the skills catalog on the website

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
- `<skill>.skill` - Packaged skill (zip format)
- `checksums.json` - SHA256 hashes for integrity verification
- `skill.json` - Skill metadata
- `SKILL.md` - Main skill documentation
- Additional files from SBOM (scripts, configs, etc.)

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

### Skill Packager

Creates a distributable `.skill` file with checksums:

```bash
python utils/package_skill.py skills/clawsec-feed ./dist
```

Outputs:
- `clawsec-feed.skill` - Zip package with all SBOM files
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
```

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
├── scripts/
│   ├── populate-local-feed.sh # Local CVE feed populator
│   ├── populate-local-skills.sh # Local skills catalog populator
│   └── release-skill.sh       # Manual skill release helper
├── skills/
│   ├── clawsec-suite/       # 📦 Suite installer (skill-of-skills)
│   ├── clawsec-feed/        # 📡 Advisory feed skill
│   ├── clawtributor/           # 🤝 Community reporting skill
│   ├── openclaw-audit-watchdog/ # 🔭 Automated audit skill
│   └── soul-guardian/         # 👻 File integrity skill
├── utils/
│   ├── package_skill.py       # Skill packager utility
│   └── validate_skill.py      # Skill validator utility
├── .github/workflows/
│   ├── poll-nvd-cves.yml      # CVE polling pipeline
│   ├── skill-release.yml      # Skill release pipeline
│   └── deploy-pages.yml       # Pages deployment
└── public/                     # Static assets and published skills
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

---

## 📄 License

- Source code: MIT License - See [LICENSE](LICENSE) for details.
- Fonts in `font/`: Licensed separately - See [`font/README.md`](font/README.md).

---

<div align="center">

**ClawSec** · Prompt Security, SentinelOne

🦞 Hardening agentic workflows, one skill at a time.

</div>
