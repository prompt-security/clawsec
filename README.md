<h1 align="center">
  <img src="./img/prompt-icon.svg" alt="prompt-icon" width="40">
  ClawSec: Security Skill Suite for AI Agents
  <img src="./img/prompt-icon.svg" alt="prompt-icon" width="40">
</h1>

<div align="center">

## Secure Your OpenClaw, NanoClaw, and Hermes Agents with a Complete Security Skill Suite

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

## 🌍 Translations

[Deutsch](README.de.md) | [Español](README.es.md) | [Français](README.fr.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | **English**

Wiki indexes: [DE](wiki/de/INDEX.md) · [ES](wiki/es/INDEX.md) · [FR](wiki/fr/INDEX.md) · [JA](wiki/ja/INDEX.md) · [KO](wiki/ko/INDEX.md) · [EN](wiki/INDEX.md)

## 🦞 What is ClawSec?

ClawSec is a **complete security skill suite for AI agent platforms**. It provides unified security monitoring, integrity verification, and threat intelligence-protecting your agent's cognitive architecture against prompt injection, drift, and malicious instructions.

### Supported Platforms

- **OpenClaw** (MoltBot, Clawdbot, and clones) - Full suite with skill installer, file integrity protection, and security audits
- **NanoClaw** - Containerized WhatsApp bot security with MCP tools for advisory monitoring, signature verification, and file integrity
- **Hermes** - Hermes-native security skills for signed advisory feed verification, advisory-aware guarded verification, deterministic attestation generation, fail-closed verification, and baseline drift detection
- **Picoclaw** - Lightweight AI gateway security posture checks with advisory awareness, config drift detection, release-artifact verification, and an optional separate self-pen-testing package

### Skill Feature Matrix

| Skill name | supported platform| security feed verification| config drift | agent self pen testing| supply-chain install verification | runtime traffic monitoring |
|---|---|---|---|---|---|---|
| claw-release | OpenClaw | No | No | No | Yes | No |
| clawsec-clawhub-checker | OpenClaw + clawsec-suite integration | No | No | No | Yes | No |
| clawsec-feed | OpenClaw | Yes | No | No | Yes | No |
| clawsec-nanoclaw | NanoClaw | Yes | Yes | Yes | Yes | No |
| clawsec-scanner | OpenClaw | Yes | No | Yes | Yes | No |
| clawsec-suite | OpenClaw | Yes | Yes | No | Yes | No |
| clawtributor | All core platforms | No | No | No | No | No |
| hermes-attestation-guardian | Hermes | Yes (signed advisory feed verification) | Yes | No | Limited (advisory preflight gating only; no artifact signature/provenance install verification) | No |
| hermes-traffic-guardian | Hermes | No | Planned posture export only | No | No | Spec baseline |
| nanoclaw-traffic-guardian | NanoClaw | No | No | No | No | Spec baseline |
| openclaw-audit-watchdog | OpenClaw | No | No | Yes | No | No |
| openclaw-traffic-guardian | OpenClaw | No | No | No | No | Spec baseline |
| picoclaw-security-guardian | Picoclaw | Yes | Yes | No | Yes | No |
| picoclaw-self-pen-testing | Picoclaw | No | No | Yes | No | No |
| picoclaw-traffic-guardian | Picoclaw | No | Planned profile export only | No | No | Spec baseline |
| soul-guardian | OpenClaw | No | Yes | No | No | No |

`Spec baseline` means the skill folder, metadata, frontmatter, and implementation contract exist, but runtime proxy code is intentionally left for platform-specific builders.

### Core Capabilities

- **📦 Suite Installer** - One-command installation of all security skills with integrity verification
- **🛡️ File Integrity Protection** - Drift detection and auto-restore for critical agent files (SOUL.md, IDENTITY.md, etc.)
- **📡 Live Security Advisories** - Automated NVD CVE polling and community threat intelligence
- **🔍 Security Audits** - Self-check scripts to detect prompt injection markers and vulnerabilities
- **🔐 Checksum Verification** - SHA256 checksums for all skill artifacts
- **Runtime Traffic Monitoring Baselines** - Platform-specific specs for opt-in proxy inspection, exfiltration detection, and inbound injection detection
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

## 🧭 Platform & Suite Documentation

Detailed platform and suite docs live in the wiki modules:
- NanoClaw: [wiki/modules/nanoclaw-integration.md](wiki/modules/nanoclaw-integration.md)
- Hermes: [wiki/modules/hermes-attestation-guardian.md](wiki/modules/hermes-attestation-guardian.md)
- Picoclaw: [wiki/modules/picoclaw-security-guardian.md](wiki/modules/picoclaw-security-guardian.md)
- Picoclaw self-pen-testing: [wiki/modules/picoclaw-self-pen-testing.md](wiki/modules/picoclaw-self-pen-testing.md)
- ClawSec Suite (OpenClaw): [wiki/modules/clawsec-suite.md](wiki/modules/clawsec-suite.md)
- CI/CD pipelines: [wiki/modules/automation-release.md](wiki/modules/automation-release.md)

Quick install links:
- NanoClaw install: [skills/clawsec-nanoclaw/INSTALL.md](skills/clawsec-nanoclaw/INSTALL.md)
- Hermes skill package: `skills/hermes-attestation-guardian/`
- Picoclaw guardian package: `skills/picoclaw-security-guardian/`
- Picoclaw self-pen-testing package: `skills/picoclaw-self-pen-testing/`
- Suite package: `skills/clawsec-suite/`

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
- **Picoclaw Platform**: `Picoclaw`, `picoclaw`, lightweight AI gateways, MCP gateway exposure
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
- `"hermes"` - Hermes only
- `"picoclaw"` - Picoclaw only
- `["openclaw", "nanoclaw", "hermes", "picoclaw"]` - All core platforms
- (empty/missing) - All platforms (backward compatible)

---

## 🔄 CI/CD Pipelines

CI/CD pipeline details were moved to the wiki module page:
- [wiki/modules/automation-release.md](wiki/modules/automation-release.md)

Related operations docs:
- [wiki/security-signing-runbook.md](wiki/security-signing-runbook.md)
- [wiki/migration-signed-feed.md](wiki/migration-signed-feed.md)

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
│   ├── feed.json                    # Main advisory feed
│   ├── feed.json.sig                # Detached signature for feed.json
│   └── feed-signing-public.pem      # Public key for feed verification
├── components/                      # React components
├── pages/                           # Route/page components
├── wiki/                            # Source-of-truth docs (synced to GitHub Wiki)
├── scripts/
│   ├── generate-wiki-llms.mjs       # wiki/*.md -> public/wiki/**/llms.txt
│   ├── populate-local-feed.sh       # Local CVE feed populator
│   ├── populate-local-skills.sh     # Local skills catalog populator
│   ├── populate-local-wiki.sh       # Local wiki llms export populator
│   ├── prepare-to-push.sh           # Local CI-style quality gate
│   ├── validate-release-links.sh    # Release link checks
│   └── release-skill.sh             # Manual skill release helper
├── skills/
│   ├── claw-release/                # 🚀 Release automation workflow skill
│   ├── clawsec-suite/               # 📦 Suite installer (skill-of-skills)
│   ├── clawsec-feed/                # 📡 Advisory feed skill
│   ├── clawsec-scanner/             # 🔍 Vulnerability scanner (deps + SAST + OpenClaw DAST)
│   ├── clawsec-nanoclaw/            # 📱 NanoClaw platform security suite
│   ├── clawsec-clawhub-checker/     # 🧪 ClawHub reputation checks
│   ├── clawtributor/                # 🤝 Community reporting skill
│   ├── hermes-attestation-guardian/ # 🛡️ Hermes attestation + drift verification
│   ├── openclaw-audit-watchdog/     # 🔭 Automated audit skill
│   ├── picoclaw-security-guardian/  # 🦐 Picoclaw posture/advisory/drift/supply-chain checks
│   ├── picoclaw-self-pen-testing/   # 🧪 Picoclaw self-pen-testing checks (separate package)
│   └── soul-guardian/               # 👻 File integrity skill
├── utils/
│   ├── package_skill.py             # Skill packager utility
│   └── validate_skill.py            # Skill validator utility
├── .github/workflows/
│   ├── ci.yml                       # Cross-platform lint/type/build + tests
│   ├── pages-verify.yml             # PR-only pages build/signing verification
│   ├── poll-nvd-cves.yml            # CVE polling pipeline
│   ├── community-advisory.yml       # Approved issue -> advisory PR
│   ├── skill-release.yml            # Skill release/signing pipeline
│   ├── deploy-pages.yml             # GitHub Pages deployment
│   ├── wiki-sync.yml                # Sync repo wiki/ to GitHub Wiki
│   ├── codeql.yml                   # CodeQL security analysis
│   └── scorecard.yml                # OpenSSF Scorecard checks
└── public/                          # Static assets + generated wiki exports
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
