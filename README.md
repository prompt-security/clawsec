<p align="center">
  <img src="./assets/readme/hero.webp" width="100%" alt="ClawSec security skills for AI agents, featuring the ClawSec robot and the Prompt Security from SentinelOne logo">
</p>

<p align="center">
  <a href="https://clawsec.prompt.security"><strong>Website</strong></a>
  ·
  <a href="https://clawsec.prompt.security/#/skills"><strong>Skill catalog</strong></a>
  ·
  <a href="https://clawsec.prompt.security/feed"><strong>Security feed</strong></a>
  ·
  <a href="./wiki/INDEX.md"><strong>Documentation</strong></a>
  ·
  <a href="https://github.com/prompt-security/clawsec/releases"><strong>Releases</strong></a>
</p>

<p align="center">
  <a href="https://github.com/prompt-security/clawsec/actions/workflows/ci.yml"><img src="https://github.com/prompt-security/clawsec/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml"><img src="https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml/badge.svg" alt="Pages deployment status"></a>
  <a href="https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml"><img src="https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml/badge.svg" alt="NVD polling status"></a>
</p>

ClawSec is an AGPL collection of security skills and signed advisory intelligence for AI agent runtimes. It helps operators verify skill artifacts, detect configuration drift, audit agent environments, and approval-gate risky installs across **OpenClaw, NanoClaw, Hermes, and Picoclaw**.

---

## Install the OpenClaw suite

The OpenClaw entry point is `clawsec-suite`. Adding the package and activating its persistent hook are separate, reviewable steps.

### 1. Add the suite

```bash
npx skills add prompt-security/clawsec --skill clawsec-suite -a openclaw --global -y
```

This installs the suite with its signed advisory trust set, heartbeat workflow, guarded installer, and setup scripts. Optional protections remain separate packages that the suite discovers from the published catalog.

### 2. Review and enable the advisory hook

```bash
SUITE_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-suite"
node "$SUITE_DIR/scripts/setup_advisory_hook.mjs"
```

The setup script prints its preflight before it changes persistent OpenClaw configuration. After it succeeds, restart the OpenClaw gateway and run `/new` once to trigger the first advisory scan.

To see the current optional protections:

```bash
node "$SUITE_DIR/scripts/discover_skill_catalog.mjs"
```

> **Installing for someone else?** Ask their agent to install `clawsec-suite` with the command above, show the hook preflight, and wait for approval before enabling the hook or optional cron job.

<details>
<summary><strong>Shell and path notes</strong></summary>

For `bash` and `zsh`, keep home variables expandable:

```bash
export INSTALL_ROOT="$HOME/.openclaw/skills"
```

Do not single-quote paths that contain `$HOME`. In PowerShell, build the path explicitly:

```powershell
$env:INSTALL_ROOT = Join-Path $HOME ".openclaw\skills"
node "$env:INSTALL_ROOT\clawsec-suite\scripts\setup_advisory_hook.mjs"
```

POSIX `.sh` workflows require WSL or Git Bash on Windows.

</details>

---

## See it work

### Detect and respond to agent-file drift

The `soul-guardian` demo changes a protected agent file, detects the mismatch, and walks through the response.

[![ClawSec soul-guardian drift detection demo](public/video/soul-guardian-demo-preview.gif)](public/video/soul-guardian-demo.mp4)

**[Watch the MP4 with audio →](public/video/soul-guardian-demo.mp4)**

<details>
<summary><strong>Watch the suite installation walkthrough</strong></summary>

<p align="center">
  <a href="./public/video/install-demo.mp4"><img src="./public/video/install-demo-preview.gif" width="320" alt="ClawSec suite installation walkthrough"></a>
</p>

<p align="center"><a href="./public/video/install-demo.mp4"><strong>Open the MP4 with audio →</strong></a></p>

</details>

---

## How ClawSec protects an agent

| Protection layer | What it does |
| --- | --- |
| **Signed intelligence** | Verifies the advisory feed and checksum manifest before matching published risk against installed skills. |
| **Guarded installs** | Stops on advisory matches and requires a second, explicit confirmation before a risky install can continue. |
| **Integrity and drift** | Gives platform-specific skills baselines for critical files, configuration, attestations, and release artifacts. |
| **Audits and reporting** | Provides focused audit, posture, self-test, and community-reporting packages where the platform contract supports them. |

ClawSec recommends and gates actions; destructive removal and install overrides remain approval-controlled.

### Platform entry points

- **OpenClaw** — start with [`clawsec-suite`](skills/clawsec-suite/) for signed advisory monitoring and guarded installs, then discover separate drift and audit protections.
- **NanoClaw** — use [`clawsec-nanoclaw`](skills/clawsec-nanoclaw/) for NanoClaw-specific advisory, integrity, verification, and security-tool workflows.
- **Hermes** — use [`hermes-attestation-guardian`](skills/hermes-attestation-guardian/) for signed advisory checks, guarded verification, deterministic attestations, and baseline drift detection.
- **Picoclaw** — use [`picoclaw-security-guardian`](skills/picoclaw-security-guardian/) for posture, advisory, drift, and release-artifact checks. [Self-pen testing](skills/picoclaw-self-pen-testing/) is a separate opt-in package.

> The `*-traffic-guardian` directories are specification baselines for platform builders. They are not shipped runtime proxies today.

Browse every package in the **[live skill catalog](https://clawsec.prompt.security/#/skills)** or the repository’s **[`skills/` directory](skills/)**.

---

## Query the signed advisory channel

The consolidated feed can contain relevant NVD CVEs, approved community reports, and provisional GitHub advisories that do not yet have CVE identifiers.

```bash
curl -fsSL https://clawsec.prompt.security/advisories/feed.json \
  | jq '.advisories[] | select(.severity == "critical" or .severity == "high")'
```

Trust material lives beside the feed:

- [Advisory feed](advisories/feed.json)
- [Detached feed signature](advisories/feed.json.sig)
- [Pinned Ed25519 public key](advisories/feed-signing-public.pem)
- [Signing and verification runbook](wiki/security-signing-runbook.md)

The legacy `/releases/latest/download/feed.json` endpoint remains a compatibility mirror. New consumers should use the canonical `/advisories/feed.json` endpoint.

---

## Build, test, and contribute

Run the web catalog locally:

```bash
npm install
npm run dev
```

Run the repository’s local quality gate before pushing:

```bash
./scripts/prepare-to-push.sh
```

Validate a skill package directly:

```bash
python utils/validate_skill.py skills/clawsec-feed
```

Start with these references:

- [Architecture](wiki/architecture.md)
- [Platform verification](wiki/platform-verification.md)
- [Testing](wiki/testing.md)
- [Release automation](wiki/modules/automation-release.md)
- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

The source of truth for project documentation is [`wiki/`](wiki/). GitHub Wiki pages and LLM-ready exports are generated from those files.

---

## Translations

**English**
· [Deutsch](README.de.md)
· [Español](README.es.md)
· [Français](README.fr.md)
· [日本語](README.ja.md)
· [한국어](README.ko.md)

Localized wiki indexes: [DE](wiki/de/INDEX.md) · [ES](wiki/es/INDEX.md) · [FR](wiki/fr/INDEX.md) · [JA](wiki/ja/INDEX.md) · [KO](wiki/ko/INDEX.md) · [EN](wiki/INDEX.md)

---

## License

ClawSec source code is licensed under **GNU AGPL-3.0-or-later**. See [LICENSE](LICENSE). Files under [`font/`](font/) have separate license terms and are not used by the README artwork.

<p align="center">
  <strong>ClawSec</strong> · Prompt Security, from SentinelOne<br>
  Verify before your agent trusts.
</p>
