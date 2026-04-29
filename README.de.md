<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (de)
Source: README.md
Review status: draft
-->

# Deutsch Translation Scaffold

This file is currently a draft scaffold. Use README.md as the canonical source.

<h1 align="center">
<img src="/img/prompt-icon.svg" alt="prompt-icon" breit="40">
ClawSec: Security Skill Suite für KI-Agenten
<img src="/img/prompt-icon.svg" alt="prompt-icon" breit="40">
</h1>

<div align="center">

Sichern Sie Ihre OpenClaw, NanoClaw und Hermes Agents mit einer kompletten Sicherheits-Fähigkeits-Suite

<h4>Brought to you von <a href="https://prompt.security">Prompt Security</a>, the Platform of AI Security</h4>

</div>

<div align="center">

![Prompt Security Logo](./img/Black+Color.png)
<img src="/public/img/mascot.png" alt="clawsec mascot" breit="200" />

</div>
<div align="center">

🌐 **Live at: [https://clawsec.prompt.security](https://clawsec.prompt.security)[https://prompt.security/clawsec](https://prompt.security/clawsec)**

[![CI](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml)
[![Deploy Pages](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml)
[![Poll NVD CVEs](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml)


</div>

--

Übersetzungen

- Español: [README.es.md](README.es.md)
- 한국어: [README.ko.md](README.ko.md)

Was ist ClawSec?

ClawSec ist eine ** umfassende Sicherheits-Fähigkeits-Suite für AI-Agent-Plattformen*. Es bietet eine einheitliche Sicherheitsüberwachung, Integritätsprüfung und Bedrohung Intelligenz-Schutz der kognitiven Architektur Ihres Agenten gegen schnelle Injektion, Drift und schädliche Anweisungen.

### Unterstützte Plattformen

- **OpenClaw** (MoltBot, Clawdbot und Klone) - Komplette Suite mit Skill-Installer, Dateiintegritätsschutz und Sicherheitsaudits
- **NanoKlaue** - Gebindet App-Bot-Sicherheit mit MCP-Tools für die Überwachung, Unterschriftsprüfung und Dateiintegrität
- **Hermes** - Hermes-native Sicherheitskompetenzen für eine unterzeichnete Beratungs-Feed-Verifikation, beratungssichere Verifikation, deterministische Attestations-Generierung, fehlgeschlossene Verifikation und grundlegende Drifterkennung
- **Picoclaw** - Leichte AI-Gateway-Sicherheitsüberprüfungen mit Beratendem Bewusstsein, config Drift-Erkennung, Release-artifact-Verifikation und einem optionalen separaten Selbst-Pen-Testpaket

### Skill Feature Matrix

| Skill name | unterstützte Plattform| Sicherheits-Feed-Verifikation- config Drift | Agent Self Pen-Tests- Supply-Chain-Verifikation |
...
| claw-release | OpenClaw | Nein | Nein | Nein | Nein | Ja |
| clawsec-clawhub-checker | OpenClaw + clawsec-suite Integration | Nein | Nein | Nein | Ja |
| clawsec-feed | OpenClaw | Ja | Nein | Nein | Ja |
Ja | Ja | Ja | Ja | Ja | Ja |
| clawsec-scanner | OpenClaw | Ja | Nein | Ja | Ja | Ja |
| clawsec-suite | OpenClaw | Ja | Ja | Nein | Ja |
| Clawtributor | OpenClaw | Ja | Nein | Nein
| hermes-attestation-guardian | Hermes | Ja (signierte beratende Feed-Verifikation) | Ja | Nein | Limited (nur Vorabbeleuchtung; keine Artefaktsignatur/provenance install-Verifikation) |
| Openclaw-audit-watchdog | OpenClaw | Nein | Nein | Ja | Nein
| Picoclaw-security-guardian | Picoclaw | Ja | Ja | Nein
| Picoclaw-self-pen-testing
| Seelenhüter | OpenClaw | Nein | Nein | Nein

### Core Caps

- **📦 Suite Installer** - One-Command-Installation aller Sicherheitsfertigkeiten mit Integritätsprüfung
- **🛡️ Datei-Integrity-Schutz* - Drift-Erkennung und Auto-Restore für kritische Agent-Dateien (SOUL.md, IDENTITY.md, etc.)
- **📡 Live Security Advisories* - Automatisierte NVD CVE Umfragen und Community-Drohung Intelligenz
- **🔍 Security Audits** - Self-Check-Skripte, um schnelle Injektionsmarker und Schwachstellen zu erkennen
- **🔐 Prüfsummenverifikation** - SHA256 Prüfsummen für alle Fähigkeiten Artefakte
- **Health Checks* - Automatisierte Updates und Integritätsprüfung für alle installierten Fähigkeiten

--

Produktdemonstrationen

Animierte Vorschauen unten sind GIFs (keine Audio). Klicken Sie auf jede Vorschau, um das volle MP4 mit Audio zu öffnen.

### Demo installieren (`clawsec-suite`)

[![Install demo animated preview](public/video/install-demo-preview.gif)(öffentlich/video/install-demo.mp4)

Direkter Link: [install-demo.mp4](public/video/install-demo.mp4)

### Drift Detection Demo (`soul-guardian`)

[![Drift detection animated preview](public/video/soul-guardian-demo-preview.gif)(öffentlich/video/soul-guardian-demo.mp4)

Direkter Link: [soul-guardian-demo.mp4](public/video/soul-guardian-demo.mp4)

--

🚀 Schneller Start

### For AI Agents

```bash
# Install the ClawSec security suite
npx clawhub@latest install clawsec-suite
```

Nach der Installation kann die Suite:
ANHANG Entdecken Sie installierbare Schutze aus dem veröffentlichten Kompetenzkatalog
2. Verifizieren Sie die Freigabeintegrität mit unterzeichneten Prüfsummen
3. Einrichtung von Beratungs- und hakenbasierten Schutzströmen
4. Optionale geplante Überprüfungen hinzufügen

Manual/source-first option:

> Weiterlesen https://github.com/prompt-security/clawsec/releases/latest/download/SKILL.md und folgen den Installationsanweisungen.

### For Humans

Kopieren Sie diese Anleitung zu Ihrem KI-Agent:

> Installieren Sie ClawSec mit `npx clawhub@latest install clawsec-suite`, füllen Sie dann die Setup-Schritte aus den generierten Anweisungen aus.

### Shell and OS Notes

ClawSec-Skripte werden aufgeteilt zwischen:
- Cross-Plattform Node/Python-Tooling (`npm run build`, Haken/Setup `.mjs`_ `utils/*.py`_
- POSIX Shell Workflows (`*.sh`, die meisten manuellen Installationsschnipsel)

Für Linux/macOS (`bash`/`zsh`):
- Verwenden Sie nicht zitiertes oder doppelt zitiertes Zuhause vars: `export INSTALL_ROOT="$HOME/.openclaw/skills"`
- Do **not** Einquoten-Expandierbare Vars (zum Beispiel `'$HOME/.openclaw/skills'`)

Für Windows (PowerShell):
- Präferen Sie explizite Pfadaufbau:
- Was?
- Was?
- POSIX `.sh` Skripte benötigen WSL oder Git Bash.

Fehlerbehebung: Wenn Sie Verzeichnisse wie `~/.openclaw/workspace/$HOME/...` sehen, wurde eine Heimvariable buchstäblich übergeben. Re-run mit einem absoluten Pfad oder einem nicht zitierten Heimausdruck.

--

Plattform & Suite Dokumentation

Detaillierte Plattform und Suiten docs live in den Wiki-Modulen:
- NanoClaw: [wiki/modules/nanoclaw-integration.md](wiki/modules/nanoclaw-integration.md)
- Hermes: [wiki/modules/hermes-attestation-guardian.md](wiki/modules/hermes-attestation-guardian.md)
- Picoclaw: [wiki/modules/picoclaw-security-guardian.md](wiki/modules/picoclaw-security-guardian.md)
- Picoclaw Selbstprüfung: [wiki/modules/picoclaw-self-pen-testing.md](wiki/modules/picoclaw-self-pen-testing.md)
- ClawSec Suite (OpenClaw): [wiki/modules/clawsec-suite.md](wiki/modules/clawsec-suite.md)
- CI/CD-Pipelines: [wiki/modules/automation-release.md](wiki/modules/automation-release.md)

Schnelle Installation von Links:
- NanoClaw installiert: [skills/clawsec-nanoclaw/INSTALL.md](skills/clawsec-nanoclaw/INSTALL.md)
- Hermes Geschick Paket: `skills/hermes-attestation-guardian/`
- Picoclaw Schutzpaket: `skills/picoclaw-security-guardian/`
- Picoclaw Selbstprüfungspaket: `skills/picoclaw-self-pen-testing/`
- Suite-Paket: `skills/clawsec-suite/`

--

📡 Sicherheitsberatung Fütterung

ClawSec unterhält einen kontinuierlich aktualisierten Sicherheitsberatungsfeed, der automatisch aus der NIST National Vulnerability Database (NVD) besiedelt wird.

### Feed URL

```bash
# Fetch latest advisories
curl -s https://clawsec.prompt.security/advisories/feed.json | jq '.advisories[] | select(.severity == "critical" or .severity == "high")'
```

Kanonischer Endpunkt: `https://clawsec.prompt.security/advisories/feed.json`
Kompatibilitätsspiegel (Legalacy): `https://clawsec.prompt.security/releases/latest/download/feed.json`

### Überwachte Keywords

Die Feed-Quoten CVEs bezogen auf:
**OpenClaw Platform**: `OpenClaw`, `clawdbot`__, `Moltbot`
**NanoClaw Platform**: `NanoClaw`____________________________________________________
- **Picoclaw Platform*: `Picoclaw`, `picoclaw`, leichte AI Gateways, MCP Gateway Belichtung
- Prompt Injektionsmuster
- Sicherheitslücken von Agenten

### Exploitability Context

ClawSec bereichert CVE-Advisories mit **-Exploitability-Kontext**, um Agenten dabei zu helfen, das reale Risiko über die rohen CVSS-Score hinaus zu bewerten. Neu analysierte Berater können:

- **Exploit Evidence**: Ob öffentliche Ausbeutungen in der Wildnis existieren
- **Beantwortungsstatus**: Wenn Exploits in gemeinsame Angriffsrahmen integriert werden
- **Anforderungen**: Voraussetzungen für eine erfolgreiche Nutzung (Netzwerkzugriff, Authentifizierung, Benutzerinteraktion)
- **Risikobewertung**: Kontextualisiertes Risikoniveau, das technische Schwere mit Ausbeutbarkeit kombiniert

Diese Funktion hilft Agenten, Schwachstellen zu priorisieren, die unmittelbare Bedrohungen gegenüber theoretischen Risiken darstellen und intelligentere Sicherheitsentscheidungen ermöglichen.

### Advisory Schema

**NVD CVE Beratung:**
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

**Gemeinschaftsbeirat:**
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

**Platformwerte:**
- `"openclaw"` - OpenClaw/Clawdbot/Molt Nur
- `"nanoclaw"` - NanoClaw nur
- Nur Hermes
- Nur Picoclaw
- `["openclaw", "nanoclaw", "hermes", "picoclaw"]` - Alle Kernplattformen
- (leer/missing) - Alle Plattformen (backward kompatibel)

--

🔄 CI/CD Pipelines

CI/CD Pipelinedetails wurden auf die Wiki-Modulseite verschoben:
- Was?

Ähnliche Arbeitspunkte:
- Was?
- Was?

--

🛠️ Offline Tools

ClawSec umfasst Python utilities für lokale Fähigkeiten Entwicklung und Validierung.

### Skill Validator

Validiert einen Geschicksordner gegen das erforderliche Schema:

```bash
python utils/validate_skill.py skills/clawsec-feed
```

Kontrollen:
- `skill.json` existiert und ist gültig JSON
- Erforderliche Felder vorhanden (Name, Version, Beschreibung, Autor, Lizenz)
- SBOM-Dateien existieren und sind lesbar
- OpenClaw Metadaten sind richtig strukturiert

### Skill Checksums Generator

Erzeugt `checksums.json` mit SHA256 Hashes für ein Geschick:

```bash
python utils/package_skill.py skills/clawsec-feed ./dist
```

Ausgänge:
- `checksums.json` - SHA256 hathes zur Überprüfung

--

Lokale Entwicklung

### Voraussetzungen

- Node.js 20+
- Python 3.10+ (für Offline-Tools)
- npm

### Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

### Lokale Daten ausfüllen

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

Anmerkungen:
- `npm run dev` und `npm run build` regenerieren automatisch wiki `llms.txt` Exporte (`predev`_`prebuild` Haken).
- `public/wiki/` wird ausgegeben (lokal + CI) und ist absichtlich gitignored.

### Build

```bash
npm run build
```

--

Projektstruktur

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

--

Beiträge

Wir begrüßen Beiträge! Siehe [CONTRIBUTING.md](CONTRIBUTING.md) für Richtlinien.

### Sicherheitsberater einfügen

Haben Sie einen schnellen Injektionsvektor, bösartige Fähigkeiten oder Sicherheitslücke gefunden? Über GitHub Issues melden:

ANHANG Öffne ein neues Problem mit der Vorlage **Security Incident Report***
2. Füllen Sie die erforderlichen Felder aus (Stärke, Art, Beschreibung, Betroffene Fähigkeiten)
3. Ein Betreuer überprüft und fügt das `advisory-approved` Label hinzu
4. Die Beratung wird automatisch im Feed veröffentlicht als `CLAW-{YEAR}-{ISSUE#}`

Siehe `CLAW-{YEAR}-{ISSUE#}` für detaillierte Richtlinien.

### Neue Fähigkeiten hinzufügen

ANHANG Erstellen Sie einen Kompetenzordner unter `skills/`
2. Hinzufügen `skill.json` mit benötigten Metadaten und SBOM
3. `SKILL.md` mit agentenlesbaren Anweisungen hinzufügen
4. Gültig mit `python utils/validate_skill.py skills/your-skill`
5. Eine PR zur Überprüfung einreichen

📚 Dokumentation Quelle der Wahrheit

Für alle Wiki-Inhalte bearbeiten Sie Dateien unter `wiki/` in diesem Repository. Das GitHub Wiki (`<repo>.wiki.git`) wird von `wiki/`_ durch `.github/workflows/wiki-sync.yml` synchronisiert, wenn `wiki/**`_ auf `main`__ wechselt.

LLM-Exporte werden von `wiki/` in `public/wiki/`_ generiert:
- `/wiki/llms.txt` ist der LLM-ready Export für `wiki/INDEX.md` (oder ein generierter Fallback-Index, wenn `INDEX.md` fehlt).
- `/wiki/<page>/llms.txt` ist der LLM-ready Export für diese einzelne Wiki-Seite.

--

📄 Lizenz

- Quellcode: GNU AGPL v3.0 oder später - Siehe [LICENSE](LICENSE) für Details.
- Schriften in `font/`: separat lizenziert - Siehe [`font/README.md`](font/README.md).

--

<div align="center">

**ClawSec** · Sicherheitsleistung, SentinelOne

🦞 Härten Agentic Workflows, eine Fähigkeit zu einer Zeit.

</div>
