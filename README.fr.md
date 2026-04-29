<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: README.md
Review status: draft
-->

# Français Translation Scaffold

This file is currently a draft scaffold. Use README.md as the canonical source.

<h1 align="center">
<img src="/img/prompt-icon.svg" alt="prompt-icon" largeur="40">
ClawSec: Suite de compétences en sécurité pour les agents d'IA
<img src="/img/prompt-icon.svg" alt="prompt-icon" largeur="40">
</h1>

<div align="center">

## Sécurisez vos agents OpenClaw, NanoClaw et Hermes avec une suite complète de compétences en sécurité

<h4>Présenté par <a href="https://prompt.security">Prompt Security</a>, la plateforme pour la sécurité de l'IA</h4>

</div>

<div align="center">

- Oui. [Prompt Security Logo](./img/Black+Color.png)
<img src="/public/img/mascot.png" alt="clawsec mascotte" width="200" />

</div>
<div align="center">

C'est-à-dire **Live at: [https://clawsec.prompt.security](https://clawsec.prompt.security) [https://prompt.security/clawsec](https://prompt.security/clawsec)**

[![CI](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml)
[![Deploy Pages](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml)
[![Poll NVD CVEs](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml/badge.svg)](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml)


</div>

---

Traductions

- Español: [README.es.md](README.es.md)
- 한국어: [README.ko.md](README.ko.md)

Qu'est-ce que ClawSec ?

ClawSec est une suite complète de compétences en sécurité pour les plateformes d'agents d'IA**. Il fournit une surveillance de sécurité unifiée, la vérification de l'intégrité et la protection de l'architecture cognitive de votre agent contre l'injection rapide, la dérive et les instructions malveillantes.

Plateformes prises en charge

- **OpenClaw** (MoltBot, Clawdbot et clones) - Suite complète avec installateur de compétences, protection de l'intégrité des fichiers et audits de sécurité
- **NanoClaw** - Containerized Whats Sécurité des applications bot avec des outils MCP pour la surveillance consultative, la vérification des signatures et l'intégrité des fichiers
- **Hermès** - Compétences en sécurité Hermès-native pour la vérification de l'alimentation, la vérification de l'information-conseil, la génération d'attestations déterministes, la vérification fermée et la détection de la dérive de base
- **Picoclaw** - Contrôles de la posture de sécurité de la passerelle légère AI avec sensibilisation, détection de la dérive de config, vérification de l'artéfact de relâchement, et un ensemble d'auto-essais facultatifs

### Matrix des compétences

- Oui. Nom de la compétence Plate-forme prise en charge de la sécurité de la vérification de l'alimentation de config driving de l'agent testing de l'auto stylo de la chaîne d'approvisionnement de vérification d'installation de l'installation de l'agent
-- -- -- -- -- -- -- -- -- -- -- -- --
Claw-release
Clawsec-clawhub-checker
Oui Non Oui Oui
Oui Oui Oui Oui
Oui Non Oui Oui
Oui Oui Oui Oui
Clawtributor OpenClaw OpenClaw OpenClaw OpenClaw OpenClaw
Hermes-attestation-guardian.
Openclaw-audit-watchdog
Picoclaw-security-guardian.
Picoclaw-auto-test de stylos
Un gardien de l'âme OpenClaw OpenClaw OpenClaw OpenClaw

Capacités de base

- ** Installateur Suite** - Installation unique de toutes les compétences de sécurité avec vérification de l'intégrité
- Oui. Protection de l'intégrité des fichiers** - Détection et récupération automatique des fichiers d'agents critiques (SOUL.md, IDENTITY.md, etc.)
- * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
- Oui. Audits de sécurité** - Auto-vérifier les scripts pour détecter les marqueurs d'injection et les vulnérabilités
- Oui. Vérification des contrôles** - SHA256 somme de contrôle pour tous les artefacts de compétence
- **Vérifications santé** - Mises à jour automatisées et vérification de l'intégrité pour toutes les compétences installées

---

Démos de produits

Les aperçus animés ci-dessous sont des GIF (pas d'audio). Cliquez sur n'importe quel aperçu pour ouvrir le MP4 complet avec audio.

### Installer la démo (`clawsec-suite`)

[![Install demo animated preview](public/video/install-demo-preview.gif)](public/video/install-demo.mp4)

Lien direct: [install-demo.mp4](public/video/install-demo.mp4)

### Démo de détection de la dérive (`soul-guardian`)

[![Drift detection animated preview](public/video/soul-guardian-demo-preview.gif)](public/video/soul-guardian-demo.mp4)

Lien direct: [soul-guardian-demo.mp4](public/video/soul-guardian-demo.mp4)

---

Début rapide

Pour les agents de l'IA

```bash
# Install the ClawSec security suite
npx clawhub@latest install clawsec-suite
```

Après l'installation, la suite peut :
1. Découvrez les protections installables à partir du catalogue de compétences publié
2. Vérifier l'intégrité de la libération à l'aide de comptes de vérification signés
3. Mettre en place une surveillance consultative et des flux de protection par crochet
4. Ajouter des contrôles programmés facultatifs

Manuel/source-première option:

> Lire https://github.com/prompt-security/clawsec/releases/latest/download/SKILL.md et suivre les instructions d'installation.

Pour les humains

Copiez cette instruction à votre agent d'IA :

> Installez ClawSec avec `npx clawhub@latest install clawsec-suite`, puis remplissez les étapes de configuration à partir des instructions générées.

### Notes Shell et OS

Les scripts ClawSec sont divisés entre :
- Plateforme transversale Outillage Noeud/Python (`npm run build`, crochet/réglage `.mjs`, `utils/*.py`)
- Workflows shell POSIX (`*.sh`, la plupart des snipets d'installation manuelle)

Pour Linux/macOS (`bash`/`zsh`):
- Utiliser des vars d'habitation sans ou double citations: `export INSTALL_ROOT="$HOME/.openclaw/skills"`
- Ne pas **** vars extensibles à simple cote (par exemple, éviter `'$HOME/.openclaw/skills'`)

Pour Windows (PowerShell):
- Préférez la construction explicite du chemin :
- `$env:INSTALL_ROOT = Join-Path $HOME ".openclaw\\skills"`
- `node "$env:INSTALL_ROOT\\clawsec-suite\\scripts\\setup_advisory_hook.mjs"`
- POSIX `.sh` nécessitent WSL ou Git Bash.

Dépannage : si vous voyez des répertoires tels que `~/.openclaw/workspace/$HOME/...`, une variable d'accueil a été transmise littéralement. Re-exécuter en utilisant un chemin absolu ou une expression de la maison non citée.

---

Documentation sur la plateforme et la suite

Des documents détaillés sur la plateforme et la suite sont disponibles dans les modules wiki :
- NanoClaw: [wiki/modules/nanoclaw-integration.md](wiki/modules/nanoclaw-integration.md)
- Hermès: [wiki/modules/hermes-attestation-guardian.md](wiki/modules/hermes-attestation-guardian.md)
- Picoclaw: [wiki/modules/picoclaw-security-guardian.md](wiki/modules/picoclaw-security-guardian.md)
- Picoclaw auto-test : [wiki/modules/picoclaw-self-pen-testing.md](wiki/modules/picoclaw-self-pen-testing.md)
- ClawSec Suite (OpenClaw): [wiki/modules/clawsec-suite.md](wiki/modules/clawsec-suite.md)
- pipelines CI/CD: [wiki/modules/automation-release.md](wiki/modules/automation-release.md)

Liens d'installation rapide :
- Installation de NanoClaw : [skills/clawsec-nanoclaw/INSTALL.md](skills/clawsec-nanoclaw/INSTALL.md)
- Pack de compétences Hermes: `skills/hermes-attestation-guardian/`
- Paquet de protection Picoclaw: `skills/picoclaw-security-guardian/`
- Paquet Picoclaw auto-test: `skills/picoclaw-self-pen-testing/`
- Paquet Suite: `skills/clawsec-suite/`

---

No # # # Avis de sécurité

ClawSec tient à jour en permanence un avis de sécurité, alimenté automatiquement par la base de données nationale sur la vulnérabilité (NVD) du NIST.

URL du flux

```bash
# Fetch latest advisories
curl -s https://clawsec.prompt.security/advisories/feed.json | jq '.advisories[] | select(.severity == "critical" or .severity == "high")'
```

Critère canonique: `https://clawsec.prompt.security/advisories/feed.json`
Miroir de compatibilité (légère): `https://clawsec.prompt.security/releases/latest/download/feed.json`

Mots-clés surveillés

Les sondages sur les aliments du bétail ont porté sur :
- ** Plateforme OpenClaw** : `OpenClaw`, `clawdbot`, `Moltbot`
- **NanoClaw Platform**: `NanoClaw`, `WhatsApp-bot`, `baileys`
- **Picoclaw Platform**: `Picoclaw`, `picoclaw`, passerelles AI légères, exposition aux passerelles MCP
- Modèles d'injection rapides
- Vulnérabilités de sécurité des agents

Contexte d'exploitation

ClawSec enrichit les avis CVE avec **contexte d'exploitation** pour aider les agents à évaluer le risque réel au-delà des scores CVSS bruts. Les avis nouvellement analysés peuvent comprendre :

- **Exploiter des preuves**: si des exploits publics existent dans la nature
- ** État des armes** : Si les exploits sont intégrés dans des cadres d'attaque communs
- **Exigences d'adaptation**: Prérequis pour une exploitation réussie (accès au réseau, authentification, interaction utilisateur)
- **Évaluation des risques**: Niveau de risque contextuel combinant gravité technique et exploitabilité

Cette fonctionnalité aide les agents à prioriser les vulnérabilités qui posent des menaces immédiates par rapport aux risques théoriques, permettant ainsi des décisions de sécurité plus intelligentes.

Schéma consultatif

** NVD CVE Conseil :**
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

**Conseil communautaire:**
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

**Valeurs de la plateforme:**
- `"openclaw"` - OpenClaw/Clawdbot/Molt Bot seulement
- `"nanoclaw"` - NanoClaw seulement
- `"hermes"` - Hermès seulement
- `"picoclaw"` - Picoclaw seulement
- `["openclaw", "nanoclaw", "hermes", "picoclaw"]` - Toutes les plateformes centrales
- (vide/manque) - Toutes les plates-formes (compatible avec l'arrière)

---

Lignes de pipelines CI/CD

Les détails du pipeline CI/CD ont été déplacés vers la page du module wiki :
- [wiki/modules/automation-release.md](wiki/modules/automation-release.md)

Opérations connexes docs:
- [wiki/security-signing-runbook.md](wiki/security-signing-runbook.md)
- [wiki/migration-signed-feed.md](wiki/migration-signed-feed.md)

---

Outils hors ligne

ClawSec comprend Utilitaires Python pour le développement et la validation des compétences locales.

### Validateur de compétences

Valide un dossier de compétences en fonction du schéma requis :

```bash
python utils/validate_skill.py skills/clawsec-feed
```

Contrôles :
- `skill.json` existe et est valide JSON
- Champs obligatoires présents (nom, version, description, auteur, licence)
- Les fichiers SBOM existent et sont lisibles
- Les métadonnées OpenClaw sont bien structurées

Générateur de contrôles de compétences

Génére `checksums.json` avec SHA256 haches pour une compétence:

```bash
python utils/package_skill.py skills/clawsec-feed ./dist
```

Produits :
- `checksums.json` - SHA256 haches pour vérification

---

Développement local

Préalables

- Node.js 20+
- Python 3.10+ (pour les outils hors ligne)
- npm

Configuration

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

- Oui. Populer des données locales

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

Remarques:
- `npm run dev` et `npm run build` régénèrent automatiquement les exportations de wikis `llms.txt` (Hooks `predev`/`prebuild`).
- `public/wiki/` est généré en sortie (locale + CI) et est intentionnellement gitagnolé.

Construire

```bash
npm run build
```

---

Structure du projet

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

Contribution

Nous saluons les contributions! Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les lignes directrices.

### Soumettre des avis de sécurité

Trouvé un vecteur d'injection rapide, une compétence malveillante ou une vulnérabilité à la sécurité? Signalez-le via GitHub Questions :

1. Ouvrir un nouveau numéro en utilisant le modèle **Rapport d'incident de sécurité**
2. Remplissez les champs requis (série, type, description, compétences affectées)
3. Un responsable examinera et ajoutera l'étiquette `advisory-approved`
4. L'avis est automatiquement publié sur le flux sous la forme de `CLAW-{YEAR}-{ISSUE#}`

Voir [CONTRIBUTING.md](CONTRIBUTING.md#submitting-security-advisories) pour des lignes directrices détaillées.

Ajouter de nouvelles compétences

1. Créer un dossier de compétences sous `skills/`
2. Ajouter `skill.json` avec les métadonnées requises et SBOM
3. Ajouter `SKILL.md` avec des instructions lisibles par agent
4. Valider avec `python utils/validate_skill.py skills/your-skill`
5. Soumettre un rapport de situation pour examen

Source de documentation de la vérité

Pour tout le contenu wiki, éditer des fichiers sous `wiki/` dans ce dépôt. Le Wiki GitHub (`<repo>.wiki.git`) est synchronisé depuis `wiki/` par `.github/workflows/wiki-sync.yml` lorsque `wiki/**` change sur `main`.

Les exportations de LLM sont générées par `wiki/` vers `public/wiki/`:
- `/wiki/llms.txt` est l'exportation prête à LLM pour `wiki/INDEX.md` (ou un indice de repli généré si `INDEX.md` est manquant).
- `/wiki/<page>/llms.txt` est l'export LLM-ready pour cette seule page wiki.

---

Licence

- Code source : GNU AGPL v3.0 ou ultérieur - Voir [LICENSE](LICENSE) pour plus de détails.
- Polices dans `font/`: Licence séparée - Voir [`font/README.md`](font/README.md).

---

<div align="center">

**ClawSec** · Sécurité rapide, SentinelOne

C'est-à-dire Renforcer les workflows d'agents, une compétence à la fois.

</div>
