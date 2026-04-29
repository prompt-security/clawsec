<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../overview.md
Review status: draft
-->

♪ Aperçu général

Objet
- ClawSec est un dépôt axé sur la sécurité qui combine un catalogue web public avec des compétences de sécurité installables pour les environnements OpenClaw et NanoClaw.
- Oui. La base de codes prend en charge trois modes de livraison à la fois : l'édition statique du site Web, la distribution de conseils signée et l'emballage de libération par compétence GitHub.
- Les principaux utilisateurs sont les opérateurs d'agents, les développeurs de compétences et les responsables de l'automatisation de la sécurité basée sur l'IC.

![Prompt Security Logo](../assets/overview_img_01_prompt-security-logo.png)
![ClawSec Mascot](../assets/overview_img_02_clawsec-mascot.png)

Oui. Mise en page
Rôle Remarques
- Oui.
`pages/`, `components/`, `App.tsx`, `index.tsx`.Vite + React UI. - Oui.
Chaque compétence a `skill.json`, `SKILL.md`, scripts/tests/docs optionnels. - Oui.
`advisories/` Assemblage d'avis de dépôt Signé `feed.json` + `feed.json.sig` et matériel clé. - Oui.
`scripts/`= Automatisation locale= Popular feed/skills, pré-push checks, aide à la libération. - Oui.
`.github/workflows/`=1 pipelines CI/CD=1 IC, rejets, sondage NVD, ingestion de conseils communautaires, pages déployées. - Oui.
Utilitaires de Python de `utils/` de `utils/`. - Oui.
`public/`S Actifs statiques publiés. - Oui.
`wiki/`=Moyeu de documentation= Architecture, opérations, guides d'exécution, compatibilité et guides de vérification. - Oui.

Points d'entrée
Entrée Type Objet
- Oui.
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . - Oui.
`App.tsx`=Définit la carte de route pour les pages home, kills, feed et wiki. - Oui.
`scripts/prepare-to-push.sh` Obtenir le flux de travail Dev Exécute les contrôles de lint/type/build/security avant de pousser. - Oui.
`scripts/populate-local-feed.sh`= Données bootstrap=Pulls CVEs de NVD et met à jour les flux de conseils locaux. - Oui.
`scripts/populate-local-skills.sh`=_____________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________ - Oui.
`scripts/generate-wiki-llms.mjs`=Exportation de Docs=Génère `public/wiki/llms.txt` et des exportations wiki par page. - Oui.
`.github/workflows/skill-release.yml`= Entrée de la mainlevée. - Oui.
`.github/workflows/poll-nvd-cves.yml`= Mises à jour des flux programmés= Polls NVD et mises à jour des avis. - Oui.

Les principaux objets
Artefact Produit par Consommé par
- Oui.
`advisories/feed.json` Exclusivité du sondage NVD + flux de travail de conseil communautaire Exclusivité de l'interface Web, crochet clawsec-suite, installateurs. - Oui.
`advisories/feed.json.sig`=Signing workflow steps=Vérification de signature dans l'outil suite/nanoclaw. - Oui.
`public/skills/index.json`=Déployer le workflow / popular local script=`pages/SkillsCatalog.tsx` et `pages/SkillDetail.tsx`. - Oui.
`public/wiki/llms.txt` + `public/wiki/**/llms.txt`= script de générateur de Wiki + build hooks= Exportations de wikis LLM-ready liées depuis l'interface utilisateur wiki. - Oui.
`public/checksums.json` + `public/checksums.sig`.Déployer le flux de travail. - Oui.
`release-assets/checksums.json`=Skill release workflow Release consumers verified zip integrity. - Oui.
`skills/*/skill.json`= Auteurs qualifiés= Génération de catalogue de site, validateurs et pipelines de libération. - Oui.

Oui. Principaux flux de travail
- Développement web local : `npm install` puis `npm run dev`.
- Aperçu des données de sécurité locale: exécutez `./scripts/populate-local-skills.sh` et `./scripts/populate-local-feed.sh` avant de charger les pages `/skills` et `/feed`.
- Porte de qualité prépush: exécuter `./scripts/prepare-to-push.sh` (en option `--fix`).
- Cycle de vie des compétences : éditer `skills/<name>/`, valider avec `python utils/validate_skill.py`, puis marquer `<skill>-vX.Y.Z` pour déclencher le flux de travail de libération.
- Cycle de vie consultatif : le sondage prévu sur la DNV et l'ingestion communautaire fondée sur l'étiquetage des émissions fusionnent dans le même aliment signé.

## Exemples d'extraits
```bash
# local UI + locally populated data
npm install
./scripts/populate-local-skills.sh
./scripts/populate-local-feed.sh --days 120
npm run dev
```

```bash
# canonical TypeScript quality checks used by CI
npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0
npx tsc --noEmit
npm run build
```

Oui. Par où commencer
- Lire `README.md` pour le positionnement des produits et l'installation des chemins.
- Ouvrez `App.tsx` et `pages/` pour comprendre le comportement orienté vers l'utilisateur.
- Ouvrez `skills/clawsec-suite/skill.json` pour comprendre le contrat de suite et les composants intégrés.
- Examiner `.github/workflows/ci.yml`, `.github/workflows/pages-verify.yml`, `.github/workflows/skill-release.yml`, `.github/workflows/deploy-pages.yml` et `.github/workflows/wiki-sync.yml` pour le comportement de production.

Oui. Comment naviguer
- Le comportement de l'interface utilisateur est centré sur `pages/`; les enveloppes visuelles sont placées dans `components/`.
- La logique spécifique à la compétence est isolée par dossier sous `skills/` ; chaque dossier comprend ses propres scripts/tests/docs.
- La gestion des flux apparaît en trois couches : fichiers de flux de dépôt, mises à jour de flux de travail et consommateurs d'exécution (`clawsec-suite`/`clawsec-nanoclaw`).
- Portes de qualité opérationnelle en direct dans les fichiers `scripts/` et YAML workflow.
- Pour les traces de génération et la mise à jour des lignes de base, commencer à partir de `wiki/GENERATION.md` puis brancher dans les pages de module.

Pièges communs
- L'utilisation de jetons d'accueil littéraux (par exemple `\$HOME`) dans le chemin de configuration env vars peut déclencher des défaillances de validation de chemin.
- La saisie de JSON à partir des routes SPA peut retourner HTML avec l'état 200; pages garde pour cela et le traiter comme vide-état.
- Le mode de contournement d'alimentation non signé (`CLAWSEC_ALLOW_UNSIGNED_FEED=1`) existe pour la compatibilité de migration et ne doit pas être utilisé en état d'équilibre.
- L'automatisation des sorties de compétences prévoit la parité de version entre `skill.json` et `SKILL.md`.
- Certains scripts sont orientés vers le shell POSIX ; les utilisateurs de Windows devraient préférer les équivalents PowerShell ou WSL.

## Mettre à jour les notes
- 2026-02-26: Mise à jour de la mise en page pour pointer la documentation opérationnelle à `wiki/` au lieu du répertoire racine `docs/` supprimé.

Références sources
- PRÊT.md
- paquet.json
- App.tsx
- index.tsx
- pages/Home.tsx
- pages / SkillsCatalog.tsx
- pages/SkillDetail.tsx
- pages/FeedSetup.tsx
- scripts/prepare-to-poush.sh
- scripts/popular-local-feed.sh
- scripts/popular-local-skills.sh
- compétences/clawsec-suite/skill.json
- .github/workflows/ci.yml
- .github/workflows/pages-vérify.yml
- .github/workflows/kill-release.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/wiki-sync.yml
