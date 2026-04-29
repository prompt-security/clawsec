<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../configuration.md
Review status: draft
-->

Configuration #

Portée
- La configuration couvre les paramètres de construction frontend, les chemins de flux d'exécution, les déclencheurs de workflow et les contrats de métadonnées de compétences.
- La plupart des commandes sensibles à l'exécution sont des variables d'environnement préfixées avec `CLAWSEC_` ou `OPENCLAW_`.
- La normalisation du chemin est sensible à la sécurité et rejette intentionnellement les littérales non résolues.

## Variables d'exécution du noyau
Variable par défaut
- Oui.
`CLAWSEC_FEED_URL`.Hosted advisory URL.Hosted Suite hook and garded installator feed loading. - Oui.
`CLAWSEC_FEED_SIG_URL`= `<feed>.sig`= Source de signature séparée. - Oui.
`CLAWSEC_FEED_CHECKSUMS_URL`= `checksums.json` près de l'URL du flux. - Oui.
`CLAWSEC_FEED_PUBLIC_KEY`. - Oui.
`CLAWSEC_ALLOW_UNSIGNED_FEED`= `0`=Flag de contournement de migration temporaire. - Oui.
`CLAWSEC_VERIFY_CHECKSUM_MANIFEST`= `1`=Active la vérification du manifeste de contrôle. - Oui.
`CLAWSEC_HOOK_INTERVAL_SECONDS`= `300`=L'accélérateur de balayage du crochet. - Oui.

Règles de résolution du chemin
Règle du comportement Lieu d'exécution
- Oui.
Expansion `~` Résolue au répertoire d'origine détecté. - Oui.
`$HOME` / `${HOME}` expansion Resolved when unscaped. - Oui.
- Oui. Jetons d'accueil de Windows: `%USERPROFILE%`, `$env:USERPROFILE` normalisé. - Oui.
Les jetons échappés (`\$HOME`) sont rejetés par erreur explicite. - Oui.
Un chemin explicite non valide peut revenir au chemin par défaut avec un avertissement. - Oui.

Configuration de frontend et de build
- `vite.config.ts` définit le port (`3000`), l'hôte (`0.0.0.0`) et l'alias de chemin (`@`).
- `index.html` fournit Tailwind runtime config, polices personnalisées et jetons de couleur de base.
- `tsconfig.json` utilise la résolution de module de groupeur, `noEmit` et la configuration d'exécution JSX.
- `eslint.config.js` applique les règles TS, React, Hooks et les règles de linte spécifiques au script.

## Métadonnées sur les compétences Configuration
Groupe de champ Lieu Fonction
- Oui.
- Oui. Identité de la compétence de base: `skills/*/skill.json`. - Oui.
La liste des fichiers SBOM de `skill.json -> sbom.files` declare les artefacts requis pour la libération. - Oui.
Les métadonnées de la plate-forme sont des blocs `openclaw` ou `nanoclaw`. - Oui.
Suite catalog metatalogs. - Oui.

Configuration du flux de travail
- La configuration du programme existe dans les entrées `cron` (`poll-nvd-cves`, `codeql`, `scorecard`).
- Release workflow s'attend à la désignation de tag pattern `<skill>-v<semver>`.
- Le flux de travail de déploiement est déclenché par les événements CI/release `workflow_run` et l'expédition manuelle.
- La signature composite nécessite des entrées de clé privée et vérifie les signatures immédiatement après la signature.

## Exemples d'extraits
```bash
# run guarded install with explicit local signed feed paths
CLAWSEC_LOCAL_FEED="$HOME/.openclaw/skills/clawsec-suite/advisories/feed.json" \
CLAWSEC_LOCAL_FEED_SIG="$HOME/.openclaw/skills/clawsec-suite/advisories/feed.json.sig" \
CLAWSEC_FEED_PUBLIC_KEY="$HOME/.openclaw/skills/clawsec-suite/advisories/feed-signing-public.pem" \
node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill clawtributor --dry-run
```

```json
{
  "name": "example-skill",
  "version": "1.2.3",
  "sbom": {
    "files": [
      { "path": "SKILL.md", "required": true, "description": "Install docs" }
    ]
  }
}
```

Notes opérationnelles
- Continuez à signer les clés en dehors du dépôt et injectez uniquement via GitHub Secrets.
- Préférez les chemins absolus ou les expressions de la maison non-sacrées dans les variables d'environnement local.
- Traiter le mode d'alimentation non signé comme un support temporaire de migration, et non comme un fonctionnement normal.
- Relancer la validation des liens de sortie lors de l'édition des URL `SKILL.md` pour éviter les références d'artefact cassées.

Références sources
- rite.config.ts
- index.html
- tsconfig.json
- eslint.config.js
- compétences/clawsec-suite/skill.json
- compétences/clawsec-nanoclaw/skill.json
- compétences/clawsec-suite/hooks/clawsec-advisory-guardian/lib/utils.mjs
- compétences/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- compétences/clawsec-suite/scripts/guarded_skill_install.mjs
- scripts/validate-release-links.sh
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/kill-release.yml
- .github/actions/sign-and-vérify/action.yml
