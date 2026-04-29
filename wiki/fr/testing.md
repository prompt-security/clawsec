<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../testing.md
Review status: draft
-->

# Essais

## Stratégie d'essai
- Oui. Le dépôt utilise une vérification en couches plutôt qu'une seule commande racine `npm test`.
- La confiance de base provient de portes en peluche/type/construction plus compétences-local Suites de test de nœud.
- Les outils Python et shell sont validés au moyen de contrôles de lint/security dédiés.
- Les pipelines Workflow exécutent les mêmes classes de commande que celles utilisées pour l'automatisation pré-poussière locale.

## Calques de vérification
Calque Commandes Portée
- Oui.
Contrôles frontaux/statiques - Oui.
Tests d'unité d'aptitudeSpéciaux `node skills/<skill>/test/*.test.mjs`S Signature, correspondance, suppression, contrats d'installation. - Oui.
Qualité du python: `ruff check utils/`, `bandit -r utils/ -ll`. - Oui.
Shell / qualité de l'écriture ShellCheck + script manuel smoke runs. - Oui.
Tests de sécurité CI : Trivy, npm audit, CodeQL, Scorecard. - Oui.
Local pre-push security scan en option `gitleaks detect` via `scripts/prepare-to-push.sh`. - Oui.

## Matrice de test de compétence
Compétences Dossiers de test
- Oui.
`clawsec-suite`= `feed_verification`, `guarded_install`, `path_resolution`, tests de fuzz=Contrôle de signature, mise en garde, sécurité du trajet, robustesse correspondante. - Oui.
`openclaw-audit-watchdog` , config de suppression et render des tests , config parsing , le comportement de suppression , le formatage de rapport . - Oui.
`clawsec-clawhub-checker`.`reputation_check.test.mjs`.`reputation_check.test.mjs`.Z.Vérification d'entrée et comportement de gating de réputation. - Oui.

Couverture du flux de travail de l'IC
Flux de travail - Oui.
- Oui.
Lint/type/build, Python checks, scans de sécurité, tests de compétence. - Oui.
`codeql.yml` (en anglais seulement) - Oui.
`scorecard.yml`="horaire/poussoir" Rapport de posture de la chaîne d'approvisionnement et téléchargement SARIF. - Oui.
Tags de `skill-release.yml` PRs. - Oui.

Commandes locales de test
```bash
# baseline frontend + config checks
npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0
npx tsc --noEmit
npm run build
```

```bash
# representative skill tests
node skills/clawsec-suite/test/feed_verification.test.mjs
node skills/clawsec-suite/test/guarded_install.test.mjs
node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
```

## Modèles d'échec à regarder
- Les dispositifs de signature/test peuvent échouer lorsque les fichiers attendus sont régénérés de façon incohérente.
- Les tests de résolution de trajectoire échouent intentionnellement sur les jetons de maison échappés; ce comportement est attendu et pertinent pour la sécurité.
- Les scripts locaux s'appuyant sur les binaires `openclaw` ou `clawhub` peuvent échouer dans des environnements où ces CLI sont absents.
- Déployer/release logique peut passer localement alors qu'il échoue dans CI si la signature de secrets ou les autorisations de workflow diffèrent.

## Ordre d'essai suggéré
1. Lancez `./scripts/prepare-to-push.sh` pour une porte locale complète.
2. Exécuter des tests de compétence-local directement touchés.
3. Pour les modifications d'alimentation et de signalisation, exécutez d'abord les tests de vérification de la suite (`feed_verification`, `guarded_install`).
4. Pour les modifications de flux de travail ou de publication, exécutez également `scripts/validate-release-links.sh` et le script de cohérence des clés.

## Mettre à jour les notes
- 2026-02-26: Mise à jour des références sources à la liste de contrôle `wiki/platform-verification.md` migrée.

Références sources
- Agents.md
- scripts/prepare-to-poush.sh
- scripts/validate-release-links.sh
- .github/workflows/ci.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/workflows/kill-release.yml
- compétences/clawsec-suite/test/feed_vérification.test.mjs
- compétences/clawsec-suite/test/guarded_install.test.mjs
- compétences/clawsec-suite/test/path_resolution.test.mjs
- compétences/openclaw-audit-watchdog/test/suppression_config.test.mjs
- compétences/clawsec-clawhub-checker/test/reputation_check.test.mjs
- wiki/plateforme-vérification.md
