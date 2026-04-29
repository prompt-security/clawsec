<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../platform-verification.md
Review status: draft
-->

# Liste de vérification de la plateforme

Utilisez cette liste de contrôle pour valider la portabilité et le comportement de manipulation du chemin après les changements.

## Vérification Linux

1. Exécuter les essais de Noyau:
   ```bash
   node skills/clawsec-suite/test/path_resolution.test.mjs
   node skills/clawsec-suite/test/guarded_install.test.mjs
   node skills/clawsec-suite/test/advisory_suppression.test.mjs
   node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
   ```
Prévue : tous les tests sont réussis.

2. Vérifier que le chemin `$HOME` n'est pas accepté au sens littéral :
   ```bash
   CLAWSEC_LOCAL_FEED='\$HOME/advisories/feed.json' \
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
Attendu : sort non-zéro avec l'erreur `Unexpanded home token`.

3. Vérifier que `$HOME` fonctionne :
   ```bash
   HOME=/tmp/clawsec-home node skills/clawsec-suite/test/path_resolution.test.mjs
   ```
Prévu: `$HOME` tests d'extension réussi.

## MacOS Vérification

1. Exécutez la même suite de test Node que Linux.
2. Confirmer que les hypothèses de chemin d'outillage OpenSSL sont documentées :
- Si vous utilisez des variations LibreSSL/OpenSSL, assurez-vous d'utiliser les formulaires de commande testés des docs.
3. Vérifier l'expansion de tilde dans le chemin de configuration :
   ```bash
   OPENCLAW_AUDIT_CONFIG=~/.openclaw/security-audit.json \
   node skills/openclaw-audit-watchdog/scripts/load_suppression_config.mjs --enable-suppressions
   ```
Attente : le chemin résout correctement (ou efface l'erreur de fichier non trouvée à l'emplacement élargi).

## Vérification de Windows (PowerShell)

1. Essais des nœuds de course:
   ```powershell
   node skills/clawsec-suite/test/path_resolution.test.mjs
   node skills/clawsec-suite/test/guarded_install.test.mjs
   node skills/clawsec-suite/test/advisory_suppression.test.mjs
   ```
Attendu : tous passent.

2. Vérifier la puissance Comportement d'extension du chemin Shell env :
   ```powershell
   $env:CLAWSEC_LOCAL_FEED = '$env:USERPROFILE\advisories\feed.json'
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
Attendu : le jeton de chemin est élargi/normalisé ou échoue avec une erreur claire si les fichiers cibles sont manquants.

3. Vérifier le rejet littéral des jetons échappés :
   ```powershell
   $env:CLAWSEC_LOCAL_FEED = '\$HOME\advisories\feed.json'
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
Prévue : erreur `Unexpanded home token` ; aucune création de répertoire avec `$HOME` littérale.

Oui. Sanité des extrémités de ligne

1. Confirmer que la politique de LF est présente :
   ```bash
   test -f .gitattributes && grep -n "eol=lf" .gitattributes
   ```
Attendu : les modèles de fichiers script/config font appliquer LF.

2. Après une commande CRLF-prone, vérifier les scripts toujours analyse:
   ```bash
   bash -n scripts/populate-local-feed.sh
   bash -n scripts/populate-local-skills.sh
   ```
Prévue : pas d'erreurs `^M` shebang/parse.

## Vérification explicite du bogue: Pas de `$HOME` Création de répertoires

1. Configurer un chemin avec un jeton littéral/échapé.
2. Exécutez la commande configuration/installation.
3. Vérifier la commande échoue tôt avec l'erreur symbolique.
4. Confirmer qu'aucun répertoire de segment `$HOME` n'a été créé sous les répertoires de travail.

Résultat attendu : ** aucun répertoire contenant `$HOME` littéral n'est créé par des scripts de configuration supportés. **

Références sources
- .gitattributes
- scripts/popular-local-feed.sh
- scripts/popular-local-skills.sh
- compétences/clawsec-suite/test/path_resolution.test.mjs
- compétences/clawsec-suite/test/guarded_install.test.mjs
- compétences/clawsec-suite/test/advisory_suppression.test.mjs
- compétences/clawsec-suite/scripts/guarded_skill_install.mjs
- compétences/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- compétences/openclaw-audit-watchdog/test/suppression_config.test.mjs
