<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../remediation-plan.md
Review status: draft
-->

# Plan d'assainissement transplateforme

Oui. Phase 1 : Fermeture immédiate du risque (achevée)

Jalons
- Mettre en œuvre l'expansion explicite du chemin d'accès à domicile + rejet de jeton suspect dans les chemins d'accès/installation à haut risque.
- Ajouter des tests de régression pour l'expansion du chemin et le rejet du jeton échappé.
- Ajouter la politique `.gitattributes` LF.
- Expand Node lint/type/build CI couverture vers Linux/macOS/Windows.
- Mettre à jour les documents d'installation avec le guidage spécifique au shell et le dépannage littéral `$HOME`.

Résultats
- Bogue de propagation du chemin `$HOME` adressée à la source.
- Core advisory/install path config échoue maintenant rapidement sur les jetons de chemin invalides.

---

Oui. Phase 2: Parité Windows pour les flux de travail critiques (suivant)

### gagne rapidement
- Ajouter de la puissance Équivalents Shell pour les commandes manuelles d'installation/de vérification les plus utilisées dans:
- `skills/clawsec-suite/SKILL.md`
- `skills/openclaw-audit-watchdog/SKILL.md`
- `README.md`
- Ajouter un `scripts/preflight.mjs` léger pour détecter les outils manquants et imprimer des conseils d'installation spécifiques à l'OS.

Jalons
- Pouvoir autochtone Instructions Shell pour la configuration de la suite et le crochet de conseil.
- Retour WSL/Git Bash documenté où les scripts shell sont inévitables.

---

Oui. Phase 3: Réduire le POSIX Surface de la coquille (réfacteur de l'épereur)

Objectifs de refactor
- `scripts/populate-local-feed.sh`
- `scripts/populate-local-skills.sh`
- `scripts/release-skill.sh`

Approche
- Re-implémenter des chemins critiques dans Node/Python pour supprimer la dépendance sur les pipelines `jq/sed/awk/find/chmod`.
- Préserver les enveloppes shell pour la compatibilité arrière; route vers de nouvelles implémentations multiplateforme.

Notes de migration
- Gardez les anciens points d'entrée de script comme enveloppes pour au moins une version mineure.
- Emiter les avertissements de déprécation avec des commandes de migration exactes.

---

Oui. Phase 4 : durcissement de l'IC et vérification continue

Jalons
- Gardez la matrice de nœuds (Linux/macOS/Windows) au besoin.
- Ajouter des tests de fumée Windows ciblés pour la manipulation du chemin d'installation.
- Ajoutez les notes de compatibilité de la commande OpenSSL, le cas échéant.

- Oui. Stratégie d'essai
- Local :
- Exécutez les suites de test Node qui couvrent l'expansion du chemin/la suppression/le comportement d'installation.
- Exécutez des vérifications de syntaxe pour les scripts modifiés.
- Oui.
- Contrôles des nœuds Matrix + essais d'installateur/suppression/path.
- Les scans de sécurité Linux-seulement restent, mais explicitement marqués comme Linux-scoped.

---

## Déroulement / considérations de libération

- Oui. Pas de changement d'interface de rupture introduit dans ce patch set; le comportement est plus strict seulement pour les jetons de chemin invalides/non élargis.
- Communiquer dans les notes de mise en liberté :
- validation du jeton de chemin maintenant appliquée
- comment corriger les valeurs env non valides
- où le pouvoir Exemples de Shell en direct

Références sources
- .gitattributes
- .github/workflows/ci.yml
- scripts/popular-local-feed.sh
- scripts/popular-local-skills.sh
- scripts/release-skill.sh
- compétences/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts
- compétences/clawsec-suite/scripts/guarded_skill_install.mjs
- compétences/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- wiki/plateforme-vérification.md
