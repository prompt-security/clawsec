<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../glossary.md
Review status: draft
-->

♪ Glossaire

Termes
Définition
- Oui.
Le document JSON (`feed.json`) contenant des avis de sécurité pour les compétences/plateformes. - Oui.
Specificateur affecté Obtenir un sélecteur de compétences tel que `skill@1.2.3`, wildcard ou gamme utilisé dans la logique correspondante. - Oui.
Installation surveillée Installation en deux étapes qui nécessite une confirmation explicite lorsque les avis correspondent. - Oui.
Dossiers SBOM Liste des artefacts déclarés dans `skill.json` utilisés pour l'emballage et la validation. - Oui.
Signature détachée (`.sig`) stockée séparément de la charge utile signée. - Oui.
Voir la carte de hachage du fichier (`checksums.json`) utilisée pour vérifier l'intégrité de la charge utile. - Oui.

## Conditions d'emballage des compétences
Définition
- Oui.
Catégorie de compétences Git tag formaté en `<skill>-v<semver>` utilisé par l'automatisation de la libération. - Oui.
Release Assets (en anglais seulement) Fichiers attachés à la version GitHub (zip, `skill.json`, checksums, signatures). - Oui.
Index du catalogue , liste générée consommée par le catalogue web. - Oui.
Composantes embarquées Ensemble de capacités d'une compétence incluse dans une autre (par exemple, alimentation intégrée dans la suite). - Oui.

## Avis et conditions de sécurité
Définition
- Oui.
Vérification clôturée par échec. - Oui.
Mode de compatibilité non signé. - Oui.
Règle de répression ─ Entrée config correspondant à `checkId` et `skill` pour supprimer les constatations connues/acceptées. - Oui.
Digest SHA-256 de clé publique encodée DER utilisée pour les contrôles de cohérence des clés. - Oui.

## Termes d'exécution et de plate-forme
Définition
- Oui.
OpenClaw Hook (`clawsec-advisory-guardian`) qui vérifie les avis. - Oui.
NanoClaw IPC= Échange de tâches d'hôte/conteneur pour la mise à jour des conseils, la vérification de la signature, les vérifications d'intégrité. - Oui.
L'intégrité Base de données L'enregistrement des hashes/snapshots approuvés pour les fichiers protégés. - Oui.
Registre de vérification à la suite d'une enquête Ajouter seulement le journal de vérification où chaque entrée dépend du hash antérieur. - Oui.

## Conditions CI/CD
Définition
- Oui.
Poll NVD CVEs Workflow (en anglais seulement) Workflow programmé qui récupère et transforme les CVE NVD en avis. - Oui.
Déroulement du travail d'avis de la collectivité Obtenir un document d'information qui publie les avis approuvés de la collectivité. - Oui.
Release Workflow (en anglais seulement) Emballage/signation/publishing pipeline pour les compétences. - Oui.
Déploiement des pages Flux de travail Flux de travail qui construit les actifs du site et les miroirs rejets/artefacts consultatifs. - Oui.

Références sources
- types.ts
- compétences/clawsec-suite/skill.json
- compétences/clawsec-nanoclaw/skill.json
- compétences/clawsec-suite/scripts/guarded_skill_install.mjs
- compétences/clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs
- compétences/clawec-suite/hooks/clawec-advisory-guardian/lib/suppression.mjs
- compétences/clawsec-nanoclaw/guardian/integrity-monitor.ts
- scripts/popular-local-feed.sh
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/kill-release.yml
- .github/workflows/deploy-pages.yml
