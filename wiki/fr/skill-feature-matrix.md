<!--
Translation source: ../skill-feature-matrix.md
Last synchronized: 2026-08-02
Method: Codex-assisted translation with repository terminology and structural parity checks
Review status: native-speaker review pending
-->

# Matrice des fonctionnalités par skill

Cette page conserve la comparaison des fonctionnalités de chaque package ClawSec. La page anglaise est la source canonique ; cette traduction garde le même ordre de packages et le même sens pour chaque statut.

La synthèse par plateforme regroupe la couverture de la famille de packages actuelle. Une fonctionnalité peut nécessiter un skill distinct au lieu d’être incluse dans le point d’entrée principal de la plateforme.

## Synthèse par plateforme

| Plateforme | Gestion des avis et du flux | Intégrité et dérive | Audit et posture | Contrôle du risque à l’installation | Vérification de l’artefact candidat à l’installation | Signalement communautaire | Trafic à l’exécution |
| --- | --- | --- | --- | --- | --- | --- | --- |
| OpenClaw | Vérification des signatures et recherches externes | Via le package facultatif `soul-guardian` | Disponible | Contrôles par avis et réputation | Aucun vérificateur intégré d’artefacts candidats ; installation déléguée à ClawHub | Sur activation volontaire | Spécification uniquement |
| NanoClaw | Vérification des signatures en mode fail-closed | Intégrée | Audit des avis et vulnérabilités | Pré-vérification des avis | Intégration NanoClaw implémentée ; vérification des signatures des packages candidats avec une clé épinglée | Sur activation volontaire | Spécification uniquement |
| Hermes | Vérification des signatures en mode fail-closed | Intégrée | Vérification des attestations et de la posture | Pré-vérification des avis uniquement | Aucune vérification de l’artefact candidat | Sur activation volontaire | Spécification uniquement |
| Picoclaw | Consomme un état de flux vérifié en amont | Intégrée | Profilage de posture intégré + examen distinct en lecture seule | Aucun contrôle d’installation | Vérification exécutable des artefacts de version ; clé approuvée par l’appelant | Sur activation volontaire | Spécification uniquement |

Chaque package ClawSec publié documente un contrôle préalable manuel du manifeste signé pour sa propre archive autonome. Cette base commune d’intégrité des versions n’est pas répétée dans chaque ligne. `claw-release` guide aussi la production de ces versions signées. La colonne de vérification des candidats est réservée aux artefacts d’installation autres que l’archive propre au package.

## Couverture package par package

<!-- skill-feature-matrix:start -->
| Nom du skill | Plateforme | Gestion des avis et du flux | Intégrité et dérive | Audit et posture | Contrôle du risque à l’installation | Vérification de l’artefact candidat à l’installation | Signalement communautaire | Trafic à l’exécution |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `claw-release` | OpenClaw | Non | Non | Non | Non | Aucune vérification de l’artefact candidat | Non | Non |
| `clawsec-clawhub-checker` | OpenClaw + intégration à `clawsec-suite` | Contrôle d’avis de la suite | Non | Non | Réputation ClawHub + contrôle d’avis de la suite | Aucune vérification de l’artefact candidat | Non | Non |
| `clawsec-feed` | OpenClaw | Package de données d’avis ; interrogation gérée par la suite ou l’opérateur ; aucune vérification de signature du flux | Non | Non | Non | Aucune vérification de l’artefact candidat | Non | Non |
| `clawsec-nanoclaw` | NanoClaw | Vérification des signatures en mode fail-closed | Fichiers de référence + restauration facultative | Audit des avis/vulnérabilités ; aucun test actif | Pré-vérification des avis | Intégration NanoClaw implémentée ; vérification des signatures de packages candidats avec clé épinglée | Non | Non |
| `clawsec-scanner` | OpenClaw | Recherche externe de CVE ; aucune vérification du flux signé | Non | Audit des dépendances, SAST et hooks statiques ; aucune exploitation active | Non | Aucune vérification de l’artefact candidat | Non | Non |
| `clawsec-suite` | OpenClaw | Vérification du flux signé + du manifeste de sommes de contrôle | Via `soul-guardian` facultatif ; non intégré | Non | Contrôle d’avis + confirmation explicite | Aucun vérificateur intégré d’artefacts candidats ; uniquement un utilitaire générique de vérification des signatures détachées ; installation déléguée à ClawHub | Non | Non |
| `clawtributor` | Toutes les plateformes principales | Non | Non | Non | Non | Non | Préparation locale soumise à approbation + envoi manuel | Non |
| `hermes-attestation-guardian` | Hermes | Vérification des signatures en mode fail-closed | Dérive des attestations, de la configuration et des ancres de confiance | Vérification des attestations et de la posture | Pré-vérification des avis uniquement | Aucune vérification de l’artefact candidat | Non | Non |
| `hermes-traffic-guardian` | Hermes | Non | Export de posture prévu uniquement | Non | Non | Non | Non | Spécification uniquement ; aucun proxy d’exécution |
| `nanoclaw-traffic-guardian` | NanoClaw | Non | Non | Non | Non | Non | Non | Spécification uniquement ; aucun proxy d’exécution |
| `openclaw-audit-watchdog` | OpenClaw | Non | Non | Audit automatisé avec mode approfondi ; aucune exploitation active | Non | Non | Non | Non |
| `openclaw-traffic-guardian` | OpenClaw | Non | Non | Non | Non | Non | Non | Spécification uniquement ; aucun proxy d’exécution |
| `picoclaw-security-guardian` | Picoclaw | Consomme un état de flux vérifié ; vérification cryptographique en amont | Dérive déterministe du profil et de la configuration | Contrôles de posture en lecture seule | Non | Vérification exécutable des artefacts de version Picoclaw par vérification de la somme de contrôle et du manifeste signé ; clé approuvée par l’appelant | Non | Non |
| `picoclaw-self-pen-testing` | Picoclaw | Non | Non | Examen de posture self-pen en lecture seule ; aucune exploitation active | Non | Non | Non | Non |
| `picoclaw-traffic-guardian` | Picoclaw | Non | Export de profil prévu uniquement | Non | Non | Non | Non | Spécification uniquement ; aucun proxy d’exécution |
| `soul-guardian` | OpenClaw | Non | État de référence des fichiers du workspace, détection de dérive et restauration facultative | Non | Non | Non | Non | Non |
<!-- skill-feature-matrix:end -->

## Définition des statuts

- **Vérification des signatures** signifie que le package vérifie lui-même les éléments de confiance signés. La **surveillance**, la **recherche externe** et l’**état vérifié en amont** restent distincts.
- Le **contrôle du risque à l’installation** couvre les avis ou la réputation avant l’installation. Il ne prouve pas la provenance de l’artefact candidat.
- Le **contrôle préalable commun du package lui-même** ne couvre que l’archive de version correspondante. La colonne de vérification des candidats enregistre le contrôle d’autres artefacts d’installation.
- **Audit et posture** regroupe les contrôles statiques, de dépendances, d’avis, d’attestations et de posture en lecture seule. La matrice précise lorsqu’aucune exploitation active n’a lieu.
- **Via un module complémentaire facultatif** signifie que le package principal peut découvrir ou coordonner un skill distinct sans livrer lui-même la fonctionnalité.
- **Spécification uniquement** signifie que le dossier, les métadonnées, le frontmatter et le contrat d’implémentation existent, mais qu’aucun proxy d’exécution n’est livré.
- **Export de posture/profil prévu uniquement** décrit un contrat d’intégration dans une spécification traffic-guardian, et non un moniteur de dérive livré.

`clawtributor` est un package de signalement d’incidents multiplateforme. Ses valeurs `Non` indiquent que les autres capacités de protection de la matrice sortent du périmètre du signalement, pas que le package est inactif.

## Maintenance

Les 16 lignes de packages ont été récupérées depuis l’ancienne matrice du README. Les axes ont été séparés lorsque les anciennes valeurs binaires confondaient surveillance et vérification, audit et test actif, module complémentaire et fonction intégrée, ou contrôle d’avis et provenance des artefacts.

La matrice doit rester alignée sur les répertoires sous `skills/`. Le contrôle qualité des traductions vérifie que chaque matrice localisée conserve les mêmes 16 identifiants de package, le même ordre et une structure à neuf colonnes.

## Références source

- `skills/*/skill.json`
- `skills/*/SKILL.md`
- [Cœur de ClawSec Suite](../modules/clawsec-suite.md)
- [ClawSec Scanner](../modules/clawsec-scanner.md)
- [Intégration NanoClaw](../modules/nanoclaw-integration.md)
- [Hermes Attestation Guardian](../modules/hermes-attestation-guardian.md)
- [Picoclaw Security Guardian](../modules/picoclaw-security-guardian.md)
- [Picoclaw Self Pen Testing](../modules/picoclaw-self-pen-testing.md)
- [Spécification de référence Runtime Traffic Guardian](../modules/runtime-traffic-guardian-baseline.md)
