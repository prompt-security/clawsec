<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../migration-signed-feed.md
Review status: draft
-->

# Enregistrement de migration: Nourriture non signée → Nourriture signée (Complété)

Oui. 1) Objectif et statut

Documentez comment la distribution de conseils ClawSec est passée de la livraison non signée `feed.json` à la vérification de la signature individuelle, la compatibilité étant préservée pour les anciens clients.

Situation actuelle sur `main`:
- La publication de flux signés est active dans les flux de travail de conseil et de déploiement.
- Les consommateurs de Suite et NanoClaw sont par défaut sur les paramètres d'alimentation signés.
- Le comportement non signé n'existe que sous forme de contournement de compatibilité explicite (`CLAWSEC_ALLOW_UNSIGNED_FEED=1`).

Oui. 2) Données de référence (aujourd ' hui, après la migration)

Voies d'alimentation actuelles en utilisation active:
- Source de vérité: `advisories/feed.json`
- Signature de la source: `advisories/feed.json.sig`
- Copie des compétences : `skills/clawsec-feed/advisories/feed.json`
- Signature de la copie de compétence: `skills/clawsec-feed/advisories/feed.json.sig`
- Copie des pages : `public/advisories/feed.json`
- Signature des pages : `public/advisories/feed.json.sig`
- Dernière copie miroir: `public/releases/latest/download/advisories/feed.json` (+ `.sig`)

Par défaut du consommateur actuel :
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`
- `skills/clawsec-nanoclaw/lib/advisories.ts`
- URL par défaut : `https://clawsec.prompt.security/advisories/feed.json`

Oui. 3) Principes migratoires

- **Deuxième publication : publier les signatures avant de procéder à la vérification.
- **Non ouvert seulement pendant la transition** : la période de compatibilité temporaire est explicite et limitée dans le temps.
- **Mentions de déploiement**: faire appliquer la vérification après télémétrie confirme la stabilité de l'édition signée.
- **Fast runback**: préserver un chemin de retour au comportement non signé pendant que la cause racine est étudiée.

Oui. 4) Chronologie progressive (historique)

- Oui. Phase 0 — Préparation (achevée)

Produits livrables:
- clés de signature générées et empreintes digitales enregistrées
- Les secrets de GitHub créés
- clé(s) publique(s) ajoutée(s) en repo
- runbooks approuvés (`security-signing-runbook.md`, ce fichier)

Critères de sortie:
- empreintes clés vérifiées par l'examinateur
- contrôle des branches/flux de travail protégé activé

- Oui. Phase 1 — La signature de l'IC est activée, aucune exécution par le client (achevée)

Mettre en œuvre :
- ajouter l'étape de signature/le flux de travail pour produire `advisories/feed.json.sig`
- produire en option `advisories/checksums.json` + `.sig`
- s'assurer que l'IC vérifie les signatures avant la publication des artefacts

Actualiser également le déploiement :
- copier les artefacts `.sig` vers `public/advisories/`
- miroir `.sig` en `public/releases/latest/download/advisories/`

Critères de sortie:
- signatures générées avec succès pour tous les chemins de mise à jour de flux
- les artefacts de déploiement contiennent à la fois la charge utile et les compagnons de signature

- Oui. Phase 2 — Soutien à double lecture/vérification du consommateur (achevé)

Mettre en œuvre chez les consommateurs:
- lire `feed.json` et `feed.json.sig`
- vérifier avec la clé publique
- garder le contrôle temporaire non signé retour pendant la fenêtre de migration

Validation:
- parcours d'essai à distance signé
- tester le chemin de repli signé local
- essai de refus de signature non valide

Critères de sortie:
- logique de vérification libérée et testée
- aucune défaillance de vérification faussement positive pendant la période de stabilisation

- Oui. Phase 3 — Exécution (achevée)

Actions:
- désactiver le comportement de repli temporaire non signé dans les chemins par défaut
- ajouter des portes CI/publish qui échouent lorsque `.sig` est manquant
- annoncer la date d'exécution dans les notes de diffusion et les documents

Critères de sortie:
- tous les clients de production vérifient les signatures par défaut
- aucune dépendance d'alimentation non signée dans le débit d'installation standard

- Oui. Phase 4 — Stabilisation (en cours)

Actions:
- exécuter la première clé de rotation de la perceuse de table
- perceuse de table en marche arrière
- migration étroite avec examen post-mise en œuvre

Oui. 5) Plan de redressement

### Déclencheurs arrière

Lancer un renversement si l'une des situations suivantes se produit:
- défaillances persistantes de la vérification de la signature entre les clients
- la signature de workflow ne peut pas produire de signatures valides
- compromis clé suspecté mais la clé de remplacement n'est pas encore déployée
- chemin de déploiement publie des paires de charge utile/signature erronées

Niveau de recul

Niveau 1 (préféré): Fenêtre de contournement de vérification, publication signée

Utilisation lorsque : la signature est saine, le vérificateur côté client a un défaut.

Actions:
1. Réactiver le comportement temporaire non signé-acceptation dans la branche de libération du client.
2. Sortie du patch du navire avec date d'expiration explicite pour le contournement.
3. Continuez à signer le pipeline actif pour éviter les lacunes en matière d'authenticité.

Objectif de récupération: restaurer une vérification stricte dans les 24–48h.

Niveau 2 : pipeline signé interrompu, alimentation non signée faisant temporairement autorité

Utiliser lorsque : la signalisation est instable ou produit des artefacts incohérents.

Actions:
1. Désactiver le workflow de signature ou l'étape de signature.
2. Continuer à publier `advisories/feed.json` non signé via les workflows existants.
3. Révertissez les portes de déploiement qui nécessitent des artefacts `.sig`.
4. Ouvrir l'enregistrement des incidents et le temps de suivi en mode non signé.

Objectif de récupération: restaurer l'édition signée ASAP, idéalement <72h.

Niveau 3 : Gel complet

Utiliser quand: compromis ou intégrité du dépôt / flux de travail est en doute.

Actions:
1. Pas de mutation de flux d'alimentation et de déploiement.
2. Restaurer le commit connu-bon pour les fichiers de conseil / flux de travail.
3. Rotation des clés et des références.
4. Reprendre le pipeline seulement après l'approbation de l'examen de la sécurité.

Rouler après le retour

- identifier la cause racine
Ajouter les essais/portes de régression
- redéployer les artefacts signés
- publier un résumé de l'incident + des mesures correctives

Oui. 6) Plan de communication

Pour les événements d'exécution et de recul, communiquer :
- ce qui a changé
- action attendue de l'opérateur/client
- durée du mode de compatibilité temporaire (le cas échéant)
- commandes de vérification pour les utilisateurs

Chaînes recommandées:
- Notes de sortie de GitHub
- mises à jour du dépôt README/docs
- rapport d'incident dans le dépôt

Oui. 7) Liste de contrôle aller/pas aller

Allez seulement si tout est vrai:
- le taux de réussite des processus de signature est stable
- les signatures sont en miroir avec tous les paramètres d'alimentation documentés
- Voie de vérification du consommateur testée pour la distance + recul local
- le propriétaire de retour est assigné et accessible
- la procédure de rotation clé a été à sec au moins une fois

Références sources
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml
- compétences/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts
- compétences/clawsec-suite/scripts/guarded_skill_install.mjs
- avis/feed.json
- wiki/security-signing-runbook.md
