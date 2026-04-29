<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../security.md
Review status: draft
-->

♪ Sécurité

## Aperçu du modèle de sécurité
- ClawSec sécurise à la fois la distribution du contenu (artefacts signés) et le comportement d'exécution (gage consultatif, surveillance de l'intégrité).
- Les ancres de confiance sont piquées les clés publiques engagées en repo et vérifiées par rapport aux sorties générées par le workflow.
- Runtime consommateurs par défaut à la vérification-premier comportement avec des drapeaux de contournement de migration explicite.

Contrôles cryptographiques
Mécanisme de contrôle Lieu
- Oui.
- Oui. Authenticité de l'alimentation: Ed25519 signatures détachées (`feed.json.sig`) . - Oui.
L'intégrité de l'artefact Les manifestes de somme de contrôle SHA-256 (`checksums.json`) - Oui.
- Oui. Comparaison des empreintes digitales entre les docs + PEM canoniques. - Oui.
Mesure de vérification de la signature - Oui.

Contrôles d'exécution
Contrôle Composante Effet
- Oui.
`clawsec-advisory-guardian`= Alertes et conseils prudents basés sur des avis assortis. - Oui.
Installateur double confirmation Depuis `guarded_skill_install.mjs` Sortie `42` jusqu'à confirmation explicite des avis correspondants. - Oui.
Extension de la réputation de `clawsec-clawhub-checker`. - Oui.
`skill-signature-handler.ts` + outil MCP. - Oui.
Moniteur de base de l'intégrité : `soul-guardian` + NanoClaw Moniteur de l'intégrité : détection de la dérive, quarantaine, restauration, historique vérifiable. - Oui.

Contrôles de la chaîne d'approvisionnement et de l'IC
- L'IC court Trivy, npm audit, CodeQL, et Scorecard workflows.
- Les vérifications pré-push locales peuvent exécuter `gitleaks detect` lorsque `gitleaks` est installé.
- Release workflows valide l'existence du fichier SBOM avant l'emballage.
- Déployer le flux de travail vérifie l'empreinte de la clé de signature générée contre le matériel de clé canonique.
- Les documents de publication comprennent des commandes de vérification manuelle pour les consommateurs en aval.

## Livres d'incident et de rotation
- `wiki/security-signing-runbook.md` définit les phases de génération, de garde, de rotation et d'incident.
- `wiki/migration-signed-feed.md` définit les niveaux d'exécution et de renversement par étapes.
- Les chemins de retour priorisent la préservation de l'édition signée dans la mesure du possible et le décalage horaire.

## Exemples d'extraits
```bash
# verify canonical public key fingerprint
openssl pkey -pubin -in clawsec-signing-public.pem -outform DER | shasum -a 256
```

```bash
# run repo key-consistency guardrail used in CI
./scripts/ci/verify_signing_key_consistency.sh
```

## Échanges connus sur la sécurité
- Le mode de compatibilité non signé peut réduire l'assurance et devrait être désactivé une fois la migration terminée.
- Certains chemins de déploiement tolèrent les actifs de bilan non signés pour la compatibilité en arrière.
- Les contrôles de réputation reposent sur la sortie d'outillage externe et peuvent inclure les faux positifs/négatifs heuristiques.
- Les scripts locaux héritent de la confiance en l'environnement ; les shells locaux compromis peuvent encore subvertir les workflows de l'opérateur.

Possibilités de durcissement
- Supprimer les drapeaux de compatibilité non signés après stabilisation de la migration.
- Étendre la vérification déterministe de la somme de contrôle/signature de tous les fichiers de libération miroir.
- Ajouter des tests explicites pour les scénarios d'échec de signature au niveau du workflow.
- Augmenter la télémétrie d'exécution pour les défauts de récupération/vérification pour simplifier le triage des incidents.

## Mettre à jour les notes
- 2026-02-26: Repointed signature et références de migration à partir de fichiers racine `docs/` vers les pages d'exploitation `wiki/` dédiées.

Références sources
- Sécurité md
- wiki/security-signing-runbook.md
- wiki/migration-signé-feed.md
- scripts/ci/vérify_signing_key_consistance.sh
- .github/actions/sign-and-vérify/action.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/kill-release.yml
- .github/workflows/deploy-pages.yml
- compétences/clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs
- compétences/clawsec-suite/scripts/guarded_skill_install.mjs
- compétences/clawsec-clawhub-checker/scripts/enhanced_guarded_install.mjs
- compétences/soul-guardian/scripts/soul_guardian.py
- compétences/clawsec-nanoclaw/host-services/skill-signature-handler.ts
- compétences/clawsec-nanoclaw/guardian/integrity-monitor.ts
