<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../security-signing-runbook.md
Review status: draft
-->

# ClawSec - Manuel des opérations de signature

Oui. 1) Objet

Ce runbook définit les procédures opérationnelles d'introduction et d'exécution de la signature cryptographique dans le dépôt ClawSec.

Il couvre:
- génération clé
- Gestion secrète GitHub
- signature de l'intégration du flux de travail
- rotation et révocation des clés
- réponse incidente

Oui. 2) État d'exploitation actuel (important)

Sur `main`, les canaux de consultation et de diffusion sont signés et vérifiés par défaut:

- Rédactrices :
- `.github/workflows/poll-nvd-cves.yml` mises à jour `advisories/feed.json` et signes `advisories/feed.json.sig`
- `.github/workflows/community-advisory.yml` fait la même chose pour les rapports de diffusion approuvés
- les deux artefacts de flux signés synchronisés dans `skills/clawsec-feed/advisories/`
- Chemin de publication du flux :
- `.github/workflows/deploy-pages.yml` publie `public/advisories/feed.json` + `.sig`
- génère et signe `public/checksums.json` + `public/checksums.sig`
- publie la clé canonique `public/signing-public.pem` et `public/advisories/feed-signing-public.pem`
- les artefacts de compatibilité des miroirs sous `public/releases/latest/download/` (y compris `feed.json`, `feed.json.sig`, `checksums.json`, `checksums.sig`, `signing-public.pem`)
- consommateurs d'aliments pour animaux:
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`
- `skills/clawsec-nanoclaw/lib/advisories.ts`
- URL de flux par défaut est `https://clawsec.prompt.security/advisories/feed.json`

Le mode non signé reste un contournement de compatibilité explicite (`CLAWSEC_ALLOW_UNSIGNED_FEED=1`) et n'est pas le modèle d'exploitation à l'état stationnaire.

Oui. 3) Artefacts ciblés signés

Voie d'alimentation consultative
- `advisories/feed.json` (charge utile)
- `advisories/feed.json.sig` (signé Ed25519; base64)
- `advisories/feed-signing-public.pem` (clé publique piquée)

- Oui. Release artefact canal
- `<release>/checksums.json`
- `<release>/checksums.sig`
- `<release>/signing-public.pem`

Oui. 4) Rôles clés et garde

- **Propriétaire de la sécurité**: approuve les changements clés du cycle de vie et les mesures d'incident.
- **Platform owner**: maintient les flux de travail et les secrets GitHub.
- **Reviewer**: valide les empreintes digitales dans les PR/releases.

Politique :
- les clés privées ne sont jamais engagées
- les clés publiques sont engagées et revues par code
- la génération de clés se produit sur un poste de travail d'opérateur fiable ou un environnement soutenu par HSM

Oui. 5) Génération de clés (Ed25519)

> Courez depuis un poste de travail sécurisé. Ne pas courir sur les coureurs CI partagés.

```bash
# Feed signing keypair
openssl genpkey -algorithm Ed25519 -out feed-signing-private.pem
openssl pkey -in feed-signing-private.pem -pubout -out feed-signing-public.pem

# Release checksums signing keypair (optional separate key)
openssl genpkey -algorithm Ed25519 -out release-signing-private.pem
openssl pkey -in release-signing-private.pem -pubout -out release-signing-public.pem
```

Générer des empreintes digitales (stocker dans l'enregistrement de ticket/changement):

```bash
openssl pkey -pubin -in feed-signing-public.pem -outform DER | shasum -a 256
openssl pkey -pubin -in release-signing-public.pem -outform DER | shasum -a 256
```

Signe d'essai facultatif avant publication:

```bash
echo '{"probe":"ok"}' > /tmp/probe.json
openssl pkeyutl -sign -rawin -inkey feed-signing-private.pem -in /tmp/probe.json -out /tmp/probe.sig.bin
openssl base64 -A -in /tmp/probe.sig.bin -out /tmp/probe.sig
openssl base64 -d -A -in /tmp/probe.sig -out /tmp/probe.sig.bin
openssl pkeyutl -verify -rawin -pubin -inkey feed-signing-public.pem -in /tmp/probe.json -sigfile /tmp/probe.sig.bin
```

Oui. 6) Configuration des secrets GitHub

- Oui. Secrets requis

- `CLAWSEC_SIGNING_PRIVATE_KEY` — Clé privée Ed25519 codée par PEM (utilisée à la fois pour la signature de flux et de libération)
- `CLAWSEC_SIGNING_PRIVATE_KEY_PASSPHRASE` — (facultatif) passphrase si la clé privée est chiffrée

Procédure

1. Aller à **Paramètres de repo → Secrets et variables → Actions → Nouveau secret de dépôt**.
2. Coller le PEM complet, y compris l'en-tête/le pied.
3. Préférez GitHub ** Secrets environnementaux** (avec les examinateurs requis) pour l'établissement de la portée des tâches, dans la mesure du possible.
4. Enregistrer le ticket de changement avec :
- nom secret
- créateur
- temps de création
- empreinte digitale clé

- Oui. Protections environnementales recommandées

- Exiger l'approbation manuelle des flux de travail qui peuvent utiliser des secrets de signature.
- Restreindre qui peut modifier les workflows protégés.
- Activer la protection des branches pour `main` et exiger un examen pour les changements de flux de travail.

Oui. 7) Points d'intégration des flux de travail

Cette repo impose la signature comme un contrôle post-mutation, pré-publication.

Ligne d'alimentation

Points de mutation d'alimentation actuels:
- `.github/workflows/poll-nvd-cves.yml`
- `.github/workflows/community-advisory.yml`

Comportement actuel :
- l'étape du workflow signe `advisories/feed.json` dans `advisories/feed.json.sig`
- l'action de signature vérifie les signatures générées pendant l'exécution du workflow
- les artefacts signés sont engagés via l'automatisation des PR

- Oui. pipeline de pages

Éditeur actuel :
- `.github/workflows/deploy-pages.yml`

Comportement actuel :
- copie la charge utile/signature à `public/advisories/`
- génère + signes `public/checksums.json` et `public/checksums.sig`
- publie la clé de signature pour `public/signing-public.pem` et `public/advisories/feed-signing-public.pem`
- conseils miroirs + signe/checksum/clés compagnons dans les chemins de compatibilité `public/releases/latest/download/`

- Oui. pipeline de libération des compétences (durcissement recommandé)

Générateur de sortie actuel & #160;:
- `.github/workflows/skill-release.yml`

Comportement actuel :
- crée `checksums.json`, le signe comme `checksums.sig` et vérifie la signature avant de publier
- inclut `signing-public.pem` dans les actifs de libération
- valide les empreintes à clé publique générées par rapport au matériel à clé canonique

Oui. 8) Politique et manuel de rotation

Cadence de rotation
- Routine: tous les 90 jours (ou politique d'orga nisation plus stricte).
- Immédiatement : en cas d'exposition présumée, de changement de flux de travail non autorisé ou d'inadéquation de signature inexpliquée.

Étapes de rotation courantes

1. Générer de nouvelles paires de clés.
2. Ouvrez le PR qui met à jour les fichiers à clé publique et la documentation des empreintes digitales.
3. Ajoutez de nouvelles clés privées comme GitHub secret(s).
4. Fusionner les changements de flux de travail qui utilisent de nouvelles clés.
5. Resigner les derniers manifestes d'alimentation/libération.
6. Valider la vérification en CI et dans un client externe.
7. Enlever l'ancien secret de clé privée.
8. Conserver l'ancienne référence à la clé publique seulement aussi longtemps que nécessaire pour la vérification historique.

Étapes de révocation

1. Désactiver les workflows en utilisant la clé compromise.
2. Supprimer les secrets de GitHub compromis.
3. Communiquez la note de révocation et la nouvelle clé publique.
4. Résignez les derniers artefacts avec la clé de remplacement.
5. Publier un avis d'incident avec horodatage et fenêtre impactée.

Oui. 9) Manuel de réponse aux incidents (spécifique à la signature)

Déclencheurs
- non-vérification de la signature pour les aliments pour animaux/délivrance nouvellement publiés
- validations/modifications de flux de travail inconnues touchant les chemins de signature
- fuite de matériel clé, abattage accidentel ou accès secret suspect

Guide de gravité
- **SEV-1**: publication de la charge utile confirmée ou signée par malveillance
- **SEV-2**: défaillances de vérification pour cause inconnue
- **SEV-3**: non-respect des procédures, pas de compromis actif

- Oui. Phases de réponse

1. **Contenu* *
- pause signature/publication des workflows
- bloquer les flux de fusion si l'authenticité est incertaine
2. **Enquête**
- revoir les journaux d'exécution des flux de travail
- l'examen s'engage à affecter `.github/workflows/`, `advisories/`, et les fichiers clés
- déterminer le premier horodatage et les artefacts affectés
3. **Éradication**
- rotation/revocation des clés compromises
- restaurer des artefacts de confiance à partir de commit de bien connu
4. **Récupération**
- resigner les artefacts
- des pages/éditions redéployées
- vérifier par un contrôle indépendant du client
5. **Après un incident* *
- publier le calendrier et le résumé des mesures correctives
- renforcer les contrôles (portes d'examen, environnements protégés, portée secrète)

## 10) Liste de vérification des éléments probants

Pour chaque cycle de libération ou exécution de la signalisation d'alimentation, conserver:
- Exécuter URL et commit SHA
- empreinte digitale de la clé de signature utilisée
- registres des résultats de vérification
- les agréments d'opérateur/d'examinateur
- toute exception ou justification de contournement

## 11) Critères d'acceptation minimum avant des changements de politique plus stricts

Avant de renforcer la politique (par exemple, supprimer les voies de contournement de compatibilité):
- les artefacts signés sont produits régulièrement pendant au moins 2 semaines
- Déployer les compagnons de signature des miroirs de pipeline
- une perceuse de renversement et une perceuse de rotation clé terminée avec succès
- réponse à l'incident sur appel propriétaire identifié et documenté

Références sources
- avis/feed.json
- avis/feed.json.sig
- avis/signature d'alimentation-public.pem
- clawsec-signing-public.pem
- .github/actions/sign-and-vérify/action.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/kill-release.yml
- scripts/ci/vérify_signing_key_consistance.sh
- wiki/migration-signé-feed.md
