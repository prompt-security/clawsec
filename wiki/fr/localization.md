<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../localization.md
Review status: draft
-->

# Flux de travail de localisation

Objet
Définir un pipeline de localisation des docs répétables pour les pages de ClawSec README et wiki.

Portée
- Langue source: anglais (`README.md`, `wiki/*.md`)
- Langue traduite actuelle: espagnol (`README.es.md`, `wiki/es/*.md`)
- Langue pilote coréenne: coréen (`README.ko.md`, `wiki/ko/*.md`)
- Langues futures: `wiki/<lang>/...` et `README.<lang>.md`

Source des règles de vérité
1. Les fichiers anglais sont canoniques.
2. Les traductions doivent préserver les commandes, les chemins de fichiers, les blocs de code et les identifiants exactement.
3. Les noms de produits et les noms de compétences restent non traduits (`ClawSec`, `OpenClaw`, `NanoClaw`, `Hermes`, `Picoclaw`, noms de paquets de compétences).
4. Lorsque la couverture de traduction est partielle, les fichiers traduits doivent indiquer explicitement la portée.

## Dossier Conventions
- Traductions README :
- `README.es.md`
- Futur: `README.fr.md`, `README.de.md`, `README.ja.md`, etc.
- Traductions Wiki :
- `wiki/es/INDEX.md`
- `wiki/es/<page>.md`
- Avenir: `wiki/fr/<page>.md`, `wiki/de/<page>.md`, etc.
- Actifs de localisation :
- `wiki/i18n/terminology-en-es.md`
- `wiki/i18n/translation-tracker.md`

## Mettre à jour le flux de travail
1. **Normaliser les documents sources d'abord* *
- Mettre à jour les documents source en anglais pour plus de clarté et de structure avant la traduction.
2. **Enregistrement delta**
- Note modifiée pages en anglais dans `wiki/i18n/translation-tracker.md`.
3. **Translate changed pages**
- Préserver la structure de balisage et les niveaux de cap.
- Gardez les blocs de commande intacts.
4. **QA pass**
- Vérifier si les liens sont résolus.
- Vérifier que les blocs de code et les commandes en ligne sont inchangés.
- Vérifier la cohérence terminologique en utilisant `terminology-en-es.md`.
5. **Regenerate exports**
- Exécutez `npm run gen:wiki-llms`.
6. **Review and PR**
- Inclure un résumé des pages traduites et des lacunes restantes.

## Liste de contrôle de l'AQ pour la traduction
- [ ] Hiérarchie de cap conservée.
- Le commandement n'a pas changé.
- [ ] Chemins de fichiers et URLs inchangés.
- [ ] Compétence et noms de plate-forme inchangés.
- La terminologie de la sécurité est cohérente.
- [ ] `wiki/INDEX.md` a des entrées de lien de traduction.
- [ ] `wiki/<lang>/INDEX.md` renvoie à des pages anglaises clés lorsqu'elles ne sont pas traduites.

## Suggestion de déploiement du langage
1. Espagnol (`es`) – effectué au niveau de la phase 1.
2. Français (`fr`) et allemand (`de`) pour un large public technique.
3. Japonais (`ja`) pour les documents de plate-forme haute fidélité.

Références sources
- PRÊT.md
- LECTME.es.md
- wiki/INDEX.md
- wiki/es/INDEX.md
- wiki/es/overview.md
