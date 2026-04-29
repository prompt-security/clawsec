<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (de)
Source: ../localization.md
Review status: draft
-->

# Localization Workflow

## Purpose
Define a repeatable docs localization pipeline for ClawSec README and wiki pages.

## Scope
- Source language: English (`README.md`, `wiki/*.md`)
- Current translated language: Spanish (`README.es.md`, `wiki/es/*.md`)
- Korean pilot language: Korean (`README.ko.md`, `wiki/ko/*.md`)
- Future languages: `wiki/<lang>/...` and `README.<lang>.md`

## Source of Truth Rules
1. English files are canonical.
2. Translations must preserve commands, file paths, code blocks, and identifiers exactly.
3. Product names and skill names stay untranslated (`ClawSec`, `OpenClaw`, `NanoClaw`, `Hermes`, `Picoclaw`, skill package names).
4. When translation coverage is partial, translated files must state scope explicitly.

## Folder Conventions
- README translations:
  - `README.es.md`
  - Future: `README.fr.md`, `README.de.md`, `README.ja.md`, etc.
- Wiki translations:
  - `wiki/es/INDEX.md`
  - `wiki/es/<page>.md`
  - Future: `wiki/fr/<page>.md`, `wiki/de/<page>.md`, etc.
- Localization assets:
  - `wiki/i18n/terminology-en-es.md`
  - `wiki/i18n/translation-tracker.md`

## Update Workflow
1. **Normalize source docs first**
   - Update English source docs for clarity and structure before translation.
2. **Record delta**
   - Note changed English pages in `wiki/i18n/translation-tracker.md`.
3. **Translate changed pages**
- Präservieren Sie die Struktur und die Rubriken.
- Halten Sie Befehlsblöcke unberührt.
4. **QA pass**
- Verifizieren Sie die Links.
- Überprüfen Sie Codeblöcke und Inline-Befehle sind unverändert.
- Verifizieren Sie die Terminologiekonsistenz mit `terminology-en-es.md`.
5. **Regenerate exports**
- Laufen `npm run gen:wiki-llms`.
6. **Review and PR**
- Inklusive Zusammenfassung der übersetzten Seiten und Restlücken.

Übersetzung QA Checkliste
- [ ] Die Rubrik Hierarchie erhalten.
- Kommandoschnipsel unverändert und lauffähig.
- [ ] Dateipfade und URLs unverändert.
- [ ] Geschicklichkeit und Plattformnamen unverändert.
- Sicherheitsterminologie konsistent.
- [ ] `wiki/INDEX.md` hat Übersetzungslinkeinträge.
- [ ] `wiki/<lang>/INDEX.md` verlinkt zurück zu den wichtigsten englischen Seiten, wenn nicht übersetzt.

Sprache Rollout vorschlagen
1. Spanisch (`es`) – in Phase 1 Basislinie.
2. Französisch (`fr`) und Deutsch (`de`) für breites technisches Publikum.
3. Japanisch (`ja`) für High-Fidelity-Plattformen.

Quellenangaben
- README.md
- README.es.md
- wiki/INDEX.md
- wiki/es/INDEX.md
- wiki/es/overview.md
