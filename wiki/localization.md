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
3. **Scaffold missing pages (loop/script)**
   - Dry-run: `python scripts/i18n/bootstrap_language_from_en.py --lang <code> --dry-run`
   - Apply: `python scripts/i18n/bootstrap_language_from_en.py --lang <code>`
   - Optional overwrite: `python scripts/i18n/bootstrap_language_from_en.py --lang <code> --overwrite`
   - Convenience scripts: `npm run i18n:bootstrap:ko|fr|de|ja`
4. **Translate changed pages**
   - Preserve markdown structure and heading levels.
   - Keep command blocks untouched.
5. **QA pass**
   - Verify links resolve.
   - Verify code blocks and inline commands are unchanged.
   - Verify terminology consistency using `terminology-en-es.md`.
6. **Regenerate exports**
   - Run `npm run gen:wiki-llms`.
7. **Review and PR**
   - Include summary of translated pages and remaining gaps.

## Translation QA Checklist
- [ ] Heading hierarchy preserved.
- [ ] Command snippets unchanged and runnable.
- [ ] File paths and URLs unchanged.
- [ ] Skill and platform names unchanged.
- [ ] Security terminology consistent.
- [ ] `wiki/INDEX.md` has translation link entries.
- [ ] `wiki/<lang>/INDEX.md` links back to key English pages when untranslated.

## Suggested Language Rollout
1. Spanish (`es`) – done in phase 1 baseline.
2. French (`fr`) and German (`de`) for broad technical audience.
3. Japanese (`ja`) for high-fidelity platform docs.

## Source References
- README.md
- README.es.md
- wiki/INDEX.md
- wiki/es/INDEX.md
- wiki/es/overview.md
