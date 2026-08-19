# Translation Tracker

Track translation coverage and freshness versus English source docs.

_Last updated: 2026-08-18_

## README Coverage

| Language | Target | Status | Notes |
| --- | --- | --- | --- |
| German | `README.de.md` | current | Localized homepage, hero, and feature-matrix entry point; native review pending. |
| Spanish | `README.es.md` | current | Localized homepage, hero, and feature-matrix entry point; native review pending. |
| French | `README.fr.md` | current | Localized homepage, hero, and feature-matrix entry point; native review pending. |
| Japanese | `README.ja.md` | current | Localized homepage, hero, and feature-matrix entry point; native review pending. |
| Korean | `README.ko.md` | current | Localized homepage, hero, and feature-matrix entry point; native review pending. |

## Skill Feature Matrix Coverage

The English matrix at `wiki/skill-feature-matrix.md` is canonical. Localized matrices are Codex-assisted translations checked for terminology and structural parity; independent native-speaker review remains pending.

| Language | Localized page | Structure | Native review |
| --- | --- | --- | --- |
| German | `wiki/de/skill-feature-matrix.md` | 16 rows × 9 columns | pending |
| Spanish | `wiki/es/skill-feature-matrix.md` | 16 rows × 9 columns | pending |
| French | `wiki/fr/skill-feature-matrix.md` | 16 rows × 9 columns | pending |
| Japanese | `wiki/ja/skill-feature-matrix.md` | 16 rows × 9 columns | pending |
| Korean | `wiki/ko/skill-feature-matrix.md` | 16 rows × 9 columns | pending |

## Wiki Coverage (ES)

| Source page | Spanish page | Status |
| --- | --- | --- |
| `wiki/INDEX.md` | `wiki/es/INDEX.md` | done |
| `wiki/overview.md` | `wiki/es/overview.md` | done |
| `wiki/skill-feature-matrix.md` | `wiki/es/skill-feature-matrix.md` | done |
| `wiki/localization.md` | `wiki/es/localization.md` | done |
| `wiki/architecture.md` | — | pending |
| `wiki/security.md` | `wiki/es/security.md` | done |
| `wiki/configuration.md` | — | pending |
| `wiki/testing.md` | — | pending |
| `wiki/workflow.md` | — | pending |

## English Source Freshness Notes

| Date | Changed pages | Translation impact |
| --- | --- | --- |
| 2026-08-18 | `wiki/workflow.md` | Documented PR-local Pages validation and post-deploy production endpoint verification, including retry/backoff behavior and trigger scope. Translation refresh pending. |
| 2026-06-14 | `wiki/workflow.md`, `wiki/modules/automation-release.md`, `wiki/security-signing-runbook.md`, `wiki/dependencies.md`, `wiki/glossary.md` | Added SkillSpector release-pipeline documentation, signed-report behavior, and PR comment behavior. Translation refresh pending. |

## Wiki Coverage (KO)

| Source page | Korean page | Status |
| --- | --- | --- |
| `wiki/INDEX.md` | `wiki/ko/INDEX.md` | done |
| `wiki/overview.md` | `wiki/ko/overview.md` | partial |
| `wiki/skill-feature-matrix.md` | `wiki/ko/skill-feature-matrix.md` | done |
| `wiki/security.md` | `wiki/ko/security.md` | done |
| `wiki/localization.md` | `wiki/ko/localization.md` | done |
| `wiki/configuration.md` | `wiki/ko/configuration.md` | done |

## Wiki Coverage (FR/DE/JA)

| Language | Coverage status | Notes |
| --- | --- | --- |
| `fr` | partial | Feature matrix translated; remaining pages include auto-generated draft scaffolds. |
| `de` | partial | Feature matrix translated; remaining pages include auto-generated draft scaffolds. |
| `ja` | partial | Feature matrix translated; remaining pages include auto-generated draft scaffolds. |

## Phase Plan

### Phase 1 (completed)
- Establish translation baseline:
  - `README.es.md`
  - `wiki/es/INDEX.md`
  - `wiki/es/overview.md`

### Phase 2 (in progress)
- Establish localization process:
  - `wiki/localization.md`
  - `wiki/es/localization.md`
  - terminology lock
  - translation tracker

### Phase 3 (next)
- Expand translated wiki coverage for security/operator pages.
- Add second language pilot (recommended: French or German).
