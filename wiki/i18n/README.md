# i18n Pipeline (ClawSec)

This folder defines the translation QA and operations workflow for ClawSec docs.

## Goals
- Keep English as source of truth.
- Make language switching predictable in website/wiki routes.
- Preserve technical integrity in translated docs (commands, code blocks, links, package names).

## Files
- `terminology-en-es.md` — terminology lock and no-translate terms.
- `translation-tracker.md` — coverage and status by page.
- `scripts/i18n/qa_check.py` — translation integrity QA checker.
- `scripts/i18n/bootstrap_language_from_en.py` — scaffold generator for missing language pages.

## Local QA Command
```bash
python scripts/i18n/qa_check.py
```

Or via npm:
```bash
npm run i18n:qa
```

## Bootstrap Commands (language scaffolding)
Dry-run for any language:
```bash
python scripts/i18n/bootstrap_language_from_en.py --lang <code> --dry-run
```

Create missing pages for a language:
```bash
python scripts/i18n/bootstrap_language_from_en.py --lang <code>
```

Overwrite existing scaffolds if needed:
```bash
python scripts/i18n/bootstrap_language_from_en.py --lang <code> --overwrite
```

Convenience npm scripts:
```bash
npm run i18n:bootstrap:ko
npm run i18n:bootstrap:fr
npm run i18n:bootstrap:de
npm run i18n:bootstrap:ja
```

## What QA checks
- Fenced code blocks are preserved exactly from source.
- Critical inline technical tokens are preserved.
- Absolute URLs from source still exist in translation.
- Non-translatable product/skill terms remain unchanged.

## CI integration
Workflow: `.github/workflows/i18n-qa.yml`

Runs on PRs that touch:
- `README*.md`
- `wiki/**/*.md`
- `scripts/i18n/**`
- `.github/workflows/i18n-qa.yml`

## Translation backend strategy (local/free-first)
Recommended approach:
1. Local model for draft translation (NLLB/Marian via CTranslate2 or LibreTranslate self-hosted)
2. Free API fallback for difficult segments
3. Human review for high-impact docs (README, install, security pages)

## Rollout notes
- Add new language under `wiki/<lang>/` and `README.<lang>.md`.
- Add language option in `pages/WikiBrowser.tsx` label map when introducing a new language code.
- Update `translation-tracker.md` for new pages.
