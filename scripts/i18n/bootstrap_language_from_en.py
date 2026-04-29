#!/usr/bin/env python3
"""Create missing translated wiki pages from English source.

Usage:
  python scripts/i18n/bootstrap_language_from_en.py --lang ko
  python scripts/i18n/bootstrap_language_from_en.py --lang ko --dry-run
  python scripts/i18n/bootstrap_language_from_en.py --lang ko --overwrite
"""

from __future__ import annotations

import argparse
from pathlib import Path

SKIP_TOP_LEVEL_DIRS = {"assets", "i18n", "modules"}


def build_header(lang: str, rel_path: str) -> str:
    return (
        f"<!-- AUTO-GENERATED TRANSLATION SCAFFOLD ({lang})\n"
        f"Source: ../{rel_path}\n"
        "Review status: draft\n"
        "-->\n\n"
    )


def discover_source_pages(wiki_root: Path, lang_dirs: set[str]) -> list[Path]:
    pages: list[Path] = []
    for page in wiki_root.rglob("*.md"):
        rel = page.relative_to(wiki_root)
        if not rel.parts:
            continue
        first = rel.parts[0]
        if first in SKIP_TOP_LEVEL_DIRS or first in lang_dirs:
            continue
        pages.append(page)
    return sorted(pages)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lang", required=True, help="language code, e.g. ko, es, fr")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    wiki_root = repo_root / "wiki"
    target_root = wiki_root / args.lang

    lang_dirs = {
        p.name
        for p in wiki_root.iterdir()
        if p.is_dir() and (p / "INDEX.md").exists() and p.name not in SKIP_TOP_LEVEL_DIRS
    }

    source_pages = discover_source_pages(wiki_root, lang_dirs)
    created = 0
    skipped = 0
    overwritten = 0

    for src in source_pages:
        rel = src.relative_to(wiki_root)
        dst = target_root / rel
        existed_before = dst.exists()

        if existed_before and not args.overwrite:
            skipped += 1
            continue

        src_text = src.read_text(encoding="utf-8")
        header = build_header(args.lang, rel.as_posix())
        out = header + src_text

        if not args.dry_run:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(out, encoding="utf-8")

        if existed_before:
            overwritten += 1
        else:
            created += 1

    mode = "DRY-RUN" if args.dry_run else "WRITE"
    print(f"[{mode}] lang={args.lang} source_pages={len(source_pages)} created={created} overwritten={overwritten} skipped={skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
