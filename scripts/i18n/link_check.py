#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _iter_docs() -> list[Path]:
    files = list(ROOT.glob("README*.md"))
    files.extend(ROOT.glob("wiki/**/*.md"))
    return sorted({p for p in files if p.is_file()})


def _should_skip(link: str) -> bool:
    return (
        not link
        or link.startswith("#")
        or "://" in link
        or link.startswith("mailto:")
        or link.startswith("tel:")
    )


def _resolve_target(doc: Path, link: str) -> Path:
    clean = link.split("#", 1)[0].strip()
    return (doc.parent / clean).resolve()


def main() -> int:
    failures: list[str] = []

    for doc in _iter_docs():
        rel_doc = doc.relative_to(ROOT)
        content = doc.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK_RE.finditer(content):
            raw_link = match.group(1).strip()
            if _should_skip(raw_link):
                continue

            target = _resolve_target(doc, raw_link)
            if not target.exists():
                failures.append(f"{rel_doc}: broken link -> {raw_link}")

    if failures:
        print(f"[link-check] FAILED: {len(failures)} broken link(s) found.")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("[link-check] PASS: no broken local markdown links found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
