#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _all_docs() -> set[Path]:
    files = set(ROOT.glob("README*.md"))
    files.update(ROOT.glob("wiki/**/*.md"))
    return {p for p in files if p.is_file()}


def _changed_docs(base_ref: str) -> set[Path]:
    cmd = ["git", "diff", "--name-only", f"{base_ref}...HEAD"]
    output = subprocess.check_output(cmd, cwd=ROOT, text=True)
    docs: set[Path] = set()
    for rel in output.splitlines():
        if not rel.endswith(".md"):
            continue
        p = (ROOT / rel).resolve()
        if p in _all_docs() and p.exists():
            docs.add(p)
    return docs


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


def _select_docs(changed_only: bool, base_ref: str) -> list[Path]:
    all_docs = _all_docs()
    if not changed_only:
        return sorted(all_docs)

    try:
        changed = _changed_docs(base_ref)
    except Exception as exc:  # noqa: BLE001
        print(f"[link-check] WARN: changed-only mode failed ({exc}); falling back to full scan")
        return sorted(all_docs)

    if not changed:
        print("[link-check] No changed markdown docs detected; nothing to check.")
        return []

    return sorted(changed)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check local markdown links in README/wiki docs")
    parser.add_argument("--changed-only", action="store_true", help="Check only changed markdown docs against a base ref")
    parser.add_argument("--base-ref", default="origin/main", help="Base ref for --changed-only (default: origin/main)")
    args = parser.parse_args()

    docs = _select_docs(args.changed_only, args.base_ref)
    failures: list[str] = []

    for doc in docs:
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

    scope = "changed docs" if args.changed_only else "all docs"
    print(f"[link-check] PASS: no broken local markdown links found ({scope}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
