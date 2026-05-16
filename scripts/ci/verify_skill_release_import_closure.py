#!/usr/bin/env python3
"""Verify staged skill release JS/TS relative imports are self-contained.

The skill release workflow builds archives from `skill.json.sbom.files`. If a
runtime helper exists in the repo but is omitted from the SBOM, the staged
release can contain files whose relative imports point at missing files. This
script checks the staged payload, not the source tree, so it catches exactly
what would ship.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

IMPORT_RE = re.compile(
    r"(?:"
    r"\bimport\s+(?:type\s+)?(?:[^'\";]+?\s+from\s+)?"
    r"|\bexport\s+(?:type\s+)?[^'\";]+?\s+from\s+"
    r"|\bimport\s*\(\s*"
    r"|\brequire\s*\(\s*"
    r")"
    r"['\"](?P<spec>\.{1,2}/[^'\"]+)['\"]",
    re.MULTILINE,
)

SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}
RESOLUTION_SUFFIXES = ["", ".mjs", ".js", ".cjs", ".mts", ".ts", ".cts", ".json"]
INDEX_FILENAMES = ["index.mjs", "index.js", "index.cjs", "index.mts", "index.ts", "index.cts", "index.json"]


def candidate_paths(importer: Path, spec: str) -> list[Path]:
    base = (importer.parent / spec).resolve()
    candidates = [base]
    candidates.extend(base.with_suffix(suffix) for suffix in RESOLUTION_SUFFIXES if suffix and base.suffix == "")
    candidates.extend(base / name for name in INDEX_FILENAMES)
    return candidates


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def is_resolved_file(candidate: Path, root: Path) -> bool:
    return candidate.is_file() and is_within(candidate, root)


def verify_import_closure(root: Path) -> list[str]:
    root = root.resolve()
    failures: list[str] = []

    for source in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in SOURCE_SUFFIXES):
        text = source.read_text(encoding="utf-8", errors="ignore")
        for match in IMPORT_RE.finditer(text):
            spec = match.group("spec")
            candidates = candidate_paths(source, spec)
            if any(is_resolved_file(candidate, root) for candidate in candidates):
                continue

            rel_source = source.relative_to(root).as_posix()
            display_target = (source.parent / spec).resolve()
            try:
                rel_target = display_target.relative_to(root).as_posix()
            except ValueError:
                rel_target = str(display_target)
            failures.append(f"{rel_source} imports {spec} but {rel_target} is absent from staged release")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("staged_skill_dir", type=Path, help="Staged skill payload directory, e.g. $INNER_DIR")
    args = parser.parse_args()

    root = args.staged_skill_dir
    if not root.is_dir():
        print(f"error: staged skill directory not found: {root}", file=sys.stderr)
        return 2

    failures = verify_import_closure(root)
    if failures:
        print("Release import-closure check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print("Add the missing runtime file(s) to skill.json sbom.files or remove the stale import.", file=sys.stderr)
        return 1

    print(f"Release import-closure check OK: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
