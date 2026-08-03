#!/usr/bin/env python3
"""Translation QA checks for ClawSec docs.

Validates markdown translation pairs with a focus on technical integrity:
- fenced code blocks are preserved exactly
- key inline technical tokens are preserved
- absolute URLs from source are preserved
- non-translatable product/skill terms are preserved

This script checks only pairs that already exist (partial translation is allowed).
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Pair:
    source: Path
    target: Path


NON_TRANSLATABLE_TERMS = (
    "ClawSec",
    "OpenClaw",
    "NanoClaw",
    "Hermes",
    "Picoclaw",
    "clawsec-suite",
)

FEATURE_MATRIX_START = "<!-- skill-feature-matrix:start -->"
FEATURE_MATRIX_END = "<!-- skill-feature-matrix:end -->"
FEATURE_MATRIX_COLUMNS = 9
FEATURE_MATRIX_LANGUAGES = ("de", "es", "fr", "ja", "ko")


def _extract_fenced_blocks(text: str) -> list[str]:
    return re.findall(r"```[^\n]*\n.*?```", text, flags=re.DOTALL)


def _extract_inline_code(text: str) -> list[str]:
    return re.findall(r"`([^`\n]+)`", text)


def _extract_absolute_urls(text: str) -> set[str]:
    return set(re.findall(r"https?://[^\s)>'\"]+", text))


def _extract_feature_matrix_table(text: str) -> tuple[list[str], list[list[str]]]:
    if text.count(FEATURE_MATRIX_START) != 1 or text.count(FEATURE_MATRIX_END) != 1:
        raise ValueError("expected exactly one feature-matrix marker pair")

    start = text.index(FEATURE_MATRIX_START) + len(FEATURE_MATRIX_START)
    end = text.index(FEATURE_MATRIX_END, start)
    table_lines = [line.strip() for line in text[start:end].splitlines() if line.strip().startswith("|")]
    if len(table_lines) < 3:
        raise ValueError("feature matrix must contain a header, separator, and data rows")

    rows = [[cell.strip() for cell in line.strip("|").split("|")] for line in table_lines]
    if any(not re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in rows[1]):
        raise ValueError("feature matrix separator row is invalid")

    return rows[0], rows[2:]


def _matrix_identifier(value: str) -> str:
    return value.strip().strip("`")


def _check_feature_matrix_integrity(repo_root: Path) -> list[str]:
    errors: list[str] = []
    wiki_root = repo_root / "wiki"
    matrix_pages = [("en", wiki_root / "skill-feature-matrix.md")]
    matrix_pages.extend((lang, wiki_root / lang / "skill-feature-matrix.md") for lang in FEATURE_MATRIX_LANGUAGES)

    canonical_ids: list[str] | None = None
    for lang, matrix_path in matrix_pages:
        relative_path = matrix_path.relative_to(repo_root)
        if not matrix_path.is_file():
            errors.append(f"missing matrix page: {relative_path}")
            continue

        try:
            header, rows = _extract_feature_matrix_table(matrix_path.read_text(encoding="utf-8"))
        except ValueError as error:
            errors.append(f"{relative_path}: {error}")
            continue

        if len(header) != FEATURE_MATRIX_COLUMNS:
            errors.append(f"{relative_path}: expected {FEATURE_MATRIX_COLUMNS} header columns, found {len(header)}")

        malformed_rows = [index for index, row in enumerate(rows, start=1) if len(row) != FEATURE_MATRIX_COLUMNS]
        if malformed_rows:
            errors.append(
                f"{relative_path}: rows with invalid column counts: {', '.join(str(index) for index in malformed_rows)}"
            )

        identifiers = [_matrix_identifier(row[0]) for row in rows if row]
        if len(identifiers) != len(set(identifiers)):
            errors.append(f"{relative_path}: duplicate skill identifiers")

        if lang == "en":
            canonical_ids = identifiers
            skills_root = repo_root / "skills"
            skill_directories = sorted(path.name for path in skills_root.iterdir() if path.is_dir())
            if canonical_ids != skill_directories:
                errors.append(
                    f"{relative_path}: identifiers must exactly match the sorted skills/ directories "
                    f"(matrix={canonical_ids}, skills={skill_directories})"
                )
        elif canonical_ids is not None and identifiers != canonical_ids:
            errors.append(f"{relative_path}: localized skill identifiers or order differ from the English matrix")

        index_path = wiki_root / ("INDEX.md" if lang == "en" else f"{lang}/INDEX.md")
        if not index_path.is_file() or "(skill-feature-matrix.md)" not in index_path.read_text(encoding="utf-8"):
            errors.append(f"{index_path.relative_to(repo_root)}: missing feature-matrix navigation link")

        readme_path = repo_root / ("README.md" if lang == "en" else f"README.{lang}.md")
        expected_link = (
            "(wiki/skill-feature-matrix.md)" if lang == "en" else f"(wiki/{lang}/skill-feature-matrix.md)"
        )
        if not readme_path.is_file() or expected_link not in readme_path.read_text(encoding="utf-8"):
            errors.append(f"{readme_path.relative_to(repo_root)}: missing localized feature-matrix link")

    return errors


def _is_technical_inline_token(token: str) -> bool:
    checks = (
        "/" in token,
        token.startswith("./"),
        token.startswith("../"),
        token.endswith(".md"),
        token.endswith(".yml"),
        token.endswith(".json"),
        token.startswith("npx "),
        token.startswith("npm "),
        token.startswith("python "),
        token.startswith("node "),
        "--" in token,
        bool(re.search(r"\$[A-Z_][A-Z0-9_]*", token)),
    )
    return any(checks)


def _collect_pairs(repo_root: Path) -> list[Pair]:
    pairs: list[Pair] = []

    readme_en = repo_root / "README.md"
    for translated_readme in sorted(repo_root.glob("README.*.md")):
        if translated_readme.name == "README.md":
            continue
        if readme_en.exists():
            pairs.append(Pair(readme_en, translated_readme))

    wiki_root = repo_root / "wiki"

    language_dirs = {
        p.name
        for p in wiki_root.iterdir()
        if p.is_dir() and (p / "INDEX.md").exists() and p.name not in {"modules", "i18n", "assets"}
    }

    for source in wiki_root.rglob("*.md"):
        rel = source.relative_to(wiki_root)
        rel_parts = rel.parts
        if not rel_parts:
            continue

        # Skip language roots and i18n metadata as source files.
        if rel_parts[0] in language_dirs or rel_parts[0] == "i18n":
            continue

        for lang in sorted(language_dirs):
            target = wiki_root / lang / rel
            if target.exists():
                pairs.append(Pair(source, target))

    return sorted(pairs, key=lambda p: str(p.source))


def _extract_command_lines_from_fence(block: str) -> list[str]:
    lines = block.splitlines()[1:-1]
    cleaned: list[str] = []
    for line in lines:
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        cleaned.append(candidate)
    return cleaned


def _check_pair(pair: Pair) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    source_text = pair.source.read_text(encoding="utf-8")
    target_text = pair.target.read_text(encoding="utf-8")

    source_blocks = _extract_fenced_blocks(source_text)
    target_blocks = _extract_fenced_blocks(target_text)

    partial_pair = len(source_blocks) != len(target_blocks)

    if partial_pair:
        # Allow partial translations, but preserve command lines in translated fences.
        for idx, target_block in enumerate(target_blocks, start=1):
            for command_line in _extract_command_lines_from_fence(target_block):
                if command_line not in source_text:
                    errors.append(
                        f"translated code fence #{idx} contains command line not found in source: {command_line}"
                    )
        warnings.append(
            f"partial translation detected (code fences source={len(source_blocks)} target={len(target_blocks)})"
        )
    else:
        for idx, (src_block, tgt_block) in enumerate(zip(source_blocks, target_blocks), start=1):
            src_commands = _extract_command_lines_from_fence(src_block)
            tgt_commands = _extract_command_lines_from_fence(tgt_block)
            if src_commands != tgt_commands:
                errors.append(f"code fence #{idx} command lines differ from source")

    source_inline = {tok for tok in _extract_inline_code(source_text) if _is_technical_inline_token(tok)}
    missing_inline = sorted(tok for tok in source_inline if tok not in target_text)
    if missing_inline:
        preview = ", ".join(missing_inline[:8])
        extra = "" if len(missing_inline) <= 8 else f" (+{len(missing_inline) - 8} more)"
        msg = f"missing inline technical tokens: {preview}{extra}"
        if partial_pair:
            warnings.append(f"{msg} (partial pair)")
        else:
            warnings.append(msg)

    source_urls = _extract_absolute_urls(source_text)
    missing_urls = sorted(url for url in source_urls if url not in target_text)
    if missing_urls:
        preview = ", ".join(missing_urls[:5])
        extra = "" if len(missing_urls) <= 5 else f" (+{len(missing_urls) - 5} more)"
        msg = f"missing absolute URLs: {preview}{extra}"
        if partial_pair:
            warnings.append(f"{msg} (partial pair)")
        else:
            warnings.append(msg)

    for term in NON_TRANSLATABLE_TERMS:
        if term in source_text and term not in target_text:
            errors.append(f"non-translatable term missing: {term}")

    return errors, warnings


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    pairs = _collect_pairs(repo_root)

    if not pairs:
        print("[i18n-qa] No translation pairs found. Nothing to check.")
        return 0

    print(f"[i18n-qa] Checking {len(pairs)} translation pairs...")

    total_errors = 0
    total_warnings = 0
    for pair in pairs:
        rel_source = pair.source.relative_to(repo_root)
        rel_target = pair.target.relative_to(repo_root)
        errors, warnings = _check_pair(pair)
        for warn in warnings:
            total_warnings += 1
            print(f"WARN {rel_source} -> {rel_target} :: {warn}")
        if errors:
            total_errors += len(errors)
            print(f"\nFAIL {rel_source} -> {rel_target}")
            for err in errors:
                print(f"  - {err}")
        else:
            print(f"PASS {rel_source} -> {rel_target}")

    matrix_errors = _check_feature_matrix_integrity(repo_root)
    if matrix_errors:
        total_errors += len(matrix_errors)
        print("\nFAIL localized skill feature matrices")
        for error in matrix_errors:
            print(f"  - {error}")
    else:
        print("PASS localized skill feature matrices (6 pages, exact skill and column parity)")

    if total_errors:
        print(f"\n[i18n-qa] FAILED with {total_errors} issue(s) and {total_warnings} warning(s).")
        return 1

    print(f"\n[i18n-qa] All checks passed with {total_warnings} warning(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
