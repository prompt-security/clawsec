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


def _extract_fenced_blocks(text: str) -> list[str]:
    return re.findall(r"```[^\n]*\n.*?```", text, flags=re.DOTALL)


def _extract_inline_code(text: str) -> list[str]:
    return re.findall(r"`([^`\n]+)`", text)


def _extract_absolute_urls(text: str) -> set[str]:
    return set(re.findall(r"https?://[^\s)>'\"]+", text))


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

    if total_errors:
        print(f"\n[i18n-qa] FAILED with {total_errors} issue(s) and {total_warnings} warning(s).")
        return 1

    print(f"\n[i18n-qa] All checks passed with {total_warnings} warning(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
