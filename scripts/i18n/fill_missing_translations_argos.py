#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from collections.abc import Iterable
from pathlib import Path

from argostranslate import translate

RE_INLINE_CODE = re.compile(r"`[^`]*`")
RE_MD_LINK = re.compile(r"\[[^\]]*\]\([^\)]*\)")
ENGLISH_HINTS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "before",
    "by",
    "for",
    "from",
    "if",
    "in",
    "is",
    "of",
    "on",
    "or",
    "the",
    "this",
    "to",
    "use",
    "using",
    "when",
    "with",
    "you",
    "your",
}


def _protect_tokens(line: str) -> tuple[str, dict[str, str]]:
    mapping: dict[str, str] = {}
    idx = 0

    def repl(pattern: re.Pattern[str], text: str) -> str:
        nonlocal idx

        def _r(m: re.Match[str]) -> str:
            nonlocal idx
            key = f"ZXQTOKEN{idx}QXZ"
            idx += 1
            mapping[key] = m.group(0)
            return key

        return pattern.sub(_r, text)

    out = line
    out = repl(RE_MD_LINK, out)
    out = repl(RE_INLINE_CODE, out)
    return out, mapping


def _restore_tokens(line: str, mapping: dict[str, str]) -> str:
    out = line
    for key, value in mapping.items():
        out = out.replace(key, value)

        old_style = re.fullmatch(r"__TOK_(\d+)__", key)
        if old_style:
            idx = old_style.group(1)
            out = re.sub(rf"_{{1,2}}TOK_{idx}_{{1,2}}", value, out)
            continue

        new_style = re.fullmatch(r"ZXQTOKEN(\d+)QXZ", key)
        if new_style:
            idx = new_style.group(1)
            out = re.sub(rf"ZXQTOKEN{idx}\s+QXZ", value, out)
    return out


def _should_translate(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    if s.startswith("<!--") or s.endswith("-->"):
        return False
    return True


def _translate_line(tr, line: str) -> str:
    protected, mapping = _protect_tokens(line)
    translated = tr.translate(protected)
    restored = _restore_tokens(translated, mapping)
    return restored


def _normalize_line(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def _looks_like_english(line: str) -> bool:
    words = re.findall(r"[A-Za-z]+", line.lower())
    if not words:
        return False
    hint_count = sum(1 for word in words if word in ENGLISH_HINTS)
    return hint_count >= 2


def _should_process_target_line(target_line: str, source_lines: set[str]) -> bool:
    normalized = _normalize_line(target_line)
    return normalized in source_lines or _looks_like_english(target_line)


def _process_pair(source: Path, target: Path, tr) -> int:
    src_lines = source.read_text(encoding="utf-8").splitlines()
    src_set = {_normalize_line(line) for line in src_lines if line.strip()}
    tgt_lines = target.read_text(encoding="utf-8").splitlines()
    changed = 0
    in_code = False

    for i, tgt in enumerate(tgt_lines):
        if tgt.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue

        # Only fill lines that are still unchanged or visibly retain English fragments.
        if not _should_process_target_line(tgt, src_set):
            continue
        if not _should_translate(tgt):
            continue

        new = _translate_line(tr, tgt)
        if new and new != tgt:
            tgt_lines[i] = new
            changed += 1

    if changed:
        target.write_text("\n".join(tgt_lines) + "\n", encoding="utf-8")
    return changed


def _normalize_only(values: Iterable[str] | None) -> set[str]:
    normalized: set[str] = set()
    for value in values or []:
        item = value.strip().replace("\\", "/")
        if not item:
            continue
        normalized.add(item)
        normalized.add(Path(item).name)
    return normalized


def _matches_only(path: Path, repo: Path, only: set[str]) -> bool:
    if not only:
        return True

    rel = path.relative_to(repo).as_posix()
    candidates = {path.name, rel}
    return bool(candidates & only)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lang", required=True, choices=["de", "es", "fr", "ja", "ko"])
    parser.add_argument(
        "--only",
        nargs="*",
        default=None,
        help="Optional list of target markdown filenames to process (e.g. README.ja.md overview.md security.md)",
    )
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    tr = translate.get_translation_from_codes("en", args.lang)
    if tr is None:
        raise SystemExit(f"Missing Argos en->{args.lang} model. Install first.")

    total = 0

    only = _normalize_only(args.only)

    # README
    readme_target = repo / f"README.{args.lang}.md"
    if _matches_only(readme_target, repo, only):
        total += _process_pair(repo / "README.md", readme_target, tr)

    # wiki/<lang>
    lang_root = repo / "wiki" / args.lang
    for lang_file in sorted(lang_root.glob("*.md")):
        if not _matches_only(lang_file, repo, only):
            continue
        if lang_file.name in {"INDEX.md", "GENERATION.md"}:
            continue
        src = repo / "wiki" / lang_file.name
        if src.exists():
            total += _process_pair(src, lang_file, tr)

    print(f"Updated translated lines for {args.lang}: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
