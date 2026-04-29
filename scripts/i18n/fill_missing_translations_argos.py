#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

import argparse

from argostranslate import translate

RE_INLINE_CODE = re.compile(r"`[^`]*`")
RE_MD_LINK = re.compile(r"\[[^\]]*\]\([^\)]*\)")


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
    for k, v in mapping.items():
        out = out.replace(k, v)
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


def _process_pair(source: Path, target: Path, tr) -> int:
    src_lines = source.read_text(encoding="utf-8").splitlines()
    src_set = {l for l in src_lines if l.strip()}
    tgt_lines = target.read_text(encoding="utf-8").splitlines()
    changed = 0
    in_code = False

    for i, tgt in enumerate(tgt_lines):
        if tgt.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue

        # only fill lines still in English (line text matches a source line)
        if tgt not in src_set:
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

    only = set(args.only or [])

    # README
    readme_target = f"README.{args.lang}.md"
    if not only or readme_target in only:
        total += _process_pair(repo / "README.md", repo / readme_target, tr)

    # wiki/de
    lang_root = repo / "wiki" / args.lang
    for lang_file in sorted(lang_root.glob("*.md")):
        if only and lang_file.name not in only:
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
