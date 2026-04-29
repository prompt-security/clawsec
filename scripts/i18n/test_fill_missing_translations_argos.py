from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path


def _load_module():
    translate_stub = types.SimpleNamespace(get_translation_from_codes=lambda *_args: None)
    sys.modules.setdefault("argostranslate", types.SimpleNamespace(translate=translate_stub))

    module_path = Path(__file__).with_name("fill_missing_translations_argos.py")
    spec = importlib.util.spec_from_file_location("fill_missing_translations_argos", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeTranslator:
    def translate(self, line: str) -> str:
        return (
            line.replace("Brought to you von", "Bereitgestellt von")
            .replace("the Platform of AI Security", "die Plattform fuer KI-Sicherheit")
            .replace("requires WSL or Git Bash", "erfordern WSL oder Git Bash")
        )


class FillMissingTranslationsArgosTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def test_restore_tokens_handles_placeholder_variants(self) -> None:
        mapping = {
            "__TOK_0__": "`bash`",
            "__TOK_1__": "[Prompt Security](https://prompt.security)",
            "ZXQTOKEN2QXZ": "`node`",
        }

        restored = self.module._restore_tokens(
            "Use __TOK_0_, _TOK_1__, and ZXQTOKEN2 QXZ before running.",
            mapping,
        )

        self.assertEqual(
            restored,
            "Use `bash`, [Prompt Security](https://prompt.security), and `node` before running.",
        )

    def test_process_pair_translates_lines_that_still_contain_english_fragments(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = root / "source.md"
            target = root / "target.md"
            source.write_text(
                '<h4>Brought to you by <a href="https://prompt.security">Prompt Security</a>, '
                "the Platform of AI Security</h4>\n",
                encoding="utf-8",
            )
            target.write_text(
                '<h4>Brought to you von <a href="https://prompt.security">Prompt Security</a>, '
                "the Platform of AI Security>/h4>\n",
                encoding="utf-8",
            )

            changed = self.module._process_pair(source, target, FakeTranslator())

            self.assertEqual(changed, 1)
            self.assertIn("Bereitgestellt von", target.read_text(encoding="utf-8"))
            self.assertIn("die Plattform fuer KI-Sicherheit", target.read_text(encoding="utf-8"))

    def test_only_matching_accepts_repo_relative_wiki_targets(self) -> None:
        repo = Path("/repo")
        target = repo / "wiki" / "ja" / "overview.md"
        matches_only = getattr(self.module, "_matches_only", lambda *_args: False)

        self.assertTrue(matches_only(target, repo, {"wiki/ja/overview.md"}))
        self.assertTrue(matches_only(target, repo, {"overview.md"}))
        self.assertFalse(matches_only(target, repo, {"wiki/ja/security.md"}))


if __name__ == "__main__":
    unittest.main()
