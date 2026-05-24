from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


def _load_module():
    module_path = Path(__file__).with_name("verify_skill_release_import_closure.py")
    spec = importlib.util.spec_from_file_location("verify_skill_release_import_closure", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class VerifySkillReleaseImportClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def test_empty_directory_does_not_satisfy_relative_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "runtime-lib").mkdir()
            (root / "main.mjs").write_text("import './runtime-lib';\n", encoding="utf-8")

            failures = self.module.verify_import_closure(root)

            self.assertEqual(len(failures), 1)
            self.assertIn("main.mjs imports ./runtime-lib", failures[0])

    def test_directory_import_requires_index_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            runtime_lib = root / "runtime-lib"
            runtime_lib.mkdir()
            (runtime_lib / "index.mjs").write_text("export {};\n", encoding="utf-8")
            (root / "main.mjs").write_text("import './runtime-lib';\n", encoding="utf-8")

            failures = self.module.verify_import_closure(root)

            self.assertEqual(failures, [])

    def test_ts_source_accepts_js_import_specifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "types.ts").write_text("export type Value = string;\n", encoding="utf-8")
            (root / "main.ts").write_text("import type { Value } from './types.js';\n", encoding="utf-8")

            failures = self.module.verify_import_closure(root)

            self.assertEqual(failures, [])

    def test_comment_import_examples_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.ts").write_text(
                "/*\n"
                " * Example integration:\n"
                " * import { Missing } from '../external/project/file';\n"
                " */\n"
                "export {};\n",
                encoding="utf-8",
            )

            failures = self.module.verify_import_closure(root)

            self.assertEqual(failures, [])

    def test_url_string_does_not_hide_following_relative_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.ts").write_text(
                'const feedUrl = "https://example.test/feed.json"; import value from "./missing.js";\n',
                encoding="utf-8",
            )

            failures = self.module.verify_import_closure(root)

            self.assertEqual(len(failures), 1)
            self.assertIn("main.ts imports ./missing.js", failures[0])

    def test_remote_import_spec_survives_comment_stripping(self) -> None:
        source = 'import remote from "https://example.test/module.mjs";\n'
        stripped = self.module.strip_js_ts_comments(source)

        specs = [match.group("spec") for match in self.module.IMPORT_RE.finditer(stripped)]

        self.assertEqual(specs, ["https://example.test/module.mjs"])

    def test_remote_runtime_import_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.mjs").write_text(
                'import remote from "https://example.test/module.mjs";\n',
                encoding="utf-8",
            )

            failures = self.module.verify_import_closure(root)

            self.assertEqual(len(failures), 1)
            self.assertIn("remote runtime import https://example.test/module.mjs", failures[0])


if __name__ == "__main__":
    unittest.main()
