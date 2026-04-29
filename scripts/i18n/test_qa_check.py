from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


def _load_module():
    module_path = Path(__file__).with_name("qa_check.py")
    spec = importlib.util.spec_from_file_location("qa_check", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class QaCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def test_partial_pairs_still_fail_when_non_translatable_terms_are_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = root / "source.md"
            target = root / "target.md"
            source.write_text("ClawSec keeps this term.\n```sh\nnpm run build\n```\n", encoding="utf-8")
            target.write_text("Translated text without the product term.\n", encoding="utf-8")

            errors, warnings = self.module._check_pair(self.module.Pair(source, target))

            self.assertIn("non-translatable term missing: ClawSec", errors)
            self.assertTrue(any("partial translation detected" in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
