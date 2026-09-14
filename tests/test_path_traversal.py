#!/usr/bin/env python3
"""Regression tests for path-traversal guards in validate_skill and package_skill."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Allow importing from utils/ whether tests are run from the repo root or utils/
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "utils"))

from validate_skill import SkillPathError, validate_skill  # noqa: E402
from package_skill import package_skill  # noqa: E402

SKILLS_DIR = REPO_ROOT / "skills"

_MINIMAL_SKILL_JSON = {
    "name": "{name}",
    "version": "0.1.0",
    "description": "test skill",
    "author": "test",
    "license": "MIT",
    "sbom": {"files": [{"path": "skill.json"}]},
}


def _make_skill(parent: Path, name: str) -> Path:
    skill_dir = parent / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    data = dict(_MINIMAL_SKILL_JSON)
    data["name"] = name
    (skill_dir / "skill.json").write_text(json.dumps(data))
    return skill_dir


class TestValidateSkillPathGuard(unittest.TestCase):
    def setUp(self):
        self.in_tree_skill = _make_skill(SKILLS_DIR, "_test_tmp_skill_path_traversal")

    def tearDown(self):
        shutil.rmtree(self.in_tree_skill, ignore_errors=True)

    def test_rejects_dot_dot(self):
        with self.assertRaises(SkillPathError):
            validate_skill("../../etc")

    def test_rejects_absolute_outside_skills(self):
        with self.assertRaises(SkillPathError):
            validate_skill("/etc/passwd")

    def test_rejects_out_of_tree_tempdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_skill(Path(tmp), "evil")
            with self.assertRaises(SkillPathError):
                validate_skill(str(Path(tmp) / "evil"))

    def test_direct_call_out_of_tree(self):
        """validate_skill() called directly (not via main()) still raises SkillPathError."""
        with tempfile.TemporaryDirectory() as tmp:
            outside = _make_skill(Path(tmp), "direct_evil")
            with self.assertRaises(SkillPathError):
                validate_skill(str(outside))

    def test_accepts_in_tree_skill(self):
        """A skill inside skills/ should pass the containment check."""
        ok, _msg = validate_skill(str(self.in_tree_skill))
        self.assertTrue(ok)

    def test_symlink_escape_rejected(self):
        """A symlink inside skills/ that points outside skills/ is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            real_target = _make_skill(Path(tmp), "real_outside")
            link = SKILLS_DIR / "_test_symlink_escape"
            link.symlink_to(real_target)
            try:
                with self.assertRaises(SkillPathError):
                    validate_skill(str(link))
            finally:
                link.unlink(missing_ok=True)


class TestPackageSkillPathGuard(unittest.TestCase):
    def test_rejects_out_of_tree_path(self):
        """package_skill() must return (None, None) for a path outside skills/."""
        with tempfile.TemporaryDirectory() as tmp:
            outside = _make_skill(Path(tmp), "evil_pkg")
            result = package_skill(str(outside))
            self.assertEqual(result, (None, None))

    def test_rejects_dot_dot(self):
        result = package_skill("../../etc")
        self.assertEqual(result, (None, None))


if __name__ == "__main__":
    unittest.main()
