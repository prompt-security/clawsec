#!/usr/bin/env python3
"""Offline release-package contract tests for clawsec-ps-fuzz."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_INSTALL = "npx skills add prompt-security/clawsec --skill clawsec-ps-fuzz -a openclaw -y"
EXPECTED_ARTIFACTS = {
    "CHANGELOG.md",
    "README.md",
    "SKILL.md",
    "THIRD_PARTY_NOTICES.md",
    "skill.json",
    "resources/capabilities-v2.1.0.json",
    "resources/requirements.in",
    "resources/requirements.lock",
    "resources/upstream.json",
    "scripts/ps_fuzz_runner.py",
    "test/test_package_contract.py",
    "test/test_ps_fuzz_runner.py",
}


class PackageContractTests(unittest.TestCase):
    """Keep install metadata and operator guidance aligned with the runner."""

    def setUp(self) -> None:
        self.skill = json.loads((SKILL_ROOT / "skill.json").read_text(encoding="utf-8"))
        self.docs = {
            filename: (SKILL_ROOT / filename).read_text(encoding="utf-8")
            for filename in ("SKILL.md", "README.md")
        }

    def test_metadata_is_public_harness_neutral_and_version_aligned(self) -> None:
        self.assertEqual(self.skill["name"], "clawsec-ps-fuzz")
        self.assertEqual(self.skill["version"], "0.1.0")
        self.assertEqual(self.skill["license"], "AGPL-3.0-or-later")
        self.assertEqual(self.skill["platforms"], ["openclaw", "nanoclaw", "hermes", "picoclaw"])
        self.assertNotIn("hooks", self.skill)
        self.assertNotIn("scheduler", self.skill)
        self.assertNotIn("proxy", self.skill)
        self.assertIn("version: 0.1.0", self.docs["SKILL.md"])

    def test_sbom_is_a_complete_package_closure(self) -> None:
        sbom_paths = {entry["path"] for entry in self.skill["sbom"]["files"]}
        self.assertEqual(sbom_paths, EXPECTED_ARTIFACTS)
        self.assertTrue(all((SKILL_ROOT / path).is_file() for path in sbom_paths))

    def test_install_docs_and_scope_contract_are_present(self) -> None:
        for filename, document in self.docs.items():
            with self.subTest(filename=filename):
                self.assertIn(REQUIRED_INSTALL, document)
                self.assertIn("-a codex -y", document)
                self.assertIn("npx clawhub@latest install clawsec-ps-fuzz", document)
                self.assertIn("rag_poisoning", document)
                self.assertIn("synthetic local Chroma", document)
                self.assertIn("no generic agent HTTP", document)
                self.assertIn("MCP", document)
                self.assertIn("no debug", document)
                self.assertIn("custom benchmark", document)
                self.assertIn("no real vector-store mutation", document)


if __name__ == "__main__":
    unittest.main()
