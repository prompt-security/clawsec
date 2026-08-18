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

    def test_credential_guidance_uses_only_existing_secure_environment_injection(self) -> None:
        for filename, document in self.docs.items():
            with self.subTest(filename=filename):
                self.assertIn(
                    "Provider credentials are inherited only from the calling environment.",
                    document,
                )
                self.assertIn("OPENAI_API_KEY", document)
                self.assertIn("preflight reports its presence", document)
                self.assertIn(
                    "do not run until the harness/operator's existing secure environment-injection mechanism provides it",
                    document,
                )
                self.assertIn(
                    "Native ollama mode has no credential environment requirement.",
                    document,
                )
                self.assertIn(
                    "Never put a credential in argv, URL, `.env`, report, or authorization ID.",
                    document,
                )
                self.assertIn("does not define or install a credential mechanism", document)
                self.assertNotIn("export OPENAI_API_KEY=", document)


if __name__ == "__main__":
    unittest.main()
