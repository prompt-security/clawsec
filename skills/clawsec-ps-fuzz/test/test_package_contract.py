#!/usr/bin/env python3
"""Offline release-package contract tests for clawsec-ps-fuzz."""

from __future__ import annotations

import json
from pathlib import Path
import re
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
    "scripts/verified_install.py",
    "test/test_package_contract.py",
    "test/test_ps_fuzz_runner.py",
    "test/test_verified_install.py",
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

    def test_first_install_trust_ordering_is_explicit(self) -> None:
        required_phrases = (
            "out-of-band trusted ClawSec",
            "unverified candidate `SKILL.md`",
            "cannot authenticate itself",
            "Ed25519 public key",
            "711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8",
            "`checksums.json` is the signed release manifest",
            "there is no `skills.json` trust manifest",
            "`clawsec-suite` is optional",
            "not sufficient for candidate attestation",
            "convenience path",
            "does not provide this local cryptographic attestation",
            "python3 scripts/verified_install.py --version 0.1.0",
            "--confirm-install",
        )
        for filename, document in self.docs.items():
            with self.subTest(filename=filename):
                for phrase in required_phrases:
                    self.assertIn(phrase, document)

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

    def test_supported_python_native_wheel_boundary_and_chroma_numpy_lock_are_reviewed(self) -> None:
        requirements_in = (SKILL_ROOT / "resources" / "requirements.in").read_text(encoding="utf-8")
        lock = (SKILL_ROOT / "resources" / "requirements.lock").read_text(encoding="utf-8")
        manifest = json.loads((SKILL_ROOT / "resources" / "upstream.json").read_text(encoding="utf-8"))

        self.assertRegex(requirements_in, r"(?m)^chromadb==0\.5\.0\s*$")
        self.assertRegex(requirements_in, r"(?m)^numpy<2\s*$")
        self.assertIn("chromadb==0.5.0", lock)
        self.assertIn("uv pip compile --python-version 3.9 --universal", lock.splitlines()[1])
        self.assertEqual(
            manifest["python"],
            {
                "implementation": "CPython",
                "minimum": "3.9",
                "maximum": "3.11",
                "native_wheel_platforms": [
                    "windows-amd64",
                    "linux-glibc-2.28+-x86_64",
                    "linux-glibc-2.28+-aarch64",
                    "macos-14+-arm64",
                ],
            },
        )

        numpy_versions = [
            match.group(1)
            for line in lock.splitlines()
            if (match := re.match(r"^numpy==([0-9]+(?:\.[0-9]+){1,2})(?:\s|;)", line))
        ]
        self.assertTrue(numpy_versions, "the universal lock must resolve NumPy")
        for version in numpy_versions:
            with self.subTest(version=version):
                self.assertLess(int(version.split(".", 1)[0]), 2)


if __name__ == "__main__":
    unittest.main()
