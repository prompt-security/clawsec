#!/usr/bin/env python3
"""Security regression tests for verify_skill_release_bundle.py."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify_skill_release_bundle.py")
SKILL = "demo-skill"
VERSION = "1.2.3"
TAG = f"{SKILL}-v{VERSION}"
ARCHIVE_NAME = f"{TAG}.zip"


def _select_openssl_3() -> str:
    candidates = [os.environ.get("OPENSSL_BIN"), shutil.which("openssl"), "/opt/homebrew/bin/openssl"]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            result = subprocess.run(
                [candidate, "version"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
        if re.match(r"^OpenSSL\s+3(?:\.|\s)", result.stdout.strip()):
            return candidate
    raise unittest.SkipTest("OpenSSL 3 is required for release-verifier tests")


def _run_checked(command: list[str]) -> bytes:
    return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


class ReleaseBundleVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = _select_openssl_3()
        cls.key_temp = tempfile.TemporaryDirectory(prefix="clawsec-verifier-key-")
        cls.private_key = Path(cls.key_temp.name) / "private.pem"
        cls.public_key = Path(cls.key_temp.name) / "public.pem"
        _run_checked([cls.openssl, "genpkey", "-algorithm", "ED25519", "-out", os.fspath(cls.private_key)])
        _run_checked(
            [
                cls.openssl,
                "pkey",
                "-in",
                os.fspath(cls.private_key),
                "-pubout",
                "-out",
                os.fspath(cls.public_key),
            ]
        )
        der = _run_checked(
            [
                cls.openssl,
                "pkey",
                "-pubin",
                "-in",
                os.fspath(cls.public_key),
                "-outform",
                "DER",
            ]
        )
        cls.fingerprint = hashlib.sha256(der).hexdigest()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.key_temp.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="clawsec-verifier-test-")
        self.root = Path(self.temp.name)
        self.release_dir = self.root / "release"
        self.release_dir.mkdir()
        self.output_dir = self.root / "verified-output"
        shutil.copyfile(self.public_key, self.release_dir / "signing-public.pem")
        self.entries = self._valid_entries()
        self._write_archive(self.entries)
        self._refresh_manifest_and_signature()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _valid_entries() -> list[tuple[str, bytes, int, int]]:
        markdown = f"---\nname: {SKILL}\nversion: {VERSION}\ndescription: test fixture\n---\n\n# Test\n".encode()
        skill_json = json.dumps({"name": SKILL, "version": VERSION, "sbom": {"files": []}}).encode()
        return [
            (f"{SKILL}/", b"", stat.S_IFDIR | 0o755, zipfile.ZIP_STORED),
            (f"{SKILL}/SKILL.md", markdown, stat.S_IFREG | 0o644, zipfile.ZIP_DEFLATED),
            (f"{SKILL}/skill.json", skill_json, stat.S_IFREG | 0o600, zipfile.ZIP_DEFLATED),
            (f"{SKILL}/lib/main.txt", b"safe\n", stat.S_IFREG | 0o644, zipfile.ZIP_DEFLATED),
        ]

    def _write_archive(self, entries: list[tuple[str, bytes, int, int]]) -> None:
        archive_path = self.release_dir / ARCHIVE_NAME
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name, content, mode, compression in entries:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = mode << 16
                    info.compress_type = compression
                    archive.writestr(info, content)

    def _refresh_manifest_and_signature(self) -> None:
        archive = self.release_dir / ARCHIVE_NAME
        manifest = {
            "skill": SKILL,
            "version": VERSION,
            "tag": TAG,
            "archive": {
                "filename": ARCHIVE_NAME,
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "size": archive.stat().st_size,
            },
            "files": {},
        }
        manifest_path = self.release_dir / "checksums.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
        self._sign_current_manifest()

    def _sign_current_manifest(self) -> None:
        manifest_path = self.release_dir / "checksums.json"
        signature = _run_checked(
            [
                self.openssl,
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                os.fspath(self.private_key),
                "-in",
                os.fspath(manifest_path),
            ]
        )
        (self.release_dir / "checksums.sig").write_bytes(base64.b64encode(signature) + b"\n")

    def _run(
        self,
        *extra: str,
        include_canonical: bool = False,
        fingerprint: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            os.fspath(SCRIPT),
            "--release-dir",
            os.fspath(self.release_dir),
            "--output-dir",
            os.fspath(self.output_dir),
            "--skill",
            SKILL,
            "--version",
            VERSION,
            "--tag",
            TAG,
            "--spki-sha256",
            fingerprint if fingerprint is not None else self.fingerprint,
            "--openssl",
            self.openssl,
        ]
        if include_canonical:
            command.extend(["--canonical-key", os.fspath(self.public_key)])
        command.extend(extra)
        return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def _assert_rejected(self, result: subprocess.CompletedProcess[str], message: str = "") -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.output_dir.exists(), message or result.stdout + result.stderr)

    def test_success_verifies_and_extracts_to_absent_output(self) -> None:
        result = self._run(include_canonical=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = self.output_dir / SKILL
        self.assertEqual(json.loads((extracted / "skill.json").read_text())["version"], VERSION)
        self.assertTrue((extracted / "SKILL.md").is_file())
        self.assertFalse(any(self.root.glob(f".{self.output_dir.name}.staging-*")))

    def test_extraction_normalizes_authenticated_modes(self) -> None:
        executable_mode = stat.S_IFREG | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o010
        non_executable_mode = stat.S_IFREG | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o666
        directory_mode = stat.S_IFDIR | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o777
        self._write_archive(
            self.entries
            + [
                (f"{SKILL}/bin/", b"", directory_mode, zipfile.ZIP_STORED),
                (f"{SKILL}/bin/run.sh", b"#!/bin/sh\n", executable_mode, zipfile.ZIP_STORED),
                (f"{SKILL}/notes.txt", b"not executable\n", non_executable_mode, zipfile.ZIP_STORED),
            ]
        )
        self._refresh_manifest_and_signature()

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = self.output_dir / SKILL
        self.assertEqual(stat.S_IMODE(self.output_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(extracted.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((extracted / "bin").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((extracted / "bin" / "run.sh").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((extracted / "notes.txt").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((extracted / "SKILL.md").stat().st_mode), 0o600)

    def test_wrong_key_fingerprint_is_rejected(self) -> None:
        replacement = "0" if self.fingerprint[0] != "0" else "1"
        result = self._run(fingerprint=replacement + self.fingerprint[1:])

        self._assert_rejected(result)
        self.assertIn("release signing key fingerprint mismatch", result.stderr)

    def test_archive_tamper_is_rejected(self) -> None:
        with (self.release_dir / ARCHIVE_NAME).open("ab") as archive:
            archive.write(b"tamper")
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("archive size mismatch", result.stderr)

    def test_equal_size_archive_sha_tamper_is_rejected(self) -> None:
        archive_path = self.release_dir / ARCHIVE_NAME
        original_size = archive_path.stat().st_size
        archive = bytearray(archive_path.read_bytes())
        archive[len(archive) // 2] ^= 0x01
        archive_path.write_bytes(archive)
        self.assertEqual(archive_path.stat().st_size, original_size)

        result = self._run()

        self._assert_rejected(result)
        self.assertIn("archive SHA-256 mismatch", result.stderr)

    def test_manifest_tamper_fails_signature(self) -> None:
        manifest_path = self.release_dir / "checksums.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["tag"] = "attacker-v9.9.9"
        manifest_path.write_text(json.dumps(manifest))
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("signature", result.stderr.lower())

    def test_validly_signed_manifest_must_match_explicit_tag(self) -> None:
        manifest_path = self.release_dir / "checksums.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["tag"] = "demo-skill-v1.2.3-wrong"
        manifest_path.write_text(json.dumps(manifest))
        self._sign_current_manifest()
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("tag mismatch", result.stderr)

    def test_traversal_entry_is_rejected(self) -> None:
        self._write_archive(self.entries + [(f"{SKILL}/../escape", b"bad", stat.S_IFREG | 0o644, zipfile.ZIP_STORED)])
        self._refresh_manifest_and_signature()
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("relative path component", result.stderr)

    def test_absolute_and_backslash_entries_are_rejected(self) -> None:
        malicious_names = ["/absolute", f"{SKILL}\\escape"]
        for index, malicious_name in enumerate(malicious_names):
            with self.subTest(name=malicious_name):
                self.output_dir = self.root / f"output-{index}"
                self._write_archive(
                    self.entries + [(malicious_name, b"bad", stat.S_IFREG | 0o644, zipfile.ZIP_STORED)]
                )
                self._refresh_manifest_and_signature()
                self._assert_rejected(self._run())

    def test_symlink_entry_is_rejected(self) -> None:
        self._write_archive(
            self.entries + [(f"{SKILL}/link", b"../../escape", stat.S_IFLNK | 0o777, zipfile.ZIP_STORED)]
        )
        self._refresh_manifest_and_signature()
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("symlink or special file", result.stderr)

    def test_special_file_entry_is_rejected(self) -> None:
        self._write_archive(
            self.entries + [(f"{SKILL}/pipe", b"", stat.S_IFIFO | 0o600, zipfile.ZIP_STORED)]
        )
        self._refresh_manifest_and_signature()
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("symlink or special file", result.stderr)

    def test_encrypted_entry_flag_is_rejected_before_extraction(self) -> None:
        archive_path = self.release_dir / ARCHIVE_NAME
        archive = bytearray(archive_path.read_bytes())
        central_header = archive.find(b"PK\x01\x02")
        self.assertGreaterEqual(central_header, 0)
        flag_offset = central_header + 8
        flags = int.from_bytes(archive[flag_offset : flag_offset + 2], "little") | 0x1
        archive[flag_offset : flag_offset + 2] = flags.to_bytes(2, "little")
        archive_path.write_bytes(archive)
        self._refresh_manifest_and_signature()
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("encrypted entry", result.stderr)

    def test_duplicate_and_case_colliding_entries_are_rejected(self) -> None:
        variants = [
            [(f"{SKILL}/lib/main.txt", b"duplicate", stat.S_IFREG | 0o644, zipfile.ZIP_STORED)],
            [
                (f"{SKILL}/Case.txt", b"one", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
                (f"{SKILL}/case.txt", b"two", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
            ],
        ]
        for index, extra_entries in enumerate(variants):
            with self.subTest(index=index):
                self.output_dir = self.root / f"collision-output-{index}"
                self._write_archive(self.entries + extra_entries)
                self._refresh_manifest_and_signature()
                result = self._run()
                self._assert_rejected(result)
                self.assertIn("collid", result.stderr.lower())

    def test_unicode_collision_is_rejected(self) -> None:
        self._write_archive(
            self.entries
            + [
                (f"{SKILL}/caf\u00e9.txt", b"one", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
                (f"{SKILL}/cafe\u0301.txt", b"two", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
            ]
        )
        self._refresh_manifest_and_signature()
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("collid", result.stderr.lower())

    def test_file_directory_prefix_collision_is_rejected(self) -> None:
        self._write_archive(
            self.entries
            + [
                (f"{SKILL}/blocked", b"file", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
                (f"{SKILL}/blocked/child", b"child", stat.S_IFREG | 0o644, zipfile.ZIP_STORED),
            ]
        )
        self._refresh_manifest_and_signature()
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("prefix collision", result.stderr)

    def test_output_directory_must_not_preexist(self) -> None:
        self.output_dir.mkdir()
        marker = self.output_dir / "do-not-touch"
        marker.write_text("preserved")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), "preserved")
        self.assertIn("must not already exist", result.stderr)

    def test_windows_unsafe_component_is_rejected(self) -> None:
        self._write_archive(
            self.entries + [(f"{SKILL}/CON.txt", b"bad", stat.S_IFREG | 0o644, zipfile.ZIP_STORED)]
        )
        self._refresh_manifest_and_signature()
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("reserved Windows", result.stderr)

    def test_excessive_entry_count_and_compression_ratio_are_rejected(self) -> None:
        result = self._run("--max-entries", "3")
        self._assert_rejected(result)
        self.assertIn("limit is 3", result.stderr)

        self.output_dir = self.root / "ratio-output"
        self._write_archive(
            self.entries
            + [(f"{SKILL}/compressed.txt", b"0" * 1_000_000, stat.S_IFREG | 0o644, zipfile.ZIP_DEFLATED)]
        )
        self._refresh_manifest_and_signature()
        result = self._run("--max-compression-ratio", "10")
        self._assert_rejected(result)
        self.assertIn("compression ratio", result.stderr)

    def test_extracted_identity_mismatch_is_rejected(self) -> None:
        wrong_json = json.dumps({"name": SKILL, "version": "9.9.9"}).encode()
        entries = [entry for entry in self.entries if entry[0] != f"{SKILL}/skill.json"]
        entries.append((f"{SKILL}/skill.json", wrong_json, stat.S_IFREG | 0o600, zipfile.ZIP_STORED))
        self._write_archive(entries)
        self._refresh_manifest_and_signature()
        result = self._run()
        self._assert_rejected(result)
        self.assertIn("identity mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
