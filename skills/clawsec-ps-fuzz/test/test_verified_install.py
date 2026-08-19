#!/usr/bin/env python3
"""Offline behavior tests for the signed clawsec-ps-fuzz installer."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile


SKILL_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = SKILL_ROOT / "scripts" / "verified_install.py"
SPEC = importlib.util.spec_from_file_location("verified_install", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load verified installer")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class OfflineRelease:
    VERSION = "0.1.0"
    ROOT = "clawsec-ps-fuzz"

    def __init__(self, directory: Path, private_key: Path, public_key: bytes) -> None:
        self.directory = directory
        self.private_key = private_key
        self.public_key = public_key
        self.payload = {
            "README.md": b"readme\n",
            "SKILL.md": b"skill instructions must remain inert\n",
            "scripts/verified_install.py": b"print('fixture, never execute')\n",
        }

    @property
    def tag(self) -> str:
        return f"clawsec-ps-fuzz-v{self.VERSION}"

    @property
    def archive_name(self) -> str:
        return f"{self.tag}.zip"

    @property
    def base_url(self) -> str:
        return f"https://github.com/prompt-security/clawsec/releases/download/{self.tag}"

    def _skill_json(self, *, sbom_paths: list[str] | None = None, version: str | None = None) -> bytes:
        paths = sbom_paths or [
            "README.md",
            "SKILL.md",
            "skill.json",
            "scripts/verified_install.py",
            "test/test_verified_install.py",
        ]
        value = {
            "name": self.ROOT,
            "version": version or self.VERSION,
            "sbom": {"files": [{"path": path, "required": True} for path in paths]},
        }
        return json.dumps(value, separators=(",", ":")).encode()

    def build(
        self,
        *,
        entries: list[tuple[str, bytes, int | None]] | None = None,
        sbom_paths: list[str] | None = None,
        manifest_change=None,
        manifest_files_change=None,
        raw_manifest: bytes | None = None,
        archive_bytes_change=None,
        signature_change=None,
        public_key: bytes | None = None,
        skill_version: str | None = None,
    ) -> dict[str, bytes]:
        skill_json = self._skill_json(sbom_paths=sbom_paths, version=skill_version)
        payload = {**self.payload, "skill.json": skill_json}
        if entries is None:
            entries = [(f"{self.ROOT}/{path}", content, None) for path, content in payload.items()]

        archive_io = io.BytesIO()
        with zipfile.ZipFile(archive_io, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content, mode in entries:
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED
                if mode is not None:
                    info.create_system = 3
                    info.external_attr = mode << 16
                archive.writestr(info, content)
        archive_bytes = archive_io.getvalue()
        if archive_bytes_change:
            archive_bytes = archive_bytes_change(archive_bytes)

        manifest_files = {
            path: {
                "path": path,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in payload.items()
        }
        if manifest_files_change:
            manifest_files_change(manifest_files)
        manifest = {
            "skill": self.ROOT,
            "version": self.VERSION,
            "generated_at": "2026-08-19T00:00:00Z",
            "repository": "prompt-security/clawsec",
            "tag": self.tag,
            "archive": {
                "filename": self.archive_name,
                "sha256": hashlib.sha256(archive_bytes).hexdigest(),
                "size": len(archive_bytes),
                "url": f"{self.base_url}/{self.archive_name}",
            },
            "files": manifest_files,
        }
        if manifest_change:
            manifest_change(manifest)
        manifest_bytes = raw_manifest or json.dumps(manifest, separators=(",", ":")).encode()
        manifest_path = self.directory / "checksums.json"
        signature_path = self.directory / "checksums.sig.bin"
        manifest_path.write_bytes(manifest_bytes)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                os.fspath(self.private_key),
                "-in",
                os.fspath(manifest_path),
                "-out",
                os.fspath(signature_path),
            ],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError("fixture signing failed")
        signature = base64.b64encode(signature_path.read_bytes())
        if signature_change:
            signature = signature_change(signature)
        return {
            f"{self.base_url}/checksums.json": manifest_bytes,
            f"{self.base_url}/checksums.sig": signature,
            f"{self.base_url}/signing-public.pem": public_key or self.public_key,
            f"{self.base_url}/{self.archive_name}": archive_bytes,
        }


class VerifiedInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("openssl") is None:
            raise unittest.SkipTest("system openssl is unavailable")
        cls.class_tmp = tempfile.TemporaryDirectory()
        directory = Path(cls.class_tmp.name)
        cls.private_key = directory / "private.pem"
        cls.public_key_path = directory / "public.pem"
        result = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", os.fspath(cls.private_key)],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            raise unittest.SkipTest("system openssl lacks Ed25519 support")
        result = subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                os.fspath(cls.private_key),
                "-pubout",
                "-out",
                os.fspath(cls.public_key_path),
            ],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            raise unittest.SkipTest("unable to derive fixture Ed25519 public key")
        cls.public_key = cls.public_key_path.read_bytes()
        der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", os.fspath(cls.public_key_path), "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        cls.fingerprint = hashlib.sha256(der).hexdigest()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.class_tmp.cleanup()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.release = OfflineRelease(self.root, self.private_key, self.public_key)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def fetcher(self, assets: dict[str, bytes], calls: list[str] | None = None):
        def fetch(url: str, limit: int) -> bytes:
            if calls is not None:
                calls.append(url)
            data = assets[url]
            if len(data) > limit:
                raise verifier.VerifiedInstallError("download exceeds allowed size")
            return data

        return fetch

    def install(self, assets: dict[str, bytes], **kwargs):
        with mock.patch.object(verifier, "CANONICAL_SPKI_SHA256", self.fingerprint):
            return verifier.install_verified_release(
                self.release.VERSION,
                self.root / "installed",
                confirm_install=True,
                fetcher=self.fetcher(assets),
                **kwargs,
            )

    def assert_blocked(self, label: str, assets: dict[str, bytes], **kwargs) -> None:
        with self.assertRaisesRegex(verifier.VerifiedInstallError, f"^{label}$"):
            self.install(assets, **kwargs)

    def test_confirmation_gate_precedes_network_or_filesystem_changes(self) -> None:
        calls: list[str] = []
        with self.assertRaisesRegex(verifier.VerifiedInstallError, "^installation confirmation is required$"):
            verifier.install_verified_release(
                self.release.VERSION,
                self.root / "new-root",
                confirm_install=False,
                fetcher=lambda url, limit: calls.append(url) or b"",
            )
        self.assertEqual(calls, [])
        self.assertFalse((self.root / "new-root").exists())

    def test_canonical_fingerprint_rejects_candidate_supplied_key(self) -> None:
        assets = self.release.build()
        with self.assertRaisesRegex(verifier.VerifiedInstallError, "^release signing key is not trusted$"):
            verifier.install_verified_release(
                self.release.VERSION,
                self.root / "installed",
                confirm_install=True,
                fetcher=self.fetcher(assets),
            )

    def test_signature_tampering_fails_before_manifest_parse_or_archive_fetch(self) -> None:
        assets = self.release.build(signature_change=lambda value: value[:-1] + b"!")
        calls: list[str] = []
        with mock.patch.object(verifier, "CANONICAL_SPKI_SHA256", self.fingerprint):
            with self.assertRaisesRegex(verifier.VerifiedInstallError, "^release signature is invalid$"):
                verifier.install_verified_release(
                    self.release.VERSION,
                    self.root / "installed",
                    confirm_install=True,
                    fetcher=self.fetcher(assets, calls),
                )
        self.assertNotIn(f"{self.release.base_url}/{self.release.archive_name}", calls)

    def test_key_algorithm_and_signature_length_are_strict(self) -> None:
        rsa_private = self.root / "rsa-private.pem"
        rsa_public = self.root / "rsa-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", rsa_private],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", rsa_private, "-pubout", "-out", rsa_public],
            check=True,
            capture_output=True,
        )
        assets = self.release.build(public_key=rsa_public.read_bytes())
        with mock.patch.object(verifier, "CANONICAL_SPKI_SHA256", hashlib.sha256(b"not-used").hexdigest()):
            with self.assertRaisesRegex(verifier.VerifiedInstallError, "^release signing key is invalid$"):
                verifier.install_verified_release(
                    self.release.VERSION,
                    self.root / "installed-rsa",
                    confirm_install=True,
                    fetcher=self.fetcher(assets),
                )

        def short_signature(value: bytes) -> bytes:
            return base64.b64encode(base64.b64decode(value)[:-1])

        self.assert_blocked("release signature is invalid", self.release.build(signature_change=short_signature))

    def test_duplicate_manifest_keys_are_rejected_after_signature_verification(self) -> None:
        duplicate = (
            b'{"repository":"prompt-security/clawsec","repository":"prompt-security/clawsec",'
            b'"skill":"clawsec-ps-fuzz","version":"0.1.0","tag":"clawsec-ps-fuzz-v0.1.0",'
            b'"archive":{},"files":{}}'
        )
        self.assert_blocked("signed release manifest is invalid", self.release.build(raw_manifest=duplicate))

    def test_nested_duplicates_nonfinite_numbers_bool_sizes_and_oversized_values_are_rejected(self) -> None:
        baseline = self.release.build()
        raw = baseline[f"{self.release.base_url}/checksums.json"]
        filename = f'"filename":"{self.release.archive_name}"'.encode()
        nested_duplicate = raw.replace(filename, filename + b"," + filename, 1)
        nonfinite = raw.replace(b'"generated_at":"2026-08-19T00:00:00Z"', b'"generated_at":NaN', 1)
        self.assert_blocked("signed release manifest is invalid", self.release.build(raw_manifest=nested_duplicate))
        self.assert_blocked("signed release manifest is invalid", self.release.build(raw_manifest=nonfinite))
        self.assert_blocked(
            "signed release manifest is invalid",
            self.release.build(manifest_change=lambda value: value["archive"].__setitem__("size", True)),
        )
        self.assert_blocked(
            "signed release manifest is invalid",
            self.release.build(
                manifest_change=lambda value: value["archive"].__setitem__("size", verifier.MAX_ARCHIVE_BYTES + 1)
            ),
        )

    def test_version_is_canonical_before_any_url_is_built_or_fetched(self) -> None:
        for version in ("latest", "01.2.3", "1.02.3", "1.2.03", "1.2", "1.2.3/escape", "1.2.3+meta"):
            calls: list[str] = []
            with self.subTest(version=version):
                with self.assertRaisesRegex(verifier.VerifiedInstallError, "^requested version is invalid$"):
                    verifier.install_verified_release(
                        version,
                        self.root / "installed-version",
                        confirm_install=True,
                        fetcher=lambda url, limit: calls.append(url) or b"",
                    )
                self.assertEqual(calls, [])

    def test_signed_manifest_identity_is_exact(self) -> None:
        cases = {
            "repository": lambda value: value.__setitem__("repository", "fork/clawsec"),
            "skill": lambda value: value.__setitem__("skill", "other-skill"),
            "version": lambda value: value.__setitem__("version", "9.9.9"),
            "tag": lambda value: value.__setitem__("tag", "clawsec-ps-fuzz-vlatest"),
            "archive filename": lambda value: value["archive"].__setitem__("filename", "other.zip"),
            "archive URL": lambda value: value["archive"].__setitem__("url", "https://example.test/file.zip"),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                self.assert_blocked("signed release identity is invalid", self.release.build(manifest_change=change))

    def test_archive_size_and_hash_must_match_authenticated_manifest(self) -> None:
        changes = (
            lambda value: value["archive"].__setitem__("size", value["archive"]["size"] + 1),
            lambda value: value["archive"].__setitem__("sha256", "0" * 64),
        )
        for change in changes:
            with self.subTest(change=change):
                self.assert_blocked("release archive verification failed", self.release.build(manifest_change=change))

    def test_archive_is_not_fetched_before_key_signature_and_identity_checks(self) -> None:
        for label, assets in (
            ("key", self.release.build()),
            ("signature", self.release.build(signature_change=lambda value: b"!" + value[1:])),
            (
                "identity",
                self.release.build(manifest_change=lambda value: value.__setitem__("repository", "fork/clawsec")),
            ),
        ):
            calls: list[str] = []
            fingerprint = "0" * 64 if label == "key" else self.fingerprint
            with self.subTest(label=label), mock.patch.object(verifier, "CANONICAL_SPKI_SHA256", fingerprint):
                with self.assertRaises(verifier.VerifiedInstallError):
                    verifier.install_verified_release(
                        self.release.VERSION,
                        self.root / f"installed-{label}",
                        confirm_install=True,
                        fetcher=self.fetcher(assets, calls),
                    )
            self.assertNotIn(f"{self.release.base_url}/{self.release.archive_name}", calls)

    def test_unsafe_zip_paths_are_rejected(self) -> None:
        unsafe = ("", "/absolute", "C:/drive", "clawsec-ps-fuzz\\backslash", "clawsec-ps-fuzz/../escape")
        for path in unsafe:
            entries = [(path, b"bad", None)]
            with self.subTest(path=path):
                self.assert_blocked("release archive layout is unsafe", self.release.build(entries=entries))

    def test_duplicate_normalized_and_outside_root_entries_are_rejected(self) -> None:
        duplicate = [
            ("clawsec-ps-fuzz/README.md", b"a", None),
            ("clawsec-ps-fuzz/./README.md", b"b", None),
        ]
        outside = [("other/README.md", b"bad", None)]
        for entries in (duplicate, outside):
            with self.subTest(entries=entries):
                self.assert_blocked("release archive layout is unsafe", self.release.build(entries=entries))

    def test_symlinks_and_other_non_regular_zip_types_are_rejected(self) -> None:
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600):
            entries = [("clawsec-ps-fuzz/README.md", b"target", mode)]
            with self.subTest(mode=mode):
                self.assert_blocked("release archive entry type is unsafe", self.release.build(entries=entries))

    def test_encryption_and_unsupported_compression_are_rejected(self) -> None:
        def mark_encrypted(value: bytes) -> bytes:
            changed = bytearray(value)
            local = changed.find(b"PK\x03\x04")
            central = changed.find(b"PK\x01\x02")
            struct.pack_into("<H", changed, local + 6, struct.unpack_from("<H", changed, local + 6)[0] | 1)
            struct.pack_into("<H", changed, central + 8, struct.unpack_from("<H", changed, central + 8)[0] | 1)
            return bytes(changed)

        self.assert_blocked(
            "release archive entry type is unsafe",
            self.release.build(archive_bytes_change=mark_encrypted),
        )

        archive_io = io.BytesIO()
        with zipfile.ZipFile(archive_io, "w", compression=zipfile.ZIP_BZIP2) as archive:
            archive.writestr("clawsec-ps-fuzz/README.md", b"content")
        unsupported = archive_io.getvalue()
        self.assert_blocked(
            "release archive entry type is unsafe",
            self.release.build(archive_bytes_change=lambda _value: unsupported),
        )

    def test_file_directory_casefold_unicode_and_windows_name_collisions_are_rejected(self) -> None:
        cases = (
            [
                ("clawsec-ps-fuzz/node", b"file", None),
                ("clawsec-ps-fuzz/node/child", b"child", None),
            ],
            [
                ("clawsec-ps-fuzz/README.md", b"a", None),
                ("clawsec-ps-fuzz/readme.md", b"b", None),
            ],
            [
                ("clawsec-ps-fuzz/caf\u00e9", b"a", None),
                ("clawsec-ps-fuzz/cafe\u0301", b"b", None),
            ],
            [("clawsec-ps-fuzz/CON.txt", b"bad", None)],
            [("clawsec-ps-fuzz/trailing. ", b"bad", None)],
            [("clawsec-ps-fuzz/name:stream", b"bad", None)],
        )
        for entries in cases:
            with self.subTest(entries=entries):
                self.assert_blocked("release archive layout is unsafe", self.release.build(entries=entries))

    def test_release_test_exclusion_policy_matches_packaging_workflow(self) -> None:
        excluded = (
            "test/a.py",
            "src/tests/a.py",
            "src/__tests__/a.py",
            "scripts/test_helper.py",
            "scripts/test-helper.py",
            "scripts/spec_helper.py",
            "scripts/spec-helper.py",
            "scripts/name.test.py",
            "scripts/name.spec.py",
        )
        included = ("scripts/contest.py", "scripts/latest.py", "scripts/verified_install.py")
        self.assertTrue(all(verifier._is_test_release_path(path) for path in excluded))
        self.assertFalse(any(verifier._is_test_release_path(path) for path in included))

    def test_zip_resource_limits_reject_entry_count_size_total_and_ratio(self) -> None:
        cases = (
            ([(f"clawsec-ps-fuzz/{index}.txt", b"x", None) for index in range(513)], {}),
            ([("clawsec-ps-fuzz/large", b"x" * 33, None)], {"max_file_size": 32}),
            (
                [("clawsec-ps-fuzz/a", b"x" * 20, None), ("clawsec-ps-fuzz/b", b"y" * 20, None)],
                {"max_total_size": 32},
            ),
            ([("clawsec-ps-fuzz/ratio", b"x" * 4096, None)], {"max_compression_ratio": 2}),
        )
        for entries, limits in cases:
            with self.subTest(limits=limits):
                self.assert_blocked(
                    "release archive exceeds safety limits",
                    self.release.build(entries=entries),
                    **limits,
                )

    def test_unsigned_extra_and_missing_payload_entries_fail_closed(self) -> None:
        extra_entries = None
        assets = self.release.build()
        archive_url = f"{self.release.base_url}/{self.release.archive_name}"
        with zipfile.ZipFile(io.BytesIO(assets[archive_url]), "r") as source:
            extra_entries = [(info.filename, source.read(info), None) for info in source.infolist()]
        extra_entries.append(("clawsec-ps-fuzz/UNSIGNED.txt", b"extra", None))
        self.assert_blocked("release payload does not match package SBOM", self.release.build(entries=extra_entries))

        entries = [
            (f"clawsec-ps-fuzz/{path}", content, None)
            for path, content in {**self.release.payload, "skill.json": self.release._skill_json()}.items()
            if path != "README.md"
        ]
        self.assert_blocked("release payload does not match package SBOM", self.release.build(entries=entries))

    def test_payload_files_require_signed_size_and_hash(self) -> None:
        for change in (
            lambda files: files.pop("README.md"),
            lambda files: files["README.md"].__setitem__("sha256", "0" * 64),
            lambda files: files["README.md"].__setitem__("size", 999),
        ):
            with self.subTest(change=change):
                self.assert_blocked(
                    "release payload verification failed",
                    self.release.build(manifest_files_change=change),
                )

    def test_skill_metadata_identity_and_sbom_paths_are_strict(self) -> None:
        cases = (
            {"skill_version": "9.9.9"},
            {"sbom_paths": ["README.md", "../escape", "skill.json", "scripts/verified_install.py"]},
            {"sbom_paths": ["README.md", "README.md", "skill.json", "scripts/verified_install.py"]},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                self.assert_blocked("package metadata is invalid", self.release.build(**kwargs))

    def test_extraction_rechecks_hash_and_never_publishes_corrupt_output(self) -> None:
        assets = self.release.build()
        original = verifier._copy_verified_member

        def corrupting_copy(source, destination, expected_size, expected_hash):
            if destination.name == "README.md":
                expected_hash = "0" * 64
            return original(source, destination, expected_size, expected_hash)

        with mock.patch.object(verifier, "_copy_verified_member", side_effect=corrupting_copy):
            self.assert_blocked("release extraction verification failed", assets)
        self.assertFalse((self.root / "installed" / "clawsec-ps-fuzz").exists())

    def test_existing_destination_is_preserved_on_every_failure(self) -> None:
        destination = self.root / "installed" / "clawsec-ps-fuzz"
        destination.mkdir(parents=True)
        marker = destination / "preserve.txt"
        marker.write_text("original", encoding="utf-8")
        self.assert_blocked("installation destination already exists", self.release.build())
        self.assertEqual(marker.read_text(encoding="utf-8"), "original")

    def test_atomic_publish_never_replaces_an_existing_empty_directory(self) -> None:
        parent = self.root / "publish"
        staging = parent / "staging"
        destination = parent / "destination"
        staging.mkdir(parents=True)
        destination.mkdir()
        (staging / "payload").write_text("new", encoding="utf-8")
        with self.assertRaisesRegex(verifier.VerifiedInstallError, "^installation destination already exists$"):
            verifier._atomic_publish_no_replace(staging, destination)
        self.assertTrue(destination.is_dir())
        self.assertEqual(list(destination.iterdir()), [])
        self.assertTrue((staging / "payload").is_file())

    def test_successful_install_is_atomic_and_contains_only_authenticated_payload(self) -> None:
        assets = self.release.build()
        destination = self.install(assets)
        self.assertEqual(destination, (self.root / "installed" / "clawsec-ps-fuzz").resolve())
        files = {
            path.relative_to(destination).as_posix()
            for path in destination.rglob("*")
            if path.is_file()
        }
        self.assertEqual(files, {"README.md", "SKILL.md", "skill.json", "scripts/verified_install.py"})
        self.assertEqual((destination / "README.md").read_bytes(), b"readme\n")
        self.assertFalse(any(path.name.startswith(".clawsec-ps-fuzz-") for path in destination.parent.iterdir()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
