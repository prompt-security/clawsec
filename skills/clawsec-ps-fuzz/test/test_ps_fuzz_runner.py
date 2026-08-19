#!/usr/bin/env python3
"""Offline behavior tests for the ps-fuzz provisioning boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
RUNNER = SKILL_ROOT / "scripts" / "ps_fuzz_runner.py"
MANIFEST = SKILL_ROOT / "resources" / "upstream.json"


def approved_state_root(temp_dir: Path) -> Path:
    return temp_dir / ".clawsec" / "clawsec-ps-fuzz"


def load_runner():
    spec = importlib.util.spec_from_file_location("ps_fuzz_runner", RUNNER)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Provisioning runtime is missing: {RUNNER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def selected_runtime(
    *,
    implementation: str = "CPython",
    major: int = 3,
    minor: int = 11,
    system: str = "Linux",
    machine: str = "x86_64",
    libc: str = "glibc",
    libc_version: str = "2.28",
    macos_version: str = "",
) -> dict[str, object]:
    return {
        "implementation": implementation,
        "major": major,
        "minor": minor,
        "system": system,
        "machine": machine,
        "libc": libc,
        "libc_version": libc_version,
        "macos_version": macos_version,
    }


class OsNameView:
    """Expose one test platform name without mutating pathlib's process-wide os module."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)


def fake_runtime_probe(
    args: list[str], runtime: dict[str, object] | None = None
) -> subprocess.CompletedProcess[str] | None:
    if "-c" in args and args[-1].startswith("import json, platform, sys;"):
        return subprocess.CompletedProcess(args, 0, json.dumps(runtime or selected_runtime()) + "\n", "")
    return None


def create_fake_executable(root: Path, name: str) -> str:
    executable = root / name
    executable.write_bytes(b"fake executable")
    executable.chmod(0o700)
    return str(executable.resolve())


def create_fake_entrypoint(state_root: Path, content: bytes = b"fake executable") -> Path:
    executable = state_root / "venv" / (
        "Scripts/prompt-security-fuzzer.exe" if os.name == "nt" else "bin/prompt-security-fuzzer"
    )
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(content)
    venv_python = state_root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    venv_python.write_bytes(b"fake venv python")
    if os.name != "nt":
        executable.chmod(0o700)
        venv_python.chmod(0o700)
    for directory in (state_root, state_root / "venv", executable.parent):
        directory.chmod(0o700)
    return executable


def write_fake_receipt(state_root: Path, executable: Path, *, source: str = "wheel") -> Path:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    canonical_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    receipt = {
        "schema_version": 1,
        "manifest_sha256": hashlib.sha256(canonical_manifest).hexdigest(),
        "source": source,
        "selected_interpreter": {
            "path": str(Path(sys.executable).resolve()),
            "runtime": selected_runtime(),
        },
        "entrypoint": {
            "relative_path": executable.relative_to(state_root).as_posix(),
            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        },
    }
    receipt_path = state_root / "provision-receipt.json"
    receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    if os.name != "nt":
        receipt_path.chmod(0o600)
    return receipt_path


class PsFuzzProvisioningTests(unittest.TestCase):
    """Prove that provisioning validates first and writes only the state root."""

    def test_preflight_is_inspection_only_and_does_not_require_authorization(self) -> None:
        """Adding a provision authorization gate to public preflight must fail this test."""
        runner = load_runner()
        calls: list[list[str]] = []

        def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        runner.preflight(
            runner.load_manifest(MANIFEST),
            source="wheel",
            python_executable="python3",
            python_version=(3, 11),
            python_runtime=selected_runtime(),
            command=command,
        )
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(Path(args[0]).is_absolute() for args in calls))
        self.assertEqual(calls[0][1:], ["-I", "-B", "-m", "venv", "--help"])
        self.assertEqual(calls[1][1:], ["-I", "-B", "-m", "pip", "--version"])

    def test_provision_rejects_missing_authorization_before_runtime_checks(self) -> None:
        """Removing the provisioning authorization gate must make this test fail."""
        runner = load_runner()
        calls: list[list[str]] = []

        def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with tempfile.TemporaryDirectory() as td:
            state_root = approved_state_root(Path(td))
            with self.assertRaisesRegex(runner.ProvisionError, "confirm-authorized-provision"):
                runner.provision(
                    runner.load_manifest(MANIFEST),
                    state_root=state_root,
                    source="wheel",
                    confirm_authorized_provision=False,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=command,
                )
            with self.assertRaisesRegex(runner.ProvisionError, "authorization-id"):
                runner.provision(
                    runner.load_manifest(MANIFEST),
                    state_root=state_root,
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="  ",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=command,
                )
        self.assertEqual(calls, [], "authorization rejection must precede runtime checks")

    def test_preflight_rejects_unsupported_python_and_missing_venv_or_pip(self) -> None:
        """Broadening Python support or ignoring capability failures must fail this test."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)

        with self.assertRaisesRegex(runner.ProvisionError, "unsupported Python"):
            runner.preflight(
                manifest,
                source="wheel",
                python_executable="python3",
                python_version=(3, 8),
                python_runtime=selected_runtime(minor=8),
                command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
            )

        with self.assertRaisesRegex(runner.ProvisionError, "unsupported Python 3.12"):
            runner.preflight(
                manifest,
                source="wheel",
                python_executable="python3",
                python_version=(3, 12),
                python_runtime=selected_runtime(minor=12),
                command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
            )

        with self.assertRaisesRegex(runner.ProvisionError, "--source"):
            runner.preflight(
                manifest,
                source="branch:main",
                python_executable="python3",
                python_version=(3, 11),
                python_runtime=selected_runtime(),
                command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
            )

        def missing_venv(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args, 1, "", "venv unavailable")

        with self.assertRaisesRegex(runner.ProvisionError, "venv"):
            runner.preflight(
                manifest,
                source="wheel",
                python_executable="python3",
                python_version=(3, 11),
                python_runtime=selected_runtime(),
                command=missing_venv,
            )

        def missing_pip(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if args[-2:] == ["venv", "--help"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 1, "", "pip unavailable")

        with self.assertRaisesRegex(runner.ProvisionError, "pip"):
            runner.preflight(
                manifest,
                source="wheel",
                python_executable="python3",
                python_version=(3, 11),
                python_runtime=selected_runtime(),
                command=missing_pip,
            )

    def test_direct_provision_probes_omitted_runtime_before_state_write(self) -> None:
        """A direct caller cannot substitute wrapper identity for --python's runtime."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        calls: list[list[str]] = []

        with tempfile.TemporaryDirectory() as td:
            selected_executable = create_fake_executable(Path(td), "selected-python-312")

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(args)
                if "-c" in args:
                    return subprocess.CompletedProcess(args, 0, json.dumps(selected_runtime(minor=12)) + "\n", "")
                return subprocess.CompletedProcess(args, 0, "", "")

            state_root = approved_state_root(Path(td))
            with self.assertRaisesRegex(runner.ProvisionError, "unsupported Python 3.12"):
                runner.provision(
                    manifest,
                    state_root=state_root,
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable=selected_executable,
                    python_version=(3, 11),
                    command=command,
                    downloader=lambda _url, _destination: self.fail("unsupported interpreter reached download"),
                )
            self.assertEqual(
                calls,
                [[selected_executable, "-I", "-B", "-c", runner.PYTHON_VERSION_PROBE]],
            )
            self.assertFalse(state_root.exists())

    def test_direct_provision_never_trusts_caller_supplied_runtime_identity(self) -> None:
        """A supplied runtime mapping cannot bypass probing the authorized selected interpreter."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        calls: list[list[str]] = []

        def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            if "-c" in args:
                return subprocess.CompletedProcess(args, 0, json.dumps(selected_runtime(minor=12)) + "\n", "")
            self.fail("unsupported selected interpreter reached a capability or mutating command")

        with tempfile.TemporaryDirectory() as td:
            state_root = approved_state_root(Path(td))
            with self.assertRaisesRegex(runner.ProvisionError, "unsupported Python 3.12"):
                runner.provision(
                    manifest,
                    state_root=state_root,
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable=sys.executable,
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=command,
                )
            self.assertEqual(len(calls), 1)
            self.assertIn("-I", calls[0])
            self.assertIn("-B", calls[0])
            self.assertFalse(state_root.exists())

    def test_preflight_accepts_every_reviewed_cpython_native_wheel_matrix(self) -> None:
        """Every recorded CPython/native-wheel support cell remains usable."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        platform_cases = (
            (
                "linux-glibc-2.28+-x86_64",
                {"system": "Linux", "machine": "x86_64", "libc": "glibc", "libc_version": "2.28"},
            ),
            (
                "linux-glibc-2.28+-aarch64",
                {"system": "Linux", "machine": "aarch64", "libc": "glibc", "libc_version": "2.28"},
            ),
            (
                "macos-14+-arm64",
                {"system": "Darwin", "machine": "arm64", "libc": "", "libc_version": "", "macos_version": "14.0"},
            ),
        )

        for minor in (9, 10, 11):
            for expected_platform, runtime_overrides in platform_cases:
                with self.subTest(python=f"3.{minor}", platform=expected_platform):
                    inspection = runner.preflight(
                        manifest,
                        source="wheel",
                        python_executable=sys.executable,
                        python_version=(3, minor),
                        python_runtime=selected_runtime(minor=minor, **runtime_overrides),
                        command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
                    )
                    self.assertEqual(
                        inspection["python_support"]["selected_native_wheel_platform"], expected_platform
                    )

    def test_preflight_reports_windows_runtime_unsupported_without_capability_probes(self) -> None:
        """Windows remains inspection-only and reports that its unverified ACL boundary is unsupported."""
        runner = load_runner()
        calls: list[list[str]] = []

        with self.assertRaisesRegex(runner.ProvisionError, "unsupported native-wheel platform"):
            runner.preflight(
                runner.load_manifest(MANIFEST),
                source="wheel",
                python_executable=sys.executable,
                python_version=(3, 11),
                python_runtime=selected_runtime(
                    system="Windows",
                    machine="AMD64",
                    libc="",
                    libc_version="",
                    macos_version="",
                ),
                command=lambda args, **_kwargs: calls.append(args)
                or subprocess.CompletedProcess(args, 0, "", ""),
            )
        self.assertEqual(calls, [])

    def test_provision_fails_closed_on_windows_after_authorization_and_before_state_write(self) -> None:
        """A mutating provision cannot rely on unverified Windows state-root ACL privacy."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        original_os = runner.os
        with tempfile.TemporaryDirectory() as td:
            state_root = approved_state_root(Path(td))
            runner.os = OsNameView("nt")
            try:
                with self.assertRaisesRegex(runner.ProvisionError, "confirm-authorized-provision"):
                    runner.provision(
                        manifest,
                        state_root=state_root,
                        source="wheel",
                        confirm_authorized_provision=False,
                        authorization_id="AUTH-42",
                        python_executable=sys.executable,
                        python_version=(3, 11),
                        command=lambda *_args, **_kwargs: self.fail("unauthorized provision reached a command"),
                    )
                with self.assertRaisesRegex(runner.ProvisionError, "Windows.*ACL privacy"):
                    runner.provision(
                        manifest,
                        state_root=state_root,
                        source="wheel",
                        confirm_authorized_provision=True,
                        authorization_id="AUTH-42",
                        python_executable=sys.executable,
                        python_version=(3, 11),
                        command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 1, "", ""),
                    )
            finally:
                runner.os = original_os
            self.assertFalse(state_root.exists())

    def test_cli_rejects_non_cpython_and_unsupported_native_wheels_before_state_write(self) -> None:
        """The selected interpreter must match the reviewed wheel support envelope."""
        import contextlib
        import io

        runner = load_runner()
        unsupported_runtimes = (
            (
                "selected-python-312",
                selected_runtime(minor=12),
                "unsupported Python 3.12",
            ),
            (
                "selected-pypy",
                selected_runtime(implementation="PyPy"),
                "unsupported Python implementation",
            ),
            (
                "selected-musl",
                selected_runtime(libc="musl", libc_version="1.2.5"),
                "unsupported native-wheel platform",
            ),
            (
                "selected-old-glibc",
                selected_runtime(libc_version="2.27"),
                "unsupported native-wheel platform",
            ),
            (
                "selected-windows-arm",
                selected_runtime(system="Windows", machine="ARM64", libc="", libc_version=""),
                "unsupported native-wheel platform",
            ),
            (
                "selected-macos-x86",
                selected_runtime(system="Darwin", machine="x86_64", libc="", libc_version="", macos_version="14.0"),
                "unsupported native-wheel platform",
            ),
            (
                "selected-old-macos-arm",
                selected_runtime(system="Darwin", machine="arm64", libc="", libc_version="", macos_version="13.7"),
                "unsupported native-wheel platform",
            ),
        )
        with tempfile.TemporaryDirectory() as td:
            for executable_name, runtime, expected_error in unsupported_runtimes:
                calls: list[list[str]] = []
                executable = create_fake_executable(Path(td), executable_name)

                def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                    calls.append(args)
                    if "-c" in args:
                        return subprocess.CompletedProcess(args, 0, json.dumps(runtime) + "\n", "")
                    self.fail("unsupported runtime reached a capability check")

                state_root = approved_state_root(Path(td) / f"case-{executable_name}")
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    status = runner.main(
                        [
                            "provision",
                            "--confirm-authorized-provision",
                            "--authorization-id",
                            "AUTH-42",
                            "--state-root",
                            str(state_root),
                            "--python",
                            executable,
                        ],
                        command=command,
                    )
                self.assertEqual(status, 2)
                self.assertEqual(calls, [[executable, "-I", "-B", "-c", runner.PYTHON_VERSION_PROBE]])
                self.assertIn(expected_error, stderr.getvalue())
                self.assertFalse(state_root.exists())

    def test_cli_selected_python_38_blocks_before_venv_probe_or_state_write(self) -> None:
        import contextlib
        import io

        runner = load_runner()
        calls: list[list[str]] = []
        probe = runner.PYTHON_VERSION_PROBE
        with tempfile.TemporaryDirectory() as td:
            executable = create_fake_executable(Path(td), "selected-python-38")

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(args)
                if "-c" in args:
                    return subprocess.CompletedProcess(args, 0, json.dumps(selected_runtime(minor=8)) + "\n", "")
                self.fail("preflight invoked a selected Python capability command before its version gate")

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = runner.main(["preflight", "--python", executable], command=command)
            self.assertEqual(status, 2)
            self.assertEqual(calls, [[executable, "-I", "-B", "-c", probe]])
            self.assertIn("unsupported Python 3.8", stderr.getvalue())

    def test_cli_uses_selected_python_311_when_wrapper_version_is_unsupported(self) -> None:
        import contextlib
        import io

        runner = load_runner()
        calls: list[list[str]] = []
        probe = runner.PYTHON_VERSION_PROBE
        original_version = runner.sys.version_info
        with tempfile.TemporaryDirectory() as td:
            executable = create_fake_executable(Path(td), "selected-python-311")

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(args)
                if "-c" in args:
                    return subprocess.CompletedProcess(args, 0, json.dumps(selected_runtime()) + "\n", "")
                return subprocess.CompletedProcess(args, 0, "", "")

            stdout = io.StringIO()
            try:
                runner.sys.version_info = (3, 8)
                with contextlib.redirect_stdout(stdout):
                    status = runner.main(["preflight", "--python", executable], command=command)
            finally:
                runner.sys.version_info = original_version
            self.assertEqual(status, 0)
            self.assertEqual(
                calls,
                [
                    [executable, "-I", "-B", "-c", probe],
                    [executable, "-I", "-B", "-m", "venv", "--help"],
                    [executable, "-I", "-B", "-m", "pip", "--version"],
                ],
            )
        inspection = json.loads(stdout.getvalue().splitlines()[0])
        self.assertEqual(
            inspection["python_support"],
            {
                "implementation": "CPython",
                "supported_versions": ["3.9", "3.10", "3.11"],
                "native_wheel_platforms": [
                    "linux-glibc-2.28+-x86_64",
                    "linux-glibc-2.28+-aarch64",
                    "macos-14+-arm64",
                ],
                "selected_native_wheel_platform": "linux-glibc-2.28+-x86_64",
            },
        )
        self.assertIn("preflight passed", stdout.getvalue())

    def test_cli_provision_authorization_precedes_selected_python_probe(self) -> None:
        import contextlib
        import io

        runner = load_runner()
        calls: list[list[str]] = []

        def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            self.fail("an unauthorized provision reached the selected Python version probe")

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = runner.main(
                [
                    "provision",
                    "--state-root",
                    "/tmp/clawsec-test/clawsec-ps-fuzz",
                    "--python",
                    "selected-python",
                ],
                command=command,
            )
        self.assertEqual(status, 2)
        self.assertEqual(calls, [])
        self.assertIn("confirm-authorized-provision", stderr.getvalue())

    def test_wheel_provision_verifies_hash_before_pip_and_keeps_writes_in_state_root(self) -> None:
        """Skipping the wheel hash check or installing outside state_root must fail this test."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        wheel_bytes = b"reviewed ps-fuzz wheel fixture"
        manifest["artifacts"]["release_wheel"]["sha256"] = hashlib.sha256(wheel_bytes).hexdigest()

        with tempfile.TemporaryDirectory() as td:
            state_root = approved_state_root(Path(td)).resolve()
            calls: list[list[str]] = []
            downloads: list[tuple[str, Path]] = []

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(args)
                probe_result = fake_runtime_probe(args)
                if probe_result is not None:
                    return probe_result
                if "venv" in args and "--help" not in args:
                    create_fake_entrypoint(state_root)
                return subprocess.CompletedProcess(args, 0, "", "")

            def downloader(url: str, destination: Path) -> None:
                downloads.append((url, destination))
                destination.write_bytes(wheel_bytes)

            result = runner.provision(
                manifest,
                state_root=state_root,
                source="wheel",
                confirm_authorized_provision=True,
                authorization_id="AUTH-42",
                python_executable="python3",
                python_version=(3, 11),
                python_runtime=selected_runtime(),
                command=command,
                downloader=downloader,
            )

            self.assertEqual(result.mode, "wheel")
            self.assertTrue(result.venv_python.is_relative_to(state_root))
            self.assertTrue(result.artifact.is_relative_to(state_root))
            self.assertTrue(result.artifact.is_relative_to(state_root / "downloads"))
            self.assertEqual(downloads[0][0], manifest["artifacts"]["release_wheel"]["url"])
            pip_calls = [args for args in calls if "install" in args]
            self.assertTrue(pip_calls, "expected an isolated pip install")
            self.assertTrue(all(args[0].startswith(str(state_root)) for args in pip_calls))
            locked_install = next(args for args in pip_calls if "--require-hashes" in args)
            self.assertIn("--only-binary=:all:", locked_install)
            venv_create = next(args for args in calls if args[-1] == str(state_root / "venv"))
            self.assertTrue(Path(venv_create[0]).is_absolute())
            self.assertIn("--copies", venv_create)
            receipt_path = state_root / "provision-receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            canonical_manifest = json.dumps(
                manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            self.assertEqual(receipt["schema_version"], 1)
            self.assertEqual(receipt["manifest_sha256"], hashlib.sha256(canonical_manifest).hexdigest())
            self.assertEqual(receipt["source"], "wheel")
            self.assertTrue(Path(receipt["selected_interpreter"]["path"]).is_absolute())
            self.assertEqual(receipt["selected_interpreter"]["runtime"], selected_runtime())
            entrypoint = state_root / receipt["entrypoint"]["relative_path"]
            self.assertEqual(receipt["entrypoint"]["sha256"], hashlib.sha256(entrypoint.read_bytes()).hexdigest())
            if os.name != "nt":
                self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(state_root.stat().st_mode & 0o777, 0o700)

    def test_wheel_hash_mismatch_stops_before_pip_install(self) -> None:
        """Allowing a mismatched upstream artifact to reach pip must fail this test."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)

        with tempfile.TemporaryDirectory() as td:
            calls: list[list[str]] = []

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(args)
                probe_result = fake_runtime_probe(args)
                if probe_result is not None:
                    return probe_result
                if "venv" in args and "--help" not in args:
                    create_fake_entrypoint(approved_state_root(Path(td)))
                return subprocess.CompletedProcess(args, 0, "", "")

            with self.assertRaisesRegex(runner.ProvisionError, "SHA-256 mismatch"):
                runner.provision(
                    manifest,
                    state_root=approved_state_root(Path(td)),
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=command,
                    downloader=lambda _url, destination: destination.write_bytes(b"tampered"),
                )
            self.assertFalse([args for args in calls if "install" in args], "pip install ran after hash mismatch")

    def test_source_provision_checks_out_and_verifies_only_the_pinned_commit(self) -> None:
        """Checking out a branch or accepting a different commit must fail this test."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)

        with tempfile.TemporaryDirectory() as td:
            state_root = approved_state_root(Path(td)).resolve()
            calls: list[list[str]] = []

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(args)
                probe_result = fake_runtime_probe(args)
                if probe_result is not None:
                    return probe_result
                if "venv" in args and "--help" not in args:
                    create_fake_entrypoint(state_root)
                if args[-2:] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(args, 0, manifest["upstream"]["commit"] + "\n", "")
                if "wheel" in args:
                    wheel_dir = Path(args[args.index("--wheel-dir") + 1])
                    wheel_dir.mkdir(parents=True, exist_ok=True)
                    (wheel_dir / "prompt_security_fuzzer-0.0.1-py3-none-any.whl").write_bytes(b"source wheel fixture")
                return subprocess.CompletedProcess(args, 0, "", "")

            result = runner.provision(
                manifest,
                state_root=state_root,
                source="source",
                confirm_authorized_provision=True,
                authorization_id="AUTH-42",
                python_executable="python3",
                python_version=(3, 11),
                python_runtime=selected_runtime(),
                command=command,
                downloader=lambda _url, _destination: self.fail("source provisioning must not download the release wheel"),
            )

            checkout_calls = [args for args in calls if "checkout" in args]
            self.assertEqual(checkout_calls[0][-1], manifest["upstream"]["commit"])
            clone_calls = [args for args in calls if len(args) > 1 and args[1] == "clone"]
            self.assertEqual(clone_calls[0][2:6], ["--depth", "1", "--branch", manifest["upstream"]["tag"]])
            self.assertTrue(Path(clone_calls[0][0]).is_absolute())
            self.assertTrue(result.artifact.is_relative_to(state_root / "built-wheels"))
            receipt = json.loads((state_root / "provision-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["source"], "source")

    def test_command_failure_diagnostics_never_surface_child_output(self) -> None:
        runner = load_runner()
        token = "ghp_verySecretDiagnosticToken"
        failure = subprocess.CompletedProcess(["pip"], 17, "stdout " + token, "stderr " + token)
        with self.assertRaisesRegex(runner.ProvisionError, "locked dependency installation failed with exit status 17") as raised:
            runner._require_success(failure, "locked dependency installation")
        self.assertNotIn(token, str(raised.exception))

    def test_wheel_download_failure_never_surfaces_downloader_exception(self) -> None:
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        token = "ghp_verySecretDownloadFailure"
        with tempfile.TemporaryDirectory() as td:
            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                probe_result = fake_runtime_probe(args)
                if probe_result is not None:
                    return probe_result
                if "venv" in args and "--help" not in args:
                    create_fake_entrypoint(approved_state_root(Path(td)))
                return subprocess.CompletedProcess(args, 0, "", "")

            def downloader(_url: str, _destination: Path) -> None:
                raise RuntimeError(token)

            with self.assertRaisesRegex(runner.ProvisionError, "release wheel download failed") as raised:
                runner.provision(
                    manifest,
                    state_root=approved_state_root(Path(td)),
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=command,
                    downloader=downloader,
                )
            self.assertNotIn(token, str(raised.exception))

    def test_default_command_launch_failure_is_stable_without_oserror_detail(self) -> None:
        runner = load_runner()
        token = "ghp_verySecretLaunchFailure"
        original_run = runner.subprocess.run

        def failing_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            raise OSError(token)

        try:
            runner.subprocess.run = failing_run
            result = runner._run_command(["unavailable-python"])
        finally:
            runner.subprocess.run = original_run

        self.assertEqual(result.returncode, 127)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        with self.assertRaisesRegex(runner.ProvisionError, "launch capability check failed with exit status 127") as raised:
            runner._require_success(result, "launch capability check")
        self.assertNotIn(token, str(raised.exception))

    def test_state_artifact_read_failure_is_static_without_oserror_detail(self) -> None:
        runner = load_runner()
        token = "ghp_verySecretArtifactReadFailure"
        original_read = runner.os.read

        def failing_read(_descriptor: int, _size: int) -> bytes:
            raise OSError(token)

        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "artifact"
            artifact.write_bytes(b"reviewed bytes")
            try:
                runner.os.read = failing_read
                with self.assertRaisesRegex(runner.ProvisionError, "could not be read safely") as raised:
                    runner._sha256(artifact)
            finally:
                runner.os.read = original_read
        self.assertNotIn(token, str(raised.exception))

    def test_source_revision_mismatch_never_surfaces_git_stdout(self) -> None:
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        token = "ghp_verySecretRevisionOutput"
        with tempfile.TemporaryDirectory() as td:
            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                probe_result = fake_runtime_probe(args)
                if probe_result is not None:
                    return probe_result
                if "venv" in args and "--help" not in args:
                    create_fake_entrypoint(approved_state_root(Path(td)))
                if args[-2:] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(args, 0, token, "")
                return subprocess.CompletedProcess(args, 0, "", "")

            with self.assertRaisesRegex(runner.ProvisionError, "source commit mismatch") as raised:
                runner.provision(
                    manifest,
                    state_root=approved_state_root(Path(td)),
                    source="source",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=command,
                )
            self.assertNotIn(token, str(raised.exception))

    def test_source_commit_mismatch_stops_before_dependencies_or_build(self) -> None:
        """Accepting a ref that is not the reviewed commit must fail this test."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)

        with tempfile.TemporaryDirectory() as td:
            calls: list[list[str]] = []

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(args)
                probe_result = fake_runtime_probe(args)
                if probe_result is not None:
                    return probe_result
                if "venv" in args and "--help" not in args:
                    create_fake_entrypoint(approved_state_root(Path(td)))
                if args[-2:] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(args, 0, "d" * 40 + "\n", "")
                return subprocess.CompletedProcess(args, 0, "", "")

            with self.assertRaisesRegex(runner.ProvisionError, "source commit mismatch"):
                runner.provision(
                    manifest,
                    state_root=approved_state_root(Path(td)),
                    source="source",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=command,
                )
            self.assertFalse([args for args in calls if "install" in args])
            self.assertFalse([args for args in calls if "wheel" in args])

    def test_external_state_root_rejects_the_project_and_project_symlinks(self) -> None:
        """Allowing a state root inside the checkout must fail this test."""
        runner = load_runner()
        project_root = SKILL_ROOT.parents[1].resolve()

        with tempfile.TemporaryDirectory() as td:
            project_link = Path(td) / "project-link"
            project_link.symlink_to(project_root, target_is_directory=True)
            for candidate in (project_root, project_link):
                calls: list[list[str]] = []

                def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                    calls.append(args)
                    return subprocess.CompletedProcess(args, 0, "", "")

                with self.assertRaisesRegex(runner.ProvisionError, "state-root"):
                    runner.provision(
                        runner.load_manifest(MANIFEST),
                        state_root=candidate,
                        source="wheel",
                        confirm_authorized_provision=True,
                        authorization_id="AUTH-42",
                        python_executable="python3",
                        python_version=(3, 11),
                        python_runtime=selected_runtime(),
                        command=command,
                        downloader=lambda _url, _destination: self.fail("project state root reached downloader"),
                    )
                self.assertFalse([args for args in calls if "venv" in args and "--help" not in args])

    def test_external_state_root_allows_only_the_dedicated_child_of_a_caller_base(self) -> None:
        """Accepting root, temporary, or arbitrary state paths must fail this test."""
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            expected = approved_state_root(Path(td))
            self.assertEqual(
                runner.external_state_root(expected),
                expected.resolve(),
            )
            for candidate in (Path("/"), Path("/tmp"), Path(td) / "unrelated", Path(td) / "other-skill"):
                with self.assertRaisesRegex(runner.ProvisionError, "dedicated"):
                    runner.external_state_root(candidate)

    def test_provision_rejects_root_and_direct_mutable_child_symlinks_before_mutation(self) -> None:
        """Following any mutable state child symlink into the checkout must fail this test."""
        runner = load_runner()
        project_root = SKILL_ROOT.parents[1].resolve()
        mutable_children = ("venv", "downloads", "source", "built-wheels", "home", "pip-cache", "xdg-cache", "tmp")

        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td)
            linked_root = approved_state_root(temp_root / "linked-base")
            linked_target = approved_state_root(temp_root / "target-base")
            linked_target.mkdir(parents=True)
            linked_root.parent.mkdir(parents=True)
            linked_root.symlink_to(linked_target, target_is_directory=True)
            with self.assertRaisesRegex(runner.ProvisionError, "symlink"):
                runner.provision(
                    runner.load_manifest(MANIFEST),
                    state_root=linked_root,
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=lambda _args, **_kwargs: self.fail("root symlink reached a command"),
                    downloader=lambda _url, _destination: self.fail("root symlink reached downloader"),
                )

            for child in mutable_children:
                state_root = approved_state_root(temp_root / child)
                state_root.mkdir(parents=True)
                (state_root / child).symlink_to(project_root, target_is_directory=True)
                calls: list[list[str]] = []

                def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                    calls.append(args)
                    return subprocess.CompletedProcess(args, 0, "", "")

                with self.assertRaisesRegex(runner.ProvisionError, "symlink|escapes"):
                    runner.provision(
                        runner.load_manifest(MANIFEST),
                        state_root=state_root,
                        source="wheel",
                        confirm_authorized_provision=True,
                        authorization_id="AUTH-42",
                        python_executable="python3",
                        python_version=(3, 11),
                        python_runtime=selected_runtime(),
                        command=command,
                        downloader=lambda _url, _destination: self.fail("child symlink reached downloader"),
                    )
                self.assertEqual(calls, [], "a rejected state child must block before any command")

    def test_source_clone_target_symlink_is_rejected_before_git_or_build(self) -> None:
        """A preexisting source/ps-fuzz symlink must not become Git's clone target."""
        runner = load_runner()
        project_root = SKILL_ROOT.parents[1].resolve()
        with tempfile.TemporaryDirectory() as td:
            state_root = approved_state_root(Path(td))
            source_root = state_root / "source"
            source_root.mkdir(parents=True)
            (source_root / "ps-fuzz").symlink_to(project_root, target_is_directory=True)
            calls: list[list[str]] = []

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(args)
                return subprocess.CompletedProcess(args, 0, "", "")

            with self.assertRaisesRegex(runner.ProvisionError, "symlink|escapes"):
                runner.provision(
                    runner.load_manifest(MANIFEST),
                    state_root=state_root,
                    source="source",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=command,
                )
            self.assertEqual(calls, [], "a rejected source target must block before any command")

    def test_provision_rejects_release_artifact_symlink_before_any_command(self) -> None:
        """The pinned wheel leaf must not redirect downloader or virtualenv work through a symlink."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        filename = manifest["artifacts"]["release_wheel"]["filename"]
        self.assertIsInstance(filename, str)
        project_root = SKILL_ROOT.parents[1].resolve()
        with tempfile.TemporaryDirectory() as td:
            state_root = approved_state_root(Path(td))
            downloads = state_root / "downloads"
            downloads.mkdir(parents=True)
            (downloads / filename).symlink_to(project_root, target_is_directory=True)
            with self.assertRaisesRegex(runner.ProvisionError, "symlink|escapes"):
                runner.provision(
                    manifest,
                    state_root=state_root,
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=lambda _args, **_kwargs: self.fail("artifact symlink reached a command"),
                    downloader=lambda _url, _destination: self.fail("artifact symlink reached downloader"),
                )

    def test_provision_rejects_symlinked_venv_python_before_pip_or_download(self) -> None:
        """The state-local interpreter executed after venv creation must be a bound regular leaf."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state_root = approved_state_root(root)
            outside = root / "outside-python"
            outside.write_bytes(b"outside")
            outside.chmod(0o700)

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                probe_result = fake_runtime_probe(args)
                if probe_result is not None:
                    return probe_result
                if "venv" in args and "--help" not in args:
                    venv_python = state_root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                    venv_python.parent.mkdir(parents=True, exist_ok=True)
                    venv_python.symlink_to(outside)
                    return subprocess.CompletedProcess(args, 0, "", "")
                if "--help" in args or "--version" in args:
                    return subprocess.CompletedProcess(args, 0, "", "")
                self.fail("symlinked venv Python reached a later command")

            with self.assertRaisesRegex(runner.ProvisionError, "virtual environment Python|symlink"):
                runner.provision(
                    manifest,
                    state_root=state_root,
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable=sys.executable,
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=command,
                    downloader=lambda *_args: self.fail("symlinked venv Python reached download"),
                )

    def test_isolated_environment_rejects_symlinked_home_and_cache_children(self) -> None:
        """Pip/Git environment directories must not resolve through a child symlink."""
        runner = load_runner()
        project_root = SKILL_ROOT.parents[1].resolve()
        for child in ("home", "pip-cache", "xdg-cache", "tmp"):
            with tempfile.TemporaryDirectory() as td:
                state_root = approved_state_root(Path(td))
                state_root.mkdir(parents=True)
                (state_root / child).symlink_to(project_root, target_is_directory=True)
                with self.assertRaisesRegex(runner.ProvisionError, "symlink|escapes"):
                    runner.isolated_environment(state_root)

    def test_provision_uses_precreated_state_tmp_instead_of_hostile_ambient_temp(self) -> None:
        """Ambient TMPDIR/TEMP/TMP must never enter the pip, Git, or build environment."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        wheel_bytes = b"safe temp fixture"
        manifest["artifacts"]["release_wheel"]["sha256"] = hashlib.sha256(wheel_bytes).hexdigest()
        hostile_temp = str(SKILL_ROOT.parents[1].resolve())
        previous = {key: os.environ.get(key) for key in ("TMPDIR", "TEMP", "TMP")}
        captured_environments: list[dict[str, str]] = []
        with tempfile.TemporaryDirectory() as td:
            try:
                os.environ.update({"TMPDIR": hostile_temp, "TEMP": hostile_temp, "TMP": hostile_temp})
                state_root = approved_state_root(Path(td))

                def command(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                    environment = kwargs.get("env")
                    if isinstance(environment, dict) and "TMPDIR" in environment:
                        captured_environments.append(environment)
                    probe_result = fake_runtime_probe(args)
                    if probe_result is not None:
                        return probe_result
                    if "venv" in args and "--help" not in args:
                        create_fake_entrypoint(state_root)
                    return subprocess.CompletedProcess(args, 0, "", "")

                runner.provision(
                    manifest,
                    state_root=state_root,
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=command,
                    downloader=lambda _url, destination: destination.write_bytes(wheel_bytes),
                )
                expected_tmp = str((state_root / "tmp").resolve())
                self.assertTrue((state_root / "tmp").is_dir())
                self.assertTrue(captured_environments)
                for environment in captured_environments:
                    self.assertEqual(environment["TMPDIR"], expected_tmp)
                    self.assertEqual(environment["TEMP"], expected_tmp)
                    self.assertEqual(environment["TMP"], expected_tmp)
                    self.assertNotEqual(environment["TMPDIR"], hostile_temp)
            finally:
                for key, value in previous.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

    def test_wheel_download_path_cannot_escape_the_state_downloads_directory(self) -> None:
        """Allowing a wheel filename to leave state_root/downloads must fail this test."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        manifest["artifacts"]["release_wheel"]["filename"] = "../outside.whl"
        with tempfile.TemporaryDirectory() as td:
            state_root = approved_state_root(Path(td))
            with self.assertRaisesRegex(runner.ProvisionError, "filename|downloads"):
                runner.provision(
                    manifest,
                    state_root=state_root,
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
                    downloader=lambda _url, _destination: self.fail("escaped wheel path reached downloader"),
                )

    def test_execution_environment_excludes_ambient_pip_python_and_git_configuration(self) -> None:
        """Inheriting ambient package, import, or Git configuration must fail this test."""
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            state_root = approved_state_root(Path(td))
            previous = {
                "PIP_CONFIG_FILE": os.environ.get("PIP_CONFIG_FILE"),
                "PIP_INDEX_URL": os.environ.get("PIP_INDEX_URL"),
                "PYTHONPATH": os.environ.get("PYTHONPATH"),
                "GIT_CONFIG_GLOBAL": os.environ.get("GIT_CONFIG_GLOBAL"),
                "HTTPS_PROXY": os.environ.get("HTTPS_PROXY"),
            }
            try:
                os.environ.update(
                    {
                        "PIP_CONFIG_FILE": "/tmp/host-pip.conf",
                        "PIP_INDEX_URL": "https://host.invalid/simple",
                        "PYTHONPATH": "/tmp/host-imports",
                        "GIT_CONFIG_GLOBAL": "/tmp/host-gitconfig",
                        "HTTPS_PROXY": "http://proxy.example:8080",
                    }
                )
                environment = runner.isolated_environment(state_root)
            finally:
                for key, value in previous.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

        self.assertEqual(environment["HOME"], str((state_root / "home").resolve()))
        self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["HTTPS_PROXY"], "http://proxy.example:8080")
        self.assertNotIn("PIP_INDEX_URL", environment)
        self.assertNotIn("PYTHONPATH", environment)

    def test_preflight_probes_use_trusted_tools_isolated_flags_environment_and_cwd(self) -> None:
        """Hostile import/config/cwd state must not influence ungated local capability probes."""
        runner = load_runner()
        calls: list[tuple[list[str], dict[str, object]]] = []
        hostile_keys = {
            "PYTHONPATH": "/hostile/imports",
            "PYTHONHOME": "/hostile/home",
            "PYTHONSTARTUP": "/hostile/startup.py",
            "PYTHONUSERBASE": "/hostile/userbase",
            "PIP_CONFIG_FILE": "/hostile/pip.conf",
            "PIP_NO_INDEX": "0",
            "PIP_DISABLE_PIP_VERSION_CHECK": "0",
            "GIT_CONFIG_GLOBAL": "/hostile/gitconfig",
            "GIT_CONFIG_NOSYSTEM": "0",
            "GIT_TERMINAL_PROMPT": "1",
        }

        def command(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append((args, kwargs))
            if "-c" in args:
                return subprocess.CompletedProcess(args, 0, json.dumps(selected_runtime()) + "\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        previous_environment = {key: os.environ.get(key) for key in hostile_keys}
        previous_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as td:
            hostile_cwd = Path(td)
            (hostile_cwd / "sitecustomize.py").write_text("raise RuntimeError('loaded')\n", encoding="utf-8")
            (hostile_cwd / ".env").write_text("OPENAI_API_KEY=must-not-load\n", encoding="utf-8")
            before = sorted(path.relative_to(hostile_cwd) for path in hostile_cwd.rglob("*"))
            try:
                os.environ.update(hostile_keys)
                os.chdir(hostile_cwd)
                runner.preflight(
                    runner.load_manifest(MANIFEST),
                    source="source",
                    python_executable=sys.executable,
                    python_version=(0, 0),
                    python_runtime=None,
                    command=command,
                )
            finally:
                os.chdir(previous_cwd)
                for key, value in previous_environment.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            after = sorted(path.relative_to(hostile_cwd) for path in hostile_cwd.rglob("*"))

        self.assertEqual(after, before)
        self.assertGreaterEqual(len(calls), 4)
        if os.name == "nt":
            system_root = Path(os.environ.get("SystemRoot", os.environ.get("WINDIR", "C:\\"))).resolve()
            expected_cwd = Path(system_root.anchor).resolve()
        else:
            expected_cwd = Path(os.path.abspath(os.sep)).resolve()
        for args, kwargs in calls:
            actual_cwd = Path(str(kwargs["cwd"])).resolve()
            self.assertEqual(actual_cwd, expected_cwd)
            self.assertFalse(actual_cwd.is_relative_to(runner.PROJECT_ROOT))
            self.assertNotEqual(actual_cwd, hostile_cwd.resolve())
            environment = kwargs["env"]
            self.assertIsInstance(environment, dict)
            for key in hostile_keys:
                self.assertNotEqual(environment.get(key), hostile_keys[key])
            self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")
            self.assertEqual(environment["PYTHONNOUSERSITE"], "1")
            self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)
            self.assertEqual(environment["PIP_NO_INDEX"], "1")
            self.assertEqual(environment["PIP_DISABLE_PIP_VERSION_CHECK"], "1")
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
            if Path(args[0]).name.startswith("python"):
                self.assertTrue(Path(args[0]).is_absolute())
                self.assertEqual(args[1:3], ["-I", "-B"])
            if Path(args[0]).name == "git":
                self.assertTrue(Path(args[0]).is_absolute())

    def test_provision_rejects_squatted_or_nonprivate_state_root_before_commands(self) -> None:
        """Provisioning may initialize only an absent or empty private dedicated root."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            occupied_root = approved_state_root(base / "occupied")
            occupied_root.mkdir(parents=True, mode=0o700)
            marker = occupied_root / "untrusted-state"
            marker.write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(runner.ProvisionError, "empty|existing"):
                runner.provision(
                    manifest,
                    state_root=occupied_root,
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable=sys.executable,
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=lambda *_args, **_kwargs: self.fail("occupied root reached a command"),
                )
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

            if os.name != "nt":
                nonprivate_root = approved_state_root(base / "nonprivate")
                nonprivate_root.mkdir(parents=True, mode=0o700)
                nonprivate_root.chmod(0o777)
                with self.assertRaisesRegex(runner.ProvisionError, "private|permission"):
                    runner.provision(
                        manifest,
                        state_root=nonprivate_root,
                        source="wheel",
                        confirm_authorized_provision=True,
                        authorization_id="AUTH-42",
                        python_executable=sys.executable,
                        python_version=(3, 11),
                        python_runtime=selected_runtime(),
                        command=lambda *_args, **_kwargs: self.fail("nonprivate root reached a command"),
                    )

    def test_security_validation_survives_python_optimized_mode(self) -> None:
        """Security checks must not disappear when the wrapper runs with python -O."""
        original_manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        invalid_manifest = json.loads(json.dumps(original_manifest))
        invalid_manifest["upstream"]["clone_url"] = "https://untrusted.example/ps-fuzz.git"
        capabilities_path = SKILL_ROOT / "resources" / "capabilities-v2.1.0.json"
        invalid_capabilities = json.loads(capabilities_path.read_text(encoding="utf-8"))
        invalid_capabilities["upstream_tag"] = "latest"
        probe_script = r'''
import importlib.util
import json
import subprocess
import sys

runner_path, invalid_manifest_path, invalid_capabilities_path, valid_manifest_path = sys.argv[1:]
spec = importlib.util.spec_from_file_location("optimized_ps_fuzz_runner", runner_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

for loader, path, code in (
    (module.load_manifest, invalid_manifest_path, 10),
    (module.load_capabilities, invalid_capabilities_path, 11),
):
    try:
        loader(module.Path(path))
    except module.ProvisionError:
        pass
    else:
        raise SystemExit(code)

invalid_runtime = {
    "implementation": 7,
    "major": True,
    "minor": 11,
    "system": "Linux",
    "machine": "x86_64",
    "libc": "glibc",
    "libc_version": "2.28",
    "macos_version": "",
}
def fake_probe(args, **kwargs):
    return subprocess.CompletedProcess(args, 0, json.dumps(invalid_runtime), "")
try:
    module._selected_python_runtime(sys.executable, fake_probe)
except module.ProvisionError:
    pass
else:
    raise SystemExit(12)

valid_manifest = module.load_manifest(module.Path(valid_manifest_path))
valid_manifest["python"]["native_wheel_platforms"] = "linux-glibc-2.28+-x86_64"
try:
    module._runtime_support(valid_manifest, (3, 11), {
        "implementation": "CPython", "major": 3, "minor": 11,
        "system": "Linux", "machine": "x86_64", "libc": "glibc",
        "libc_version": "2.28", "macos_version": "",
    })
except module.ProvisionError:
    pass
else:
    raise SystemExit(13)
'''
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            invalid_manifest_path = root / "invalid-manifest.json"
            invalid_capabilities_path = root / "invalid-capabilities.json"
            invalid_manifest_path.write_text(json.dumps(invalid_manifest), encoding="utf-8")
            invalid_capabilities_path.write_text(json.dumps(invalid_capabilities), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "-O",
                    "-c",
                    probe_script,
                    str(RUNNER),
                    str(invalid_manifest_path),
                    str(invalid_capabilities_path),
                    str(MANIFEST),
                ],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_manifest_rejects_malformed_hash_commit_tag_and_release_url(self) -> None:
        """Relaxing pinned-artifact manifest validation must fail this test."""
        runner = load_runner()
        original = json.loads(MANIFEST.read_text(encoding="utf-8"))
        invalid_fields = (
            ("sha256", "not-a-sha256"),
            ("commit", "main"),
            ("tag", "v2.1.0/unsafe"),
            ("url", "https://github.com/prompt-security/ps-fuzz/releases/download/v9.9.9/other.whl"),
            ("url_query", original["artifacts"]["release_wheel"]["url"] + "?download=attacker"),
            ("url_fragment", original["artifacts"]["release_wheel"]["url"] + "#fragment"),
            ("filename", "../../outside.whl"),
            ("clone_url", "https://evil.example/ps-fuzz.git"),
            ("lock_path", "../requirements.lock"),
            ("python_implementation", "PyPy"),
            ("python_minimum", "3.8"),
            ("python_maximum", "3.12"),
            ("python_platforms", []),
        )

        with tempfile.TemporaryDirectory() as td:
            for field, value in invalid_fields:
                candidate = json.loads(json.dumps(original))
                if field == "sha256":
                    candidate["artifacts"]["release_wheel"][field] = value
                elif field in {"url", "url_query", "url_fragment", "filename"}:
                    target_field = "url" if field.startswith("url") else field
                    candidate["artifacts"]["release_wheel"][target_field] = value
                elif field == "clone_url":
                    candidate["upstream"][field] = value
                elif field == "lock_path":
                    candidate["dependency_lock"]["path"] = value
                elif field == "python_implementation":
                    candidate["python"]["implementation"] = value
                elif field == "python_minimum":
                    candidate["python"]["minimum"] = value
                elif field == "python_maximum":
                    candidate["python"]["maximum"] = value
                elif field == "python_platforms":
                    candidate["python"]["native_wheel_platforms"] = value
                else:
                    candidate["upstream"][field] = value
                candidate_path = Path(td) / f"invalid-{field}.json"
                candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
                with self.assertRaisesRegex(runner.ProvisionError, "malformed"):
                    runner.load_manifest(candidate_path)

class PsFuzzActiveRunTests(unittest.TestCase):
    """Offline tests for the actively-authorized, redacted execution boundary."""

    def test_cli_help_describes_current_run_state_root_requirement(self) -> None:
        runner = load_runner()
        help_text = runner._parser().format_help()
        self.assertIn("required for provision and run", " ".join(help_text.split()))
        self.assertNotIn("Task 2", help_text)

    def _prepared_state(self, root: Path) -> tuple[Path, Path]:
        state_root = approved_state_root(root)
        executable = create_fake_entrypoint(state_root)
        write_fake_receipt(state_root, executable)
        return state_root, executable

    def _run_kwargs(self, root: Path) -> dict[str, object]:
        state_root, _executable = self._prepared_state(root)
        prompt = root / "system-prompt.txt"
        prompt.write_text("SYSTEM SECRET: do not disclose", encoding="utf-8")
        return {
            "state_root": state_root,
            "confirm_authorized_test": True,
            "authorization_id": "AUTH-RUN-42",
            "system_prompt_file": prompt,
            "target_provider": "open_ai",
            "target_model": "target-model",
            "attack_provider": "open_ai",
            "attack_model": "attack-model",
            "tests": ["system_prompt_stealer"],
            "attempts": 2,
            "threads": 1,
            "output_dir": root / "redacted-report",
        }

    def test_capability_snapshot_is_static_direct_model_scope_without_debug_or_generic_adapters(self) -> None:
        runner = load_runner()
        capabilities = runner.load_capabilities()
        self.assertEqual(set(capabilities["providers"]), {"open_ai", "ollama"})
        self.assertIn("system_prompt_stealer", capabilities["attacks"])
        self.assertIn("rag_poisoning", capabilities["attacks"])
        self.assertNotIn("custom_benchmark_test", capabilities["attacks"])
        self.assertIn("registers custom_benchmark_test", capabilities["known_upstream_behavior"])
        self.assertIn("-d", capabilities["batch_flags"])
        prohibited = {"--debug", "--debug-level", "--custom-benchmark", "--mcp", "--tool", "--agent-url"}
        self.assertFalse(prohibited.intersection(capabilities["batch_flags"]))

    def test_footer_parser_uses_only_the_real_ansi_prettytable_total_row(self) -> None:
        runner = load_runner()
        captured = """\x1b[1mTest results\x1b[0m ...
╭───┬────────────────────────────────────────────────────┬────────┬───────────┬────────┬─────────┬──────────╮
│   │ Attack Type                                        │ Broken │ Resilient │ Errors │ Skipped │ Strength │
├───┼────────────────────────────────────────────────────┼────────┼───────────┼────────┼─────────┼──────────┤
│ \x1b[31m✘\x1b[0m │ amnesia .......................................... │ 8      │ 1         │ 2      │ 0       │ [==      ] │
│ \x1b[32m✔\x1b[0m │ system_prompt_stealer ........................... │ 0      │ 4         │ 0      │ 0       │ [========] │
├───┼────────────────────────────────────────────────────┼────────┼───────────┼────────┼─────────┼──────────┤
│ \x1b[31m✘\x1b[0m │ Total (# tests): ................................ │ 1      │ 1         │ 0      │ 1       │ [====    ] │
╰───┴────────────────────────────────────────────────────┴────────┴───────────┴────────┴─────────┴──────────╯"""
        self.assertEqual(runner._aggregate_counts(captured), {"broken": 1, "resilient": 1, "errors": 0, "skipped": 1})
        self.assertIsNone(runner._aggregate_counts("| Total (# tests): | 1 | 2 | 3 | 4 |"))

    def test_zero_rc_requires_one_complete_nonempty_error_free_footer(self) -> None:
        """A zero child status cannot become a successful assessment without complete aggregate evidence."""
        runner = load_runner()
        output_cases = (
            ("empty", "", "invalid-output", None),
            (
                "malformed",
                "│ ✘ │ Total (# tests): .... │ bad │ 1 │ 0 │ 0 │ [====] │",
                "invalid-output",
                None,
            ),
            (
                "duplicate",
                (
                    "│ ✘ │ Total (# tests): .... │ 1 │ 1 │ 0 │ 0 │ [====] │\n"
                    "│ ✘ │ Total (# tests): .... │ 1 │ 1 │ 0 │ 0 │ [====] │"
                ),
                "invalid-output",
                None,
            ),
            (
                "malformed-plus-valid",
                (
                    "Total (# tests): malformed\n"
                    "│ ✘ │ Total (# tests): .... │ 1 │ 1 │ 0 │ 0 │ [====] │"
                ),
                "invalid-output",
                None,
            ),
            (
                "zero-total",
                "│ ✘ │ Total (# tests): .... │ 0 │ 0 │ 0 │ 0 │ [====] │",
                "invalid-output",
                None,
            ),
            (
                "errors",
                "│ ✘ │ Total (# tests): .... │ 0 │ 1 │ 1 │ 0 │ [====] │",
                "incomplete",
                {"broken": 0, "resilient": 1, "errors": 1, "skipped": 0},
            ),
            (
                "skipped",
                "│ ✘ │ Total (# tests): .... │ 0 │ 1 │ 0 │ 1 │ [====] │",
                "incomplete",
                {"broken": 0, "resilient": 1, "errors": 0, "skipped": 1},
            ),
        )
        with tempfile.TemporaryDirectory() as td:
            for name, stdout, assessment_status, expected_counts in output_cases:
                with self.subTest(name=name):
                    root = Path(td) / name
                    root.mkdir()
                    kwargs = self._run_kwargs(root)
                    result = runner.run(
                        runner.load_manifest(MANIFEST),
                        runner.load_capabilities(),
                        command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, stdout, "raw error"),
                        **kwargs,
                    )
                    self.assertNotEqual(result.exit_status, 0)
                    self.assertEqual(result.upstream_exit_status, 0)
                    self.assertEqual(result.assessment_status, assessment_status)
                    self.assertEqual(result.aggregate_counts, expected_counts)
                    report = json.loads((Path(kwargs["output_dir"]) / "run.json").read_text(encoding="utf-8"))
                    self.assertEqual(report["assessment_status"], assessment_status)
                    self.assertNotEqual(report["wrapper_exit_status"], 0)
                    self.assertEqual(report["upstream_exit_status"], 0)
                    self.assertEqual(report["aggregate_result_counts"], expected_counts)
                    persisted = "\n".join(
                        path.read_text(encoding="utf-8") for path in Path(kwargs["output_dir"]).iterdir()
                    )
                    self.assertNotIn("raw error", persisted)

    def test_preflight_inspects_safe_selected_config_without_state_or_network(self) -> None:
        runner = load_runner()
        calls: list[list[str]] = []
        previous = os.environ.get("OPENAI_API_KEY")
        os.environ["OPENAI_API_KEY"] = "not-reported"
        try:
            inspection = runner.preflight(
                runner.load_manifest(MANIFEST),
                source="wheel",
                python_executable="python3",
                python_version=(3, 11),
                python_runtime=selected_runtime(),
                command=lambda args, **_kwargs: calls.append(args) or subprocess.CompletedProcess(args, 0, "", ""),
                capabilities=runner.load_capabilities(),
                target_provider="open_ai",
                target_model="target-model",
                attack_provider="ollama",
                attack_model="attack-model",
                tests=["rag_poisoning"],
                target_base_url="https://target.example/v1",
                approved_target_url="https://target.example/v1/",
                embedding_provider="open_ai",
                embedding_model="embed-model",
                embedding_base_url="https://embed.example/v1",
                approved_embedding_url="https://embed.example/v1/",
            )
        finally:
            if previous is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = previous
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(Path(args[0]).is_absolute() for args in calls))
        self.assertEqual(calls[0][1:], ["-I", "-B", "-m", "venv", "--help"])
        self.assertEqual(calls[1][1:], ["-I", "-B", "-m", "pip", "--version"])
        self.assertEqual(inspection["target"]["origin"], "https://target.example")
        self.assertTrue(inspection["credential_environment_present"]["OPENAI_API_KEY"])
        with self.assertRaisesRegex(runner.ProvisionError, "approved-embedding-url"):
            runner.preflight(
                runner.load_manifest(MANIFEST),
                source="wheel",
                python_executable="python3",
                python_version=(3, 11),
                python_runtime=selected_runtime(),
                command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
                capabilities=runner.load_capabilities(),
                target_provider="open_ai",
                target_model="target-model",
                attack_provider="ollama",
                attack_model="attack-model",
                tests=["rag_poisoning"],
                embedding_provider="open_ai",
                embedding_model="embed-model",
                embedding_base_url="https://embed.example/v1",
            )
        with self.assertRaisesRegex(runner.ProvisionError, "provider-wide"):
            runner.preflight(
                runner.load_manifest(MANIFEST),
                source="wheel",
                python_executable="python3",
                python_version=(3, 11),
                python_runtime=selected_runtime(),
                command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
                capabilities=runner.load_capabilities(),
                target_provider="open_ai",
                target_model="target-model",
                attack_provider="open_ai",
                attack_model="attack-model",
                tests=["system_prompt_stealer"],
                target_base_url="https://target.example/v1",
                approved_target_url="https://target.example/v1",
            )

    def test_custom_base_url_requires_safe_approval_for_both_same_provider_roles(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            kwargs = self._run_kwargs(Path(td))
            kwargs.update({"target_base_url": "https://target.example/v1", "approved_target_url": "https://target.example/v1"})
            with self.assertRaisesRegex(runner.ProvisionError, "approved-attack-url"):
                runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), **kwargs)

    def test_orphan_target_or_attack_approval_is_rejected_before_prompt_or_output_access(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            for role in ("target", "attack"):
                with self.subTest(role=role):
                    root = Path(td) / role
                    root.mkdir()
                    kwargs = self._run_kwargs(root)
                    kwargs[f"approved_{role}_url"] = f"https://{role}.example/v1"
                    Path(kwargs["system_prompt_file"]).unlink()
                    with self.assertRaisesRegex(runner.ProvisionError, f"approved-{role}-url.*only with"):
                        runner.run(
                            runner.load_manifest(MANIFEST),
                            runner.load_capabilities(),
                            command=lambda *_args, **_kwargs: self.fail("orphan approval reached the fuzzer"),
                            **kwargs,
                        )
                    self.assertFalse(Path(kwargs["output_dir"]).exists())

    def test_run_fails_closed_on_windows_after_authorization_and_before_prompt_access(self) -> None:
        runner = load_runner()
        original_os = runner.os
        with tempfile.TemporaryDirectory() as td:
            kwargs = self._run_kwargs(Path(td))
            Path(kwargs["system_prompt_file"]).unlink()
            runner.os = OsNameView("nt")
            try:
                kwargs["confirm_authorized_test"] = False
                with self.assertRaisesRegex(runner.ProvisionError, "confirm-authorized-test"):
                    runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), **kwargs)
                kwargs["confirm_authorized_test"] = True
                with self.assertRaisesRegex(runner.ProvisionError, "Windows.*ACL privacy") as raised:
                    runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), **kwargs)
            finally:
                runner.os = original_os
            self.assertNotIn("system-prompt-file", str(raised.exception))
            self.assertFalse(Path(kwargs["output_dir"]).exists())

    def test_boolean_attempts_or_threads_fail_before_prompt_or_output_access(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            for field in ("attempts", "threads"):
                with self.subTest(field=field):
                    root = Path(td) / field
                    root.mkdir()
                    kwargs = self._run_kwargs(root)
                    kwargs[field] = True
                    Path(kwargs["system_prompt_file"]).unlink()
                    with self.assertRaisesRegex(runner.ProvisionError, "positive integers"):
                        runner.run(
                            runner.load_manifest(MANIFEST),
                            runner.load_capabilities(),
                            command=lambda *_args, **_kwargs: self.fail("invalid invocation reached fuzzer"),
                            **kwargs,
                        )
                    self.assertFalse(Path(kwargs["output_dir"]).exists())

    def test_ollama_only_child_environment_excludes_openai_secret(self) -> None:
        runner = load_runner()
        previous = os.environ.get("OPENAI_API_KEY")
        os.environ["OPENAI_API_KEY"] = "sk-should-not-reach-ollama"
        try:
            with tempfile.TemporaryDirectory() as td:
                kwargs = self._run_kwargs(Path(td))
                kwargs.update({"target_provider": "ollama", "attack_provider": "ollama"})
                def command(args: list[str], **command_kwargs: object) -> subprocess.CompletedProcess[str]:
                    self.assertNotIn("OPENAI_API_KEY", command_kwargs["env"])
                    return subprocess.CompletedProcess(args, 0, "", "")
                runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), command=command, **kwargs)
        finally:
            if previous is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = previous

    def test_invalid_model_or_authorization_never_reaches_preview_or_reports(self) -> None:
        import contextlib
        import io
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            kwargs = self._run_kwargs(Path(td))
            kwargs["authorization_id"] = "sk-raw-token-leak"
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture), self.assertRaisesRegex(runner.ProvisionError, "authorization-id"):
                runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), **kwargs)
            self.assertNotIn("sk-raw-token-leak", capture.getvalue())
            self.assertFalse(Path(kwargs["output_dir"]).exists())
            kwargs["authorization_id"] = "AUTH-RUN-42"
            kwargs["target_model"] = "SYSTEM SECRET: do not disclose"
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture), self.assertRaisesRegex(runner.ProvisionError, "target-model"):
                runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), **kwargs)
            self.assertNotIn("SYSTEM SECRET", capture.getvalue())

    def test_active_launch_oserror_is_a_static_error_without_report_or_detail(self) -> None:
        import contextlib
        import io

        runner = load_runner()
        token = "ghp_verySecretActiveLaunchFailure"
        with tempfile.TemporaryDirectory() as td:
            kwargs = self._run_kwargs(Path(td))

            def command(_args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                raise OSError(token)

            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaisesRegex(
                runner.ProvisionError, "ps-fuzz invocation failed"
            ) as raised:
                runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), command=command, **kwargs)
            self.assertNotIn(token, output.getvalue())
            self.assertNotIn(token, str(raised.exception))
            self.assertFalse(Path(kwargs["output_dir"]).exists())

    def test_run_verifies_receipt_and_entrypoint_before_prompt_or_credentials(self) -> None:
        """Missing, malformed, linked, or stale provision evidence must stop before sensitive inputs."""
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in (
                "missing-receipt",
                "bad-receipt",
                "tampered-entrypoint",
                "symlink-entrypoint",
            ):
                with self.subTest(name=name):
                    case_root = root / name
                    case_root.mkdir()
                    kwargs = self._run_kwargs(case_root)
                    state_root = Path(kwargs["state_root"])
                    receipt = state_root / "provision-receipt.json"
                    executable = state_root / "venv" / "bin" / "prompt-security-fuzzer"
                    if name == "missing-receipt":
                        receipt.unlink()
                    elif name == "bad-receipt":
                        receipt.write_text("{}\n", encoding="utf-8")
                    elif name == "tampered-entrypoint":
                        executable.write_bytes(b"tampered")
                    else:
                        target = case_root / "outside-fuzzer"
                        target.write_bytes(b"fake executable")
                        target.chmod(0o700)
                        executable.unlink()
                        executable.symlink_to(target)
                    Path(kwargs["system_prompt_file"]).unlink()
                    with self.assertRaisesRegex(runner.ProvisionError, "receipt|entrypoint|executable|symlink") as raised:
                        runner.run(
                            runner.load_manifest(MANIFEST),
                            runner.load_capabilities(),
                            command=lambda *_args, **_kwargs: self.fail("invalid provision reached fuzzer"),
                            **kwargs,
                        )
                    self.assertNotIn("system-prompt-file", str(raised.exception))
                    self.assertFalse(Path(kwargs["output_dir"]).exists())

            case_root = root / "credentials-order"
            case_root.mkdir()
            kwargs = self._run_kwargs(case_root)
            (Path(kwargs["state_root"]) / "provision-receipt.json").unlink()
            original_reviewed_keys = runner._reviewed_credential_keys
            try:
                runner._reviewed_credential_keys = lambda *_args, **_kwargs: self.fail(
                    "receipt failure reached credential selection"
                )
                with self.assertRaisesRegex(runner.ProvisionError, "receipt"):
                    runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), **kwargs)
            finally:
                runner._reviewed_credential_keys = original_reviewed_keys

    @unittest.skipIf(os.name == "nt", "POSIX ownership and mode checks")
    def test_run_rejects_nonprivate_state_root_and_children(self) -> None:
        """Group/world-accessible state must not be trusted for receipts, executables, or prompts."""
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, relative in (("root", Path()), ("child", Path("venv"))):
                with self.subTest(name=name):
                    case_root = root / name
                    case_root.mkdir()
                    kwargs = self._run_kwargs(case_root)
                    state_root = Path(kwargs["state_root"])
                    target = state_root / relative
                    target.chmod(0o777)
                    Path(kwargs["system_prompt_file"]).unlink()
                    with self.assertRaisesRegex(runner.ProvisionError, "private|permission") as raised:
                        runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), **kwargs)
                    self.assertNotIn("system-prompt-file", str(raised.exception))

            case_root = root / "wrong-owner"
            case_root.mkdir()
            kwargs = self._run_kwargs(case_root)
            Path(kwargs["system_prompt_file"]).unlink()
            real_getuid = runner.os.getuid
            try:
                runner.os.getuid = lambda: real_getuid() + 1
                with self.assertRaisesRegex(runner.ProvisionError, "owned|owner") as raised:
                    runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), **kwargs)
            finally:
                runner.os.getuid = real_getuid
            self.assertNotIn("system-prompt-file", str(raised.exception))

    @unittest.skipUnless(sys.platform == "darwin", "Darwin ACL validation")
    def test_run_rejects_allow_acl_before_prompt_or_credentials(self) -> None:
        """Mode 0700 state with an extended allow ACL is not a private trust root."""
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            kwargs = self._run_kwargs(Path(td))
            Path(kwargs["system_prompt_file"]).unlink()
            original_run = runner.subprocess.run

            def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                if args[:2] == ["/bin/ls", "-lde"]:
                    acl_output = "drwx------  4 owner  staff  128 Aug 19 00:00 state\n 0: group:everyone allow write\n"
                    return subprocess.CompletedProcess(args, 0, acl_output, "")
                return original_run(args, **_kwargs)

            try:
                runner.subprocess.run = fake_run
                with self.assertRaisesRegex(runner.ProvisionError, "ACL") as raised:
                    runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), **kwargs)
            finally:
                runner.subprocess.run = original_run
            self.assertNotIn("system-prompt-file", str(raised.exception))

    def test_secret_shaped_identifiers_and_provider_names_never_reach_preview(self) -> None:
        import contextlib
        import io

        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        capabilities = runner.load_capabilities()
        secret_values = (
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "vendor:sk-proj-raw-token",
            "github_pat_abcdefghijklmnopqrstuvwxyz0123456789",
            "AKIAABCDEFGHIJKLMNOP",
            "xoxb-1234567890-secret",
            "hf_abcdefghijklmnopqrstuvwxyz",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signaturepayload",
        )
        with tempfile.TemporaryDirectory() as td:
            for secret in secret_values:
                kwargs = self._run_kwargs(Path(td))
                kwargs["target_model"] = secret
                capture = io.StringIO()
                with contextlib.redirect_stdout(capture), self.assertRaisesRegex(runner.ProvisionError, "target-model"):
                    runner.run(manifest, capabilities, **kwargs)
                self.assertNotIn(secret, capture.getvalue())
                self.assertFalse(Path(kwargs["output_dir"]).exists())

                kwargs = self._run_kwargs(Path(td))
                kwargs["attack_model"] = secret
                with self.assertRaisesRegex(runner.ProvisionError, "attack-model"):
                    runner.run(manifest, capabilities, **kwargs)

                kwargs = self._run_kwargs(Path(td))
                kwargs.update(
                    {
                        "tests": ["rag_poisoning"],
                        "embedding_provider": "open_ai",
                        "embedding_model": secret,
                    }
                )
                with self.assertRaisesRegex(runner.ProvisionError, "embedding-model"):
                    runner.run(manifest, capabilities, **kwargs)

            kwargs = self._run_kwargs(Path(td))
            kwargs["authorization_id"] = secret_values[0]
            with self.assertRaisesRegex(runner.ProvisionError, "authorization-id"):
                runner.run(manifest, capabilities, **kwargs)

            kwargs = self._run_kwargs(Path(td))
            kwargs["authorization_id"] = "AUTH-ghp_abcdefghijklmnopqrstuvwxyz0123456789"
            with self.assertRaisesRegex(runner.ProvisionError, "authorization-id") as raised:
                runner.run(manifest, capabilities, **kwargs)
            self.assertNotIn(kwargs["authorization_id"], str(raised.exception))

            with self.assertRaisesRegex(runner.ProvisionError, "unsupported provider") as raised:
                runner.preflight(
                    manifest,
                    source="wheel",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
                    capabilities=capabilities,
                    target_provider=secret_values[0],
                    target_model="target-model",
                    attack_provider="open_ai",
                    attack_model="attack-model",
                    tests=["system_prompt_stealer"],
                )
            self.assertNotIn(secret_values[0], str(raised.exception))

    def test_cli_parser_never_echoes_secret_shaped_argument_values(self) -> None:
        import contextlib
        import io

        runner = load_runner()
        token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as exited:
            runner.main(["run", "--attempts", token])
        self.assertEqual(exited.exception.code, 2)
        self.assertIn("invalid arguments", stderr.getvalue())
        self.assertNotIn(token, stderr.getvalue())

    def test_temperature_is_finite_unit_interval_and_slash_model_ids_are_safe(self) -> None:
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        capabilities = runner.load_capabilities()
        inspection = runner.preflight(
            manifest,
            source="wheel",
            python_executable="python3",
            python_version=(3, 11),
            python_runtime=selected_runtime(),
            command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
            capabilities=capabilities,
            target_provider="open_ai",
            target_model="meta-llama/Meta-Llama-3.1-8B-Instruct",
            attack_provider="open_ai",
            attack_model="openai/gpt-oss-20b",
            tests=["system_prompt_stealer"],
            attack_temperature=0.6,
        )
        self.assertEqual(inspection["target"]["model"], "meta-llama/Meta-Llama-3.1-8B-Instruct")
        for model in ("openai/sk-proj-raw-token", "meta-llama/api_key_raw", "vendor/bearer-token"):
            with self.assertRaisesRegex(runner.ProvisionError, "target-model"):
                runner.preflight(
                    manifest,
                    source="wheel",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
                    capabilities=capabilities,
                    target_provider="open_ai",
                    target_model=model,
                    attack_provider="open_ai",
                    attack_model="attack-model",
                    tests=["system_prompt_stealer"],
                )
        for model in (" target-model", "target-model ", "target-model\n"):
            with self.assertRaisesRegex(runner.ProvisionError, "target-model"):
                runner.preflight(
                    manifest,
                    source="wheel",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
                    capabilities=capabilities,
                    target_provider="open_ai",
                    target_model=model,
                    attack_provider="open_ai",
                    attack_model="attack-model",
                    tests=["system_prompt_stealer"],
                )
        for value in (2, -0.1, float("nan"), float("inf")):
            with self.assertRaisesRegex(runner.ProvisionError, "attack-temperature"):
                runner.preflight(
                    manifest,
                    source="wheel",
                    python_executable="python3",
                    python_version=(3, 11),
                    python_runtime=selected_runtime(),
                    command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
                    capabilities=capabilities,
                    target_provider="open_ai",
                    target_model="target-model",
                    attack_provider="open_ai",
                    attack_model="attack-model",
                    tests=["system_prompt_stealer"],
                    attack_temperature=value,
                )
        with tempfile.TemporaryDirectory() as td:
            kwargs = self._run_kwargs(Path(td))
            kwargs["attack_temperature"] = float("nan")
            with self.assertRaisesRegex(runner.ProvisionError, "attack-temperature"):
                runner.run(manifest, capabilities, **kwargs)

    def test_run_rejects_confirmation_before_reading_prompt_or_creating_output(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            kwargs = self._run_kwargs(root)
            kwargs["confirm_authorized_test"] = False
            prompt = Path(kwargs["system_prompt_file"])
            prompt.unlink()
            with self.assertRaisesRegex(runner.ProvisionError, "confirm-authorized-test"):
                runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), **kwargs)
            self.assertFalse(Path(kwargs["output_dir"]).exists())

    def test_prompt_ingestion_rejects_symlinks_and_files_over_one_mib_before_launch(self) -> None:
        """Prompt validation must bind one small regular file, not follow links or read unbounded data."""
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in ("symlink", "oversize"):
                with self.subTest(name=name):
                    case_root = root / name
                    case_root.mkdir()
                    kwargs = self._run_kwargs(case_root)
                    prompt = Path(kwargs["system_prompt_file"])
                    if name == "symlink":
                        target = case_root / "real-prompt.txt"
                        target.write_text("real prompt", encoding="utf-8")
                        prompt.unlink()
                        prompt.symlink_to(target)
                    else:
                        prompt.write_bytes(b"x" * (1024 * 1024 + 1))
                    with self.assertRaisesRegex(runner.ProvisionError, "system-prompt-file"):
                        runner.run(
                            runner.load_manifest(MANIFEST),
                            runner.load_capabilities(),
                            command=lambda *_args, **_kwargs: self.fail("invalid prompt reached fuzzer"),
                            **kwargs,
                        )
                    self.assertFalse(Path(kwargs["output_dir"]).exists())

    def test_run_uses_only_reviewed_batch_arguments_and_an_isolated_prompt_copy(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            kwargs = self._run_kwargs(root)
            seen: dict[str, object] = {}

            def command(args: list[str], **command_kwargs: object) -> subprocess.CompletedProcess[str]:
                seen["args"] = args
                seen["kwargs"] = command_kwargs
                return subprocess.CompletedProcess(args, 0, "│ ✘ │ Total (# tests): .... │ 1 │ 2 │ 0 │ 0 │ [====] │", "")

            result = runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), command=command, **kwargs)
            args = seen["args"]
            self.assertIn("-b", args)
            copied_prompt = Path(args[-1])
            self.assertNotEqual(copied_prompt, kwargs["system_prompt_file"])
            self.assertFalse(copied_prompt.exists(), "temporary prompt must be removed after the fuzzer exits")
            self.assertIn("--target-provider", args)
            self.assertIn("--attack-provider", args)
            self.assertIn("--tests", args)
            self.assertIn("-d", args)
            self.assertEqual(args[args.index("-d") + 1], "0")
            self.assertLess(args.index("-d"), len(args) - 1, "quiet logging must precede the prompt positional")
            self.assertEqual(result.aggregate_counts, {"broken": 1, "resilient": 2, "errors": 0, "skipped": 0})
            self.assertEqual(result.exit_status, 0)
            self.assertEqual(result.upstream_exit_status, 0)
            self.assertEqual(result.assessment_status, "complete")
            report = json.loads((Path(kwargs["output_dir"]) / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(report["wrapper_exit_status"], 0)
            self.assertEqual(report["upstream_exit_status"], 0)
            self.assertEqual(report["assessment_status"], "complete")

    def test_run_isolates_child_environment_and_never_persists_raw_output(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            kwargs = self._run_kwargs(root)
            previous = os.environ.get("OPENAI_API_KEY")
            os.environ["OPENAI_API_KEY"] = "sk-test-raw-token"
            try:
                def command(args: list[str], **command_kwargs: object) -> subprocess.CompletedProcess[str]:
                    environment = command_kwargs["env"]
                    self.assertEqual(environment["OPENAI_API_KEY"], "sk-test-raw-token")
                    self.assertNotEqual(environment["HOME"], os.environ.get("HOME"))
                    self.assertEqual(command_kwargs["cwd"], environment["HOME"])
                    self.assertNotIn("PYTHONPATH", environment)
                    self.assertEqual(environment["ANONYMIZED_TELEMETRY"], "false")
                    return subprocess.CompletedProcess(
                        args,
                        0,
                        "SYSTEM SECRET: do not disclose\nsk-test-raw-token\nmodel response: stolen\n| system_prompt_stealer | 3 | 4 | 0 | 1 |",
                        "also secret",
                    )

                runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), command=command, **kwargs)
            finally:
                if previous is None:
                    os.environ.pop("OPENAI_API_KEY", None)
                else:
                    os.environ["OPENAI_API_KEY"] = previous

            output_dir = Path(kwargs["output_dir"])
            self.assertEqual(sorted(path.name for path in output_dir.iterdir()), ["run.json", "summary.md"])
            if os.name != "nt":
                self.assertEqual(output_dir.stat().st_mode & 0o777, 0o700)
                for report_path in output_dir.iterdir():
                    self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
            persisted = "\n".join(path.read_text(encoding="utf-8") for path in output_dir.iterdir())
            self.assertNotIn("SYSTEM SECRET", persisted)
            self.assertNotIn("sk-test-raw-token", persisted)
            self.assertNotIn("model response: stolen", persisted)
            self.assertNotIn("synthetic local Chroma demonstration", persisted)
            self.assertFalse((root / ".env").exists())
            self.assertEqual(Path(kwargs["system_prompt_file"]).read_text(encoding="utf-8"), "SYSTEM SECRET: do not disclose")

    def test_run_uses_validated_state_tmp_when_ambient_temp_points_at_checkout(self) -> None:
        """Active-run temp cwd, HOME, prompt copy, and logs must not follow ambient TMPDIR."""
        runner = load_runner()
        original_temporary_directory = runner.tempfile.TemporaryDirectory
        project_root = SKILL_ROOT.parents[1].resolve()
        previous = {key: os.environ.get(key) for key in ("TMPDIR", "TEMP", "TMP")}
        seen: dict[str, object] = {}

        def checked_temporary_directory(*args: object, **kwargs: object):
            directory = kwargs.get("dir")
            if directory is None:
                raise AssertionError("run attempted to use an ambient temporary directory")
            seen["temporary_dir"] = Path(str(directory)).resolve()
            return original_temporary_directory(*args, **kwargs)

        try:
            with tempfile.TemporaryDirectory() as td:
                os.environ.update({"TMPDIR": str(project_root), "TEMP": str(project_root), "TMP": str(project_root)})
                runner.tempfile.TemporaryDirectory = checked_temporary_directory
                root = Path(td)
                kwargs = self._run_kwargs(root)

                def command(args: list[str], **command_kwargs: object) -> subprocess.CompletedProcess[str]:
                    seen["arguments"] = args
                    seen["environment"] = command_kwargs["env"]
                    seen["cwd"] = Path(str(command_kwargs["cwd"])).resolve()
                    return subprocess.CompletedProcess(args, 0, "| Total (# tests): | 1 | 2 | 0 | 0 | [====] |", "")

                runner.run(runner.load_manifest(MANIFEST), runner.load_capabilities(), command=command, **kwargs)
                state_tmp = (Path(kwargs["state_root"]) / "tmp").resolve()
                self.assertEqual(seen["temporary_dir"], state_tmp)
                self.assertTrue(state_tmp.is_dir())
                self.assertTrue(seen["cwd"].is_relative_to(state_tmp))
                environment = seen["environment"]
                self.assertTrue(Path(environment["HOME"]).resolve().is_relative_to(state_tmp))
                self.assertTrue(Path(environment["TMPDIR"]).resolve().is_relative_to(state_tmp))
                self.assertTrue(Path(seen["arguments"][-1]).resolve().is_relative_to(state_tmp))
                self.assertFalse(seen["cwd"].is_relative_to(project_root))
        finally:
            runner.tempfile.TemporaryDirectory = original_temporary_directory
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_run_rejects_unapproved_urls_unknown_attacks_and_incomplete_rag_before_launch(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for updates, message in (
                ({"target_base_url": "https://key@host.example/v1", "approved_target_url": "https://host.example/v1"}, "credentials"),
                ({"target_base_url": "https://host.example/v1?secret=1", "approved_target_url": "https://host.example/v1"}, "query"),
                ({"target_base_url": "https://host.example:bad/v1", "approved_target_url": "https://host.example:bad/v1"}, "invalid port"),
                ({"target_base_url": 7, "approved_target_url": "https://host.example/v1"}, "absolute"),
                ({"target_base_url": "https://host.example/v1", "approved_target_url": "https://other.example/v1"}, "approved"),
                ({"tests": ["unknown_attack"]}, "supported"),
                ({"tests": ["rag_poisoning"]}, "embedding"),
            ):
                kwargs = self._run_kwargs(root)
                kwargs.update(updates)
                with self.assertRaisesRegex(runner.ProvisionError, message):
                    runner.run(
                        runner.load_manifest(MANIFEST),
                        runner.load_capabilities(),
                        command=lambda *_args, **_kwargs: self.fail("invalid invocation reached fuzzer"),
                        **kwargs,
                    )
                self.assertFalse(Path(kwargs["output_dir"]).exists())

    def test_rag_poisoning_report_states_the_synthetic_chroma_limitation(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            kwargs = self._run_kwargs(root)
            kwargs.update(
                {
                    "tests": ["rag_poisoning"],
                    "embedding_provider": "ollama",
                    "embedding_model": "nomic-embed-text",
                }
            )
            runner.run(
                runner.load_manifest(MANIFEST),
                runner.load_capabilities(),
                command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "| rag_poisoning | 0 | 1 | 0 | 0 |", ""),
                **kwargs,
            )
            persisted = "\n".join(path.read_text(encoding="utf-8") for path in Path(kwargs["output_dir"]).iterdir())
            self.assertIn("synthetic local Chroma demonstration", persisted)
            self.assertIn("not evidence about a user's retrieval", persisted)
            self.assertIn("requested selectors are reported separately", persisted)

    def test_run_rejects_nonzero_or_malformed_fuzzer_output_without_raw_fallback(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            kwargs = self._run_kwargs(root)
            result = runner.run(
                runner.load_manifest(MANIFEST),
                runner.load_capabilities(),
                command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 9, "raw prompt and response", "api token sk-bad"),
                **kwargs,
            )
            self.assertEqual(result.exit_status, 9)
            self.assertEqual(result.upstream_exit_status, 9)
            self.assertEqual(result.assessment_status, "upstream-failed")
            self.assertIsNone(result.aggregate_counts)
            report = json.loads((Path(kwargs["output_dir"]) / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(report["wrapper_exit_status"], 9)
            self.assertEqual(report["upstream_exit_status"], 9)
            self.assertEqual(report["assessment_status"], "upstream-failed")
            persisted = "\n".join(path.read_text(encoding="utf-8") for path in Path(kwargs["output_dir"]).iterdir())
            self.assertNotIn("raw prompt", persisted)
            self.assertNotIn("sk-bad", persisted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
