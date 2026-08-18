#!/usr/bin/env python3
"""Offline behavior tests for the ps-fuzz provisioning boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
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
            python_version=(3, 12),
            command=command,
        )
        self.assertEqual(calls, [["python3", "-m", "venv", "--help"], ["python3", "-m", "pip", "--version"]])

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
                    python_version=(3, 12),
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
                    python_version=(3, 12),
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
                command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
            )

        with self.assertRaisesRegex(runner.ProvisionError, "--source"):
            runner.preflight(
                manifest,
                source="branch:main",
                python_executable="python3",
                python_version=(3, 12),
                command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
            )

        def missing_venv(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args, 1, "", "venv unavailable")

        with self.assertRaisesRegex(runner.ProvisionError, "venv"):
            runner.preflight(
                manifest,
                source="wheel",
                python_executable="python3",
                python_version=(3, 12),
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
                python_version=(3, 12),
                command=missing_pip,
            )

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
                python_version=(3, 12),
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

    def test_wheel_hash_mismatch_stops_before_pip_install(self) -> None:
        """Allowing a mismatched upstream artifact to reach pip must fail this test."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)

        with tempfile.TemporaryDirectory() as td:
            calls: list[list[str]] = []

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(args)
                return subprocess.CompletedProcess(args, 0, "", "")

            with self.assertRaisesRegex(runner.ProvisionError, "SHA-256 mismatch"):
                runner.provision(
                    manifest,
                    state_root=approved_state_root(Path(td)),
                    source="wheel",
                    confirm_authorized_provision=True,
                    authorization_id="AUTH-42",
                    python_executable="python3",
                    python_version=(3, 12),
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
                python_version=(3, 12),
                command=command,
                downloader=lambda _url, _destination: self.fail("source provisioning must not download the release wheel"),
            )

            checkout_calls = [args for args in calls if "checkout" in args]
            self.assertEqual(checkout_calls[0][-1], manifest["upstream"]["commit"])
            self.assertTrue(result.artifact.is_relative_to(state_root / "built-wheels"))

    def test_source_commit_mismatch_stops_before_dependencies_or_build(self) -> None:
        """Accepting a ref that is not the reviewed commit must fail this test."""
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)

        with tempfile.TemporaryDirectory() as td:
            calls: list[list[str]] = []

            def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(args)
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
                    python_version=(3, 12),
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
                        python_version=(3, 12),
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
                    python_version=(3, 12),
                    command=lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", ""),
                    downloader=lambda _url, _destination: self.fail("escaped wheel path reached downloader"),
                )

    def test_execution_environment_excludes_ambient_pip_python_and_git_configuration(self) -> None:
        """Inheriting ambient package, import, or Git configuration must fail this test."""
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            state_root = Path(td) / "caller-state"
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

        self.assertEqual(environment["HOME"], str(state_root / "home"))
        self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["HTTPS_PROXY"], "http://proxy.example:8080")
        self.assertNotIn("PIP_INDEX_URL", environment)
        self.assertNotIn("PYTHONPATH", environment)

    def test_manifest_rejects_malformed_hash_commit_tag_and_release_url(self) -> None:
        """Relaxing pinned-artifact manifest validation must fail this test."""
        runner = load_runner()
        original = json.loads(MANIFEST.read_text(encoding="utf-8"))
        invalid_fields = (
            ("sha256", "not-a-sha256"),
            ("commit", "main"),
            ("tag", "v2.1.0/unsafe"),
            ("url", "https://github.com/prompt-security/ps-fuzz/releases/download/v9.9.9/other.whl"),
            ("filename", "../../outside.whl"),
            ("clone_url", "https://evil.example/ps-fuzz.git"),
            ("lock_path", "../requirements.lock"),
        )

        with tempfile.TemporaryDirectory() as td:
            for field, value in invalid_fields:
                candidate = json.loads(json.dumps(original))
                if field == "sha256":
                    candidate["artifacts"]["release_wheel"][field] = value
                elif field in {"url", "filename"}:
                    candidate["artifacts"]["release_wheel"][field] = value
                elif field == "clone_url":
                    candidate["upstream"][field] = value
                elif field == "lock_path":
                    candidate["dependency_lock"]["path"] = value
                else:
                    candidate["upstream"][field] = value
                candidate_path = Path(td) / f"invalid-{field}.json"
                candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
                with self.assertRaisesRegex(runner.ProvisionError, "malformed"):
                    runner.load_manifest(candidate_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
