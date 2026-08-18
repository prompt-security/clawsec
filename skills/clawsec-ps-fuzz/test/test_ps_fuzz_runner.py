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

class PsFuzzActiveRunTests(unittest.TestCase):
    """Offline tests for the actively-authorized, redacted execution boundary."""

    def test_cli_help_describes_current_run_state_root_requirement(self) -> None:
        runner = load_runner()
        help_text = runner._parser().format_help()
        self.assertIn("required for provision and run", " ".join(help_text.split()))
        self.assertNotIn("Task 2", help_text)

    def _prepared_state(self, root: Path) -> tuple[Path, Path]:
        state_root = approved_state_root(root)
        executable = state_root / "venv" / "bin" / "prompt-security-fuzzer"
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_text("fake executable", encoding="utf-8")
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
        prohibited = {"-d", "--debug", "--custom-benchmark", "--mcp", "--tool", "--agent-url"}
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
                python_version=(3, 12),
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
            )
        finally:
            if previous is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = previous
        self.assertEqual(calls, [["python3", "-m", "venv", "--help"], ["python3", "-m", "pip", "--version"]])
        self.assertEqual(inspection["target"]["origin"], "https://target.example")
        self.assertTrue(inspection["credential_environment_present"]["OPENAI_API_KEY"])
        with self.assertRaisesRegex(runner.ProvisionError, "provider-wide"):
            runner.preflight(
                runner.load_manifest(MANIFEST),
                source="wheel",
                python_executable="python3",
                python_version=(3, 12),
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

    def test_temperature_is_finite_unit_interval_and_slash_model_ids_are_safe(self) -> None:
        runner = load_runner()
        manifest = runner.load_manifest(MANIFEST)
        capabilities = runner.load_capabilities()
        inspection = runner.preflight(
            manifest,
            source="wheel",
            python_executable="python3",
            python_version=(3, 12),
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
                    python_version=(3, 12),
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
                    python_version=(3, 12),
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
            self.assertNotIn("-d", args)
            self.assertEqual(result.aggregate_counts, {"broken": 1, "resilient": 2, "errors": 0, "skipped": 0})

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
            persisted = "\n".join(path.read_text(encoding="utf-8") for path in output_dir.iterdir())
            self.assertNotIn("SYSTEM SECRET", persisted)
            self.assertNotIn("sk-test-raw-token", persisted)
            self.assertNotIn("model response: stolen", persisted)
            self.assertNotIn("synthetic local Chroma demonstration", persisted)
            self.assertFalse((root / ".env").exists())
            self.assertEqual(Path(kwargs["system_prompt_file"]).read_text(encoding="utf-8"), "SYSTEM SECRET: do not disclose")

    def test_run_rejects_unapproved_urls_unknown_attacks_and_incomplete_rag_before_launch(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for updates, message in (
                ({"target_base_url": "https://key@host.example/v1", "approved_target_url": "https://host.example/v1"}, "credentials"),
                ({"target_base_url": "https://host.example/v1?secret=1", "approved_target_url": "https://host.example/v1"}, "query"),
                ({"target_base_url": "https://host.example:bad/v1", "approved_target_url": "https://host.example:bad/v1"}, "invalid port"),
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
            self.assertIsNone(result.aggregate_counts)
            persisted = "\n".join(path.read_text(encoding="utf-8") for path in Path(kwargs["output_dir"]).iterdir())
            self.assertNotIn("raw prompt", persisted)
            self.assertNotIn("sk-bad", persisted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
