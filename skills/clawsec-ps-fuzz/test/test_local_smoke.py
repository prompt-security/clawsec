#!/usr/bin/env python3
"""Offline executable contracts for the packaged local-smoke shell guidance."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import textwrap
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
GUIDE_PATH = SKILL_ROOT / "resources" / "local-smoke.md"
MODEL_HASH = "8e30dff3ac4c8434c49a7036fa15564bdbb6044e42bf04550bf1a096ad7e6a52"
MODEL_SIZE = "2841481184"
FIXTURE = "fixture"


def guide() -> str:
    return GUIDE_PATH.read_text(encoding="utf-8")


def marked_bash_block(marker: str) -> str:
    blocks = re.findall(r"```bash\n(.*?)\n```", guide(), flags=re.DOTALL)
    matches = [block for block in blocks if marker in block]
    if len(matches) != 1:
        raise AssertionError(f"expected one {marker} shell block, found {len(matches)}")
    return matches[0]


def write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o755)


class LocalSmokeShellTests(unittest.TestCase):
    """Run the published shell logic with fake external commands and no network/server."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls.log"
        self.hash_count = self.root / "hash-count"
        self.model_dir = self.root / "model"
        self.model_file = self.model_dir / "gemma-4-E2B-it-Q4_0.gguf"
        write_executable(
            self.bin / "curl",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            output=''
            while (($#)); do
              if [[ "$1" == '--output' ]]; then
                output="$2"
                shift 2
              else
                shift
              fi
            done
            [[ -n "$output" ]]
            printf '%s' "${FAKE_DOWNLOAD_CONTENT:?}" > "$output"
            printf 'curl\n' >> "$CALL_LOG"
            """,
        )
        write_executable(
            self.bin / "shasum",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            cat >/dev/null
            count=0
            if [[ -f "$HASH_COUNT_FILE" ]]; then
              read -r count < "$HASH_COUNT_FILE"
            fi
            count=$((count + 1))
            printf '%s\n' "$count" > "$HASH_COUNT_FILE"
            printf 'hash-%s\n' "$count" >> "$CALL_LOG"
            if [[ "${FAKE_RACE_FINAL_ON_HASH:-0}" == "$count" ]]; then
              printf 'raced-final' > "$RACE_FINAL_PATH"
            fi
            if [[ "${FAKE_HASH_FAIL_ON_CALL:-0}" == "$count" ]]; then
              exit 1
            fi
            """,
        )
        write_executable(
            self.bin / "llama-server",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            if [[ "${1:-}" == '--help' ]]; then
              printf '%s\n' "$FAKE_LLAMA_HELP"
              printf 'help\n' >> "$CALL_LOG"
              exit 0
            fi
            printf 'launch:%s\n' "$*" >> "$CALL_LOG"
            """,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def environment(self, **updates: str) -> dict[str, str]:
        environment = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "CALL_LOG": os.fspath(self.log),
            "HASH_COUNT_FILE": os.fspath(self.hash_count),
            "FAKE_DOWNLOAD_CONTENT": FIXTURE,
            "FAKE_HASH_FAIL_ON_CALL": "0",
            "FAKE_RACE_FINAL_ON_HASH": "0",
            "RACE_FINAL_PATH": os.fspath(self.model_file),
        }
        environment.update(updates)
        return environment

    def prepared_script(self, marker: str) -> str:
        script = marked_bash_block(marker)
        script = script.replace(
            "MODEL_DIR=/secure/models/gemma-4-E2B-it",
            f"MODEL_DIR={shlex.quote(os.fspath(self.model_dir))}",
        )
        script = script.replace(
            "MODEL_FILE=/secure/models/gemma-4-E2B-it/gemma-4-E2B-it-Q4_0.gguf",
            f"MODEL_FILE={shlex.quote(os.fspath(self.model_file))}",
        )
        return script.replace(MODEL_SIZE, str(len(FIXTURE))).replace(MODEL_HASH, "0" * 64)

    def run_script(self, marker: str, **environment: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash"],
            input=self.prepared_script(marker),
            text=True,
            capture_output=True,
            check=False,
            env=self.environment(**environment),
        )

    def log_lines(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").splitlines()

    def test_download_failures_never_publish_or_overwrite(self) -> None:
        """A failed guard, size, hash, or no-replace publish must stop before publication."""
        self.model_dir.mkdir()
        self.model_file.write_text("existing-final", encoding="utf-8")
        result = self.run_script("# local-smoke-download")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.model_file.read_text(encoding="utf-8"), "existing-final")
        self.assertEqual(self.log_lines(), [])

        self.model_file.unlink()
        result = self.run_script("# local-smoke-download", FAKE_DOWNLOAD_CONTENT="bad")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.model_file.exists())
        self.assertEqual(self.log_lines(), ["curl"])

        self.log.unlink()
        partial = self.model_file.with_suffix(self.model_file.suffix + ".partial")
        if partial.exists():
            partial.unlink()
        result = self.run_script("# local-smoke-download", FAKE_HASH_FAIL_ON_CALL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.model_file.exists())
        self.assertEqual(self.log_lines(), ["curl", "hash-1"])

        self.log.unlink()
        self.hash_count.unlink()
        if partial.exists():
            partial.unlink()
        result = self.run_script("# local-smoke-download", FAKE_RACE_FINAL_ON_HASH="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.model_file.read_text(encoding="utf-8"), "raced-final")
        self.assertTrue(partial.is_file(), "failed no-replace publication must retain the verified partial")

    def test_download_publishes_no_replace_and_reverifies_final(self) -> None:
        """Successful publication must hard-link no-replace, remove partial, and hash the final again."""
        result = self.run_script("# local-smoke-download")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.model_file.read_text(encoding="utf-8"), FIXTURE)
        self.assertFalse(self.model_file.with_suffix(self.model_file.suffix + ".partial").exists())
        self.assertEqual(self.log_lines(), ["curl", "hash-1", "hash-2"])
        self.assertIn("published and re-verified", result.stdout)

    def test_failed_prelaunch_checks_never_start_server(self) -> None:
        """Missing flags, wrong size, or bad hash may probe help but must never launch a server."""
        all_flags = (
            "--model --alias --host --port --ctx-size --parallel --no-mmproj --no-webui "
            "--log-disable --offline --no-slots --no-cache-prompt --reasoning-budget"
        )
        self.model_dir.mkdir()
        self.model_file.write_text("bad", encoding="utf-8")
        result = self.run_script("# local-smoke-server", FAKE_LLAMA_HELP=all_flags)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log_lines(), ["help"])

        self.model_file.write_text(FIXTURE, encoding="utf-8")
        self.log.unlink()
        result = self.run_script(
            "# local-smoke-server",
            FAKE_LLAMA_HELP=all_flags,
            FAKE_HASH_FAIL_ON_CALL="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log_lines(), ["help", "hash-1"])

        self.log.unlink()
        self.hash_count.unlink()
        result = self.run_script("# local-smoke-server", FAKE_LLAMA_HELP=all_flags.replace("--offline ", ""))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log_lines(), ["help"])

    def test_server_launch_uses_safe_flags_and_optional_reasoning_array(self) -> None:
        """Only a verified model may launch, with quoted fixed flags and no ambient option injection."""
        required = (
            "--model --alias --host --port --ctx-size --parallel --no-mmproj --no-webui "
            "--log-disable --offline --no-slots --no-cache-prompt"
        )
        self.model_dir.mkdir()
        self.model_file.write_text(FIXTURE, encoding="utf-8")
        for help_text, expected_reasoning in ((required, False), (required + " --reasoning-budget", True)):
            with self.subTest(reasoning=expected_reasoning):
                if self.log.exists():
                    self.log.unlink()
                if self.hash_count.exists():
                    self.hash_count.unlink()
                result = self.run_script(
                    "# local-smoke-server",
                    FAKE_LLAMA_HELP=help_text,
                    LLAMA_REASONING_FLAGS="--host 0.0.0.0 --parallel 99",
                    MODEL_FILE="/tmp/ambient-injection.gguf",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                launch = next(line for line in self.log_lines() if line.startswith("launch:"))
                self.assertIn(f"--model {self.model_file}", launch)
                self.assertIn("--host 127.0.0.1", launch)
                self.assertIn("--parallel 1", launch)
                self.assertIn("--no-slots", launch)
                self.assertIn("--no-cache-prompt", launch)
                self.assertNotIn("0.0.0.0", launch)
                self.assertEqual("--reasoning-budget 0" in launch, expected_reasoning)

    def test_preflight_example_omits_run_only_attempt_controls(self) -> None:
        """The offline preflight preview must not imply it validates run-only attempt controls."""
        block = next(
            value
            for value in re.findall(r"```bash\n(.*?)\n```", guide(), flags=re.DOTALL)
            if "ps_fuzz_runner.py preflight" in value
        )
        self.assertNotIn("--attempts", block)
        self.assertNotIn("--threads", block)
        self.assertNotIn("--attack-temperature", block)


if __name__ == "__main__":
    unittest.main(verbosity=2)
