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
import urllib.error
import urllib.request
from unittest import mock


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


def marked_python_block(marker: str) -> str:
    blocks = re.findall(r"```(?:bash|python)\n(.*?)\n```", guide(), flags=re.DOTALL)
    matches = [block for block in blocks if marker in block]
    if len(matches) != 1:
        raise AssertionError(f"expected one {marker} Python block, found {len(matches)}")
    match = re.fullmatch(r"python3 - <<'PY'\n(.*)\nPY", matches[0], flags=re.DOTALL)
    if match is None:
        raise AssertionError(f"expected {marker} to be a quoted Python heredoc")
    return match.group(1)


def write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o755)


class FakeHttpResponse:
    """A local, in-memory stand-in for the one HTTP response a snippet consumes."""

    def __init__(self, url: str, body: bytes) -> None:
        self.status = 200
        self._url = url
        self._body = body

    def __enter__(self) -> "FakeHttpResponse":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self, _limit: int) -> bytes:
        return self._body


class FakeHttpOpener:
    """Returns explicitly supplied in-memory responses and never opens a socket."""

    def __init__(self, responses: list[FakeHttpResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[urllib.request.Request, int]] = []

    def open(self, request: urllib.request.Request, timeout: int) -> FakeHttpResponse:
        self.requests.append((request, timeout))
        if not self.responses:
            raise AssertionError("snippet issued an unexpected HTTP request")
        return self.responses.pop(0)


class LocalSmokeShellTests(unittest.TestCase):
    """Run the published shell logic with fake external commands and no network/server."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls.log"
        self.curl_args = self.root / "curl-args"
        self.hash_count = self.root / "hash-count"
        self.model_dir = self.root / "model"
        self.model_file = self.model_dir / "gemma-4-E2B-it-Q4_0.gguf"
        write_executable(
            self.bin / "curl",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            args=("$@")
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
            printf '%s\n' "${args[@]}" > "$CURL_ARGS_FILE"
            printf 'curl\n' >> "$CALL_LOG"
            """,
        )
        write_executable(
            self.bin / "mktemp",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            template="${!#}"
            directory="${template//XXXXXXXX/TEST}"
            mkdir -m 700 "$directory"
            printf '%s\n' "$directory"
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
            "CURL_ARGS_FILE": os.fspath(self.curl_args),
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

    def staging_dirs(self) -> list[Path]:
        return list(self.model_dir.glob(".clawsec-ps-fuzz-download.*")) if self.model_dir.exists() else []

    def test_download_failures_never_publish_or_overwrite(self) -> None:
        """A failed guard, size, hash, or no-replace publish must stop before publication."""
        self.model_dir.mkdir()
        self.model_file.write_text("existing-final", encoding="utf-8")
        result = self.run_script("# local-smoke-download")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.model_file.read_text(encoding="utf-8"), "existing-final")
        self.assertEqual(self.log_lines(), [])

        self.model_file.unlink()
        self.model_dir.chmod(0o700)
        result = self.run_script("# local-smoke-download", FAKE_DOWNLOAD_CONTENT="bad")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.model_file.exists())
        self.assertEqual(self.log_lines(), ["curl"])

        self.log.unlink()
        result = self.run_script("# local-smoke-download", FAKE_HASH_FAIL_ON_CALL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.model_file.exists())
        self.assertEqual(self.log_lines(), ["curl", "hash-1"])
        self.assertEqual(self.staging_dirs(), [])

        self.log.unlink()
        self.hash_count.unlink()
        result = self.run_script("# local-smoke-download", FAKE_RACE_FINAL_ON_HASH="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.model_file.read_text(encoding="utf-8"), "raced-final")
        self.assertEqual(self.staging_dirs(), [], "failure cleanup must remove only the created staging directory")

    def test_download_publishes_no_replace_and_reverifies_final(self) -> None:
        """Successful publication must hard-link no-replace, remove partial, and hash the final again."""
        result = self.run_script("# local-smoke-download")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.model_file.read_text(encoding="utf-8"), FIXTURE)
        self.assertFalse(self.model_file.with_suffix(self.model_file.suffix + ".partial").exists())
        self.assertEqual(self.staging_dirs(), [])
        self.assertEqual(self.log_lines(), ["curl", "hash-1", "hash-2"])
        self.assertIn("published and re-verified", result.stdout)

    def test_download_requires_a_private_model_directory_and_private_staging(self) -> None:
        """A group/world-accessible model directory must block before curl or staging creation."""
        self.model_dir.mkdir(mode=0o700)
        self.model_dir.chmod(0o755)
        result = self.run_script("# local-smoke-download")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("current-user-owned and mode 0700", result.stderr)
        self.assertEqual(self.log_lines(), [])
        self.assertEqual(self.staging_dirs(), [])

    def test_download_uses_a_private_staging_directory_and_bounded_hardened_curl(self) -> None:
        """The download is isolated in a fresh private stage and cannot exceed the reviewed artifact size."""
        result = self.run_script("# local-smoke-download")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.staging_dirs(), [])
        curl_args = self.curl_args.read_text(encoding="utf-8").splitlines()
        self.assertIn("--disable", curl_args)
        self.assertIn("--fail", curl_args)
        self.assertIn("--location", curl_args)
        self.assertIn("--proto", curl_args)
        self.assertIn("=https", curl_args)
        self.assertIn("--tlsv1.2", curl_args)
        self.assertIn("--max-filesize", curl_args)
        max_size = curl_args.index("--max-filesize")
        self.assertEqual(curl_args[max_size + 1], str(len(FIXTURE)))
        output = curl_args.index("--output")
        staged_partial = Path(curl_args[output + 1])
        self.assertEqual(staged_partial.parent, self.model_dir / ".clawsec-ps-fuzz-download.TEST")
        self.assertEqual(staged_partial.name, "gemma-4-E2B-it-Q4_0.gguf.partial")

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

    def test_preflight_example_validates_temperature_but_omits_run_only_attempt_controls(self) -> None:
        """Preflight must validate exact temperature while leaving attempts/threads to the active run."""
        block = next(
            value
            for value in re.findall(r"```bash\n(.*?)\n```", guide(), flags=re.DOTALL)
            if "ps_fuzz_runner.py preflight" in value
        )
        self.assertNotIn("--attempts", block)
        self.assertNotIn("--threads", block)
        self.assertEqual(re.findall(r"--attack-temperature\s+(\S+)", block), ["0.2"])


class LocalSmokeHttpSnippetTests(unittest.TestCase):
    """Execute the published Python snippets with in-memory HTTP only."""

    HEALTH_URL = "http://127.0.0.1:8081/health"
    MODELS_URL = "http://127.0.0.1:8081/v1/models"
    COMPLETION_URL = "http://127.0.0.1:8081/v1/chat/completions"

    def execute_with_opener(
        self,
        source: str,
        responses: list[FakeHttpResponse],
    ) -> tuple[FakeHttpOpener, mock.Mock, mock.Mock]:
        opener = FakeHttpOpener(responses)
        build_opener = mock.Mock(return_value=opener)
        direct_urlopen = mock.Mock(side_effect=lambda *_args, **_kwargs: opener.responses.pop(0))
        with mock.patch("urllib.request.build_opener", build_opener), mock.patch(
            "urllib.request.urlopen", direct_urlopen
        ):
            exec(compile(source, "local-smoke-snippet", "exec"), {"__name__": "__main__"})
        return opener, build_opener, direct_urlopen

    def test_snippets_build_a_redirect_rejecting_opener(self) -> None:
        """A regression to urlopen or a redirect-following opener would bypass the loopback boundary."""
        cases = (
            (
                "local smoke readiness passed",
                [
                    FakeHttpResponse(self.HEALTH_URL, b'{"status":"ok"}'),
                    FakeHttpResponse(self.MODELS_URL, b'{"data":[{"id":"psfuzz-local"}]}'),
                ],
            ),
            (
                "local completion shape passed; response discarded",
                [
                    FakeHttpResponse(
                        self.COMPLETION_URL,
                        b'{"choices":[{"message":{"content":"hello"}}]}',
                    )
                ],
            ),
        )
        for marker, responses in cases:
            with self.subTest(marker=marker):
                opener, build_opener, direct_urlopen = self.execute_with_opener(marked_python_block(marker), responses)
                build_opener.assert_called_once()
                direct_urlopen.assert_not_called()
                self.assertTrue(opener.requests)
                redirect_handler = build_opener.call_args.args[0]
                for code in (301, 302, 303, 307, 308):
                    with self.subTest(code=code), self.assertRaises(urllib.error.HTTPError) as raised:
                        redirect_handler.redirect_request(
                            urllib.request.Request(self.HEALTH_URL), None, code, "redirect", {}, "http://example.test/"
                        )
                    self.assertEqual(raised.exception.code, code)
                    raised.exception.close()

    def test_snippets_reject_a_response_whose_final_url_is_not_the_literal_loopback_url(self) -> None:
        """A redirected or otherwise rewritten final URL must fail before its JSON is trusted."""
        cases = (
            (
                "local smoke readiness passed",
                [
                    FakeHttpResponse("http://127.0.0.1:8081/redirected", b'{"status":"ok"}'),
                    FakeHttpResponse(self.MODELS_URL, b'{"data":[{"id":"psfuzz-local"}]}'),
                ],
            ),
            (
                "local completion shape passed; response discarded",
                [
                    FakeHttpResponse(
                        "http://127.0.0.1:8081/redirected",
                        b'{"choices":[{"message":{"content":"hello"}}]}',
                    )
                ],
            ),
        )
        for marker, responses in cases:
            with self.subTest(marker=marker):
                with self.assertRaises(SystemExit):
                    self.execute_with_opener(marked_python_block(marker), responses)


if __name__ == "__main__":
    unittest.main(verbosity=2)
