#!/usr/bin/env python3
"""Regression tests for install_launchd_plist.py default state-dir selection."""

from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "skills" / "soul-guardian" / "scripts" / "install_launchd_plist.py"


def run(cmd: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, env=env)


def must_ok(cp: subprocess.CompletedProcess) -> None:
    if cp.returncode != 0:
        raise AssertionError(f"Expected rc=0, got {cp.returncode}\nSTDOUT:\n{cp.stdout}\nSTDERR:\n{cp.stderr}")


def load_program_arguments(plist_path: Path) -> list[str]:
    with plist_path.open("rb") as handle:
        return plistlib.load(handle)["ProgramArguments"]


def run_case(home_dir: Path, agent_id: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["HOME"] = str(home_dir)
    plist_path = home_dir / "LaunchAgents" / f"{agent_id}.plist"
    cmd = [
        "python3",
        str(SCRIPT),
        "--workspace-root",
        str(REPO_ROOT),
        "--agent-id",
        agent_id,
        "--out",
        str(plist_path),
        "--force",
    ]
    return run(cmd, env)


def assert_contains(text: str, expected: str, label: str) -> None:
    if expected not in text:
        raise AssertionError(f"Missing {label}: expected to find {expected!r}\nActual text:\n{text}")


def load_module(home_dir: Path) -> ModuleType:
    previous_home = os.environ.get("HOME")
    os.environ["HOME"] = str(home_dir)
    try:
        spec = importlib.util.spec_from_file_location("test_install_launchd_plist_module", SCRIPT)
        if spec is None or spec.loader is None:
            raise AssertionError("Failed to load install_launchd_plist.py for testing")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home


def call_main_with_home(module: ModuleType, home_dir: Path, argv: list[str]) -> int:
    previous_home = os.environ.get("HOME")
    os.environ["HOME"] = str(home_dir)
    try:
        return module.main(argv)
    finally:
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        home_dir = Path(td)
        agent_id = "legacy-agent"
        legacy_state_dir = home_dir / ".clawdbot" / "soul-guardian" / agent_id
        legacy_state_dir.mkdir(parents=True, exist_ok=True)

        cp = run_case(home_dir, agent_id)
        must_ok(cp)

        legacy_state_suffix = "/.clawdbot/soul-guardian/legacy-agent"
        new_state_suffix = "/.openclaw/soul-guardian/legacy-agent"
        assert_contains(cp.stdout, legacy_state_suffix, "legacy state dir in stdout")
        assert_contains(cp.stderr, legacy_state_suffix, "legacy state dir warning")
        assert_contains(cp.stderr, new_state_suffix, "migration target warning")

        program_args = load_program_arguments(home_dir / "LaunchAgents" / f"{agent_id}.plist")
        if not any(arg.endswith(legacy_state_suffix) for arg in program_args):
            raise AssertionError(f"Expected plist to reference legacy state dir.\nProgramArguments: {program_args}")

    with tempfile.TemporaryDirectory() as td:
        home_dir = Path(td)
        agent_id = "fresh-agent"

        cp = run_case(home_dir, agent_id)
        must_ok(cp)

        new_state_suffix = "/.openclaw/soul-guardian/fresh-agent"
        assert_contains(cp.stdout, new_state_suffix, "new state dir in stdout")
        if cp.stderr.strip():
            raise AssertionError(f"Did not expect migration warning for fresh install.\nSTDERR:\n{cp.stderr}")

        program_args = load_program_arguments(home_dir / "LaunchAgents" / f"{agent_id}.plist")
        if not any(arg.endswith(new_state_suffix) for arg in program_args):
            raise AssertionError(f"Expected plist to reference new state dir.\nProgramArguments: {program_args}")

    with tempfile.TemporaryDirectory() as td:
        home_dir = Path(td)
        agent_id = "migrate-agent"
        legacy_label = f"com.clawdbot.soul-guardian.{agent_id}"
        legacy_plist = home_dir / "Library" / "LaunchAgents" / f"{legacy_label}.plist"
        legacy_plist.parent.mkdir(parents=True, exist_ok=True)
        legacy_plist.write_text("legacy", encoding="utf-8")

        cp = run(
            [
                "python3",
                str(SCRIPT),
                "--workspace-root",
                str(REPO_ROOT),
                "--agent-id",
                agent_id,
                "--force",
            ],
            {**os.environ, "HOME": str(home_dir)},
        )
        must_ok(cp)
        assert_contains(cp.stdout, legacy_label, "legacy label dry-run note")

        module = load_module(home_dir)
        launchctl_calls: list[list[str]] = []
        subprocess_calls: list[list[str]] = []

        def fake_run_launchctl(args: list[str]) -> subprocess.CompletedProcess[str]:
            launchctl_calls.append(args)
            return subprocess.CompletedProcess(["/bin/launchctl", *args], 0, "", "")

        def fake_subprocess_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            subprocess_calls.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        module.run_launchctl = fake_run_launchctl
        module.subprocess.run = fake_subprocess_run
        module.os.getuid = lambda: 501

        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            rc = call_main_with_home(
                module,
                home_dir,
                [
                    "--workspace-root",
                    str(REPO_ROOT),
                    "--agent-id",
                    agent_id,
                    "--force",
                    "--install",
                ],
            )
        if rc != 0:
            raise AssertionError(f"Expected install flow rc=0, got {rc}")

        expected_prefix = [
            ["disable", "gui/501/com.clawdbot.soul-guardian.migrate-agent"],
            ["bootout", "gui/501/com.clawdbot.soul-guardian.migrate-agent"],
            ["bootout", "gui/501", str(legacy_plist.resolve())],
        ]
        if launchctl_calls[:3] != expected_prefix:
            raise AssertionError(f"Expected legacy cleanup calls first.\nActual launchctl calls: {launchctl_calls}")

        if ["/bin/launchctl", "enable", "gui/501/com.openclaw.soul-guardian.migrate-agent"] not in subprocess_calls:
            raise AssertionError(f"Expected enable call for new label.\nSubprocess calls: {subprocess_calls}")

    with tempfile.TemporaryDirectory() as td:
        home_dir = Path(td)
        agent_id = "warn-agent"
        legacy_label = f"com.clawdbot.soul-guardian.{agent_id}"
        legacy_plist = home_dir / "Library" / "LaunchAgents" / f"{legacy_label}.plist"
        legacy_plist.parent.mkdir(parents=True, exist_ok=True)
        legacy_plist.write_text("legacy", encoding="utf-8")

        module = load_module(home_dir)

        def fake_run_launchctl_warn(args: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(["/bin/launchctl", *args], 1, "", "cleanup failed")

        def fake_subprocess_run_warn(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if args[:2] == ["/bin/launchctl", "bootstrap"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[:2] == ["/bin/launchctl", "enable"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[:2] == ["/bin/launchctl", "kickstart"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 1, "", "cleanup failed")

        module.run_launchctl = fake_run_launchctl_warn
        module.subprocess.run = fake_subprocess_run_warn
        module.os.getuid = lambda: 501

        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            rc = call_main_with_home(
                module,
                home_dir,
                [
                    "--workspace-root",
                    str(REPO_ROOT),
                    "--agent-id",
                    agent_id,
                    "--force",
                    "--install",
                ],
            )
        if rc != 0:
            raise AssertionError(f"Expected install flow rc=0 with cleanup warning, got {rc}")
        assert_contains(stderr_buffer.getvalue(), "launchctl bootout gui/501 com.clawdbot.soul-guardian.warn-agent", "manual cleanup warning")
        assert_contains(stderr_buffer.getvalue(), str(legacy_plist.resolve()), "legacy plist warning")

    print("OK: install_launchd_plist default state-dir tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
