#!/usr/bin/env python3
"""Regression tests for install_launchd_plist.py default state-dir selection."""

from __future__ import annotations

import os
from pathlib import Path
import plistlib
import subprocess
import tempfile


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

    print("OK: install_launchd_plist default state-dir tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
