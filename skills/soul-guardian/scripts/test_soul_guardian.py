#!/usr/bin/env python3
"""Minimal tests for soul_guardian.py.

Run:
  python3 skills/soul-guardian/scripts/test_soul_guardian.py

This is a lightweight integration test using a temp workspace.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[3]  # .../clawd
SCRIPT = REPO_ROOT / "skills" / "soul-guardian" / "scripts" / "soul_guardian.py"


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)


def must_ok(cp: subprocess.CompletedProcess) -> None:
    if cp.returncode != 0:
        raise AssertionError(f"Expected rc=0, got {cp.returncode}\nSTDOUT:\n{cp.stdout}\nSTDERR:\n{cp.stderr}")


def must_rc(cp: subprocess.CompletedProcess, rc: int) -> None:
    if cp.returncode != rc:
        raise AssertionError(f"Expected rc={rc}, got {cp.returncode}\nSTDOUT:\n{cp.stdout}\nSTDERR:\n{cp.stderr}")


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)
        state = ws / "state"

        # Create a fake workspace with the default protected files.
        (ws / "memory").mkdir(parents=True, exist_ok=True)
        (ws / "SOUL.md").write_text("hello soul\n", encoding="utf-8")
        (ws / "AGENTS.md").write_text("hello agents\n", encoding="utf-8")
        (ws / "USER.md").write_text("user v1\n", encoding="utf-8")
        (ws / "TOOLS.md").write_text("tools v1\n", encoding="utf-8")
        (ws / "IDENTITY.md").write_text("id v1\n", encoding="utf-8")
        (ws / "HEARTBEAT.md").write_text("hb v1\n", encoding="utf-8")
        (ws / "MEMORY.md").write_text("mem v1\n", encoding="utf-8")
        # Daily notes should be ignored by default.
        (ws / "memory" / "2026-01-01.md").write_text("daily\n", encoding="utf-8")

        # Init baselines.
        cp = run(["python3", str(SCRIPT), "--state-dir", str(state), "init", "--actor", "test"], cwd=ws)
        must_ok(cp)

        # No drift.
        cp = run(["python3", str(SCRIPT), "--state-dir", str(state), "check"], cwd=ws)
        must_ok(cp)

        # Drift restore-mode file: SOUL.md should be auto-restored by check.
        (ws / "SOUL.md").write_text("MALICIOUS\n", encoding="utf-8")
        cp = run(["python3", str(SCRIPT), "--state-dir", str(state), "check", "--actor", "cron"], cwd=ws)
        must_rc(cp, 2)
        assert (ws / "SOUL.md").read_text(encoding="utf-8") == "hello soul\n"

        # Drift alert-only file: USER.md should NOT be restored.
        (ws / "USER.md").write_text("user v2\n", encoding="utf-8")
        cp = run(["python3", str(SCRIPT), "--state-dir", str(state), "check"], cwd=ws)
        must_rc(cp, 2)
        assert (ws / "USER.md").read_text(encoding="utf-8") == "user v2\n"

        # Approve USER.md change.
        cp = run(["python3", str(SCRIPT), "--state-dir", str(state), "approve", "--file", "USER.md", "--actor", "test"], cwd=ws)
        must_ok(cp)

        # Now check should be clean.
        cp = run(["python3", str(SCRIPT), "--state-dir", str(state), "check"], cwd=ws)
        must_ok(cp)

        # Verify audit chain ok.
        cp = run(["python3", str(SCRIPT), "--state-dir", str(state), "verify-audit"], cwd=ws)
        must_ok(cp)

        # Tamper with audit log and ensure verify fails.
        audit = state / "audit.jsonl"
        lines = audit.read_text(encoding="utf-8").splitlines()
        assert lines, "audit log empty"
        rec = json.loads(lines[-1])
        rec["note"] = "tampered"
        lines[-1] = json.dumps(rec, ensure_ascii=False)
        audit.write_text("\n".join(lines) + "\n", encoding="utf-8")

        cp = run(["python3", str(SCRIPT), "--state-dir", str(state), "verify-audit"], cwd=ws)
        if cp.returncode == 0:
            raise AssertionError("Expected verify-audit to fail after tamper")

        print("OK: soul-guardian minimal tests passed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
