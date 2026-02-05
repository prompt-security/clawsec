#!/usr/bin/env python3
"""Onboard soul-guardian state directory outside the workspace.

Why:
- Keeping integrity state inside the workspace can be risky if the workspace is modified or wiped.
- Moving state to an external directory improves resilience and makes tampering harder.

What this script does:
- Creates an external state directory (default: ~/.clawdbot/soul-guardian/<agentId>/)
- Copies (or moves) existing in-workspace state from memory/soul-guardian/
- Writes a default policy.json if missing
- Prints recommended cron snippets (Clawdbot gateway cron and optional launchd)

This script does NOT modify your cron jobs automatically.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys


WORKSPACE_ROOT = Path.cwd()
DEFAULT_IN_WORKSPACE_STATE = WORKSPACE_ROOT / "memory" / "soul-guardian"


def agent_id_default() -> str:
    # Best-effort: workspace folder name.
    return WORKSPACE_ROOT.name


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def copytree_overwrite(src: Path, dst: Path) -> None:
    # Copy directory contents into dst (merge).
    ensure_dir(dst)
    for root, dirs, files in os.walk(src):
        r = Path(root)
        rel = r.relative_to(src)
        target_root = dst / rel
        ensure_dir(target_root)
        for d in dirs:
            ensure_dir(target_root / d)
        for f in files:
            s = r / f
            t = target_root / f
            # Overwrite.
            shutil.copy2(s, t)


DEFAULT_POLICY_JSON = """{
  "version": 1,
  "workspaceRoot": "",
  "targets": [
    {"path": "SOUL.md", "mode": "restore"},
    {"path": "AGENTS.md", "mode": "restore"},
    {"path": "USER.md", "mode": "alert"},
    {"path": "TOOLS.md", "mode": "alert"},
    {"path": "IDENTITY.md", "mode": "alert"},
    {"path": "HEARTBEAT.md", "mode": "alert"},
    {"path": "MEMORY.md", "mode": "alert"},
    {"pattern": "memory/*.md", "mode": "ignore"}
  ]
}
"""


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-id", default=agent_id_default(), help="Identifier used for default external state path.")
    ap.add_argument(
        "--state-dir",
        default=None,
        help="External state directory to create/use (default: ~/.clawdbot/soul-guardian/<agentId>/).",
    )
    ap.add_argument("--move", action="store_true", help="Move instead of copy (WARNING: deletes the old in-workspace state dir).")
    ap.add_argument("--no-copy", action="store_true", help="Do not copy/move existing in-workspace state.")
    args = ap.parse_args(argv)

    if args.state_dir:
        external = Path(args.state_dir).expanduser()
    else:
        external = (Path("~/.clawdbot/soul-guardian").expanduser() / args.agent_id)

    ensure_dir(external)

    if not args.no_copy and DEFAULT_IN_WORKSPACE_STATE.exists():
        if args.move:
            # Move by copying then removing src (safer than rename across filesystems).
            copytree_overwrite(DEFAULT_IN_WORKSPACE_STATE, external)
            shutil.rmtree(DEFAULT_IN_WORKSPACE_STATE)
            action = "moved"
        else:
            copytree_overwrite(DEFAULT_IN_WORKSPACE_STATE, external)
            action = "copied"
        print(f"Existing state {action} from {DEFAULT_IN_WORKSPACE_STATE} -> {external}")
    else:
        print(f"Using external state dir: {external}")

    policy_path = external / "policy.json"
    if not policy_path.exists():
        txt = DEFAULT_POLICY_JSON.replace('"workspaceRoot": ""', f'"workspaceRoot": "{WORKSPACE_ROOT}"')
        policy_path.write_text(txt, encoding="utf-8")
        print(f"Wrote default policy: {policy_path}")
    else:
        print(f"Policy already exists: {policy_path}")

    print("\nNext steps")
    print("1) Initialize baselines in the external state dir:")
    print(
        f"   cd '{WORKSPACE_ROOT}' && python3 skills/soul-guardian/scripts/soul_guardian.py --state-dir '{external}' init --actor 'sam' --note 'onboard external state'\n"
    )

    print("2) Update your cron/check runner to include --state-dir.")
    print("\nClawdbot gateway cron (recommended; does not require system cron):")
    print("- In your cron spec, run something like:")
    print(
        f"  cd '{WORKSPACE_ROOT}' && python3 skills/soul-guardian/scripts/soul_guardian.py --state-dir '{external}' check --actor system --note cron"
    )

    print("\nOptional: system cron / launchd (macOS) example (NOT installed automatically):")
    label = f"com.clawdbot.soul-guardian.{args.agent_id}"
    print(f"- Launchd label: {label}")
    print(f"- WorkingDirectory (recommended): {WORKSPACE_ROOT}")
    print("- ProgramArguments (example):")
    print("  [\n"
          f"    '/usr/bin/python3',\n"
          f"    '{WORKSPACE_ROOT}/skills/soul-guardian/scripts/soul_guardian.py',\n"
          f"    '--state-dir', '{external}',\n"
          f"    'check', '--actor', 'system', '--note', 'launchd'\n"
          "  ]")

    print("\nNotes")
    print("- The external state dir can contain approved snapshots, patches, and quarantined copies of drifted prompt/instruction files; keep permissions restrictive (e.g., chmod 700; go-rwx).")
    if args.move:
        print("- WARNING: --move deletes the old in-workspace state dir after copying.")
    print("- Consider mirroring the external state dir via git or offsite backups (not enforced by this tool).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
