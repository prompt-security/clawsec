#!/usr/bin/env python3
"""Generate (and optionally install) a macOS launchd plist for soul-guardian.

Goal:
- Run `soul_guardian.py check` on an interval.
- Be *silent on OK* (soul_guardian.py prints nothing + exits 0 when no drift).
- Produce a single-line stdout alert on drift (exits 2 and prints SOUL_GUARDIAN_DRIFT ...).

This script is intentionally deterministic and dependency-free.

It does NOT attempt to deliver drift alerts to Telegram/Slack/etc.
Instead it:
- writes logs to the state dir (so drift output is preserved)
- relies on you to wire notifications however you prefer

If you want OpenClaw-side delivery, use OpenClaw cron.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import sys


LEGACY_STATE_ROOT = Path("~/.clawdbot/soul-guardian").expanduser()
DEFAULT_STATE_ROOT = Path("~/.openclaw/soul-guardian").expanduser()
LEGACY_LABEL_PREFIX = "com.clawdbot.soul-guardian."
DEFAULT_LABEL_PREFIX = "com.openclaw.soul-guardian."


def agent_id_default(workspace_root: Path) -> str:
    return workspace_root.name


def legacy_label(agent_id: str) -> str:
    return f"{LEGACY_LABEL_PREFIX}{agent_id}"


def default_label(agent_id: str) -> str:
    return f"{DEFAULT_LABEL_PREFIX}{agent_id}"


def legacy_plist_path(agent_id: str) -> Path:
    return Path("~/Library/LaunchAgents").expanduser() / f"{legacy_label(agent_id)}.plist"


def default_external_state_dir(agent_id: str) -> tuple[Path, bool]:
    legacy_state_dir = LEGACY_STATE_ROOT / agent_id
    if legacy_state_dir.exists():
        return legacy_state_dir, True
    return DEFAULT_STATE_ROOT / agent_id, False


def run_launchctl(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["/bin/launchctl", *args], check=False, text=True, capture_output=True)


def cleanup_legacy_launchd(uid: int, active_label: str, agent_id: str) -> list[str]:
    legacy_job_label = legacy_label(agent_id)
    legacy_job_plist = legacy_plist_path(agent_id).expanduser().resolve()
    if active_label == legacy_job_label:
        return []

    cleanup_commands: list[tuple[list[str], str]] = [
        (
            ["disable", f"gui/{uid}/{legacy_job_label}"],
            f"launchctl disable gui/{uid}/{legacy_job_label}",
        ),
        (
            ["bootout", f"gui/{uid}/{legacy_job_label}"],
            f"launchctl bootout gui/{uid}/{legacy_job_label}",
        ),
    ]

    if legacy_job_plist.exists():
        cleanup_commands.append(
            (
                ["bootout", f"gui/{uid}", str(legacy_job_plist)],
                f"launchctl bootout gui/{uid} {legacy_job_plist}",
            )
        )

    failed_commands: list[str] = []
    for args, display_cmd in cleanup_commands:
        cp = run_launchctl(args)
        if cp.returncode != 0 and legacy_job_plist.exists():
            failed_commands.append(display_cmd)

    if not failed_commands:
        return []

    warning_lines = [
        "WARNING: Failed to fully clean up the legacy soul-guardian launchd job "
        f"{legacy_job_label}.",
        f"Manually run: launchctl bootout gui/{uid} {legacy_job_label}",
    ]
    if legacy_job_plist.exists():
        warning_lines.append(f"If needed, also remove the legacy plist: {legacy_job_plist}")
    warning_lines.append("You can rerun this installer after the legacy job is removed.")
    return warning_lines


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--workspace-root",
        default=str(Path.cwd()),
        help="Workspace root (default: current working directory).",
    )
    ap.add_argument(
        "--agent-id",
        default=None,
        help="Agent/workspace identifier used in default label + state dir (default: workspace folder name).",
    )
    ap.add_argument(
        "--state-dir",
        default=None,
        help="External state directory (recommended). Default: ~/.openclaw/soul-guardian/<agentId>/; reuses ~/.clawdbot/soul-guardian/<agentId>/ if that legacy state dir already exists.",
    )
    ap.add_argument(
        "--label",
        default=None,
        help="launchd label (default: com.openclaw.soul-guardian.<agentId>). When using a non-legacy label, --install attempts to disable/boot out the previous com.clawdbot.soul-guardian.<agentId> job first.",
    )
    ap.add_argument(
        "--interval-seconds",
        type=int,
        default=600,
        help="Run interval in seconds (StartInterval). Default: 600 (10 minutes).",
    )
    ap.add_argument("--actor", default="cron", help="--actor passed to soul_guardian.py (default: cron).")
    ap.add_argument("--note", default="launchd", help="--note passed to soul_guardian.py (default: launchd).")
    ap.add_argument(
        "--out",
        default=None,
        help="Write plist to this path (default: ~/Library/LaunchAgents/<label>.plist)",
    )
    ap.add_argument("--force", action="store_true", help="Overwrite existing plist on disk.")
    ap.add_argument(
        "--install",
        action="store_true",
        help="Install+load the plist with launchctl (bootstrap). Without this flag we only write the plist.",
    )

    args = ap.parse_args(argv)

    workspace_root = Path(args.workspace_root).expanduser().resolve()
    agent_id = args.agent_id or agent_id_default(workspace_root)
    if args.state_dir:
        state_dir = Path(args.state_dir).expanduser().resolve()
    else:
        state_dir, using_legacy_state_dir = default_external_state_dir(agent_id)
        state_dir = state_dir.resolve()
        if using_legacy_state_dir:
            migration_target = (DEFAULT_STATE_ROOT / agent_id).resolve()
            print(
                "WARNING: Detected legacy soul-guardian state dir at "
                f"{state_dir}. Using it for backward compatibility. "
                "To switch to the new default location, rerun this script with "
                f"--state-dir {migration_target}",
                file=sys.stderr,
            )

    label = args.label or default_label(agent_id)
    legacy_job_label = legacy_label(agent_id)
    legacy_job_plist = legacy_plist_path(agent_id).expanduser().resolve()
    plist_path = Path(args.out).expanduser().resolve() if args.out else (Path("~/Library/LaunchAgents").expanduser() / f"{label}.plist")

    script_path = workspace_root / "skills" / "soul-guardian" / "scripts" / "soul_guardian.py"
    if not script_path.exists():
        raise SystemExit(f"soul_guardian.py not found at {script_path}; pass --workspace-root correctly")

    # Keep logs in the external state dir.
    log_dir = state_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = log_dir / "launchd.stdout.log"
    stderr_log = log_dir / "launchd.stderr.log"

    program_args = [
        "/usr/bin/python3",
        str(script_path),
        "--state-dir",
        str(state_dir),
        "check",
        "--actor",
        str(args.actor),
        "--note",
        str(args.note),
    ]

    plist: dict[str, object] = {
        "Label": label,
        "ProgramArguments": program_args,
        "WorkingDirectory": str(workspace_root),
        "StartInterval": int(args.interval_seconds),
        "RunAtLoad": True,
        "StandardOutPath": str(stdout_log),
        "StandardErrorPath": str(stderr_log),
        # Avoid interactive UI dependencies; run in background.
        "ProcessType": "Background",
    }

    plist_path.parent.mkdir(parents=True, exist_ok=True)

    if plist_path.exists() and not args.force:
        raise SystemExit(f"Refusing to overwrite existing {plist_path}. Re-run with --force.")

    with plist_path.open("wb") as f:
        plistlib.dump(plist, f, fmt=plistlib.FMT_XML, sort_keys=True)

    print(f"Wrote plist: {plist_path}")
    print(f"State dir:  {state_dir}")
    print(f"Label:      {label}")
    if label == legacy_job_label:
        print("Legacy label mode: cleanup is skipped because the selected label matches the previous Clawdbot-era default.")
    else:
        print(f"Legacy label:      {legacy_job_label}")
        print(f"Legacy plist:      {legacy_job_plist}")
        if args.install:
            print("Migration: install mode will try to disable/boot out the legacy launchd job before starting the new label.")
        else:
            print("Dry run: --install will try to disable/boot out the legacy launchd job before starting the new label.")

    uid = os.getuid()

    if args.install:
        for warning_line in cleanup_legacy_launchd(uid, label, agent_id):
            print(warning_line, file=sys.stderr)

        # Best-effort: remove any existing job with same label, then bootstrap.
        run_launchctl(["bootout", f"gui/{uid}", label])
        run_launchctl(["bootout", f"gui/{uid}", str(plist_path)])
        res = subprocess.run(["/bin/launchctl", "bootstrap", f"gui/{uid}", str(plist_path)], text=True, capture_output=True)
        if res.returncode != 0:
            sys.stderr.write((res.stderr or res.stdout or "").strip() + "\n")
            sys.stderr.write("Failed to bootstrap. You can try manually:\n")
            sys.stderr.write(f"  launchctl bootstrap gui/{uid} {plist_path}\n")
            return 1

        subprocess.run(["/bin/launchctl", "enable", f"gui/{uid}/{label}"], check=False)
        subprocess.run(["/bin/launchctl", "kickstart", "-k", f"gui/{uid}/{label}"], check=False)
        print("Installed + started (launchctl bootstrap/enable/kickstart).")
    else:
        print("Not installed (dry write). To load it:")
        print(f"  launchctl bootstrap gui/{uid} {plist_path}")
        print(f"  launchctl enable gui/{uid}/{label}")
        print(f"  launchctl kickstart -k gui/{uid}/{label}")

    print("\nLogs:")
    print(f"  tail -n 200 -f {stdout_log}")
    print(f"  tail -n 200 -f {stderr_log}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
