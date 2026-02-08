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

If you want Clawdbot-side delivery, use Clawdbot Gateway Cron.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import sys


def agent_id_default(workspace_root: Path) -> str:
    return workspace_root.name


def default_external_state_dir(agent_id: str) -> Path:
    return Path("~/.clawdbot/soul-guardian").expanduser() / agent_id


def run_launchctl(args: list[str]) -> None:
    subprocess.run(["/bin/launchctl", *args], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
        help="External state directory (recommended). Default: ~/.clawdbot/soul-guardian/<agentId>/",
    )
    ap.add_argument(
        "--label",
        default=None,
        help="launchd label (default: com.clawdbot.soul-guardian.<agentId>)",
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
    state_dir = Path(args.state_dir).expanduser().resolve() if args.state_dir else default_external_state_dir(agent_id)

    label = args.label or f"com.clawdbot.soul-guardian.{agent_id}"
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

    uid = os.getuid()

    if args.install:
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
