#!/usr/bin/env python3
"""Workspace file integrity guard + audit (multi-file).

This is a hardened successor to the original SOUL.md-only guardian.

Key features:
- Multiple target files with per-file policy (restore | alert | ignore)
- Approved baselines stored per file (snapshot + sha256)
- Append-only audit log with hash chaining (tamper-evident)
- Optional auto-restore for restore-mode files (with quarantine copy)
- Refuses to operate on symlinks
- Atomic writes for baseline + restore operations (os.replace)

State directory (default, backward-compatible): memory/soul-guardian/

Subcommands:
- init            Initialize policy + baselines (first run)
- status          Print status JSON for all policy targets
- check           Check for drift; restore for restore-mode by default
- approve         Approve current contents as baseline (per file or all)
- restore         Restore restore-mode files to last approved baseline
- verify-audit    Validate audit log hash chain

Exit codes:
- 0: ok / no drift
- 2: drift detected (for check when any alert/restore drift happened)
- 1: error
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
from typing import Any, Iterable


WORKSPACE_ROOT = Path.cwd()
DEFAULT_STATE_DIR = WORKSPACE_ROOT / "memory" / "soul-guardian"

POLICY_FILE = "policy.json"
BASELINES_FILE = "baselines.json"
AUDIT_LOG_FILE = "audit.jsonl"
APPROVED_DIRNAME = "approved"
PATCH_DIRNAME = "patches"
QUAR_DIRNAME = "quarantine"

CHAIN_GENESIS = "0" * 64


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def sha256_text(s: str) -> str:
    return sha256_bytes(s.encode("utf-8"))


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def is_symlink(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(st.st_mode)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    ensure_dir(path.parent)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def unified_diff_text(old: str, new: str, fromfile: str, tofile: str) -> str:
    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    diff = difflib.unified_diff(old_lines, new_lines, fromfile=fromfile, tofile=tofile)
    return "".join(diff)


def safe_patch_tag(tag: str) -> str:
    return ("".join(c for c in tag if c.isalnum() or c in ("-", "_"))[:40] or "patch")


def relpath_str(path: Path, root: Path) -> str:
    # Normalize to a stable forward-slash relative string.
    try:
        rel = path.relative_to(root)
    except Exception:
        rel = Path(os.path.relpath(path, root))
    return rel.as_posix()


class GuardianState:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.policy_path = state_dir / POLICY_FILE
        self.baselines_path = state_dir / BASELINES_FILE
        self.audit_path = state_dir / AUDIT_LOG_FILE
        self.approved_dir = state_dir / APPROVED_DIRNAME
        self.patch_dir = state_dir / PATCH_DIRNAME
        self.quarantine_dir = state_dir / QUAR_DIRNAME

    def ensure_dirs(self) -> None:
        ensure_dir(self.state_dir)
        ensure_dir(self.approved_dir)
        ensure_dir(self.patch_dir)
        ensure_dir(self.quarantine_dir)


def default_policy() -> dict[str, Any]:
    # Default protected set, per requirements.
    return {
        "version": 1,
        "workspaceRoot": str(WORKSPACE_ROOT),
        "targets": [
            {"path": "SOUL.md", "mode": "restore"},
            {"path": "AGENTS.md", "mode": "restore"},
            {"path": "USER.md", "mode": "alert"},
            {"path": "TOOLS.md", "mode": "alert"},
            {"path": "IDENTITY.md", "mode": "alert"},
            {"path": "HEARTBEAT.md", "mode": "alert"},
            {"path": "MEMORY.md", "mode": "alert"},
            # Ignore daily notes by default.
            {"pattern": "memory/*.md", "mode": "ignore"},
        ],
    }


def load_policy(state: GuardianState) -> dict[str, Any]:
    if not state.policy_path.exists():
        return default_policy()
    return json.loads(state.policy_path.read_text(encoding="utf-8"))


def save_policy(state: GuardianState, policy: dict[str, Any]) -> None:
    state.ensure_dirs()
    atomic_write_text(state.policy_path, json.dumps(policy, ensure_ascii=False, indent=2) + "\n")


def load_baselines(state: GuardianState) -> dict[str, Any]:
    """Load baselines.json.

    Backward-compat:
    - If baselines.json doesn't exist but legacy SOUL.md baseline exists
      (approved.sha256 + approved/SOUL.md), import it into the in-memory baselines.
      The caller will persist it on the next save.
    """

    if state.baselines_path.exists():
        return json.loads(state.baselines_path.read_text(encoding="utf-8"))

    baselines: dict[str, Any] = {"version": 1, "files": {}}

    legacy_sha = state.state_dir / "approved.sha256"
    legacy_snap = state.approved_dir / "SOUL.md"
    if legacy_sha.exists() and legacy_snap.exists():
        sha = legacy_sha.read_text(encoding="utf-8").strip()
        if sha:
            baselines["files"]["SOUL.md"] = {"sha256": sha, "approvedAt": "legacy"}

    return baselines


def save_baselines(state: GuardianState, baselines: dict[str, Any]) -> None:
    state.ensure_dirs()
    atomic_write_text(state.baselines_path, json.dumps(baselines, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def resolve_targets(policy: dict[str, Any], root: Path) -> list[dict[str, str]]:
    """Return list of effective targets to consider.

    For entries with {path, mode}: direct file.
    For entries with {pattern, mode}: expands via globbing relative to root.

    Note: We keep it simple and only expand within workspace root.
    """

    targets: list[dict[str, str]] = []
    entries = policy.get("targets", [])

    for ent in entries:
        mode = ent.get("mode")
        if mode not in ("restore", "alert", "ignore"):
            continue

        if "path" in ent:
            p = Path(ent["path"])
            targets.append({"path": p.as_posix(), "mode": mode})
            continue

        pat = ent.get("pattern")
        if not pat:
            continue

        # Expand pattern relative to root.
        # Using glob keeps it bounded to workspace.
        for match in root.glob(pat):
            if match.is_dir():
                continue
            rel = relpath_str(match, root)
            targets.append({"path": rel, "mode": mode})

    # De-dup by path keeping the last specified mode.
    dedup: dict[str, str] = {}
    for t in targets:
        dedup[t["path"]] = t["mode"]
    return [{"path": p, "mode": m} for p, m in sorted(dedup.items())]


def policy_mode_for_path(policy: dict[str, Any], rel_path: str) -> str | None:
    # Direct match has priority; then patterns.
    entries = policy.get("targets", [])

    for ent in entries:
        if ent.get("path") == rel_path:
            return ent.get("mode")

    for ent in entries:
        pat = ent.get("pattern")
        if not pat:
            continue
        if fnmatch.fnmatch(rel_path, pat):
            return ent.get("mode")

    return None


def approved_snapshot_path(state: GuardianState, rel_path: str) -> Path:
    # Preserve relative structure under approved/.
    return state.approved_dir / Path(rel_path)


def write_patch(state: GuardianState, patch_text: str, tag: str, rel_path: str) -> Path:
    state.ensure_dirs()
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path_tag = safe_patch_tag(tag)
    file_tag = safe_patch_tag(rel_path.replace("/", "_"))
    path = state.patch_dir / f"{ts}-{file_tag}-{path_tag}.patch"
    atomic_write_text(path, patch_text)
    return path


def _canonical_json(obj: Any) -> str:
    # Stable serialization for hashing.
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _audit_needs_upgrade(state: GuardianState) -> bool:
    """Detect legacy audit logs that lack a chain field."""
    if not state.audit_path.exists():
        return False
    try:
        with state.audit_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                return "chain" not in rec
    except Exception:
        # If unreadable, force rotation so we can proceed safely.
        return True
    return False


def _rotate_legacy_audit(state: GuardianState) -> None:
    if not state.audit_path.exists():
        return
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    legacy = state.state_dir / f"audit.legacy.{ts}.jsonl"
    os.replace(state.audit_path, legacy)


def _last_audit_hash(state: GuardianState) -> str:
    if not state.audit_path.exists():
        return CHAIN_GENESIS

    # Read last non-empty line without loading huge files.
    with state.audit_path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return CHAIN_GENESIS
        block = 65536
        start = max(0, size - block)
        f.seek(start)
        data = f.read()

    lines = [ln for ln in data.splitlines() if ln.strip()]
    if not lines:
        return CHAIN_GENESIS

    last = lines[-1]
    try:
        rec = json.loads(last.decode("utf-8"))
        return rec.get("chain", {}).get("hash") or CHAIN_GENESIS
    except Exception:
        return CHAIN_GENESIS


def append_audit(state: GuardianState, entry: dict[str, Any]) -> None:
    """Append an audit entry with hash chaining.

    Each record includes: chain.prev, chain.hash
    chain.hash = sha256(prev_hash + "\n" + canonical_json(entry_without_chain))

    Backward-compat: if an existing audit.jsonl doesn't contain chain fields
    (legacy v1 logs), rotate it aside and start a new chained log.
    """

    state.ensure_dirs()

    if _audit_needs_upgrade(state):
        _rotate_legacy_audit(state)

    prev = _last_audit_hash(state)

    entry_wo_chain = dict(entry)
    entry_wo_chain.pop("chain", None)

    payload = prev + "\n" + _canonical_json(entry_wo_chain)
    cur = sha256_text(payload)

    record = dict(entry_wo_chain)
    record["chain"] = {"prev": prev, "hash": cur}

    with state.audit_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def refuse_symlink(path: Path) -> None:
    if is_symlink(path):
        raise RuntimeError(f"Refusing to operate on symlink: {path}")


def compute_file_sha(path: Path) -> str:
    return sha256_bytes(read_bytes(path))


def baseline_info_for(state: GuardianState, baselines: dict[str, Any], rel_path: str) -> dict[str, Any] | None:
    return (baselines.get("files") or {}).get(rel_path)


def set_baseline_for(state: GuardianState, baselines: dict[str, Any], rel_path: str, sha: str) -> None:
    baselines.setdefault("files", {})[rel_path] = {
        "sha256": sha,
        "approvedAt": utc_now_iso(),
    }


def init_cmd(state: GuardianState, actor: str, note: str, *, force_policy: bool = False) -> None:
    state.ensure_dirs()

    if force_policy or not state.policy_path.exists():
        save_policy(state, default_policy())

    policy = load_policy(state)
    baselines = load_baselines(state)

    targets = resolve_targets(policy, WORKSPACE_ROOT)

    initialized_any = False
    for t in targets:
        relp = t["path"]
        mode = t["mode"]
        if mode == "ignore":
            continue

        abs_path = WORKSPACE_ROOT / relp
        if not abs_path.exists():
            continue
        refuse_symlink(abs_path)

        # If already has baseline, do not overwrite.
        if baseline_info_for(state, baselines, relp) is not None and approved_snapshot_path(state, relp).exists():
            continue

        sha = compute_file_sha(abs_path)

        # Snapshot.
        snap = approved_snapshot_path(state, relp)
        ensure_dir(snap.parent)
        atomic_write_bytes(snap, read_bytes(abs_path))

        set_baseline_for(state, baselines, relp, sha)
        initialized_any = True

        append_audit(state, {
            "ts": utc_now_iso(),
            "event": "init",
            "actor": actor,
            "note": note,
            "path": relp,
            "mode": mode,
            "approvedSha": sha,
            "workspace": str(WORKSPACE_ROOT),
            "stateDir": str(state.state_dir),
        })

    save_baselines(state, baselines)

    if initialized_any:
        print(f"Initialized baselines in {state.state_dir}")
    else:
        print("Already initialized (no new baselines created).")


def status_cmd(state: GuardianState) -> None:
    state.ensure_dirs()
    policy = load_policy(state)
    baselines = load_baselines(state)

    targets = resolve_targets(policy, WORKSPACE_ROOT)
    out: dict[str, Any] = {
        "workspace": str(WORKSPACE_ROOT),
        "stateDir": str(state.state_dir),
        "policyPath": str(state.policy_path),
        "baselinesPath": str(state.baselines_path),
        "auditLog": str(state.audit_path),
        "files": [],
    }

    for t in targets:
        relp = t["path"]
        mode = t["mode"]
        abs_path = WORKSPACE_ROOT / relp

        baseline = baseline_info_for(state, baselines, relp)
        approved_sha = baseline.get("sha256") if baseline else None
        approved_snap = approved_snapshot_path(state, relp)

        current_sha = None
        if abs_path.exists() and not is_symlink(abs_path):
            try:
                current_sha = compute_file_sha(abs_path)
            except Exception:
                current_sha = None

        ok = (mode == "ignore") or (approved_sha is not None and current_sha == approved_sha)

        out["files"].append({
            "path": relp,
            "mode": mode,
            "exists": abs_path.exists(),
            "isSymlink": is_symlink(abs_path) if abs_path.exists() else False,
            "approvedSha": approved_sha,
            "currentSha": current_sha,
            "approvedSnapshot": str(approved_snap) if approved_snap.exists() else None,
            "ok": ok,
        })

    print(json.dumps(out, indent=2))


def detect_drift_for(state: GuardianState, baselines: dict[str, Any], relp: str) -> tuple[bool, dict[str, Any]]:
    abs_path = WORKSPACE_ROOT / relp

    if not abs_path.exists():
        return True, {"error": f"Missing {relp}"}

    refuse_symlink(abs_path)

    baseline = baseline_info_for(state, baselines, relp)
    if not baseline:
        return True, {"error": f"Not initialized for {relp} (missing baseline). Run init/approve."}

    approved_sha = baseline.get("sha256")
    approved_snap = approved_snapshot_path(state, relp)
    if not approved_snap.exists():
        return True, {"error": f"Not initialized for {relp} (missing approved snapshot)."}

    cur_bytes = read_bytes(abs_path)
    cur_sha = sha256_bytes(cur_bytes)

    if cur_sha == approved_sha:
        return False, {"approvedSha": approved_sha, "currentSha": cur_sha}

    old_text = read_text(approved_snap)
    new_text = read_text(abs_path)
    patch_text = unified_diff_text(old_text, new_text, f"approved/{relp}", relp)
    patch_path = write_patch(state, patch_text, tag="drift", rel_path=relp)

    return True, {
        "approvedSha": approved_sha,
        "currentSha": cur_sha,
        "patchPath": str(patch_path),
    }


def restore_one(state: GuardianState, relp: str, info: dict[str, Any]) -> dict[str, Any]:
    """Restore a single file to its approved snapshot.

    Returns: extra fields to include in audit.
    """

    abs_path = WORKSPACE_ROOT / relp
    refuse_symlink(abs_path)

    approved_snap = approved_snapshot_path(state, relp)
    if not approved_snap.exists():
        raise RuntimeError(f"Missing approved snapshot for {relp}")

    state.ensure_dirs()
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    quarantine_path = state.quarantine_dir / f"{safe_patch_tag(relp.replace('/', '_'))}.{ts}.quarantine"
    atomic_write_bytes(quarantine_path, read_bytes(abs_path))

    # Atomic restore.
    atomic_write_bytes(abs_path, read_bytes(approved_snap))

    return {"quarantinePath": str(quarantine_path), **info}


def format_alert_human(drifted: list[dict[str, Any]]) -> str:
    """Format drift results as human-readable alert for TUI notification."""
    lines = []
    lines.append("")
    lines.append("=" * 50)
    lines.append("🚨 SOUL GUARDIAN SECURITY ALERT")
    lines.append("=" * 50)
    lines.append("")
    
    for d in drifted:
        path = d.get("path", "unknown")
        mode = d.get("mode", "unknown")
        restored = d.get("restored", False)
        error = d.get("error")
        
        if error:
            lines.append(f"⚠️  ERROR: {path}")
            lines.append(f"   {error}")
        else:
            lines.append(f"📄 FILE: {path}")
            lines.append(f"   Mode: {mode}")
            if restored:
                lines.append(f"   Status: ✅ RESTORED to approved baseline")
                if d.get("quarantinePath"):
                    lines.append(f"   Quarantined: {d.get('quarantinePath')}")
            else:
                lines.append(f"   Status: ⚠️  DRIFT DETECTED (not auto-restored)")
            
            if d.get("approvedSha"):
                lines.append(f"   Expected hash: {d.get('approvedSha')[:16]}...")
            if d.get("currentSha"):
                lines.append(f"   Found hash:    {d.get('currentSha')[:16]}...")
            if d.get("patchPath"):
                lines.append(f"   Diff saved: {d.get('patchPath')}")
        lines.append("")
    
    lines.append("=" * 50)
    lines.append("Review changes and investigate the source of drift.")
    lines.append("If intentional, run: soul_guardian.py approve --file <path>")
    lines.append("=" * 50)
    lines.append("")
    
    return "\n".join(lines)


def check_cmd(state: GuardianState, actor: str, note: str, *, no_restore: bool = False, output_format: str = "json") -> int:
    state.ensure_dirs()
    policy = load_policy(state)
    baselines = load_baselines(state)

    targets = resolve_targets(policy, WORKSPACE_ROOT)

    drifted: list[dict[str, Any]] = []

    for t in targets:
        relp = t["path"]
        mode = t["mode"]
        if mode == "ignore":
            continue

        drift, info = detect_drift_for(state, baselines, relp)
        if not drift:
            continue

        if "error" in info:
            append_audit(state, {
                "ts": utc_now_iso(),
                "event": "error",
                "actor": actor,
                "note": note,
                "path": relp,
                "mode": mode,
                "error": info["error"],
            })
            drifted.append({"path": relp, "mode": mode, "error": info["error"]})
            continue

        # Drift detected.
        append_audit(state, {
            "ts": utc_now_iso(),
            "event": "drift",
            "actor": actor,
            "note": note,
            "path": relp,
            "mode": mode,
            **info,
        })

        rec: dict[str, Any] = {"path": relp, "mode": mode, **info}

        # Auto-restore for restore-mode unless disabled.
        if mode == "restore" and not no_restore:
            restored = restore_one(state, relp, info)
            append_audit(state, {
                "ts": utc_now_iso(),
                "event": "restore",
                "actor": actor,
                "note": note,
                "path": relp,
                "mode": mode,
                **restored,
            })
            rec["restored"] = True
            rec["quarantinePath"] = restored.get("quarantinePath")
        else:
            rec["restored"] = False

        drifted.append(rec)

    if not drifted:
        # Silent on OK for alert format
        if output_format != "alert":
            pass  # Could print "OK" here if desired
        return 0

    # Output based on format
    if output_format == "alert":
        # Human-readable alert suitable for direct relay to user
        print(format_alert_human(drifted))
    else:
        # JSON format (default) - single-line summary suitable for cron parsing
        summary = {
            "event": "SOUL_GUARDIAN_DRIFT",
            "count": len(drifted),
            "files": [
                {
                    "path": d["path"],
                    "mode": d.get("mode"),
                    "restored": d.get("restored"),
                    "patch": d.get("patchPath"),
                    "error": d.get("error"),
                }
                for d in drifted
            ],
        }
        print("SOUL_GUARDIAN_DRIFT " + json.dumps(summary, ensure_ascii=False))

    # Drift occurred (even if restored).
    return 2


def watch_cmd(state: GuardianState, actor: str, note: str, *, interval: int = 30) -> int:
    """Continuous watch mode - checks periodically and alerts on drift."""
    import time
    
    print(f"👻 Soul Guardian watching... (interval: {interval}s)")
    print("Press Ctrl+C to stop.\n")
    
    try:
        while True:
            result = check_cmd(state, actor, note, output_format="alert")
            if result == 0:
                # No drift - stay silent
                pass
            # Sleep before next check
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n👻 Soul Guardian stopped.")
        return 0


def enable_monitoring_cmd(state: GuardianState) -> None:
    """Output instructions and HEARTBEAT.md snippet for easy monitoring setup."""
    
    heartbeat_snippet = """
## Soul Guardian Check
- Run `cd {workspace} && python3 skills/soul-guardian/scripts/soul_guardian.py check --actor heartbeat --output-format alert`
- If any output is produced, relay it to the user immediately as a security alert
- This checks for unauthorized changes to SOUL.md, AGENTS.md, and other protected files
""".format(workspace=WORKSPACE_ROOT)

    print("""
╔══════════════════════════════════════════════════════════════╗
║           SOUL GUARDIAN - ENABLE MONITORING                 ║
╚══════════════════════════════════════════════════════════════╝

To enable automatic drift detection and alerting, you have two options:

────────────────────────────────────────────────────────────────
OPTION 1: Heartbeat Integration (Recommended)
────────────────────────────────────────────────────────────────

Add the following to your HEARTBEAT.md file:
""")
    print(heartbeat_snippet)
    print("""
────────────────────────────────────────────────────────────────
OPTION 2: Watch Mode (Foreground)
────────────────────────────────────────────────────────────────

Run this in a terminal to continuously monitor:

    python3 skills/soul-guardian/scripts/soul_guardian.py watch --interval 30

────────────────────────────────────────────────────────────────
OPTION 3: Manual Check
────────────────────────────────────────────────────────────────

Run a one-time check with human-readable output:

    python3 skills/soul-guardian/scripts/soul_guardian.py check --output-format alert

────────────────────────────────────────────────────────────────

The guardian will:
✓ Detect unauthorized changes to protected files
✓ Auto-restore SOUL.md and AGENTS.md to approved baselines
✓ Alert you immediately when drift is detected
✓ Save diffs and quarantine modified files for review

""")
    print(f"State directory: {state.state_dir}")
    print(f"Workspace: {WORKSPACE_ROOT}")
    print()


def approve_cmd(state: GuardianState, actor: str, note: str, *, files: list[str] | None, all_files: bool = False) -> None:
    state.ensure_dirs()
    policy = load_policy(state)
    baselines = load_baselines(state)

    targets = resolve_targets(policy, WORKSPACE_ROOT)
    selectable = [t for t in targets if t["mode"] != "ignore"]

    if all_files:
        chosen = selectable
    elif files:
        # Resolve to relative posix.
        wanted = {Path(f).as_posix() for f in files}
        chosen = [t for t in selectable if t["path"] in wanted]
        missing = wanted - {t["path"] for t in chosen}
        if missing:
            raise RuntimeError(f"Unknown or ignored file(s): {', '.join(sorted(missing))}")
    else:
        # Backward-compat: if nothing specified, approve SOUL.md.
        chosen = [t for t in selectable if t["path"] == "SOUL.md"]
        if not chosen:
            raise RuntimeError("No files selected to approve.")

    for t in chosen:
        relp = t["path"]
        mode = t["mode"]
        abs_path = WORKSPACE_ROOT / relp
        if not abs_path.exists():
            raise FileNotFoundError(f"Missing {relp}")
        refuse_symlink(abs_path)

        prev = baseline_info_for(state, baselines, relp)
        prev_sha = prev.get("sha256") if prev else None
        prev_text = read_text(approved_snapshot_path(state, relp)) if approved_snapshot_path(state, relp).exists() else ""

        cur_bytes = read_bytes(abs_path)
        cur_sha = sha256_bytes(cur_bytes)
        cur_text = read_text(abs_path)

        patch_text = unified_diff_text(prev_text, cur_text, f"approved/{relp}", relp)
        patch_path = write_patch(state, patch_text, tag="approve", rel_path=relp)

        snap = approved_snapshot_path(state, relp)
        ensure_dir(snap.parent)
        atomic_write_bytes(snap, cur_bytes)

        set_baseline_for(state, baselines, relp, cur_sha)

        append_audit(state, {
            "ts": utc_now_iso(),
            "event": "approve",
            "actor": actor,
            "note": note,
            "path": relp,
            "mode": mode,
            "prevApprovedSha": prev_sha,
            "approvedSha": cur_sha,
            "patchPath": str(patch_path),
        })

        print(f"Approved {relp}: sha256={cur_sha} patch={patch_path}")

    save_baselines(state, baselines)


def restore_cmd(state: GuardianState, actor: str, note: str, *, files: list[str] | None, all_files: bool = False) -> None:
    state.ensure_dirs()
    policy = load_policy(state)
    baselines = load_baselines(state)

    targets = resolve_targets(policy, WORKSPACE_ROOT)
    restorable = [t for t in targets if t["mode"] == "restore"]

    if all_files:
        chosen = restorable
    elif files:
        wanted = {Path(f).as_posix() for f in files}
        chosen = [t for t in restorable if t["path"] in wanted]
        missing = wanted - {t["path"] for t in chosen}
        if missing:
            raise RuntimeError(f"Not restorable or unknown file(s): {', '.join(sorted(missing))}")
    else:
        # Backward-compat: default restore SOUL.md.
        chosen = [t for t in restorable if t["path"] == "SOUL.md"]
        if not chosen:
            raise RuntimeError("No files selected to restore.")

    restored_any = False
    for t in chosen:
        relp = t["path"]
        mode = t["mode"]

        drift, info = detect_drift_for(state, baselines, relp)
        if "error" in info:
            raise RuntimeError(info["error"])
        if not drift:
            print(f"No drift for {relp}; nothing to restore.")
            continue

        restored = restore_one(state, relp, info)
        append_audit(state, {
            "ts": utc_now_iso(),
            "event": "restore",
            "actor": actor,
            "note": note,
            "path": relp,
            "mode": mode,
            **restored,
        })
        print(
            f"RESTORED {relp} approvedSha={info.get('approvedSha')} previousSha={info.get('currentSha')} "
            f"quarantine={restored.get('quarantinePath')} patch={info.get('patchPath')}"
        )
        restored_any = True

    if not restored_any:
        print("No restores performed.")


def verify_audit_cmd(state: GuardianState) -> None:
    state.ensure_dirs()
    if not state.audit_path.exists():
        print("No audit log present.")
        return

    if _audit_needs_upgrade(state):
        raise RuntimeError(
            "Audit log is legacy (missing hash chain). "
            "Run any command that writes audit (e.g., check) to rotate legacy log, then re-run verify-audit."
        )

    prev = CHAIN_GENESIS
    line_no = 0
    with state.audit_path.open("r", encoding="utf-8") as f:
        for line in f:
            line_no += 1
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            chain = rec.get("chain") or {}
            got_prev = chain.get("prev")
            got_hash = chain.get("hash")

            if got_prev != prev:
                raise RuntimeError(f"Audit chain broken at line {line_no}: prev mismatch (expected {prev}, got {got_prev})")

            rec_wo_chain = dict(rec)
            rec_wo_chain.pop("chain", None)
            payload = prev + "\n" + _canonical_json(rec_wo_chain)
            expect_hash = sha256_text(payload)

            if got_hash != expect_hash:
                raise RuntimeError(f"Audit chain broken at line {line_no}: hash mismatch")

            prev = got_hash

    print(f"OK: audit log hash chain verified ({line_no} lines)")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Soul Guardian - Workspace file integrity guard with alerting support.",
        epilog="For easy setup, run: soul_guardian.py enable-monitoring"
    )
    p.add_argument(
        "--state-dir",
        default=str(DEFAULT_STATE_DIR),
        help="State directory (default: memory/soul-guardian).",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--actor", default="unknown", help="Who initiated the action (best-effort).")
        sp.add_argument("--note", default="", help="Freeform note (e.g., request context).")

    sp_init = sub.add_parser("init", help="Initialize policy + baselines.")
    add_common(sp_init)
    sp_init.add_argument("--force-policy", action="store_true", help="Overwrite policy.json with defaults.")

    sub.add_parser("status", help="Print status JSON.")

    sp_check = sub.add_parser("check", help="Check for drift; restore restore-mode by default.")
    add_common(sp_check)
    sp_check.add_argument("--no-restore", action="store_true", help="Never restore during check (alert-only run).")
    sp_check.add_argument("--output-format", choices=["json", "alert"], default="json",
                          help="Output format: json (machine-readable) or alert (human-readable for TUI).")

    sp_approve = sub.add_parser("approve", help="Approve current contents as baselines.")
    add_common(sp_approve)
    sp_approve.add_argument("--file", action="append", dest="files", help="Relative file path to approve (repeatable).")
    sp_approve.add_argument("--all", action="store_true", help="Approve all non-ignored policy targets.")

    sp_restore = sub.add_parser("restore", help="Restore restore-mode files to approved baselines.")
    add_common(sp_restore)
    sp_restore.add_argument("--file", action="append", dest="files", help="Relative file path to restore (repeatable).")
    sp_restore.add_argument("--all", action="store_true", help="Restore all restore-mode targets.")

    sub.add_parser("verify-audit", help="Verify audit log hash chain.")
    
    # New commands for easier monitoring setup
    sp_watch = sub.add_parser("watch", help="Continuous watch mode - monitors and alerts on drift.")
    add_common(sp_watch)
    sp_watch.add_argument("--interval", type=int, default=30, help="Check interval in seconds (default: 30).")
    
    sub.add_parser("enable-monitoring", help="Show instructions for enabling automatic monitoring and alerts.")

    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    state = GuardianState(Path(args.state_dir).expanduser())

    try:
        if args.cmd == "init":
            init_cmd(state, args.actor, args.note, force_policy=bool(getattr(args, "force_policy", False)))
            return 0
        if args.cmd == "status":
            status_cmd(state)
            return 0
        if args.cmd == "check":
            return check_cmd(
                state, args.actor, args.note,
                no_restore=bool(getattr(args, "no_restore", False)),
                output_format=getattr(args, "output_format", "json")
            )
        if args.cmd == "approve":
            approve_cmd(state, args.actor, args.note, files=getattr(args, "files", None), all_files=bool(getattr(args, "all", False)))
            return 0
        if args.cmd == "restore":
            restore_cmd(state, args.actor, args.note, files=getattr(args, "files", None), all_files=bool(getattr(args, "all", False)))
            return 0
        if args.cmd == "verify-audit":
            verify_audit_cmd(state)
            return 0
        if args.cmd == "watch":
            return watch_cmd(state, args.actor, args.note, interval=getattr(args, "interval", 30))
        if args.cmd == "enable-monitoring":
            enable_monitoring_cmd(state)
            return 0

        raise RuntimeError(f"Unknown cmd: {args.cmd}")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
