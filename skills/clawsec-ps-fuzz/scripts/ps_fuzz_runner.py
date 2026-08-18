#!/usr/bin/env python3
"""Provision a reviewed ps-fuzz release into an explicit external state root.

The runner deliberately has no project-root default.  All mutable state belongs
to the caller-provided ``--state-root``.  Task 2 adds authorized active runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
from urllib.parse import urlparse
from typing import Callable, Mapping, Sequence


SKILL_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SKILL_ROOT.parents[1].resolve()
DEFAULT_MANIFEST_PATH = SKILL_ROOT / "resources" / "upstream.json"

Command = Callable[..., subprocess.CompletedProcess[str]]
Downloader = Callable[[str, Path], None]


class ProvisionError(RuntimeError):
    """An authorization, preflight, integrity, or provisioning failure."""


class ProvisionResult:
    """The state-root-local artifact and interpreter produced by provisioning."""

    def __init__(self, mode: str, venv_python: Path, artifact: Path) -> None:
        self.mode = mode
        self.venv_python = venv_python
        self.artifact = artifact


def load_manifest(path: Path = DEFAULT_MANIFEST_PATH) -> dict[str, object]:
    """Load the local provenance declaration without contacting the network."""
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvisionError(f"cannot read upstream manifest: {exc}") from exc

    try:
        upstream = manifest["upstream"]
        release_wheel = manifest["artifacts"]["release_wheel"]
        python = manifest["python"]
        assert isinstance(upstream, dict)
        assert isinstance(release_wheel, dict)
        assert isinstance(python, dict)
        for value in (
            upstream["clone_url"],
            upstream["commit"],
            release_wheel["filename"],
            release_wheel["url"],
            release_wheel["sha256"],
            python["minimum"],
        ):
            assert isinstance(value, str) and value
        tag = str(upstream["tag"])
        commit = str(upstream["commit"])
        filename = str(release_wheel["filename"])
        artifact_url = urlparse(str(release_wheel["url"]))
        assert re.fullmatch(r"v[0-9]+(?:\.[0-9]+)*", tag)
        assert re.fullmatch(r"[0-9a-f]{40}", commit)
        assert re.fullmatch(r"[0-9a-f]{64}", str(release_wheel["sha256"]))
        assert artifact_url.scheme == "https" and artifact_url.netloc == "github.com"
        assert artifact_url.path == f"/prompt-security/ps-fuzz/releases/download/{tag}/{filename}"
    except (AssertionError, KeyError, TypeError) as exc:
        raise ProvisionError("upstream manifest is malformed") from exc
    return manifest


def _run_command(args: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=False, text=True, capture_output=True, **kwargs)


def _download(url: str, destination: Path) -> None:
    with urllib.request.urlopen(url) as response, destination.open("wb") as output:  # nosec B310: reviewed manifest URL
        while chunk := response.read(1024 * 1024):
            output.write(chunk)


def _require_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        raise ProvisionError(f"{label} failed: {detail}")


def _version_from_text(raw: str) -> tuple[int, int]:
    major, minor = raw.split(".", 1)
    return int(major), int(minor)


def _manifest_section(manifest: Mapping[str, object], name: str) -> Mapping[str, object]:
    value = manifest.get(name)
    if not isinstance(value, dict):
        raise ProvisionError(f"upstream manifest is missing {name}")
    return value


def _validate_authorization(confirm_authorized_provision: bool, authorization_id: str) -> None:
    if not confirm_authorized_provision:
        raise ProvisionError("--confirm-authorized-provision is required")
    if not authorization_id.strip():
        raise ProvisionError("--authorization-id must be nonempty")


def preflight(
    manifest: Mapping[str, object],
    *,
    source: str,
    python_executable: str,
    python_version: tuple[int, int],
    command: Command = _run_command,
) -> None:
    """Inspect local prerequisites without authorization, network access, or state writes."""
    if source not in {"wheel", "source"}:
        raise ProvisionError("--source must be either wheel or source")

    python = _manifest_section(manifest, "python")
    try:
        minimum = _version_from_text(str(python["minimum"]))
    except (KeyError, ValueError) as exc:
        raise ProvisionError("upstream manifest has an invalid Python support floor") from exc
    if python_version < minimum:
        raise ProvisionError(
            f"unsupported Python {python_version[0]}.{python_version[1]}; "
            f"upstream requires Python {minimum[0]}.{minimum[1]} or newer"
        )

    _require_success(command([python_executable, "-m", "venv", "--help"]), "Python venv capability check")
    _require_success(command([python_executable, "-m", "pip", "--version"]), "Python pip capability check")
    if source == "source":
        _require_success(command(["git", "--version"]), "Git capability check")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _venv_python(state_root: Path) -> Path:
    return state_root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def external_state_root(value: Path) -> Path:
    """Resolve and reject any state root that would write into this checkout."""
    state_root = Path(value).expanduser().resolve()
    try:
        state_root.relative_to(PROJECT_ROOT)
    except ValueError:
        return state_root
    raise ProvisionError(f"--state-root must be outside the project checkout: {PROJECT_ROOT}")


def isolated_environment(state_root: Path) -> dict[str, str]:
    """Return the narrow environment used for all mutating pip and Git commands."""
    allowed = (
        "PATH",
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "TMPDIR",
        "TEMP",
        "TMP",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
    )
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(
        {
            "HOME": str(state_root / "home"),
            "PIP_CACHE_DIR": str(state_root / "pip-cache"),
            "XDG_CACHE_HOME": str(state_root / "xdg-cache"),
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONNOUSERSITE": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _install_locked_dependencies(venv_python: Path, lock_path: Path, state_root: Path, command: Command) -> None:
    _require_success(
        command(
            [str(venv_python), "-m", "pip", "install", "--require-hashes", "-r", str(lock_path)],
            env=isolated_environment(state_root),
        ),
        "locked dependency installation",
    )


def provision(
    manifest: Mapping[str, object],
    *,
    state_root: Path,
    source: str,
    confirm_authorized_provision: bool,
    authorization_id: str,
    python_executable: str,
    python_version: tuple[int, int],
    command: Command = _run_command,
    downloader: Downloader = _download,
) -> ProvisionResult:
    """Provision the pinned wheel or pinned source revision into ``state_root``."""
    _validate_authorization(confirm_authorized_provision, authorization_id)
    preflight(
        manifest,
        source=source,
        python_executable=python_executable,
        python_version=python_version,
        command=command,
    )

    state_root = external_state_root(state_root)
    dependency_lock = _manifest_section(manifest, "dependency_lock")
    lock_path = SKILL_ROOT / "resources" / str(dependency_lock.get("path", ""))
    if not lock_path.is_file():
        raise ProvisionError(f"reviewed dependency lock is missing: {lock_path}")

    state_root.mkdir(parents=True, exist_ok=True)
    venv_python = _venv_python(state_root)
    _require_success(
        command(
            [python_executable, "-m", "venv", str(state_root / "venv")],
            env=isolated_environment(state_root),
        ),
        "isolated virtual environment creation",
    )

    if source == "wheel":
        artifacts = _manifest_section(manifest, "artifacts")
        release_wheel = _manifest_section(artifacts, "release_wheel")
        wheel_path = state_root / "downloads" / str(release_wheel["filename"])
        wheel_path.parent.mkdir(parents=True, exist_ok=True)
        downloader(str(release_wheel["url"]), wheel_path)
        actual_sha256 = _sha256(wheel_path)
        expected_sha256 = str(release_wheel["sha256"])
        if actual_sha256 != expected_sha256:
            raise ProvisionError(
                f"release wheel SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
            )
        _require_success(
            command(
                [str(venv_python), "-m", "pip", "install", "--no-deps", str(wheel_path)],
                env=isolated_environment(state_root),
            ),
            "verified release wheel installation",
        )
        _install_locked_dependencies(venv_python, lock_path, state_root, command)
        return ProvisionResult("wheel", venv_python, wheel_path)

    upstream = _manifest_section(manifest, "upstream")
    source_dir = state_root / "source" / "ps-fuzz"
    source_dir.parent.mkdir(parents=True, exist_ok=True)
    _require_success(
        command(
            ["git", "clone", "--no-checkout", str(upstream["clone_url"]), str(source_dir)],
            env=isolated_environment(state_root),
        ),
        "pinned source clone",
    )
    commit = str(upstream["commit"])
    _require_success(
        command(
            ["git", "-C", str(source_dir), "checkout", "--detach", commit],
            env=isolated_environment(state_root),
        ),
        "pinned source checkout",
    )
    revision = command(["git", "-C", str(source_dir), "rev-parse", "HEAD"], env=isolated_environment(state_root))
    _require_success(revision, "pinned source revision verification")
    if revision.stdout.strip() != commit:
        raise ProvisionError(
            f"source commit mismatch: expected {commit}, got {revision.stdout.strip() or 'no revision'}"
        )

    _install_locked_dependencies(venv_python, lock_path, state_root, command)
    wheel_dir = state_root / "built-wheels"
    wheel_dir.mkdir(parents=True, exist_ok=True)
    _require_success(
        command(
            [
                str(venv_python),
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(wheel_dir),
                str(source_dir),
            ],
            env=isolated_environment(state_root),
        ),
        "pinned source wheel build",
    )
    built_wheels = sorted(wheel_dir.glob("prompt_security_fuzzer-*.whl"))
    if len(built_wheels) != 1:
        raise ProvisionError("pinned source build did not produce exactly one prompt-security-fuzzer wheel")
    built_wheel = built_wheels[0]
    _require_success(
        command(
            [str(venv_python), "-m", "pip", "install", "--no-deps", str(built_wheel)],
            env=isolated_environment(state_root),
        ),
        "pinned source wheel installation",
    )
    return ProvisionResult("source", venv_python, built_wheel)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "provision"))
    parser.add_argument("--state-root", help="External ClawSec state root, required only for provision.")
    parser.add_argument("--source", choices=("wheel", "source"), default="wheel")
    parser.add_argument("--confirm-authorized-provision", action="store_true")
    parser.add_argument("--authorization-id", default="")
    parser.add_argument("--python", dest="python_executable", default=sys.executable)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    manifest = load_manifest()
    try:
        if args.command == "preflight":
            preflight(
                manifest,
                source=args.source,
                python_executable=args.python_executable,
                python_version=sys.version_info[:2],
            )
            print("preflight passed; no state was written")
            return 0
        if not args.state_root:
            raise ProvisionError("--state-root is required for provision")
        result = provision(
            manifest,
            state_root=Path(args.state_root),
            source=args.source,
            confirm_authorized_provision=args.confirm_authorized_provision,
            authorization_id=args.authorization_id,
            python_executable=args.python_executable,
            python_version=sys.version_info[:2],
        )
    except ProvisionError as exc:
        print(f"ps-fuzz provisioning blocked: {exc}", file=sys.stderr)
        return 2
    print(f"provisioned {result.mode} artifact at {result.artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
