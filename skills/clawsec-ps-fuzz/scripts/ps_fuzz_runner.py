#!/usr/bin/env python3
"""Provision and run reviewed ps-fuzz in an explicit external state root.

The runner deliberately has no project-root default. All mutable state belongs
to the caller-provided ``--state-root``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
from urllib.parse import urlparse, urlunparse
from typing import Callable, Mapping, Sequence


SKILL_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SKILL_ROOT.parents[1].resolve()
RESOURCES_ROOT = SKILL_ROOT / "resources"
DEFAULT_MANIFEST_PATH = RESOURCES_ROOT / "upstream.json"
DEFAULT_CAPABILITIES_PATH = RESOURCES_ROOT / "capabilities-v2.1.0.json"
STATE_DIRECTORY_NAME = "clawsec-ps-fuzz"
STATE_DIRECTORIES = (
    "venv",
    "downloads",
    "source",
    "built-wheels",
    "home",
    "pip-cache",
    "xdg-cache",
    "tmp",
)
ENVIRONMENT_STATE_DIRECTORIES = ("home", "pip-cache", "xdg-cache", "tmp")
PROVISION_RECEIPT_FILENAME = "provision-receipt.json"
PROVISION_RECEIPT_SCHEMA = 1
MAX_SYSTEM_PROMPT_BYTES = 1024 * 1024
INVALID_ASSESSMENT_EXIT_STATUS = 3
PYTHON_RUNTIME_PROBE = (
    "import json, platform, sys; "
    "libc = platform.libc_ver(); "
    "macos = platform.mac_ver(); "
    "print(json.dumps({'implementation': platform.python_implementation(), "
    "'major': sys.version_info[0], 'minor': sys.version_info[1], "
    "'system': platform.system(), 'machine': platform.machine(), "
    "'libc': libc[0], 'libc_version': libc[1], 'macos_version': macos[0]}))"
)
PYTHON_VERSION_PROBE = PYTHON_RUNTIME_PROBE

Command = Callable[..., subprocess.CompletedProcess[str]]
Downloader = Callable[[str, Path], None]


class ProvisionError(RuntimeError):
    """An authorization, preflight, integrity, or provisioning failure."""


class _SafeArgumentParser(argparse.ArgumentParser):
    """Avoid echoing untrusted argument values in argparse conversion failures."""

    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: invalid arguments\n")


class ProvisionResult:
    """The state-root-local artifact and interpreter produced by provisioning."""

    def __init__(self, mode: str, venv_python: Path, artifact: Path) -> None:
        self.mode = mode
        self.venv_python = venv_python
        self.artifact = artifact


class RunResult:
    """Safe, aggregate-only outcome of one authorized ps-fuzz invocation."""

    def __init__(
        self,
        exit_status: int,
        aggregate_counts: dict[str, int] | None,
        *,
        upstream_exit_status: int,
        assessment_status: str,
    ) -> None:
        self.exit_status = exit_status
        self.aggregate_counts = aggregate_counts
        self.upstream_exit_status = upstream_exit_status
        self.assessment_status = assessment_status


_SECRET_PREFIX = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9])(?:sk[-_]|api[-_]|api-key|bearer|ghp_|github_pat_|hf_|xox[baprs]-)"
)
_AWS_ACCESS_KEY = re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])")
_JWT_LIKE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9])"
)


def _looks_secret_shaped(value: str) -> bool:
    """Detect token-shaped identifiers before they can reach output or a child process."""
    return bool(_SECRET_PREFIX.search(value) or _AWS_ACCESS_KEY.search(value) or _JWT_LIKE.search(value))


def _safe_resource_path(relative_path: object) -> Path:
    """Resolve a resource basename while preventing escape from skill resources."""
    if not isinstance(relative_path, str) or not relative_path or Path(relative_path).name != relative_path:
        raise ProvisionError("resource path must be a safe basename")
    resources_root = RESOURCES_ROOT.resolve()
    candidate = (resources_root / relative_path).resolve()
    try:
        candidate.relative_to(resources_root)
    except ValueError as exc:
        raise ProvisionError("resource path escapes skill resources") from exc
    return candidate


def load_manifest(path: Path = DEFAULT_MANIFEST_PATH) -> dict[str, object]:
    """Load the local provenance declaration without contacting the network."""
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ProvisionError("cannot read upstream manifest") from None

    try:
        if not isinstance(manifest, dict):
            raise ValueError
        upstream = manifest["upstream"]
        release_wheel = manifest["artifacts"]["release_wheel"]
        python = manifest["python"]
        dependency_lock = manifest["dependency_lock"]
        if not all(isinstance(value, dict) for value in (upstream, release_wheel, python, dependency_lock)):
            raise ValueError
        for value in (
            upstream["clone_url"],
            upstream["tag"],
            upstream["commit"],
            release_wheel["filename"],
            release_wheel["url"],
            release_wheel["sha256"],
            python["minimum"],
            python["maximum"],
            python["implementation"],
        ):
            if not isinstance(value, str) or not value:
                raise ValueError
        tag = str(upstream["tag"])
        commit = str(upstream["commit"])
        filename = str(release_wheel["filename"])
        artifact_url = urlparse(str(release_wheel["url"]))
        expected_platforms = [
            "linux-glibc-2.28+-x86_64",
            "linux-glibc-2.28+-aarch64",
            "macos-14+-arm64",
        ]
        valid = (
            re.fullmatch(r"v[0-9]+(?:\.[0-9]+)*", tag)
            and re.fullmatch(r"[0-9a-f]{40}", commit)
            and re.fullmatch(r"[0-9a-f]{64}", str(release_wheel["sha256"]))
            and re.fullmatch(r"prompt_security_fuzzer-[A-Za-z0-9][A-Za-z0-9_.-]*\.whl", filename)
            and Path(filename).name == filename
            and upstream["clone_url"] == "https://github.com/prompt-security/ps-fuzz.git"
            and artifact_url.scheme == "https"
            and artifact_url.netloc == "github.com"
            and artifact_url.path == f"/prompt-security/ps-fuzz/releases/download/{tag}/{filename}"
            and not artifact_url.params
            and not artifact_url.query
            and not artifact_url.fragment
            and python["implementation"] == "CPython"
            and _version_from_text(str(python["minimum"])) == (3, 9)
            and _version_from_text(str(python["maximum"])) == (3, 11)
            and python.get("native_wheel_platforms") == expected_platforms
        )
        if not valid:
            raise ValueError
        _safe_resource_path(dependency_lock["path"])
    except (KeyError, TypeError, ValueError, ProvisionError) as exc:
        raise ProvisionError("upstream manifest is malformed") from exc
    return manifest


def load_capabilities(path: Path = DEFAULT_CAPABILITIES_PATH) -> dict[str, object]:
    """Load the reviewed, package-local v2.1.0 CLI capability snapshot."""
    try:
        capabilities = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(capabilities, dict):
            raise ValueError
        providers = capabilities["providers"]
        embedding_providers = capabilities["embedding_providers"]
        attacks = capabilities["attacks"]
        batch_flags = capabilities["batch_flags"]
        rag = capabilities["rag_poisoning"]
        if capabilities["upstream_tag"] != "v2.1.0":
            raise ValueError
        if not isinstance(providers, dict) or not isinstance(embedding_providers, dict):
            raise ValueError
        if not isinstance(attacks, list) or not all(isinstance(attack, str) and attack for attack in attacks):
            raise ValueError
        if not isinstance(batch_flags, list) or not all(isinstance(flag, str) and flag for flag in batch_flags):
            raise ValueError
        if not isinstance(rag, dict) or not isinstance(rag.get("scope"), str):
            raise ValueError
        if not isinstance(capabilities["known_upstream_behavior"], str):
            raise ValueError
        for collection in (providers, embedding_providers):
            for name, details in collection.items():
                if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", name):
                    raise ValueError
                if not isinstance(details, dict):
                    raise ValueError
                credential_environment = details.get("credential_environment", [])
                if not isinstance(credential_environment, list) or not all(
                    isinstance(key, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
                    for key in credential_environment
                ):
                    raise ValueError
                if "base_url_flag" in details:
                    if details["base_url_flag"] not in batch_flags:
                        raise ValueError
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ProvisionError("capability snapshot is malformed") from exc
    return capabilities


def _capability_section(capabilities: Mapping[str, object], name: str) -> Mapping[str, object]:
    value = capabilities.get(name)
    if not isinstance(value, dict):
        raise ProvisionError(f"capability snapshot is missing {name}")
    return value


def _provider(capabilities: Mapping[str, object], provider_name: str, *, embedding: bool = False) -> Mapping[str, object]:
    collection = _capability_section(capabilities, "embedding_providers" if embedding else "providers")
    details = collection.get(provider_name) if isinstance(provider_name, str) else None
    if not isinstance(details, dict):
        kind = "embedding provider" if embedding else "provider"
        raise ProvisionError(f"unsupported {kind}")
    return details


def _validate_model(value: str, label: str) -> str:
    cleaned = value.strip() if isinstance(value, str) else ""
    if (
        not isinstance(value, str)
        or value != cleaned
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*(?:/[A-Za-z0-9][A-Za-z0-9._:-]*)*", cleaned)
        or len(cleaned) > 128
        or _looks_secret_shaped(cleaned)
    ):
        raise ProvisionError(f"--{label} must be a nonempty safe model identifier")
    return cleaned


def _validate_attack_temperature(value: float | int | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ProvisionError("--attack-temperature must be a finite number from 0.0 through 1.0")
    return float(value)


def _credential_availability(
    capabilities: Mapping[str, object], provider_names: Sequence[str], *, embedding: bool = False
) -> dict[str, bool]:
    availability: dict[str, bool] = {}
    for provider_name in provider_names:
        details = _provider(capabilities, provider_name, embedding=embedding)
        for key in details.get("credential_environment", []):
            availability[str(key)] = bool(os.environ.get(str(key)))
    return availability


def _run_command(args: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(args), check=False, text=True, capture_output=True, **kwargs)
    except OSError:
        result = subprocess.CompletedProcess(list(args), 127, "", "")
        result._clawsec_launch_failed = True  # type: ignore[attr-defined]
        return result


def _download(url: str, destination: Path) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(destination, flags, 0o600)
    try:
        with urllib.request.urlopen(url) as response:  # nosec B310: reviewed manifest URL
            while chunk := response.read(1024 * 1024):
                _write_all(descriptor, chunk)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode != 0:
        raise ProvisionError(f"{label} failed with exit status {result.returncode}")


def _safe_probe_cwd() -> Path:
    """Return an existing system root outside the project and caller working directory."""
    if os.name == "nt":
        anchor = Path(sys.executable).resolve().anchor
        candidate = Path(anchor or os.sep)
    else:
        candidate = Path(os.path.abspath(os.sep))
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise ProvisionError("safe probe working directory is unavailable") from None
    if not resolved.is_dir():
        raise ProvisionError("safe probe working directory is unavailable")
    return resolved


def _probe_environment() -> dict[str, str]:
    """Return a non-networking, no-user-config environment for read-only probes."""
    platform_keys = ("SYSTEMROOT", "SystemRoot", "WINDIR")
    environment = {key: os.environ[key] for key in platform_keys if key in os.environ}
    safe_cwd = _safe_probe_cwd()
    isolated_home = safe_cwd / ".clawsec-preflight-no-home"
    environment.update(
        {
            "HOME": str(isolated_home),
            "XDG_CONFIG_HOME": str(isolated_home / "xdg-config"),
            "XDG_CACHE_HOME": str(isolated_home / "xdg-cache"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _trusted_executable(value: str, label: str) -> Path:
    """Resolve one caller-selected local prerequisite to a non-writable regular executable."""
    if not isinstance(value, str) or not value or "\x00" in value or _looks_secret_shaped(value):
        raise ProvisionError(f"{label} executable is unavailable or unsafe")
    located = shutil.which(value)
    if located is None:
        raise ProvisionError(f"{label} executable is unavailable or unsafe")
    try:
        resolved = Path(located).resolve(strict=True)
        metadata = os.lstat(resolved)
    except OSError:
        raise ProvisionError(f"{label} executable is unavailable or unsafe") from None
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise ProvisionError(f"{label} executable is unavailable or unsafe")
    if os.name != "nt" and metadata.st_mode & 0o022:
        raise ProvisionError(f"{label} executable is unavailable or unsafe")
    return resolved


def _probe_command(command: Command, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return command(
        list(args),
        cwd=str(_safe_probe_cwd()),
        env=_probe_environment(),
    )


def _version_from_text(raw: str) -> tuple[int, int]:
    major, minor = raw.split(".", 1)
    return int(major), int(minor)


def _selected_python_runtime(python_executable: str, command: Command = _run_command) -> dict[str, object]:
    """Probe the requested interpreter with static code and never expose its output."""
    selected_python = _trusted_executable(python_executable, "selected Python")
    try:
        result = _probe_command(command, [str(selected_python), "-I", "-B", "-c", PYTHON_VERSION_PROBE])
    except OSError:
        raise ProvisionError("selected Python version probe failed") from None
    if getattr(result, "_clawsec_launch_failed", False) or result.returncode != 0:
        raise ProvisionError("selected Python version probe failed")
    output = result.stdout if isinstance(result.stdout, str) else ""
    try:
        runtime = json.loads(output)
        if not isinstance(runtime, dict):
            raise ValueError
        implementation = runtime["implementation"]
        major = runtime["major"]
        minor = runtime["minor"]
        system = runtime["system"]
        machine = runtime["machine"]
        libc = runtime["libc"]
        libc_version = runtime["libc_version"]
        macos_version = runtime["macos_version"]
        if not isinstance(implementation, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", implementation):
            raise ValueError
        if not isinstance(major, int) or isinstance(major, bool) or not 0 <= major < 100:
            raise ValueError
        if not isinstance(minor, int) or isinstance(minor, bool) or not 0 <= minor < 100:
            raise ValueError
        for value in (system, machine, libc, libc_version, macos_version):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{0,64}", value):
                raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ProvisionError("selected Python runtime probe returned invalid data") from None
    return {
        "implementation": implementation,
        "major": major,
        "minor": minor,
        "system": system,
        "machine": machine,
        "libc": libc,
        "libc_version": libc_version,
        "macos_version": macos_version,
    }


def _selected_python_version(python_executable: str, command: Command = _run_command) -> tuple[int, int]:
    """Return the selected interpreter version through the reviewed runtime probe."""
    runtime = _selected_python_runtime(python_executable, command)
    return int(runtime["major"]), int(runtime["minor"])


def _native_version_at_least(value: str, minimum: tuple[int, int]) -> bool:
    """Require a simple native-platform major.minor version without echoing it."""
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)(?:\.[0-9]+)?", value)
    return bool(match and (int(match.group(1)), int(match.group(2))) >= minimum)


def _runtime_support(
    manifest: Mapping[str, object], python_version: tuple[int, int], python_runtime: Mapping[str, object]
) -> dict[str, object]:
    """Validate one selected runtime against the pinned binary-wheel support envelope."""
    python = _manifest_section(manifest, "python")
    try:
        minimum = _version_from_text(str(python["minimum"]))
        maximum = _version_from_text(str(python["maximum"]))
        implementation = python["implementation"]
        native_wheel_platforms = python["native_wheel_platforms"]
        if implementation != "CPython" or minimum > maximum or minimum[0] != maximum[0]:
            raise ValueError
        if not isinstance(native_wheel_platforms, list) or not all(
            isinstance(item, str) and item for item in native_wheel_platforms
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise ProvisionError("upstream manifest has an invalid Python support boundary") from exc

    runtime = python_runtime
    try:
        runtime_implementation = runtime["implementation"]
        runtime_major = runtime["major"]
        runtime_minor = runtime["minor"]
        runtime_system = runtime["system"]
        runtime_machine = runtime["machine"]
        runtime_libc = runtime["libc"]
        runtime_libc_version = runtime["libc_version"]
        runtime_macos_version = runtime["macos_version"]
        if not isinstance(runtime_implementation, str):
            raise ValueError
        if not isinstance(runtime_major, int) or isinstance(runtime_major, bool):
            raise ValueError
        if not isinstance(runtime_minor, int) or isinstance(runtime_minor, bool):
            raise ValueError
        if not all(
            isinstance(value, str)
            for value in (runtime_system, runtime_machine, runtime_libc, runtime_libc_version, runtime_macos_version)
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise ProvisionError("selected Python runtime probe returned invalid data") from exc
    runtime_version = (runtime_major, runtime_minor)
    if runtime_version != python_version:
        raise ProvisionError("selected Python runtime probe returned inconsistent version data")
    if runtime_implementation != implementation:
        raise ProvisionError("unsupported Python implementation")
    if python_version < minimum or python_version > maximum:
        raise ProvisionError(
            f"unsupported Python {python_version[0]}.{python_version[1]}; "
            f"supported CPython versions are {minimum[0]}.{minimum[1]} through {maximum[0]}.{maximum[1]}"
        )

    system = runtime_system.lower()
    machine = runtime_machine.lower()
    libc = runtime_libc.lower()
    if (
        system == "linux"
        and libc == "glibc"
        and _native_version_at_least(runtime_libc_version, (2, 28))
        and machine in {"x86_64", "aarch64"}
    ):
        native_wheel_platform = f"linux-glibc-2.28+-{machine}"
    elif system == "darwin" and machine == "arm64" and _native_version_at_least(runtime_macos_version, (14, 0)):
        native_wheel_platform = "macos-14+-arm64"
    else:
        raise ProvisionError("unsupported native-wheel platform")
    if native_wheel_platform not in native_wheel_platforms:
        raise ProvisionError("unsupported native-wheel platform")
    supported_versions = [f"{minimum[0]}.{minor}" for minor in range(minimum[1], maximum[1] + 1)]
    return {
        "implementation": implementation,
        "supported_versions": supported_versions,
        "native_wheel_platforms": list(native_wheel_platforms),
        "selected_native_wheel_platform": native_wheel_platform,
    }


def _manifest_section(manifest: Mapping[str, object], name: str) -> Mapping[str, object]:
    value = manifest.get(name)
    if not isinstance(value, dict):
        raise ProvisionError(f"upstream manifest is missing {name}")
    return value


def _validate_authorization(confirm_authorized_provision: bool, authorization_id: str) -> None:
    if not confirm_authorized_provision:
        raise ProvisionError("--confirm-authorized-provision is required")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", authorization_id) or _looks_secret_shaped(authorization_id):
        raise ProvisionError("--authorization-id must be a short non-secret identifier")


def _require_verified_state_privacy() -> None:
    """Block mutation or active use where this wrapper cannot verify state ACL privacy."""
    if os.name == "nt":
        raise ProvisionError("provision and run are unsupported on Windows because state-root ACL privacy cannot be verified")


def preflight(
    manifest: Mapping[str, object],
    *,
    source: str,
    python_executable: str,
    python_version: tuple[int, int],
    python_runtime: Mapping[str, object] | None = None,
    command: Command = _run_command,
    capabilities: Mapping[str, object] | None = None,
    target_provider: str | None = None,
    target_model: str | None = None,
    attack_provider: str | None = None,
    attack_model: str | None = None,
    tests: Sequence[str] | None = None,
    target_base_url: str | None = None,
    approved_target_url: str | None = None,
    attack_base_url: str | None = None,
    approved_attack_url: str | None = None,
    embedding_provider: str | None = None,
    embedding_model: str | None = None,
    embedding_base_url: str | None = None,
    approved_embedding_url: str | None = None,
    attack_temperature: float | int | None = None,
) -> dict[str, object]:
    """Inspect local prerequisites without authorization, network access, or state writes."""
    if source not in {"wheel", "source"}:
        raise ProvisionError("--source must be either wheel or source")

    selected_python = _trusted_executable(python_executable, "selected Python")
    if python_runtime is None:
        python_runtime = _selected_python_runtime(str(selected_python), command)
        python_version = (int(python_runtime["major"]), int(python_runtime["minor"]))
    python_support = _runtime_support(manifest, python_version, python_runtime)

    _require_success(
        _probe_command(command, [str(selected_python), "-I", "-B", "-m", "venv", "--help"]),
        "Python venv capability check",
    )
    _require_success(
        _probe_command(command, [str(selected_python), "-I", "-B", "-m", "pip", "--version"]),
        "Python pip capability check",
    )
    if source == "source":
        git_executable = _trusted_executable("git", "Git")
        _require_success(_probe_command(command, [str(git_executable), "--version"]), "Git capability check")

    if capabilities is None:
        capabilities = load_capabilities()
    selected_providers = [value for value in (target_provider, attack_provider) if value]
    for provider_name in selected_providers:
        _provider(capabilities, provider_name)
    for model, label in ((target_model, "target-model"), (attack_model, "attack-model")):
        if model is not None:
            _validate_model(model, label)
    selected_tests = list(tests or [])
    supported_attacks = capabilities.get("attacks", [])
    if any(test not in supported_attacks for test in selected_tests):
        raise ProvisionError("unsupported attack selected in --tests")
    safe_attack_temperature = _validate_attack_temperature(attack_temperature)
    endpoints: Mapping[str, object] = {}
    if target_provider and attack_provider:
        endpoints = _validate_endpoint_configuration(
            capabilities,
            target_provider=target_provider,
            attack_provider=attack_provider,
            target_base_url=target_base_url,
            approved_target_url=approved_target_url,
            attack_base_url=attack_base_url,
            approved_attack_url=approved_attack_url,
            tests=selected_tests,
            embedding_provider=embedding_provider,
            embedding_model=embedding_model,
            embedding_base_url=embedding_base_url,
            approved_embedding_url=approved_embedding_url,
        )
    elif (
        target_base_url
        or approved_target_url
        or attack_base_url
        or approved_attack_url
        or embedding_provider
        or embedding_model
        or embedding_base_url
        or approved_embedding_url
    ):
        raise ProvisionError("provider roles are required to inspect base URLs or embedding settings")
    credential_presence = _credential_availability(capabilities, selected_providers)
    if embedding_provider:
        credential_presence.update(_credential_availability(capabilities, [embedding_provider], embedding=True))
    return {
        "source": source,
        "python": f"{python_version[0]}.{python_version[1]}",
        "python_support": python_support,
        "target": {"provider": target_provider, "model": target_model, "origin": endpoints.get("target_origin")},
        "attack": {"provider": attack_provider, "model": attack_model, "origin": endpoints.get("attack_origin")},
        "selected_tests": selected_tests,
        "embedding": (
            {"provider": embedding_provider, "model": embedding_model, "origin": endpoints.get("embedding_origin")}
            if embedding_provider
            else None
        ),
        "credential_environment_present": credential_presence,
        "attack_temperature": safe_attack_temperature,
    }


def _sha256(path: Path) -> str:
    """Hash one stable regular non-symlink file through a bound descriptor."""
    candidate = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    try:
        before = os.lstat(candidate)
    except OSError:
        raise ProvisionError("state artifact is unavailable") from None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProvisionError("state artifact must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError:
        raise ProvisionError("state artifact is unavailable") from None
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ProvisionError("state artifact changed while opening")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise ProvisionError("state artifact changed while reading")
    except OSError:
        raise ProvisionError("state artifact could not be read safely") from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return digest.hexdigest()


def _venv_python(state_root: Path) -> Path:
    executable_directory = _safe_state_directory(state_root, "venv", "Scripts" if os.name == "nt" else "bin")
    return executable_directory / ("python.exe" if os.name == "nt" else "python")


def _absolute_unresolved(path: Path) -> Path:
    """Make a path absolute without resolving its final symlink."""
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _lstat_optional(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise ProvisionError("path metadata is unavailable") from None


def _validate_owned_mode(metadata: os.stat_result, label: str, *, private_root: bool = False) -> None:
    if os.name == "nt":
        return
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ProvisionError(f"{label} must be owned by the current user")
    if stat.S_ISLNK(metadata.st_mode):
        return
    prohibited = 0o077 if private_root else 0o022
    if metadata.st_mode & prohibited:
        qualifier = "private" if private_root else "not group/world writable"
        raise ProvisionError(f"{label} permissions must be {qualifier}")


def _validate_state_acl_boundary(state_root: Path) -> None:
    """On Darwin, reject extended ACL entries that can override private mode bits.

    Provision and run reject Windows before reaching this boundary because the
    standard library does not expose a reliable access-check API here.
    """
    if sys.platform != "darwin":
        return
    candidates = [state_root]
    candidates.extend(state_root / name for name in STATE_DIRECTORIES)
    candidates.extend(
        (
            state_root / "source" / "ps-fuzz",
            state_root / _entrypoint_relative_path().parent,
            state_root / _entrypoint_relative_path(),
            state_root / PROVISION_RECEIPT_FILENAME,
        )
    )
    existing = [path for path in candidates if _lstat_optional(path) is not None]
    result = _run_command(
        ["/bin/ls", "-lde", *(str(path) for path in existing)],
        cwd=str(_safe_probe_cwd()),
        env=_probe_environment(),
    )
    if getattr(result, "_clawsec_launch_failed", False) or result.returncode != 0:
        raise ProvisionError("state ACL inspection failed")
    output = result.stdout if isinstance(result.stdout, str) else ""
    if any(re.match(r"^\s+[0-9]+:\s", line) for line in output.splitlines()):
        raise ProvisionError("--state-root and mutable state paths must not have extended ACL entries")


def _validate_private_state_tree(state_root: Path) -> None:
    """Reject unowned or writable provision state without following child symlinks."""
    root_metadata = _lstat_optional(state_root)
    if root_metadata is None or stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ProvisionError("--state-root must be an existing non-symlink directory")
    _validate_owned_mode(root_metadata, "--state-root", private_root=True)
    pending = [state_root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            raise ProvisionError("provisioned state cannot be inspected safely") from None
        for entry in entries:
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                raise ProvisionError("provisioned state cannot be inspected safely") from None
            _validate_owned_mode(metadata, "provisioned state child")
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(Path(entry.path))
            elif not stat.S_ISREG(metadata.st_mode):
                raise ProvisionError("provisioned state contains an unsupported file type")
    _validate_state_acl_boundary(state_root)


def _validate_provision_destination(state_root: Path) -> None:
    """Permit only a missing or empty, current-user-private dedicated root."""
    metadata = _lstat_optional(state_root)
    if metadata is None:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ProvisionError("--state-root must be a non-symlink directory")
    _validate_owned_mode(metadata, "--state-root", private_root=True)
    _validate_state_acl_boundary(state_root)
    try:
        with os.scandir(state_root) as entries:
            if next(entries, None) is not None:
                raise ProvisionError("existing --state-root must be empty before provisioning")
    except ProvisionError:
        raise
    except OSError:
        raise ProvisionError("existing --state-root cannot be inspected safely") from None


def external_state_root(value: Path) -> Path:
    """Require a caller-selected external base with the dedicated ps-fuzz leaf."""
    requested_root = _absolute_unresolved(value)
    if requested_root.name != STATE_DIRECTORY_NAME or requested_root.parent == requested_root:
        raise ProvisionError(
            f"--state-root must be a caller-selected base followed by dedicated leaf {STATE_DIRECTORY_NAME}"
        )
    requested_metadata = _lstat_optional(requested_root)
    if requested_metadata is not None and stat.S_ISLNK(requested_metadata.st_mode):
        raise ProvisionError("--state-root must not be a symlink")

    state_root = requested_root.resolve()
    try:
        state_root.relative_to(PROJECT_ROOT)
    except ValueError:
        pass
    else:
        raise ProvisionError(f"--state-root must be outside the project checkout: {PROJECT_ROOT}")

    if requested_metadata is not None and not stat.S_ISDIR(requested_metadata.st_mode):
        raise ProvisionError("--state-root must be a directory when it already exists")
    return state_root


def _safe_state_directory(state_root: Path, *components: str) -> Path:
    """Return a state-root-local directory path without traversing symlinks."""
    root = external_state_root(state_root)
    root_resolved = root.resolve()
    candidate = root
    if not components:
        return root_resolved

    for component in components:
        if not isinstance(component, str) or not component or component in {".", ".."} or Path(component).name != component:
            raise ProvisionError("internal state directory component is unsafe")
        candidate = candidate / component
        metadata = _lstat_optional(candidate)
        if metadata is not None and stat.S_ISLNK(metadata.st_mode):
            raise ProvisionError("state path must not be a symlink")
        if metadata is not None and not stat.S_ISDIR(metadata.st_mode):
            raise ProvisionError("state path must be a directory when it already exists")
        resolved_candidate = candidate.resolve()
        try:
            resolved_candidate.relative_to(root_resolved)
        except ValueError as exc:
            raise ProvisionError("state path escapes --state-root") from exc
    return resolved_candidate


def _safe_state_file(state_root: Path, directory_components: Sequence[str], filename: str) -> Path:
    """Return a safely-contained mutable artifact path without following a symlink."""
    if not isinstance(filename, str) or not filename or Path(filename).name != filename:
        raise ProvisionError("state artifact filename must be a safe basename")
    parent = _safe_state_directory(state_root, *directory_components)
    candidate = parent / filename
    metadata = _lstat_optional(candidate)
    if metadata is not None and stat.S_ISLNK(metadata.st_mode):
        raise ProvisionError("state artifact must not be a symlink")
    if metadata is not None and not stat.S_ISREG(metadata.st_mode):
        raise ProvisionError("state artifact must be a regular file when it already exists")
    resolved_candidate = candidate.resolve()
    try:
        resolved_candidate.relative_to(parent)
    except ValueError as exc:
        raise ProvisionError("state artifact escapes its state directory") from exc
    return resolved_candidate


def _provision_state_layout(state_root: Path) -> dict[str, Path]:
    """Validate every mutable provisioning location before creating or using one."""
    layout = {name: _safe_state_directory(state_root, name) for name in STATE_DIRECTORIES}
    layout["source_checkout"] = _safe_state_directory(state_root, "source", "ps-fuzz")
    return layout


def _ensure_state_directory(state_root: Path, *components: str) -> Path:
    """Create an already-validated state directory and validate it again afterward."""
    candidate = _safe_state_directory(state_root, *components)
    candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
    return _safe_state_directory(state_root, *components)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _write_exclusive_private(path: Path, content: bytes, label: str) -> None:
    """Create one private file without following or replacing an existing leaf."""
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        _write_all(descriptor, content)
        os.fsync(descriptor)
    except OSError:
        if created:
            try:
                os.unlink(path)
            except OSError:
                pass
        raise ProvisionError(f"{label} could not be written safely") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _atomic_write_private(path: Path, content: bytes, label: str) -> None:
    """Publish one private file atomically without replacing a raced destination."""
    if _lstat_optional(path) is not None:
        raise ProvisionError(f"{label} already exists")
    temporary_path: Path | None = None
    descriptor: int | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        temporary_path = Path(temporary_name)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        _write_all(descriptor, content)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(temporary_path, path)
        os.unlink(temporary_path)
        temporary_path = None
    except ProvisionError:
        raise
    except OSError:
        raise ProvisionError(f"{label} could not be written safely") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


def _read_regular_file_once(path: Path, label: str, maximum_bytes: int) -> tuple[Path, bytes]:
    """Bind and read one small regular file exactly once through the same descriptor."""
    candidate = _absolute_unresolved(path)
    before = _lstat_optional(candidate)
    if before is None or stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProvisionError(f"--{label} must be a readable nonempty regular non-symlink file")
    if before.st_size <= 0 or before.st_size > maximum_bytes:
        raise ProvisionError(f"--{label} must be a readable nonempty regular file no larger than {maximum_bytes} bytes")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError:
        raise ProvisionError(f"--{label} must be a readable nonempty regular file") from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size <= 0
            or opened.st_size > maximum_bytes
        ):
            raise ProvisionError(f"--{label} changed while opening")
        content = os.read(descriptor, maximum_bytes + 1)
        after = os.fstat(descriptor)
        if (
            len(content) != opened.st_size
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise ProvisionError(f"--{label} changed while reading")
    except OSError:
        raise ProvisionError(f"--{label} could not be read safely") from None
    finally:
        os.close(descriptor)
    return candidate, content


def _manifest_fingerprint(manifest: Mapping[str, object]) -> str:
    try:
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        raise ProvisionError("upstream manifest cannot be fingerprinted") from None
    return hashlib.sha256(canonical).hexdigest()


def _entrypoint_relative_path() -> Path:
    return Path("venv") / ("Scripts/prompt-security-fuzzer.exe" if os.name == "nt" else "bin/prompt-security-fuzzer")


def _verified_state_executable(path: Path, label: str) -> tuple[Path, str]:
    metadata = _lstat_optional(path)
    if metadata is None or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProvisionError(f"{label} must be a regular non-symlink file")
    _validate_owned_mode(metadata, label)
    if not os.access(path, os.X_OK):
        raise ProvisionError(f"{label} is not executable")
    return path, _sha256(path)


def _verified_entrypoint(state_root: Path, relative_path: Path | None = None) -> tuple[Path, str]:
    expected_relative = _entrypoint_relative_path()
    if relative_path is not None and relative_path != expected_relative:
        raise ProvisionError("provision receipt contains an unexpected entrypoint")
    parent = _safe_state_directory(state_root, *expected_relative.parts[:-1])
    return _verified_state_executable(parent / expected_relative.name, "provisioned ps-fuzz executable")


def _receipt_runtime(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProvisionError("provision receipt runtime is malformed")
    expected_keys = {"implementation", "major", "minor", "system", "machine", "libc", "libc_version", "macos_version"}
    if set(value) != expected_keys:
        raise ProvisionError("provision receipt runtime is malformed")
    implementation = value.get("implementation")
    major = value.get("major")
    minor = value.get("minor")
    strings = [value.get(name) for name in ("system", "machine", "libc", "libc_version", "macos_version")]
    if not isinstance(implementation, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", implementation):
        raise ProvisionError("provision receipt runtime is malformed")
    if not isinstance(major, int) or isinstance(major, bool) or not 0 <= major < 100:
        raise ProvisionError("provision receipt runtime is malformed")
    if not isinstance(minor, int) or isinstance(minor, bool) or not 0 <= minor < 100:
        raise ProvisionError("provision receipt runtime is malformed")
    if not all(isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_.-]{0,64}", item) for item in strings):
        raise ProvisionError("provision receipt runtime is malformed")
    return dict(value)


def _write_provision_receipt(
    state_root: Path,
    manifest: Mapping[str, object],
    *,
    source: str,
    python_executable: str,
    python_runtime: Mapping[str, object],
) -> None:
    selected_python = _trusted_executable(python_executable, "selected Python")
    runtime = _receipt_runtime(dict(python_runtime))
    _runtime_support(manifest, (int(runtime["major"]), int(runtime["minor"])), runtime)
    executable, executable_sha256 = _verified_entrypoint(state_root)
    receipt = {
        "schema_version": PROVISION_RECEIPT_SCHEMA,
        "manifest_sha256": _manifest_fingerprint(manifest),
        "source": source,
        "selected_interpreter": {"path": str(selected_python), "runtime": runtime},
        "entrypoint": {
            "relative_path": executable.relative_to(state_root).as_posix(),
            "sha256": executable_sha256,
        },
    }
    encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    _atomic_write_private(state_root / PROVISION_RECEIPT_FILENAME, encoded, "provision receipt")


def _verify_provision_receipt(state_root: Path, manifest: Mapping[str, object]) -> Path:
    """Verify the caller-owned state's receipt tripwire before sensitive run input."""
    _validate_private_state_tree(state_root)
    receipt_path = state_root / PROVISION_RECEIPT_FILENAME
    _, encoded = _read_regular_file_once(receipt_path, "provision-receipt", 64 * 1024)
    try:
        receipt = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProvisionError("provision receipt is malformed") from None
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version",
        "manifest_sha256",
        "source",
        "selected_interpreter",
        "entrypoint",
    }:
        raise ProvisionError("provision receipt is malformed")
    if receipt.get("schema_version") != PROVISION_RECEIPT_SCHEMA:
        raise ProvisionError("provision receipt schema is unsupported")
    if receipt.get("manifest_sha256") != _manifest_fingerprint(manifest):
        raise ProvisionError("provision receipt does not match the pinned manifest")
    if receipt.get("source") not in {"wheel", "source"}:
        raise ProvisionError("provision receipt source is malformed")
    selected_interpreter = receipt.get("selected_interpreter")
    if not isinstance(selected_interpreter, dict) or set(selected_interpreter) != {"path", "runtime"}:
        raise ProvisionError("provision receipt interpreter is malformed")
    interpreter_path = selected_interpreter.get("path")
    if (
        not isinstance(interpreter_path, str)
        or not interpreter_path
        or len(interpreter_path) > 4096
        or "\x00" in interpreter_path
        or not Path(interpreter_path).is_absolute()
    ):
        raise ProvisionError("provision receipt interpreter is malformed")
    runtime = _receipt_runtime(selected_interpreter.get("runtime"))
    _runtime_support(manifest, (int(runtime["major"]), int(runtime["minor"])), runtime)
    entrypoint = receipt.get("entrypoint")
    if not isinstance(entrypoint, dict) or set(entrypoint) != {"relative_path", "sha256"}:
        raise ProvisionError("provision receipt entrypoint is malformed")
    relative_raw = entrypoint.get("relative_path")
    expected_sha256 = entrypoint.get("sha256")
    if not isinstance(relative_raw, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", relative_raw):
        raise ProvisionError("provision receipt entrypoint is malformed")
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ProvisionError("provision receipt entrypoint is malformed")
    executable, actual_sha256 = _verified_entrypoint(state_root, Path(relative_raw))
    if actual_sha256 != expected_sha256:
        raise ProvisionError("provisioned ps-fuzz executable does not match its receipt")
    return executable


def isolated_environment(state_root: Path) -> dict[str, str]:
    """Return the narrow environment used for all mutating pip and Git commands."""
    allowed = (
        "PATH",
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
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
    state_root = external_state_root(state_root)
    state_paths = {
        name: _ensure_state_directory(state_root, name) for name in ENVIRONMENT_STATE_DIRECTORIES
    }
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(
        {
            "HOME": str(state_paths["home"]),
            "PIP_CACHE_DIR": str(state_paths["pip-cache"]),
            "XDG_CACHE_HOME": str(state_paths["xdg-cache"]),
            "TMPDIR": str(state_paths["tmp"]),
            "TEMP": str(state_paths["tmp"]),
            "TMP": str(state_paths["tmp"]),
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
            [
                str(venv_python),
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "--only-binary=:all:",
                "-r",
                str(lock_path),
            ],
            env=isolated_environment(state_root),
            cwd=str(state_root),
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
    python_version: tuple[int, int] | None,
    python_runtime: Mapping[str, object] | None = None,
    command: Command = _run_command,
    downloader: Downloader = _download,
) -> ProvisionResult:
    """Provision the pinned wheel or pinned source revision into ``state_root``."""
    _validate_authorization(confirm_authorized_provision, authorization_id)
    _require_verified_state_privacy()
    state_root = external_state_root(state_root)
    _provision_state_layout(state_root)
    if source not in {"wheel", "source"}:
        raise ProvisionError("--source must be either wheel or source")
    if source == "wheel":
        artifacts = _manifest_section(manifest, "artifacts")
        release_wheel = _manifest_section(artifacts, "release_wheel")
        filename = str(release_wheel["filename"])
        if not re.fullmatch(r"prompt_security_fuzzer-[A-Za-z0-9][A-Za-z0-9_.-]*\.whl", filename):
            raise ProvisionError("release wheel filename is malformed")
        _safe_state_file(state_root, ("downloads",), filename)
    _validate_provision_destination(state_root)
    selected_python = _trusted_executable(python_executable, "selected Python")
    selected_runtime = _selected_python_runtime(str(selected_python), command)
    selected_version = (int(selected_runtime["major"]), int(selected_runtime["minor"]))
    git_executable = _trusted_executable("git", "Git") if source == "source" else None
    preflight(
        manifest,
        source=source,
        python_executable=str(selected_python),
        python_version=selected_version,
        python_runtime=selected_runtime,
        command=command,
    )

    dependency_lock = _manifest_section(manifest, "dependency_lock")
    lock_path = _safe_resource_path(dependency_lock.get("path", ""))
    if not lock_path.is_file():
        raise ProvisionError(f"reviewed dependency lock is missing: {lock_path}")

    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(state_root, 0o700, follow_symlinks=False)
        except OSError:
            raise ProvisionError("--state-root permissions could not be secured") from None
    state_root = external_state_root(state_root)
    _validate_private_state_tree(state_root)
    layout = _provision_state_layout(state_root)
    venv_python = _venv_python(state_root)
    _require_success(
        command(
            [str(selected_python), "-I", "-B", "-m", "venv", "--copies", str(layout["venv"])],
            env=isolated_environment(state_root),
            cwd=str(state_root),
        ),
        "isolated virtual environment creation",
    )
    venv_python, _venv_python_sha256 = _verified_state_executable(
        _venv_python(state_root),
        "virtual environment Python",
    )

    if source == "wheel":
        artifacts = _manifest_section(manifest, "artifacts")
        release_wheel = _manifest_section(artifacts, "release_wheel")
        filename = str(release_wheel["filename"])
        if not re.fullmatch(r"prompt_security_fuzzer-[A-Za-z0-9][A-Za-z0-9_.-]*\.whl", filename):
            raise ProvisionError("release wheel filename is malformed")
        _ensure_state_directory(state_root, "downloads")
        wheel_path = _safe_state_file(state_root, ("downloads",), filename)
        if wheel_path.exists():
            existing_sha256 = _sha256(wheel_path)
            expected_sha256 = str(release_wheel["sha256"])
            if existing_sha256 != expected_sha256:
                raise ProvisionError(
                    f"existing release wheel SHA-256 mismatch: expected {expected_sha256}, got {existing_sha256}"
                )
        else:
            try:
                downloader(str(release_wheel["url"]), wheel_path)
            except Exception:
                raise ProvisionError("release wheel download failed") from None
        wheel_path = _safe_state_file(state_root, ("downloads",), filename)
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
                cwd=str(state_root),
            ),
            "verified release wheel installation",
        )
        _install_locked_dependencies(venv_python, lock_path, state_root, command)
        artifact = wheel_path
        mode = "wheel"
    else:
        upstream = _manifest_section(manifest, "upstream")
        if git_executable is None:
            raise ProvisionError("Git executable is unavailable or unsafe")
        _ensure_state_directory(state_root, "source")
        source_dir = _safe_state_directory(state_root, "source", "ps-fuzz")
        _require_success(
            command(
                [
                    str(git_executable),
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    str(upstream["tag"]),
                    "--no-checkout",
                    str(upstream["clone_url"]),
                    str(source_dir),
                ],
                env=isolated_environment(state_root),
                cwd=str(state_root),
            ),
            "pinned source clone",
        )
        commit = str(upstream["commit"])
        _require_success(
            command(
                [str(git_executable), "-C", str(source_dir), "checkout", "--detach", commit],
                env=isolated_environment(state_root),
                cwd=str(state_root),
            ),
            "pinned source checkout",
        )
        revision = command(
            [str(git_executable), "-C", str(source_dir), "rev-parse", "HEAD"],
            env=isolated_environment(state_root),
            cwd=str(state_root),
        )
        _require_success(revision, "pinned source revision verification")
        revision_output = revision.stdout if isinstance(revision.stdout, str) else ""
        if revision_output.strip() != commit:
            raise ProvisionError("source commit mismatch")

        _install_locked_dependencies(venv_python, lock_path, state_root, command)
        wheel_dir = _ensure_state_directory(state_root, "built-wheels")
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
                cwd=str(state_root),
            ),
            "pinned source wheel build",
        )
        built_wheels = sorted(wheel_dir.glob("prompt_security_fuzzer-*.whl"))
        if len(built_wheels) != 1:
            raise ProvisionError("pinned source build did not produce exactly one prompt-security-fuzzer wheel")
        built_wheel = _safe_state_file(state_root, ("built-wheels",), built_wheels[0].name)
        _require_success(
            command(
                [str(venv_python), "-m", "pip", "install", "--no-deps", str(built_wheel)],
                env=isolated_environment(state_root),
                cwd=str(state_root),
            ),
            "pinned source wheel installation",
        )
        artifact = built_wheel
        mode = "source"

    _validate_private_state_tree(state_root)
    _write_provision_receipt(
        state_root,
        manifest,
        source=mode,
        python_executable=str(selected_python),
        python_runtime=selected_runtime,
    )
    _validate_private_state_tree(state_root)
    return ProvisionResult(mode, venv_python, artifact)


def _validate_test_authorization(confirm_authorized_test: bool, authorization_id: str) -> None:
    if not confirm_authorized_test:
        raise ProvisionError("--confirm-authorized-test is required for every active run")
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", authorization_id)
        or _looks_secret_shaped(authorization_id)
    ):
        raise ProvisionError("--authorization-id must be a short non-secret identifier")


def _normalized_base_url(value: str, label: str) -> tuple[str, str]:
    """Return canonical URL and origin; credentials/query/fragment are never allowed."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ProvisionError(f"--{label} must be an absolute http(s) URL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ProvisionError(f"--{label} must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ProvisionError(f"--{label} must not contain credentials")
    if parsed.query:
        raise ProvisionError(f"--{label} must not contain a query")
    if parsed.fragment:
        raise ProvisionError(f"--{label} must not contain a fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProvisionError(f"--{label} has an invalid port") from exc
    host = parsed.hostname.lower()
    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path.rstrip("/")
    normalized = urlunparse((parsed.scheme.lower(), netloc, path, "", "", ""))
    return normalized, f"{parsed.scheme.lower()}://{netloc}"


def _approved_role_url(
    provider: str,
    details: Mapping[str, object],
    base_url: str | None,
    approved_url: str | None,
    role: str,
) -> tuple[str | None, str]:
    if base_url is None:
        if approved_url is not None:
            raise ProvisionError(f"--approved-{role}-url is allowed only with --{role}-base-url")
        return None, f"provider:{provider}"
    if not isinstance(details.get("base_url_flag"), str):
        raise ProvisionError(f"{provider} does not support a custom {role} base URL")
    if not approved_url:
        raise ProvisionError(f"--approved-{role}-url is required with a custom {role} base URL")
    normalized, origin = _normalized_base_url(base_url, f"{role}-base-url")
    approved, _ = _normalized_base_url(approved_url, f"approved-{role}-url")
    if normalized != approved:
        raise ProvisionError(f"custom {role} base URL does not exactly match --approved-{role}-url")
    return normalized, origin


def _validate_endpoint_configuration(
    capabilities: Mapping[str, object],
    *,
    target_provider: str,
    attack_provider: str,
    target_base_url: str | None = None,
    approved_target_url: str | None = None,
    attack_base_url: str | None = None,
    approved_attack_url: str | None = None,
    tests: Sequence[str] = (),
    embedding_provider: str | None = None,
    embedding_model: str | None = None,
    embedding_base_url: str | None = None,
    approved_embedding_url: str | None = None,
) -> dict[str, object]:
    target_details = _provider(capabilities, target_provider)
    attack_details = _provider(capabilities, attack_provider)
    target_url, target_origin = _approved_role_url(
        target_provider, target_details, target_base_url, approved_target_url, "target"
    )
    attack_url, attack_origin = _approved_role_url(
        attack_provider, attack_details, attack_base_url, approved_attack_url, "attack"
    )
    if target_provider == attack_provider and (target_url is not None or attack_url is not None):
        if target_url is None or attack_url is None:
            raise ProvisionError(
                "the upstream provider-wide base URL requires explicit target and attack URLs and --approved-attack-url"
            )
        if target_url != attack_url:
            raise ProvisionError("one upstream provider-wide base URL cannot represent different target and attack endpoints")
        target_origin = attack_origin = _normalized_base_url(target_url, "target-base-url")[1]

    embedding_details: Mapping[str, object] | None = None
    embedding_url: str | None = None
    embedding_origin: str | None = None
    if "rag_poisoning" in tests:
        if not embedding_provider or not embedding_model:
            raise ProvisionError("rag_poisoning requires --embedding-provider and --embedding-model")
        embedding_details = _provider(capabilities, embedding_provider, embedding=True)
        _validate_model(embedding_model, "embedding-model")
        if embedding_base_url is not None:
            embedding_url, embedding_origin = _approved_role_url(
                embedding_provider,
                embedding_details,
                embedding_base_url,
                approved_embedding_url,
                "embedding",
            )
        elif approved_embedding_url is not None:
            raise ProvisionError("--approved-embedding-url is allowed only with --embedding-base-url")
        else:
            embedding_origin = f"provider:{embedding_provider}"
    elif embedding_provider or embedding_model or embedding_base_url or approved_embedding_url:
        raise ProvisionError("embedding settings are allowed only with rag_poisoning")
    return {
        "target_url": target_url,
        "target_origin": target_origin,
        "target_details": target_details,
        "attack_url": attack_url,
        "attack_origin": attack_origin,
        "attack_details": attack_details,
        "embedding_details": embedding_details,
        "embedding_url": embedding_url,
        "embedding_origin": embedding_origin,
    }


def _require_new_external_output_dir(output_dir: Path) -> Path:
    unresolved = _absolute_unresolved(output_dir)
    if _lstat_optional(unresolved) is not None:
        raise ProvisionError("--output-dir must name a new directory")
    candidate = unresolved.resolve()
    try:
        candidate.relative_to(PROJECT_ROOT)
    except ValueError:
        pass
    else:
        raise ProvisionError("--output-dir must be outside the project checkout")
    parent_metadata = _lstat_optional(candidate.parent)
    if (
        candidate.parent == candidate
        or parent_metadata is None
        or stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
    ):
        raise ProvisionError("--output-dir parent must already exist")
    return candidate


def _reviewed_credential_keys(
    capabilities: Mapping[str, object], provider_names: Sequence[str], embedding_provider_names: Sequence[str]
) -> set[str]:
    keys: set[str] = set()
    for provider_name in set(provider_names):
        keys.update(str(key) for key in _provider(capabilities, provider_name).get("credential_environment", []))
    for provider_name in set(embedding_provider_names):
        keys.update(str(key) for key in _provider(capabilities, provider_name, embedding=True).get("credential_environment", []))
    return keys


def run_environment(
    temp_root: Path,
    capabilities: Mapping[str, object],
    *,
    provider_names: Sequence[str],
    embedding_provider_names: Sequence[str] = (),
) -> dict[str, str]:
    """Create a minimal child environment without project config or ambient secrets."""
    platform_keys = ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE")
    environment = {key: os.environ[key] for key in platform_keys if key in os.environ}
    for key in _reviewed_credential_keys(capabilities, provider_names, embedding_provider_names):
        if key in os.environ:
            environment[key] = os.environ[key]
    temporary = temp_root / "tmp"
    home = temp_root / "home"
    environment.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(temp_root / "xdg-config"),
            "XDG_CACHE_HOME": str(temp_root / "xdg-cache"),
            "XDG_DATA_HOME": str(temp_root / "xdg-data"),
            "TMPDIR": str(temporary),
            "TMP": str(temporary),
            "TEMP": str(temporary),
            "PYTHONNOUSERSITE": "1",
            "ANONYMIZED_TELEMETRY": "false",
        }
    )
    return environment


def _aggregate_counts(raw_output: str) -> dict[str, int] | None:
    """Extract the sole ANSI-stripped `Total (# tests)` footer from SINGLE_BORDER output."""
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw_output)
    if clean.count("Total (# tests):") != 1:
        return None
    footer: dict[str, int] | None = None
    for line in clean.splitlines():
        if "Total (# tests):" not in line or "│" not in line:
            continue
        cells = [cell.strip() for cell in line.split("│")]
        try:
            label_index = next(index for index, cell in enumerate(cells) if cell.startswith("Total (# tests):"))
            values = cells[label_index + 1 : label_index + 5]
            strength = cells[label_index + 5]
        except (StopIteration, IndexError):
            return None
        if len(values) != 4 or not strength or any(not re.fullmatch(r"\d+", value) for value in values):
            return None
        if footer is not None:
            return None
        footer = dict(zip(("broken", "resilient", "errors", "skipped"), (int(value) for value in values)))
    return footer


def _write_redacted_reports(
    output_dir: Path,
    manifest: Mapping[str, object],
    capabilities: Mapping[str, object],
    *,
    authorization_id: str,
    configuration: Mapping[str, object],
    wrapper_exit_status: int,
    upstream_exit_status: int,
    assessment_status: str,
    aggregate_counts: Mapping[str, int] | None,
) -> None:
    upstream = _manifest_section(manifest, "upstream")
    artifacts = _manifest_section(manifest, "artifacts")
    release_wheel = _manifest_section(artifacts, "release_wheel")
    rag = _capability_section(capabilities, "rag_poisoning")
    scope_limitations = [
        "Direct-model ps-fuzz batch mode only; this runner does not implement generic agent HTTP, MCP, tool invocation, remediation, persistence, or scheduling.",
        str(capabilities["known_upstream_behavior"]),
    ]
    if "rag_poisoning" in configuration.get("tests", []):
        scope_limitations.append(str(rag["scope"]))
    report = {
        "provenance": {
            "upstream_tag": upstream["tag"],
            "upstream_commit": upstream["commit"],
            "release_wheel_sha256": release_wheel["sha256"],
        },
        "authorization_id": authorization_id,
        "requested_configuration": dict(configuration),
        "exit_status": wrapper_exit_status,
        "wrapper_exit_status": wrapper_exit_status,
        "upstream_exit_status": upstream_exit_status,
        "assessment_status": assessment_status,
        "aggregate_result_counts": dict(aggregate_counts) if aggregate_counts is not None else None,
        "scope_limitations": scope_limitations,
    }
    try:
        os.mkdir(output_dir, 0o700)
        if os.name != "nt":
            os.chmod(output_dir, 0o700, follow_symlinks=False)
    except OSError:
        raise ProvisionError("--output-dir could not be created safely") from None
    report_content = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_exclusive_private(output_dir / "run.json", report_content, "redacted JSON report")
    counts_text = "not available" if aggregate_counts is None else ", ".join(
        f"{key}: {value}" for key, value in aggregate_counts.items()
    )
    rag_summary = ""
    if "rag_poisoning" in configuration.get("tests", []):
        rag_summary = (
            f"\nRAG embedding: {configuration['embedding_provider']} / {configuration['embedding_model']} "
            f"at {configuration['embedding_origin']}\nRAG limitation: {rag['scope']}\n"
        )
    summary = (
        "# Redacted ps-fuzz run summary\n\n"
        f"- Authorization ID: {authorization_id}\n"
        f"- Assessment status: {assessment_status}\n"
        f"- Wrapper exit status: {wrapper_exit_status}\n"
        f"- Upstream exit status: {upstream_exit_status}\n"
        f"- Aggregate results: {counts_text}\n"
        f"- Target: {configuration['target_provider']} / {configuration['target_model']}\n"
        f"- Target origin: {configuration['target_origin']}\n\n"
        f"- Attack: {configuration['attack_provider']} / {configuration['attack_model']}\n"
        f"- Attack origin: {configuration['attack_origin']}\n\n"
        "No raw system prompt, provider credential, attack payload, model response, stdout, or stderr was saved.\n"
        f"{rag_summary}"
    )
    _write_exclusive_private(output_dir / "summary.md", summary.encode("utf-8"), "redacted Markdown report")


def run(
    manifest: Mapping[str, object],
    capabilities: Mapping[str, object],
    *,
    state_root: Path,
    confirm_authorized_test: bool,
    authorization_id: str,
    system_prompt_file: Path,
    target_provider: str,
    target_model: str,
    attack_provider: str,
    attack_model: str,
    tests: Sequence[str],
    attempts: int,
    threads: int,
    output_dir: Path,
    target_base_url: str | None = None,
    approved_target_url: str | None = None,
    attack_base_url: str | None = None,
    approved_attack_url: str | None = None,
    attack_temperature: float | None = None,
    embedding_provider: str | None = None,
    embedding_model: str | None = None,
    embedding_base_url: str | None = None,
    approved_embedding_url: str | None = None,
    command: Command = _run_command,
) -> RunResult:
    """Run only the reviewed batch interface after an explicit, per-run authorization."""
    _validate_test_authorization(confirm_authorized_test, authorization_id)
    _require_verified_state_privacy()
    state_root = external_state_root(state_root)
    executable = _verify_provision_receipt(state_root, manifest)
    target_model = _validate_model(target_model, "target-model")
    attack_model = _validate_model(attack_model, "attack-model")
    if not tests or any(not isinstance(test, str) or test not in capabilities.get("attacks", []) for test in tests):
        raise ProvisionError("--tests must be a nonempty list of supported attacks")
    if (
        isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or attempts <= 0
        or isinstance(threads, bool)
        or not isinstance(threads, int)
        or threads <= 0
    ):
        raise ProvisionError("--attempts and --threads must be positive integers")
    attack_temperature = _validate_attack_temperature(attack_temperature)

    selected_tests = list(tests)
    endpoints = _validate_endpoint_configuration(
        capabilities,
        target_provider=target_provider,
        attack_provider=attack_provider,
        target_base_url=target_base_url,
        approved_target_url=approved_target_url,
        attack_base_url=attack_base_url,
        approved_attack_url=approved_attack_url,
        tests=selected_tests,
        embedding_provider=embedding_provider,
        embedding_model=embedding_model,
        embedding_base_url=embedding_base_url,
        approved_embedding_url=approved_embedding_url,
    )

    safe_output_dir = _require_new_external_output_dir(output_dir)
    _prompt_path, prompt_content = _read_regular_file_once(
        system_prompt_file,
        "system-prompt-file",
        MAX_SYSTEM_PROMPT_BYTES,
    )
    configuration: dict[str, object] = {
        "target_provider": target_provider,
        "target_model": target_model,
        "attack_provider": attack_provider,
        "attack_model": attack_model,
        "tests": selected_tests,
        "attempts": attempts,
        "threads": threads,
        "target_origin": endpoints["target_origin"],
        "attack_origin": endpoints["attack_origin"],
    }
    if attack_temperature is not None:
        configuration["attack_temperature"] = attack_temperature
    if embedding_provider:
        configuration["embedding_provider"] = embedding_provider
        configuration["embedding_model"] = embedding_model
        configuration["embedding_origin"] = endpoints["embedding_origin"]

    print(
        "Authorized ps-fuzz preview: "
        f"target={target_provider}/{target_model}, origin={endpoints['target_origin']}; "
        f"attack={attack_provider}/{attack_model}, origin={endpoints['attack_origin']}; tests={','.join(selected_tests)}, "
        f"attempts={attempts}, threads={threads}. Provider calls can consume tokens and incur charges."
    )
    if embedding_provider:
        print(
            f"RAG scope: embedding={embedding_provider}/{embedding_model}, origin={endpoints['embedding_origin']}; "
            "synthetic local Chroma demonstration only, not evidence about real retrieval, ingestion, filtering, vector stores, agent tools, or persistence."
        )
    state_tmp = _ensure_state_directory(state_root, "tmp")
    _validate_private_state_tree(state_root)
    with tempfile.TemporaryDirectory(prefix="clawsec-ps-fuzz-run-", dir=str(state_tmp)) as temporary_name:
        temporary_root = Path(temporary_name)
        home = temporary_root / "home"
        for directory in (home, temporary_root / "tmp", temporary_root / "xdg-config", temporary_root / "xdg-cache", temporary_root / "xdg-data"):
            directory.mkdir(mode=0o700)
        prompt_copy = temporary_root / "system-prompt.txt"
        _write_exclusive_private(prompt_copy, prompt_content, "temporary system prompt")
        arguments = [
            str(executable),
            "-b",
            "--target-provider",
            target_provider,
            "--target-model",
            target_model,
            "--attack-provider",
            attack_provider,
            "--attack-model",
            attack_model,
            "-n",
            str(attempts),
            "-t",
            str(threads),
            "-d",
            "0",
            "--tests",
            json.dumps(selected_tests),
        ]
        if attack_temperature is not None:
            arguments.extend(["-a", str(attack_temperature)])
        if endpoints["target_url"] is not None:
            arguments.extend([str(endpoints["target_details"]["base_url_flag"]), str(endpoints["target_url"])])
        if endpoints["attack_url"] is not None and attack_provider != target_provider:
            arguments.extend([str(endpoints["attack_details"]["base_url_flag"]), str(endpoints["attack_url"])])
        if endpoints["embedding_details"] is not None:
            arguments.extend(["--embedding-provider", str(embedding_provider), "--embedding-model", str(embedding_model)])
        if endpoints["embedding_url"] is not None and endpoints["embedding_details"] is not None:
            arguments.extend([str(endpoints["embedding_details"]["base_url_flag"]), str(endpoints["embedding_url"])])
        arguments.append(str(prompt_copy))
        try:
            result = command(
                arguments,
                cwd=str(home),
                env=run_environment(
                    temporary_root,
                    capabilities,
                    provider_names=[target_provider, attack_provider],
                    embedding_provider_names=[embedding_provider] if embedding_provider else [],
                ),
            )
        except OSError:
            raise ProvisionError("ps-fuzz invocation failed") from None
        if getattr(result, "_clawsec_launch_failed", False):
            raise ProvisionError("ps-fuzz invocation failed")
        upstream_exit_status = int(result.returncode)
        counts: dict[str, int] | None = None
        if upstream_exit_status != 0:
            wrapper_exit_status = upstream_exit_status if 1 <= upstream_exit_status <= 255 else 2
            assessment_status = "upstream-failed"
        else:
            parsed_counts = _aggregate_counts(result.stdout if isinstance(result.stdout, str) else "")
            if parsed_counts is None or sum(parsed_counts.values()) <= 0:
                wrapper_exit_status = INVALID_ASSESSMENT_EXIT_STATUS
                assessment_status = "invalid-output"
            elif parsed_counts["errors"] > 0 or parsed_counts["skipped"] > 0:
                wrapper_exit_status = INVALID_ASSESSMENT_EXIT_STATUS
                assessment_status = "incomplete"
                counts = parsed_counts
            else:
                wrapper_exit_status = 0
                assessment_status = "complete"
                counts = parsed_counts
    _write_redacted_reports(
        safe_output_dir,
        manifest,
        capabilities,
        authorization_id=authorization_id.strip(),
        configuration=configuration,
        wrapper_exit_status=wrapper_exit_status,
        upstream_exit_status=upstream_exit_status,
        assessment_status=assessment_status,
        aggregate_counts=counts,
    )
    return RunResult(
        wrapper_exit_status,
        counts,
        upstream_exit_status=upstream_exit_status,
        assessment_status=assessment_status,
    )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "provision", "run"))
    parser.add_argument("--state-root", help="External ClawSec state root, required for provision and run.")
    parser.add_argument("--source", choices=("wheel", "source"), default="wheel")
    parser.add_argument("--confirm-authorized-provision", action="store_true")
    parser.add_argument("--confirm-authorized-test", action="store_true")
    parser.add_argument("--authorization-id", default="")
    parser.add_argument("--python", dest="python_executable", default=sys.executable)
    parser.add_argument("--system-prompt-file")
    parser.add_argument("--target-provider")
    parser.add_argument("--target-model")
    parser.add_argument("--attack-provider")
    parser.add_argument("--attack-model")
    parser.add_argument("--tests", help="JSON list of reviewed exact upstream test names.")
    parser.add_argument("--attempts", type=int)
    parser.add_argument("--threads", type=int)
    parser.add_argument("--attack-temperature", type=float)
    parser.add_argument("--target-base-url")
    parser.add_argument("--approved-target-url")
    parser.add_argument("--attack-base-url")
    parser.add_argument("--approved-attack-url")
    parser.add_argument("--embedding-provider")
    parser.add_argument("--embedding-model")
    parser.add_argument("--embedding-base-url")
    parser.add_argument("--approved-embedding-url")
    parser.add_argument("--output-dir")
    return parser


def _parse_tests_argument(value: str | None) -> list[str]:
    if value is None:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ProvisionError("--tests must be a JSON list of exact attack names") from exc
    if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
        raise ProvisionError("--tests must be a JSON list of exact attack names")
    return parsed


def main(argv: Sequence[str] | None = None, *, command: Command = _run_command) -> int:
    args = _parser().parse_args(argv)
    manifest = load_manifest()
    try:
        capabilities = load_capabilities()
        selected_tests = _parse_tests_argument(args.tests)
        if args.command != "preflight" and not args.state_root:
            raise ProvisionError("--state-root is required for provision or run")
        if args.command == "provision":
            _validate_authorization(args.confirm_authorized_provision, args.authorization_id)
        selected_python_runtime: dict[str, object] | None = None
        selected_python_version: tuple[int, int] | None = None
        if args.command == "preflight":
            selected_python_runtime = _selected_python_runtime(args.python_executable, command)
            selected_python_version = (
                int(selected_python_runtime["major"]),
                int(selected_python_runtime["minor"]),
            )
        if args.command == "preflight":
            inspection = preflight(
                manifest,
                source=args.source,
                python_executable=args.python_executable,
                python_version=selected_python_version,
                python_runtime=selected_python_runtime,
                command=command,
                capabilities=capabilities,
                target_provider=args.target_provider,
                target_model=args.target_model,
                attack_provider=args.attack_provider,
                attack_model=args.attack_model,
                tests=selected_tests,
                target_base_url=args.target_base_url,
                approved_target_url=args.approved_target_url,
                attack_base_url=args.attack_base_url,
                approved_attack_url=args.approved_attack_url,
                embedding_provider=args.embedding_provider,
                embedding_model=args.embedding_model,
                embedding_base_url=args.embedding_base_url,
                approved_embedding_url=args.approved_embedding_url,
                attack_temperature=args.attack_temperature,
            )
            print(json.dumps(inspection, sort_keys=True))
            print("preflight passed; no state was written")
            return 0
        if args.command == "run":
            required = {
                "--system-prompt-file": args.system_prompt_file,
                "--target-provider": args.target_provider,
                "--target-model": args.target_model,
                "--attack-provider": args.attack_provider,
                "--attack-model": args.attack_model,
                "--attempts": args.attempts,
                "--threads": args.threads,
                "--output-dir": args.output_dir,
            }
            missing = [name for name, value in required.items() if value is None]
            if missing:
                raise ProvisionError(f"run requires {', '.join(missing)}")
            result = run(
                manifest,
                capabilities,
                state_root=Path(args.state_root),
                confirm_authorized_test=args.confirm_authorized_test,
                authorization_id=args.authorization_id,
                system_prompt_file=Path(str(args.system_prompt_file)),
                target_provider=str(args.target_provider),
                target_model=str(args.target_model),
                attack_provider=str(args.attack_provider),
                attack_model=str(args.attack_model),
                tests=selected_tests,
                attempts=args.attempts,
                threads=args.threads,
                output_dir=Path(str(args.output_dir)),
                target_base_url=args.target_base_url,
                approved_target_url=args.approved_target_url,
                attack_base_url=args.attack_base_url,
                approved_attack_url=args.approved_attack_url,
                attack_temperature=args.attack_temperature,
                embedding_provider=args.embedding_provider,
                embedding_model=args.embedding_model,
                embedding_base_url=args.embedding_base_url,
                approved_embedding_url=args.approved_embedding_url,
            )
            print(f"ps-fuzz run finished with exit status {result.exit_status}; redacted reports were written")
            return result.exit_status
        result = provision(
            manifest,
            state_root=Path(args.state_root),
            source=args.source,
            confirm_authorized_provision=args.confirm_authorized_provision,
            authorization_id=args.authorization_id,
            python_executable=args.python_executable,
            python_version=selected_python_version,
            python_runtime=selected_python_runtime,
            command=command,
        )
    except ProvisionError as exc:
        print(f"ps-fuzz provisioning blocked: {exc}", file=sys.stderr)
        return 2
    print(f"provisioned {result.mode} artifact at {result.artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
