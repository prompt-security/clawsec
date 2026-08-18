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


class RunResult:
    """Safe, aggregate-only outcome of one authorized ps-fuzz invocation."""

    def __init__(self, exit_status: int, aggregate_counts: dict[str, int] | None) -> None:
        self.exit_status = exit_status
        self.aggregate_counts = aggregate_counts


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
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvisionError(f"cannot read upstream manifest: {exc}") from exc

    try:
        upstream = manifest["upstream"]
        release_wheel = manifest["artifacts"]["release_wheel"]
        python = manifest["python"]
        dependency_lock = manifest["dependency_lock"]
        assert isinstance(upstream, dict)
        assert isinstance(release_wheel, dict)
        assert isinstance(python, dict)
        assert isinstance(dependency_lock, dict)
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
        assert re.fullmatch(r"prompt_security_fuzzer-[A-Za-z0-9][A-Za-z0-9_.-]*\.whl", filename)
        assert Path(filename).name == filename
        assert upstream["clone_url"] == "https://github.com/prompt-security/ps-fuzz.git"
        assert artifact_url.scheme == "https" and artifact_url.netloc == "github.com"
        assert artifact_url.path == f"/prompt-security/ps-fuzz/releases/download/{tag}/{filename}"
        _safe_resource_path(dependency_lock["path"])
    except (AssertionError, KeyError, TypeError, ProvisionError) as exc:
        raise ProvisionError("upstream manifest is malformed") from exc
    return manifest


def load_capabilities(path: Path = DEFAULT_CAPABILITIES_PATH) -> dict[str, object]:
    """Load the reviewed, package-local v2.1.0 CLI capability snapshot."""
    try:
        capabilities = json.loads(path.read_text(encoding="utf-8"))
        providers = capabilities["providers"]
        embedding_providers = capabilities["embedding_providers"]
        attacks = capabilities["attacks"]
        batch_flags = capabilities["batch_flags"]
        rag = capabilities["rag_poisoning"]
        assert capabilities["upstream_tag"] == "v2.1.0"
        assert isinstance(providers, dict) and isinstance(embedding_providers, dict)
        assert isinstance(attacks, list) and all(isinstance(attack, str) and attack for attack in attacks)
        assert isinstance(batch_flags, list) and all(isinstance(flag, str) and flag for flag in batch_flags)
        assert isinstance(rag, dict) and isinstance(rag["scope"], str)
        assert isinstance(capabilities["known_upstream_behavior"], str)
        for collection in (providers, embedding_providers):
            for name, details in collection.items():
                assert re.fullmatch(r"[a-z][a-z0-9_]*", name)
                assert isinstance(details, dict)
                assert isinstance(details.get("credential_environment", []), list)
                assert all(re.fullmatch(r"[A-Z][A-Z0-9_]*", key) for key in details["credential_environment"])
                if "base_url_flag" in details:
                    assert details["base_url_flag"] in batch_flags
    except (OSError, json.JSONDecodeError, AssertionError, KeyError, TypeError) as exc:
        raise ProvisionError("capability snapshot is malformed") from exc
    return capabilities


def _capability_section(capabilities: Mapping[str, object], name: str) -> Mapping[str, object]:
    value = capabilities.get(name)
    if not isinstance(value, dict):
        raise ProvisionError(f"capability snapshot is missing {name}")
    return value


def _provider(capabilities: Mapping[str, object], provider_name: str, *, embedding: bool = False) -> Mapping[str, object]:
    collection = _capability_section(capabilities, "embedding_providers" if embedding else "providers")
    details = collection.get(provider_name)
    if not isinstance(details, dict):
        kind = "embedding provider" if embedding else "provider"
        raise ProvisionError(f"unsupported {kind}: {provider_name}")
    return details


def _validate_model(value: str, label: str) -> str:
    cleaned = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", cleaned):
        raise ProvisionError(f"--{label} must be a nonempty safe model identifier")
    return cleaned


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
) -> dict[str, object]:
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
        )
    elif target_base_url or approved_target_url or attack_base_url or approved_attack_url or embedding_provider or embedding_model or embedding_base_url:
        raise ProvisionError("provider roles are required to inspect base URLs or embedding settings")
    credential_presence = _credential_availability(capabilities, selected_providers)
    if embedding_provider:
        credential_presence.update(_credential_availability(capabilities, [embedding_provider], embedding=True))
    return {
        "source": source,
        "python": f"{python_version[0]}.{python_version[1]}",
        "target": {"provider": target_provider, "model": target_model, "origin": endpoints.get("target_origin")},
        "attack": {"provider": attack_provider, "model": attack_model, "origin": endpoints.get("attack_origin")},
        "selected_tests": selected_tests,
        "embedding": (
            {"provider": embedding_provider, "model": embedding_model, "origin": endpoints.get("embedding_origin")}
            if embedding_provider
            else None
        ),
        "credential_environment_present": credential_presence,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _venv_python(state_root: Path) -> Path:
    return state_root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def external_state_root(value: Path) -> Path:
    """Require a caller-selected external base with the dedicated ps-fuzz leaf."""
    state_root = Path(value).expanduser().resolve()
    try:
        state_root.relative_to(PROJECT_ROOT)
    except ValueError:
        pass
    else:
        raise ProvisionError(f"--state-root must be outside the project checkout: {PROJECT_ROOT}")

    if state_root.name != STATE_DIRECTORY_NAME or state_root.parent == state_root:
        raise ProvisionError(
            f"--state-root must be a caller-selected base followed by dedicated leaf {STATE_DIRECTORY_NAME}"
        )
    return state_root


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
    lock_path = _safe_resource_path(dependency_lock.get("path", ""))
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
        filename = str(release_wheel["filename"])
        if not re.fullmatch(r"prompt_security_fuzzer-[A-Za-z0-9][A-Za-z0-9_.-]*\.whl", filename):
            raise ProvisionError("release wheel filename is malformed")
        downloads_root = state_root / "downloads"
        downloads_root.mkdir(parents=True, exist_ok=True)
        resolved_downloads_root = downloads_root.resolve()
        wheel_path = (resolved_downloads_root / filename).resolve()
        try:
            wheel_path.relative_to(resolved_downloads_root)
        except ValueError as exc:
            raise ProvisionError("release wheel path escapes state_root/downloads") from exc
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


def _validate_test_authorization(confirm_authorized_test: bool, authorization_id: str) -> None:
    if not confirm_authorized_test:
        raise ProvisionError("--confirm-authorized-test is required for every active run")
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", authorization_id)
        or authorization_id.lower().startswith(("sk-", "sk_", "api_", "bearer"))
    ):
        raise ProvisionError("--authorization-id must be a short non-secret identifier")


def _normalized_base_url(value: str, label: str) -> tuple[str, str]:
    """Return canonical URL and origin; credentials/query/fragment are never allowed."""
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ProvisionError(f"--{label} must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ProvisionError(f"--{label} must not contain credentials")
    if parsed.query:
        raise ProvisionError(f"--{label} must not contain a query")
    if parsed.fragment:
        raise ProvisionError(f"--{label} must not contain a fragment")
    host = parsed.hostname.lower()
    netloc = host if parsed.port is None else f"{host}:{parsed.port}"
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
            flag = embedding_details.get("base_url_flag")
            if not isinstance(flag, str):
                raise ProvisionError("embedding provider does not support a custom embedding base URL")
            embedding_url, embedding_origin = _normalized_base_url(embedding_base_url, "embedding-base-url")
        else:
            embedding_origin = f"provider:{embedding_provider}"
    elif embedding_provider or embedding_model or embedding_base_url:
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
    candidate = Path(output_dir).expanduser().resolve()
    try:
        candidate.relative_to(PROJECT_ROOT)
    except ValueError:
        pass
    else:
        raise ProvisionError("--output-dir must be outside the project checkout")
    if candidate.exists():
        raise ProvisionError("--output-dir must name a new directory")
    if candidate.parent == candidate or not candidate.parent.is_dir():
        raise ProvisionError("--output-dir parent must already exist")
    return candidate


def _require_regular_nonempty_file(path: Path, label: str) -> Path:
    candidate = Path(path).expanduser().resolve()
    if not candidate.is_file() or candidate.is_symlink() or candidate.stat().st_size == 0:
        raise ProvisionError(f"--{label} must be a readable nonempty regular file")
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
        }
    )
    return environment


def _aggregate_counts(raw_output: str) -> dict[str, int] | None:
    """Extract the sole ANSI-stripped `Total (# tests)` footer from SINGLE_BORDER output."""
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw_output)
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
    exit_status: int,
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
        "exit_status": exit_status,
        "aggregate_result_counts": dict(aggregate_counts) if aggregate_counts is not None else None,
        "scope_limitations": scope_limitations,
    }
    output_dir.mkdir(mode=0o700)
    (output_dir / "run.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
        f"- Exit status: {exit_status}\n"
        f"- Aggregate results: {counts_text}\n"
        f"- Target: {configuration['target_provider']} / {configuration['target_model']}\n"
        f"- Target origin: {configuration['target_origin']}\n\n"
        f"- Attack: {configuration['attack_provider']} / {configuration['attack_model']}\n"
        f"- Attack origin: {configuration['attack_origin']}\n\n"
        "No raw system prompt, provider credential, attack payload, model response, stdout, or stderr was saved.\n"
        f"{rag_summary}"
    )
    (output_dir / "summary.md").write_text(summary, encoding="utf-8")


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
    command: Command = _run_command,
) -> RunResult:
    """Run only the reviewed batch interface after an explicit, per-run authorization."""
    _validate_test_authorization(confirm_authorized_test, authorization_id)
    state_root = external_state_root(state_root)
    executable = state_root / "venv" / ("Scripts/prompt-security-fuzzer.exe" if os.name == "nt" else "bin/prompt-security-fuzzer")
    if not executable.is_file():
        raise ProvisionError("no provisioned ps-fuzz executable exists in --state-root")
    prompt_path = _require_regular_nonempty_file(system_prompt_file, "system-prompt-file")
    target_model = _validate_model(target_model, "target-model")
    attack_model = _validate_model(attack_model, "attack-model")
    if not tests or any(not isinstance(test, str) or test not in capabilities.get("attacks", []) for test in tests):
        raise ProvisionError("--tests must be a nonempty list of supported attacks")
    if not isinstance(attempts, int) or attempts <= 0 or not isinstance(threads, int) or threads <= 0:
        raise ProvisionError("--attempts and --threads must be positive integers")
    if attack_temperature is not None and (not isinstance(attack_temperature, (int, float)) or attack_temperature < 0):
        raise ProvisionError("--attack-temperature must be zero or greater")

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
    )

    safe_output_dir = _require_new_external_output_dir(output_dir)
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
    with tempfile.TemporaryDirectory(prefix="clawsec-ps-fuzz-run-") as temporary_name:
        temporary_root = Path(temporary_name)
        home = temporary_root / "home"
        for directory in (home, temporary_root / "tmp", temporary_root / "xdg-config", temporary_root / "xdg-cache", temporary_root / "xdg-data"):
            directory.mkdir()
        prompt_copy = temporary_root / "system-prompt.txt"
        prompt_copy.write_bytes(prompt_path.read_bytes())
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
        exit_status = result.returncode
        counts = _aggregate_counts(result.stdout) if exit_status == 0 else None
    _write_redacted_reports(
        safe_output_dir,
        manifest,
        capabilities,
        authorization_id=authorization_id.strip(),
        configuration=configuration,
        exit_status=exit_status,
        aggregate_counts=counts,
    )
    return RunResult(exit_status, counts)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "provision", "run"))
    parser.add_argument("--state-root", help="External ClawSec state root, required only for provision.")
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


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    manifest = load_manifest()
    try:
        capabilities = load_capabilities()
        selected_tests = _parse_tests_argument(args.tests)
        if args.command == "preflight":
            inspection = preflight(
                manifest,
                source=args.source,
                python_executable=args.python_executable,
                python_version=sys.version_info[:2],
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
            )
            print(json.dumps(inspection, sort_keys=True))
            print("preflight passed; no state was written")
            return 0
        if not args.state_root:
            raise ProvisionError("--state-root is required for provision or run")
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
            python_version=sys.version_info[:2],
        )
    except ProvisionError as exc:
        print(f"ps-fuzz provisioning blocked: {exc}", file=sys.stderr)
        return 2
    print(f"provisioned {result.mode} artifact at {result.artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
