#!/usr/bin/env python3
"""Verify and atomically install one signed clawsec-ps-fuzz release."""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile


REPOSITORY = "prompt-security/clawsec"
SKILL_NAME = "clawsec-ps-fuzz"
CANONICAL_SPKI_SHA256 = "711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")
DRIVE_RE = re.compile(r"[A-Za-z]:")

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_SIGNATURE_TEXT_BYTES = 4096
MAX_PUBLIC_KEY_BYTES = 16 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_FILE_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_FILES = 4096
MAX_ZIP_ENTRIES = 512
MAX_FILE_SIZE = 16 * 1024 * 1024
MAX_TOTAL_SIZE = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
OPENSSL_TIMEOUT_SECONDS = 10
DOWNLOAD_TIMEOUT_SECONDS = 30
ALLOWED_DOWNLOAD_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
}
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


class VerifiedInstallError(Exception):
    """A stable, redacted verification failure."""


class _DuplicateKey(ValueError):
    pass


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
            raise urllib.error.URLError("unsafe redirect")
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def _release_values(version: str) -> tuple[str, str, str]:
    if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
        raise VerifiedInstallError("requested version is invalid")
    tag = f"{SKILL_NAME}-v{version}"
    archive = f"{tag}.zip"
    base_url = f"https://github.com/{REPOSITORY}/releases/download/{tag}"
    return tag, archive, base_url


def _download_opaque(url: str, limit: int) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password:
        raise VerifiedInstallError("release download failed")
    request = urllib.request.Request(
        url,
        headers={"Accept-Encoding": "identity", "User-Agent": "clawsec-verified-install/1"},
        method="GET",
    )
    opener = urllib.request.build_opener(_SafeRedirectHandler())
    try:
        with opener.open(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in ALLOWED_DOWNLOAD_HOSTS:
                raise VerifiedInstallError("release download failed")
            if getattr(response, "status", 200) != 200:
                raise VerifiedInstallError("release download failed")
            encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
            if encoding not in ("", "identity"):
                raise VerifiedInstallError("release download failed")
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    declared_length = int(length, 10)
                except (TypeError, ValueError):
                    raise VerifiedInstallError("release download failed") from None
                if declared_length < 0 or declared_length > limit:
                    raise VerifiedInstallError("download exceeds allowed size")
            data = response.read(limit + 1)
    except VerifiedInstallError:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError):
        raise VerifiedInstallError("release download failed") from None
    if len(data) > limit:
        raise VerifiedInstallError("download exceeds allowed size")
    return data


def _fetch_bounded(fetcher, url: str, limit: int) -> bytes:
    try:
        value = fetcher(url, limit)
    except VerifiedInstallError:
        raise
    except Exception:
        raise VerifiedInstallError("release download failed") from None
    if not isinstance(value, bytes):
        raise VerifiedInstallError("release download failed")
    if len(value) > limit:
        raise VerifiedInstallError("download exceeds allowed size")
    return value


def _openssl_executable() -> str:
    executable = shutil.which("openssl")
    if executable is None:
        raise VerifiedInstallError("system openssl is unavailable")
    return executable


def _run_openssl(arguments: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
    try:
        return subprocess.run(
            [_openssl_executable(), *arguments],
            input=input_bytes,
            capture_output=True,
            check=False,
            shell=False,
            timeout=OPENSSL_TIMEOUT_SECONDS,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        raise VerifiedInstallError("openssl verification failed") from None


def _verify_public_key(public_key: bytes) -> None:
    result = _run_openssl(["pkey", "-pubin", "-outform", "DER"], input_bytes=public_key)
    if result.returncode != 0:
        raise VerifiedInstallError("release signing key is invalid")
    der = result.stdout
    if len(der) != len(ED25519_SPKI_PREFIX) + 32 or not der.startswith(ED25519_SPKI_PREFIX):
        raise VerifiedInstallError("release signing key is invalid")
    if hashlib.sha256(der).hexdigest() != CANONICAL_SPKI_SHA256:
        raise VerifiedInstallError("release signing key is not trusted")


def _verify_signature(public_key: bytes, signature_text: bytes, manifest_bytes: bytes) -> None:
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (binascii.Error, ValueError):
        raise VerifiedInstallError("release signature is invalid") from None
    if len(signature) != 64:
        raise VerifiedInstallError("release signature is invalid")
    with tempfile.TemporaryDirectory(prefix="clawsec-signature-") as temp_value:
        temp = Path(temp_value)
        key_path = temp / "public.pem"
        signature_path = temp / "signature.bin"
        manifest_path = temp / "checksums.json"
        key_path.write_bytes(public_key)
        signature_path.write_bytes(signature)
        manifest_path.write_bytes(manifest_bytes)
        for path in (key_path, signature_path, manifest_path):
            path.chmod(0o600)
        result = _run_openssl(
            [
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                os.fspath(key_path),
                "-sigfile",
                os.fspath(signature_path),
                "-in",
                os.fspath(manifest_path),
            ]
        )
    if result.returncode != 0:
        raise VerifiedInstallError("release signature is invalid")


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey
        value[key] = item
    return value


def _reject_nonfinite(_value: str):
    raise ValueError


def _size(value, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _hash(value) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _parse_manifest(raw: bytes, version: str, tag: str, archive_name: str, base_url: str) -> dict:
    try:
        manifest = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError, TypeError):
        raise VerifiedInstallError("signed release manifest is invalid") from None
    if not isinstance(manifest, dict):
        raise VerifiedInstallError("signed release manifest is invalid")
    expected_identity = {
        "repository": REPOSITORY,
        "skill": SKILL_NAME,
        "version": version,
        "tag": tag,
    }
    if any(
        type(manifest.get(key)) is not str or manifest.get(key) != expected
        for key, expected in expected_identity.items()
    ):
        raise VerifiedInstallError("signed release identity is invalid")
    archive = manifest.get("archive")
    expected_url = f"{base_url}/{archive_name}"
    if not isinstance(archive, dict) or any(
        type(archive.get(key)) is not str or archive.get(key) != expected
        for key, expected in (("filename", archive_name), ("url", expected_url))
    ):
        raise VerifiedInstallError("signed release identity is invalid")
    if not _hash(archive.get("sha256")) or not _size(archive.get("size"), MAX_ARCHIVE_BYTES) or archive["size"] == 0:
        raise VerifiedInstallError("signed release manifest is invalid")
    files = manifest.get("files")
    if not isinstance(files, dict) or len(files) > MAX_MANIFEST_FILES:
        raise VerifiedInstallError("signed release manifest is invalid")
    for path, record in files.items():
        if not isinstance(path, str) or not path or not isinstance(record, dict):
            raise VerifiedInstallError("signed release manifest is invalid")
        if not _hash(record.get("sha256")) or not _size(record.get("size"), MAX_MANIFEST_FILE_BYTES):
            raise VerifiedInstallError("signed release manifest is invalid")
        if "path" in record and (type(record["path"]) is not str or record["path"] != path):
            raise VerifiedInstallError("signed release manifest is invalid")
    return manifest


def _normalize_release_path(value: object) -> str:
    if not isinstance(value, str):
        raise VerifiedInstallError("package metadata is invalid")
    path = value.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    while "//" in path:
        path = path.replace("//", "/")
    if (
        not path
        or path.startswith("/")
        or DRIVE_RE.match(path)
        or path == ".."
        or path.startswith("../")
        or path.endswith("/..")
        or "/../" in path
    ):
        raise VerifiedInstallError("package metadata is invalid")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise VerifiedInstallError("package metadata is invalid")
    return "/".join(parts)


def _is_test_release_path(path: str) -> bool:
    lower = path.lower()
    parts = lower.split("/")
    name = parts[-1]
    return (
        any(part in {"test", "tests", "__tests__"} for part in parts[:-1])
        or name.startswith(("test_", "test-", "spec_", "spec-"))
        or ".test." in name
        or ".spec." in name
    )


def _windows_component_is_unsafe(component: str) -> bool:
    if component[-1:] in (".", " ") or ":" in component:
        return True
    if any(ord(character) < 32 for character in component):
        return True
    stem = component.split(".", 1)[0].upper()
    return stem in WINDOWS_RESERVED_NAMES


def _safe_zip_name(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or name.startswith("/") or DRIVE_RE.match(name):
        raise VerifiedInstallError("release archive layout is unsafe")
    stripped = name[:-1] if name.endswith("/") else name
    parts = stripped.split("/")
    if not stripped or any(part in ("", ".", "..") for part in parts):
        if stripped == SKILL_NAME and name.endswith("/"):
            return (SKILL_NAME,)
        raise VerifiedInstallError("release archive layout is unsafe")
    if parts[0] != SKILL_NAME or any(_windows_component_is_unsafe(part) for part in parts):
        raise VerifiedInstallError("release archive layout is unsafe")
    return tuple(parts)


def _collision_key(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)


def _inspect_archive(
    archive_bytes: bytes,
    *,
    max_entries: int = MAX_ZIP_ENTRIES,
    max_file_size: int = MAX_FILE_SIZE,
    max_total_size: int = MAX_TOTAL_SIZE,
    max_compression_ratio: int = MAX_COMPRESSION_RATIO,
) -> tuple[zipfile.ZipFile, dict[str, zipfile.ZipInfo]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes), "r")
        entries = archive.infolist()
    except (OSError, zipfile.BadZipFile, ValueError):
        raise VerifiedInstallError("release archive is invalid") from None
    if not entries or len(entries) > max_entries:
        archive.close()
        raise VerifiedInstallError("release archive exceeds safety limits")
    seen: dict[tuple[str, ...], bool] = {}
    regular: dict[str, zipfile.ZipInfo] = {}
    total = 0
    try:
        for info in entries:
            original_name = getattr(info, "orig_filename", info.filename)
            if "\x00" in original_name or original_name != info.filename:
                raise VerifiedInstallError("release archive layout is unsafe")
            parts = _safe_zip_name(info.filename)
            collision = _collision_key(parts)
            is_directory = info.is_dir()
            if collision in seen:
                raise VerifiedInstallError("release archive layout is unsafe")
            seen[collision] = is_directory
            if info.flag_bits & 0x1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise VerifiedInstallError("release archive entry type is unsafe")
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if is_directory:
                if file_type not in (0, stat.S_IFDIR):
                    raise VerifiedInstallError("release archive entry type is unsafe")
                continue
            if file_type not in (0, stat.S_IFREG):
                raise VerifiedInstallError("release archive entry type is unsafe")
            if len(parts) < 2:
                raise VerifiedInstallError("release archive layout is unsafe")
            if info.file_size < 0 or info.compress_size < 0 or info.file_size > max_file_size:
                raise VerifiedInstallError("release archive exceeds safety limits")
            total += info.file_size
            if total > max_total_size:
                raise VerifiedInstallError("release archive exceeds safety limits")
            if info.file_size and info.file_size / max(info.compress_size, 1) > max_compression_ratio:
                raise VerifiedInstallError("release archive exceeds safety limits")
            regular["/".join(parts[1:])] = info
        keys = set(seen)
        for key, is_directory in seen.items():
            for length in range(1, len(key)):
                prefix = key[:length]
                if prefix in seen and not seen[prefix]:
                    raise VerifiedInstallError("release archive layout is unsafe")
            if not is_directory and any(other[: len(key)] == key and len(other) > len(key) for other in keys):
                raise VerifiedInstallError("release archive layout is unsafe")
    except Exception:
        archive.close()
        raise
    return archive, regular


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, label: str) -> bytes:
    try:
        with archive.open(info, "r") as source:
            value = source.read(info.file_size + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        raise VerifiedInstallError(label) from None
    if len(value) != info.file_size:
        raise VerifiedInstallError(label)
    return value


def _expected_payload(skill_json_bytes: bytes, version: str) -> set[str]:
    try:
        metadata = json.loads(
            skill_json_bytes,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError, TypeError):
        raise VerifiedInstallError("package metadata is invalid") from None
    if not isinstance(metadata, dict) or metadata.get("name") != SKILL_NAME or metadata.get("version") != version:
        raise VerifiedInstallError("package metadata is invalid")
    sbom = metadata.get("sbom")
    entries = sbom.get("files") if isinstance(sbom, dict) else None
    if not isinstance(entries, list):
        raise VerifiedInstallError("package metadata is invalid")
    paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise VerifiedInstallError("package metadata is invalid")
        path = _normalize_release_path(entry.get("path"))
        if path in paths:
            raise VerifiedInstallError("package metadata is invalid")
        paths.add(path)
    expected = {path for path in paths if not _is_test_release_path(path)}
    expected.add("skill.json")
    return expected


def _verify_payload(
    archive: zipfile.ZipFile,
    regular: dict[str, zipfile.ZipInfo],
    manifest: dict,
    version: str,
) -> dict[str, tuple[zipfile.ZipInfo, int, str]]:
    if "skill.json" not in regular:
        raise VerifiedInstallError("release payload does not match package SBOM")
    skill_json = _read_member(archive, regular["skill.json"], "package metadata is invalid")
    expected = _expected_payload(skill_json, version)
    if set(regular) != expected:
        raise VerifiedInstallError("release payload does not match package SBOM")
    verified: dict[str, tuple[zipfile.ZipInfo, int, str]] = {}
    files = manifest["files"]
    for path in sorted(expected):
        record = files.get(path)
        if not isinstance(record, dict):
            raise VerifiedInstallError("release payload verification failed")
        info = regular[path]
        expected_size = record.get("size")
        expected_hash = record.get("sha256")
        if expected_size != info.file_size:
            raise VerifiedInstallError("release payload verification failed")
        content = skill_json if path == "skill.json" else _read_member(
            archive, info, "release payload verification failed"
        )
        if hashlib.sha256(content).hexdigest() != expected_hash:
            raise VerifiedInstallError("release payload verification failed")
        verified[path] = (info, expected_size, expected_hash)
    return verified


def _copy_verified_member(source, destination: Path, expected_size: int, expected_hash: str) -> None:
    digest = hashlib.sha256()
    written = 0
    try:
        with destination.open("xb") as output:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > expected_size:
                    raise VerifiedInstallError("release extraction verification failed")
                digest.update(chunk)
                output.write(chunk)
        destination.chmod(0o644)
    except VerifiedInstallError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile):
        raise VerifiedInstallError("release extraction verification failed") from None
    if written != expected_size or digest.hexdigest() != expected_hash:
        raise VerifiedInstallError("release extraction verification failed")


def _atomic_publish_no_replace(staging: Path, destination: Path) -> None:
    source_bytes = os.fsencode(staging)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        try:
            library = ctypes.CDLL(None, use_errno=True)
        except OSError:
            raise VerifiedInstallError("atomic no-replace is unavailable") from None
        if not hasattr(library, "renamex_np"):
            raise VerifiedInstallError("atomic no-replace is unavailable")
        result = library.renamex_np(source_bytes, destination_bytes, 0x00000004)
    elif sys.platform.startswith("linux"):
        try:
            library = ctypes.CDLL(None, use_errno=True)
        except OSError:
            raise VerifiedInstallError("atomic no-replace is unavailable") from None
        if not hasattr(library, "renameat2"):
            raise VerifiedInstallError("atomic no-replace is unavailable")
        result = library.renameat2(-100, source_bytes, -100, destination_bytes, 1)
    elif sys.platform == "win32" or os.name == "nt":
        try:
            os.rename(staging, destination)
            return
        except FileExistsError:
            raise VerifiedInstallError("installation destination already exists") from None
        except OSError:
            raise VerifiedInstallError("atomic installation failed") from None
    else:
        raise VerifiedInstallError("atomic no-replace is unavailable")
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in (errno.EEXIST, errno.ENOTEMPTY):
        raise VerifiedInstallError("installation destination already exists")
    raise VerifiedInstallError("atomic installation failed")


def _extract_atomic(
    archive: zipfile.ZipFile,
    verified: dict[str, tuple[zipfile.ZipInfo, int, str]],
    install_root: Path,
    destination: Path,
) -> None:
    try:
        install_root.mkdir(parents=True, exist_ok=True, mode=0o755)
    except OSError:
        raise VerifiedInstallError("installation root is unavailable") from None
    if not install_root.is_dir():
        raise VerifiedInstallError("installation root is unavailable")
    staging = Path(tempfile.mkdtemp(prefix=f".{SKILL_NAME}-", dir=install_root))
    staging.chmod(0o700)
    published = False
    try:
        for path in sorted(verified):
            info, expected_size, expected_hash = verified[path]
            target = staging.joinpath(*path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target.parent.chmod(0o755)
            try:
                source = archive.open(info, "r")
            except (OSError, RuntimeError, zipfile.BadZipFile):
                raise VerifiedInstallError("release extraction verification failed") from None
            with source:
                _copy_verified_member(source, target, expected_size, expected_hash)
        staging.chmod(0o755)
        _atomic_publish_no_replace(staging, destination)
        published = True
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)


def install_verified_release(
    version: str,
    install_root: str | os.PathLike[str],
    *,
    confirm_install: bool,
    fetcher=_download_opaque,
    max_entries: int = MAX_ZIP_ENTRIES,
    max_file_size: int = MAX_FILE_SIZE,
    max_total_size: int = MAX_TOTAL_SIZE,
    max_compression_ratio: int = MAX_COMPRESSION_RATIO,
) -> Path:
    """Verify a fixed signed release and publish its leaf without replacement."""
    if not confirm_install:
        raise VerifiedInstallError("installation confirmation is required")
    try:
        tag, archive_name, base_url = _release_values(version)
        root = Path(install_root).expanduser().resolve(strict=False)
        destination = root / SKILL_NAME
        if os.path.lexists(destination):
            raise VerifiedInstallError("installation destination already exists")

        manifest_bytes = _fetch_bounded(fetcher, f"{base_url}/checksums.json", MAX_MANIFEST_BYTES)
        signature_text = _fetch_bounded(fetcher, f"{base_url}/checksums.sig", MAX_SIGNATURE_TEXT_BYTES)
        public_key = _fetch_bounded(fetcher, f"{base_url}/signing-public.pem", MAX_PUBLIC_KEY_BYTES)

        _verify_public_key(public_key)
        _verify_signature(public_key, signature_text, manifest_bytes)
        manifest = _parse_manifest(manifest_bytes, version, tag, archive_name, base_url)

        archive_size = manifest["archive"]["size"]
        archive_bytes = _fetch_bounded(fetcher, f"{base_url}/{archive_name}", archive_size)
        archive_hash = hashlib.sha256(archive_bytes).hexdigest()
        if len(archive_bytes) != archive_size or archive_hash != manifest["archive"]["sha256"]:
            raise VerifiedInstallError("release archive verification failed")

        archive, regular = _inspect_archive(
            archive_bytes,
            max_entries=max_entries,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            max_compression_ratio=max_compression_ratio,
        )
        with archive:
            verified = _verify_payload(archive, regular, manifest, version)
            _extract_atomic(archive, verified, root, destination)
        return destination
    except VerifiedInstallError:
        raise
    except Exception:
        raise VerifiedInstallError("verified installation failed") from None


class _StableArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise VerifiedInstallError("command line is invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(description="Verify and install a fixed clawsec-ps-fuzz release.")
    parser.add_argument("--version", required=True, help="Exact release version; latest is never followed.")
    parser.add_argument("--install-root", required=True, help="Caller-selected parent directory.")
    parser.add_argument("--confirm-install", action="store_true", help="Confirm the verified atomic install.")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        install_verified_release(
            arguments.version,
            arguments.install_root,
            confirm_install=arguments.confirm_install,
        )
    except VerifiedInstallError as error:
        print(f"verified install blocked: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("verified install blocked: verified installation failed", file=sys.stderr)
        return 1
    print("verified installation completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
