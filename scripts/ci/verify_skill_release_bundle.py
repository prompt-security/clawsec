#!/usr/bin/env python3
"""Verify and safely extract a signed ClawSec skill release bundle.

The verifier deliberately treats every downloaded release asset as untrusted.
It authenticates ``checksums.json`` with a pinned Ed25519 public key, binds the
manifest to the caller's expected release identity, validates the complete ZIP
namespace, and only then extracts into a private staging directory.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, NoReturn


DEFAULT_MAX_ENTRIES = 4096
DEFAULT_MAX_FILE_SIZE = 128 * 1024 * 1024
DEFAULT_MAX_TOTAL_SIZE = 512 * 1024 * 1024
DEFAULT_MAX_COMPRESSION_RATIO = 200.0
MAX_MANIFEST_SIZE = 4 * 1024 * 1024
MAX_SIGNATURE_SIZE = 16 * 1024
MAX_PUBLIC_KEY_SIZE = 64 * 1024
MAX_PATH_LENGTH = 4096
MAX_COMPONENT_LENGTH = 255
COPY_CHUNK_SIZE = 1024 * 1024

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_RELEASE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_OPENSSL_3_RE = re.compile(r"^OpenSSL\s+3(?:\.|\s)")
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_WINDOWS_FORBIDDEN_CHARS = set('<>:"|?*')
_ALLOWED_COMPRESSION = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
}


class VerificationError(Exception):
    """Raised when a release bundle fails a verification boundary."""


@dataclass(frozen=True)
class Limits:
    max_entries: int
    max_file_size: int
    max_total_size: int
    max_compression_ratio: float


@dataclass(frozen=True)
class ValidatedEntry:
    info: zipfile.ZipInfo
    parts: tuple[str, ...]
    is_dir: bool
    extracted_mode: int


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def _json_object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate key: {key!r}")
        result[key] = value
    return result


def load_json_bytes(data: bytes, label: str) -> object:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not valid UTF-8: {exc}")
    try:
        return json.loads(text, object_pairs_hook=_json_object_without_duplicates)
    except json.JSONDecodeError as exc:
        fail(f"{label} is not valid JSON: {exc}")


def _require_regular_file(path: Path, label: str, max_size: int | None = None) -> os.stat_result:
    try:
        file_stat = path.lstat()
    except FileNotFoundError:
        fail(f"missing {label}: {path}")
    if not stat.S_ISREG(file_stat.st_mode):
        fail(f"{label} must be a regular file, not a symlink or special file: {path}")
    if max_size is not None and file_stat.st_size > max_size:
        fail(f"{label} exceeds the {max_size}-byte safety limit: {path}")
    return file_stat


def _read_limited(path: Path, label: str, max_size: int) -> bytes:
    expected = _require_regular_file(path, label, max_size).st_size
    try:
        with path.open("rb") as handle:
            data = handle.read(max_size + 1)
    except OSError as exc:
        fail(f"could not read {label} {path}: {exc}")
    if len(data) > max_size:
        fail(f"{label} exceeds the {max_size}-byte safety limit: {path}")
    if len(data) != expected:
        fail(f"{label} changed while it was being read: {path}")
    return data


def _run_openssl(openssl: str, arguments: list[str], label: str) -> subprocess.CompletedProcess[bytes]:
    command = [openssl, *arguments]
    try:
        return subprocess.run(
            command,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except FileNotFoundError:
        fail(f"OpenSSL executable not found: {openssl}")
    except subprocess.TimeoutExpired:
        fail(f"OpenSSL timed out while attempting to {label}")
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", "replace").strip()
        suffix = f": {detail}" if detail else ""
        fail(f"OpenSSL failed to {label}{suffix}")


def require_openssl_3(openssl: str) -> str:
    result = _run_openssl(openssl, ["version"], "report its version")
    version = result.stdout.decode("utf-8", "replace").strip()
    if not _OPENSSL_3_RE.match(version):
        fail(f"OpenSSL 3 is required; selected executable reported: {version or '<empty>'}")
    return version


def spki_sha256(openssl: str, public_key: Path, label: str) -> str:
    _require_regular_file(public_key, label, MAX_PUBLIC_KEY_SIZE)
    details = _run_openssl(
        openssl,
        ["pkey", "-pubin", "-in", os.fspath(public_key), "-text_pub", "-noout"],
        f"inspect {label}",
    )
    key_description = (details.stdout + details.stderr).decode("utf-8", "replace").upper()
    if "ED25519" not in key_description:
        fail(f"{label} is not an Ed25519 public key")
    der = _run_openssl(
        openssl,
        ["pkey", "-pubin", "-in", os.fspath(public_key), "-outform", "DER"],
        f"encode {label} as SPKI DER",
    ).stdout
    if not der:
        fail(f"OpenSSL produced an empty SPKI DER encoding for {label}")
    return hashlib.sha256(der).hexdigest()


def _normalize_fingerprint(value: str, label: str) -> str:
    if not _SHA256_RE.fullmatch(value):
        fail(f"{label} must be exactly 64 hexadecimal characters")
    return value.lower()


def verify_key_pin(
    openssl: str,
    release_key: Path,
    expected_spki_sha256: str | None,
    canonical_key: Path | None,
) -> str:
    if expected_spki_sha256 is None and canonical_key is None:
        fail("one of --spki-sha256 or --canonical-key is required")

    expected = (
        _normalize_fingerprint(expected_spki_sha256, "--spki-sha256")
        if expected_spki_sha256 is not None
        else None
    )
    if canonical_key is not None:
        canonical_fingerprint = spki_sha256(openssl, canonical_key, "canonical signing key")
        if expected is not None and canonical_fingerprint != expected:
            fail(
                "canonical signing key fingerprint does not match --spki-sha256: "
                f"expected {expected}, got {canonical_fingerprint}"
            )
        expected = canonical_fingerprint

    assert expected is not None
    actual = spki_sha256(openssl, release_key, "release signing key")
    if actual != expected:
        fail(f"release signing key fingerprint mismatch: expected {expected}, got {actual}")
    return actual


def decode_signature(signature_path: Path, destination: Path) -> None:
    encoded = _read_limited(signature_path, "checksums signature", MAX_SIGNATURE_SIZE)
    try:
        compact = b"".join(encoded.split())
        signature = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error):
        fail("checksums.sig is not valid strict base64")
    if len(signature) != 64:
        fail(f"checksums.sig must decode to a 64-byte Ed25519 signature, got {len(signature)} bytes")
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(signature)
    except OSError as exc:
        fail(f"could not stage the decoded signature: {exc}")


def verify_manifest_signature(
    openssl: str,
    public_key: Path,
    signature_path: Path,
    manifest_path: Path,
) -> None:
    _require_regular_file(manifest_path, "checksums manifest", MAX_MANIFEST_SIZE)
    with tempfile.TemporaryDirectory(prefix="clawsec-release-signature-") as temporary:
        decoded_signature = Path(temporary) / "checksums.sig.bin"
        decode_signature(signature_path, decoded_signature)
        _run_openssl(
            openssl,
            [
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                os.fspath(public_key),
                "-sigfile",
                os.fspath(decoded_signature),
                "-in",
                os.fspath(manifest_path),
            ],
            "verify the checksums.json Ed25519 signature",
        )


def _require_safe_release_component(value: str, label: str) -> None:
    if not _SAFE_RELEASE_COMPONENT_RE.fullmatch(value):
        fail(f"{label} is not a safe release identifier: {value!r}")
    _validate_windows_component(value, label)


def validate_expected_identity(skill: str, version: str, tag: str) -> str:
    _require_safe_release_component(skill, "skill")
    _require_safe_release_component(version, "version")
    _require_safe_release_component(tag, "tag")
    conventional_tag = f"{skill}-v{version}"
    if tag != conventional_tag:
        fail(f"tag must match the ClawSec release convention {conventional_tag!r}, got {tag!r}")
    return f"{tag}.zip"


def _require_string(mapping: dict[str, object], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        fail(f"{label}.{key} must be a string")
    return value


def _require_nonnegative_integer(mapping: dict[str, object], key: str, label: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{label}.{key} must be a non-negative integer")
    return value


def validate_manifest(
    manifest_path: Path,
    skill: str,
    version: str,
    tag: str,
    expected_archive_name: str,
) -> tuple[dict[str, object], str, int]:
    manifest_data = _read_limited(manifest_path, "checksums manifest", MAX_MANIFEST_SIZE)
    manifest = load_json_bytes(manifest_data, "checksums.json")
    if not isinstance(manifest, dict):
        fail("checksums.json root must be an object")

    expected_fields = {"skill": skill, "version": version, "tag": tag}
    for field, expected in expected_fields.items():
        actual = _require_string(manifest, field, "checksums.json")
        if actual != expected:
            fail(f"checksums.json {field} mismatch: expected {expected!r}, got {actual!r}")

    archive = manifest.get("archive")
    if not isinstance(archive, dict):
        fail("checksums.json.archive must be an object")
    filename = _require_string(archive, "filename", "checksums.json.archive")
    if filename != expected_archive_name:
        fail(
            "checksums.json archive filename mismatch: "
            f"expected {expected_archive_name!r}, got {filename!r}"
        )
    digest = _require_string(archive, "sha256", "checksums.json.archive")
    digest = _normalize_fingerprint(digest, "checksums.json.archive.sha256")
    size = _require_nonnegative_integer(archive, "size", "checksums.json.archive")
    return manifest, digest, size


def _sha256_stream(handle: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    for block in iter(lambda: handle.read(COPY_CHUNK_SIZE), b""):
        digest.update(block)
        size += len(block)
    return digest.hexdigest(), size


def verify_archive_digest(handle: BinaryIO, expected_digest: str, expected_size: int) -> None:
    handle.seek(0)
    actual_digest, actual_size = _sha256_stream(handle)
    if actual_size != expected_size:
        fail(f"release archive size mismatch: expected {expected_size}, got {actual_size}")
    if actual_digest != expected_digest:
        fail(f"release archive SHA-256 mismatch: expected {expected_digest}, got {actual_digest}")
    handle.seek(0)


def _validate_windows_component(component: str, label: str) -> None:
    if not component or component in {".", ".."}:
        fail(f"{label} contains an empty or relative path component")
    if len(component) > MAX_COMPONENT_LENGTH:
        fail(f"{label} contains a component longer than {MAX_COMPONENT_LENGTH} characters")
    if component[-1] in {" ", "."}:
        fail(f"{label} contains a Windows-unsafe trailing space or dot: {component!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in component):
        fail(f"{label} contains a control character")
    if any(character in _WINDOWS_FORBIDDEN_CHARS for character in component):
        fail(f"{label} contains a Windows-unsafe character: {component!r}")
    normalized = unicodedata.normalize("NFKC", component)
    if "/" in normalized or "\\" in normalized or normalized in {".", ".."}:
        fail(f"{label} changes into a path separator or relative component under Unicode normalization")
    device_name = normalized.split(".", 1)[0].upper()
    if device_name in _WINDOWS_RESERVED:
        fail(f"{label} contains a reserved Windows device name: {component!r}")


def _zip_entry_type(info: zipfile.ZipInfo) -> tuple[bool, int]:
    is_dir = info.is_dir()
    unix_mode = info.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    if is_dir:
        if file_type not in {0, stat.S_IFDIR}:
            fail(f"ZIP directory entry has a special-file mode: {info.filename!r}")
    else:
        if file_type == stat.S_IFDIR:
            fail(f"ZIP directory mode lacks a trailing slash: {info.filename!r}")
        if file_type not in {0, stat.S_IFREG}:
            fail(f"ZIP contains a symlink or special file: {info.filename!r}")
    return is_dir, file_type


def _canonical_path_key(parts: tuple[str, ...]) -> str:
    return unicodedata.normalize("NFKC", "/".join(parts)).casefold()


def _validated_entry_path(info: zipfile.ZipInfo, skill: str) -> tuple[tuple[str, ...], bool]:
    name = info.filename
    if not name:
        fail("ZIP contains an empty entry name")
    if len(name) > MAX_PATH_LENGTH:
        fail(f"ZIP entry path exceeds {MAX_PATH_LENGTH} characters")
    if "\\" in name:
        fail(f"ZIP entry uses a backslash path separator: {name!r}")
    if name.startswith("/") or name.startswith("//") or re.match(r"^[A-Za-z]:", name):
        fail(f"ZIP entry uses an absolute path: {name!r}")

    is_dir, _ = _zip_entry_type(info)
    logical_name = name[:-1] if is_dir else name
    if not logical_name or "//" in logical_name:
        fail(f"ZIP entry contains an empty path component: {name!r}")
    parts = tuple(logical_name.split("/"))
    for component in parts:
        _validate_windows_component(component, f"ZIP entry {name!r}")
    if parts[0] != skill:
        fail(f"ZIP entry is outside the exact {skill!r} skill root: {name!r}")
    if len(parts) == 1 and not is_dir:
        fail(f"ZIP skill root must be a directory, not a file: {name!r}")
    return parts, is_dir


def validate_zip_structure(
    archive: zipfile.ZipFile,
    skill: str,
    limits: Limits,
) -> list[ValidatedEntry]:
    infos = archive.infolist()
    if not infos:
        fail("release archive is empty")
    if len(infos) > limits.max_entries:
        fail(f"release archive has {len(infos)} entries; limit is {limits.max_entries}")

    entries: list[ValidatedEntry] = []
    explicit_paths: dict[str, str] = {}
    namespace: dict[str, tuple[str, str]] = {}
    total_uncompressed = 0

    for info in infos:
        if info.flag_bits & 0x1:
            fail(f"ZIP contains an encrypted entry: {info.filename!r}")
        if info.compress_type not in _ALLOWED_COMPRESSION:
            fail(f"ZIP entry uses unsupported compression method {info.compress_type}: {info.filename!r}")

        parts, is_dir = _validated_entry_path(info, skill)
        raw_path = "/".join(parts)
        canonical = _canonical_path_key(parts)
        prior_explicit = explicit_paths.get(canonical)
        if prior_explicit is not None:
            fail(
                "ZIP contains duplicate, case-colliding, or Unicode-colliding entries: "
                f"{prior_explicit!r} and {raw_path!r}"
            )

        for length in range(1, len(parts)):
            prefix_parts = parts[:length]
            prefix = "/".join(prefix_parts)
            prefix_key = _canonical_path_key(prefix_parts)
            existing = namespace.get(prefix_key)
            if existing is None:
                namespace[prefix_key] = ("dir", prefix)
            elif existing[0] != "dir":
                fail(f"ZIP file/directory prefix collision: {existing[1]!r} blocks {raw_path!r}")
            elif existing[1] != prefix:
                fail(f"ZIP case or Unicode directory collision: {existing[1]!r} and {prefix!r}")

        desired_type = "dir" if is_dir else "file"
        existing = namespace.get(canonical)
        if existing is None:
            namespace[canonical] = (desired_type, raw_path)
        elif existing[0] != desired_type:
            fail(f"ZIP file/directory prefix collision at {raw_path!r}")
        elif existing[1] != raw_path:
            fail(f"ZIP case or Unicode path collision: {existing[1]!r} and {raw_path!r}")
        elif not is_dir:
            fail(f"ZIP contains duplicate file entry: {raw_path!r}")

        explicit_paths[canonical] = raw_path

        if is_dir:
            if info.file_size != 0 or info.compress_size != 0:
                fail(f"ZIP directory entry carries data: {info.filename!r}")
        else:
            if info.file_size > limits.max_file_size:
                fail(
                    f"ZIP entry {info.filename!r} expands to {info.file_size} bytes; "
                    f"per-file limit is {limits.max_file_size}"
                )
            total_uncompressed += info.file_size
            if total_uncompressed > limits.max_total_size:
                fail(
                    f"ZIP expands to more than the {limits.max_total_size}-byte total safety limit"
                )
            if info.file_size:
                if info.compress_size == 0:
                    fail(f"ZIP entry has data but zero compressed size: {info.filename!r}")
                ratio = info.file_size / info.compress_size
                if ratio > limits.max_compression_ratio:
                    fail(
                        f"ZIP entry {info.filename!r} compression ratio {ratio:.2f} exceeds "
                        f"limit {limits.max_compression_ratio:.2f}"
                    )

        archived_mode = info.external_attr >> 16
        extracted_mode = 0o700 if is_dir or archived_mode & 0o111 else 0o600
        entries.append(
            ValidatedEntry(
                info=info,
                parts=parts,
                is_dir=is_dir,
                extracted_mode=extracted_mode,
            )
        )

    required = {
        _canonical_path_key((skill, "SKILL.md")): f"{skill}/SKILL.md",
        _canonical_path_key((skill, "skill.json")): f"{skill}/skill.json",
    }
    for key, path in required.items():
        node = namespace.get(key)
        if node is None or node[0] != "file" or node[1] != path:
            fail(f"release archive is missing required regular file: {path}")
    return entries


def _safe_open_destination(path: Path) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        fail(f"could not create staged release file {path}: {exc}")
    return os.fdopen(descriptor, "wb")


def _ensure_private_directories(staging: Path, parts: tuple[str, ...]) -> Path:
    current = staging
    for component in parts:
        current /= component
        try:
            current.mkdir(mode=0o700, exist_ok=True)
            current.chmod(0o700)
        except OSError as exc:
            fail(f"could not create private staged release directory {current}: {exc}")
    return current


def extract_manually(
    archive: zipfile.ZipFile,
    entries: list[ValidatedEntry],
    staging: Path,
    limits: Limits,
) -> None:
    total_written = 0
    for entry in entries:
        target = staging.joinpath(*entry.parts)
        if entry.is_dir:
            _ensure_private_directories(staging, entry.parts)
            continue

        try:
            _ensure_private_directories(staging, entry.parts[:-1])
            source = archive.open(entry.info, "r")
        except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
            fail(f"could not open ZIP entry {entry.info.filename!r}: {exc}")

        written = 0
        try:
            with source, _safe_open_destination(target) as destination:
                while True:
                    block = source.read(COPY_CHUNK_SIZE)
                    if not block:
                        break
                    written += len(block)
                    total_written += len(block)
                    if written > entry.info.file_size or written > limits.max_file_size:
                        fail(f"ZIP entry expanded beyond its declared or permitted size: {entry.info.filename!r}")
                    if total_written > limits.max_total_size:
                        fail("ZIP expanded beyond the permitted total size during extraction")
                    destination.write(block)
                os.fchmod(destination.fileno(), entry.extracted_mode)
        except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
            fail(f"failed while extracting ZIP entry {entry.info.filename!r}: {exc}")
        if written != entry.info.file_size:
            fail(
                f"ZIP entry size changed during extraction for {entry.info.filename!r}: "
                f"expected {entry.info.file_size}, got {written}"
            )


def _frontmatter_scalar(markdown: str, key: str) -> str:
    lines = markdown.splitlines()
    if not lines or lines[0].strip() != "---":
        fail("SKILL.md must begin with YAML frontmatter")
    values: list[str] = []
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        candidate_key, candidate_value = line.split(":", 1)
        if candidate_key.strip() == key:
            values.append(candidate_value.strip())
    else:
        fail("SKILL.md frontmatter is not terminated")
    if len(values) != 1:
        fail(f"SKILL.md frontmatter must contain exactly one {key!r} field")
    value = values[0]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        if value[0] == '"':
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError:
                fail(f"SKILL.md frontmatter {key!r} has invalid quoting")
            if not isinstance(decoded, str):
                fail(f"SKILL.md frontmatter {key!r} must be a string")
            value = decoded
        else:
            value = value[1:-1].replace("''", "'")
    if not value:
        fail(f"SKILL.md frontmatter {key!r} must not be empty")
    return value


def validate_extracted_identity(staging: Path, skill: str, version: str) -> None:
    skill_root = staging / skill
    skill_json_path = skill_root / "skill.json"
    skill_md_path = skill_root / "SKILL.md"
    _require_regular_file(skill_json_path, "extracted skill.json", DEFAULT_MAX_FILE_SIZE)
    _require_regular_file(skill_md_path, "extracted SKILL.md", DEFAULT_MAX_FILE_SIZE)

    skill_json = load_json_bytes(
        _read_limited(skill_json_path, "extracted skill.json", DEFAULT_MAX_FILE_SIZE),
        "extracted skill.json",
    )
    if not isinstance(skill_json, dict):
        fail("extracted skill.json root must be an object")
    json_name = _require_string(skill_json, "name", "extracted skill.json")
    json_version = _require_string(skill_json, "version", "extracted skill.json")
    if json_name != skill or json_version != version:
        fail(
            "extracted skill.json identity mismatch: "
            f"expected {skill}@{version}, got {json_name}@{json_version}"
        )

    try:
        markdown = _read_limited(skill_md_path, "extracted SKILL.md", DEFAULT_MAX_FILE_SIZE).decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"extracted SKILL.md is not valid UTF-8: {exc}")
    md_name = _frontmatter_scalar(markdown, "name")
    md_version = _frontmatter_scalar(markdown, "version")
    if md_name != skill or md_version != version:
        fail(
            "extracted SKILL.md identity mismatch: "
            f"expected {skill}@{version}, got {md_name}@{md_version}"
        )


def _validate_limits(arguments: argparse.Namespace) -> Limits:
    integer_limits = {
        "--max-entries": arguments.max_entries,
        "--max-file-size": arguments.max_file_size,
        "--max-total-size": arguments.max_total_size,
    }
    for name, value in integer_limits.items():
        if value <= 0:
            fail(f"{name} must be greater than zero")
    ratio = arguments.max_compression_ratio
    if not math.isfinite(ratio) or ratio < 1.0:
        fail("--max-compression-ratio must be a finite number of at least 1")
    return Limits(
        max_entries=arguments.max_entries,
        max_file_size=arguments.max_file_size,
        max_total_size=arguments.max_total_size,
        max_compression_ratio=ratio,
    )


def verify_and_extract(arguments: argparse.Namespace) -> Path:
    limits = _validate_limits(arguments)
    expected_archive_name = validate_expected_identity(arguments.skill, arguments.version, arguments.tag)

    release_dir = Path(arguments.release_dir).absolute()
    try:
        release_stat = release_dir.lstat()
    except FileNotFoundError:
        fail(f"release directory does not exist: {release_dir}")
    if not stat.S_ISDIR(release_stat.st_mode):
        fail(f"release directory must be a real directory, not a symlink: {release_dir}")

    output_dir = Path(arguments.output_dir).absolute()
    if output_dir.exists() or output_dir.is_symlink():
        fail(f"output directory must not already exist: {output_dir}")
    output_parent = output_dir.parent
    try:
        parent_stat = output_parent.lstat()
    except FileNotFoundError:
        fail(f"output directory parent does not exist: {output_parent}")
    if not stat.S_ISDIR(parent_stat.st_mode):
        fail(f"output directory parent must be a real directory, not a symlink: {output_parent}")

    manifest_path = release_dir / "checksums.json"
    signature_path = release_dir / "checksums.sig"
    release_key = release_dir / "signing-public.pem"
    archive_path = release_dir / expected_archive_name
    _require_regular_file(archive_path, "release archive")

    openssl = arguments.openssl
    require_openssl_3(openssl)
    canonical_key = Path(arguments.canonical_key).absolute() if arguments.canonical_key else None
    verify_key_pin(openssl, release_key, arguments.spki_sha256, canonical_key)
    verify_manifest_signature(openssl, release_key, signature_path, manifest_path)
    _, archive_digest, archive_size = validate_manifest(
        manifest_path,
        arguments.skill,
        arguments.version,
        arguments.tag,
        expected_archive_name,
    )

    staging: Path | None = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.staging-", dir=output_parent))
        os.chmod(staging, 0o700)
        try:
            archive_handle = archive_path.open("rb")
        except OSError as exc:
            fail(f"could not open release archive {archive_path}: {exc}")
        with archive_handle:
            opened_stat = os.fstat(archive_handle.fileno())
            if not stat.S_ISREG(opened_stat.st_mode):
                fail("release archive changed into a non-regular file")
            verify_archive_digest(archive_handle, archive_digest, archive_size)
            try:
                with zipfile.ZipFile(archive_handle, "r") as archive:
                    entries = validate_zip_structure(archive, arguments.skill, limits)
                    extract_manually(archive, entries, staging, limits)
            except zipfile.BadZipFile as exc:
                fail(f"release archive is not a valid ZIP file: {exc}")

            final_stat = os.fstat(archive_handle.fileno())
            if (
                final_stat.st_dev != opened_stat.st_dev
                or final_stat.st_ino != opened_stat.st_ino
                or final_stat.st_size != opened_stat.st_size
                or final_stat.st_mtime_ns != opened_stat.st_mtime_ns
            ):
                fail("release archive changed while it was being verified or extracted")
            verify_archive_digest(archive_handle, archive_digest, archive_size)

        validate_extracted_identity(staging, arguments.skill, arguments.version)
        if output_dir.exists() or output_dir.is_symlink():
            fail(f"output directory appeared before final rename: {output_dir}")
        try:
            os.rename(staging, output_dir)
        except OSError as exc:
            fail(f"could not atomically publish verified output directory {output_dir}: {exc}")
        staging = None
        return output_dir / arguments.skill
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify and safely extract a signed ClawSec skill release bundle.",
    )
    parser.add_argument("--release-dir", required=True, help="Directory containing the four downloaded release assets")
    parser.add_argument("--output-dir", required=True, help="Absent directory to receive the verified archive contents")
    parser.add_argument("--skill", required=True, help="Expected skill package name")
    parser.add_argument("--version", required=True, help="Expected skill package version")
    parser.add_argument("--tag", required=True, help="Exact expected release tag")
    parser.add_argument(
        "--spki-sha256",
        help="Pinned SHA-256 fingerprint of the trusted Ed25519 public key's SPKI DER encoding",
    )
    parser.add_argument(
        "--canonical-key",
        help="Trusted canonical Ed25519 public key whose SPKI fingerprint pins the downloaded release key",
    )
    parser.add_argument(
        "--openssl",
        default=os.environ.get("OPENSSL_BIN", "openssl"),
        help="OpenSSL 3 executable (default: OPENSSL_BIN or openssl)",
    )
    parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    parser.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE)
    parser.add_argument("--max-total-size", type=int, default=DEFAULT_MAX_TOTAL_SIZE)
    parser.add_argument("--max-compression-ratio", type=float, default=DEFAULT_MAX_COMPRESSION_RATIO)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        extracted_skill = verify_and_extract(arguments)
    except VerificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: operating-system failure: {exc}", file=sys.stderr)
        return 1
    print(f"Verified and extracted {arguments.skill}@{arguments.version} to {extracted_skill}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
