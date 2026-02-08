#!/usr/bin/env python3
"""
Skill Checksums Generator - Generates checksums.json for a skill

Usage:
    python utils/package_skill.py <path/to/skill-folder> [output-directory]

Example:
    python utils/package_skill.py skills/prompt-agent
    python utils/package_skill.py skills/prompt-agent ./dist
"""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from validate_skill import validate_skill


def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def package_skill(skill_path: str, output_dir: str = None) -> tuple[Path | None, Path | None]:
    """
    Generate checksums for a skill folder.

    Args:
        skill_path: Path to the skill folder
        output_dir: Optional output directory (defaults to current directory)

    Returns:
        Tuple of (None, checksums_file_path) or (None, None) on error
    """
    skill_path = Path(skill_path).resolve()

    # Validate skill first
    print("Validating skill...")
    valid, message = validate_skill(skill_path)
    if not valid:
        print(f"[ERROR] Validation failed:\n{message}")
        print("   Please fix validation errors before packaging.")
        return None, None
    print(f"[OK] {message}\n")

    # Load skill.json
    skill_json_path = skill_path / "skill.json"
    with open(skill_json_path) as f:
        skill_data = json.load(f)

    skill_name = skill_data["name"]
    version = skill_data["version"]

    # Determine output location
    if output_dir:
        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)
    else:
        output_path = Path.cwd()

    checksums_filename = output_path / "checksums.json"

    # Collect files from SBOM
    files_to_checksum = []
    sbom_files = skill_data.get("sbom", {}).get("files", [])

    for file_entry in sbom_files:
        file_rel_path = file_entry["path"]
        full_path = skill_path / file_rel_path
        if full_path.exists():
            files_to_checksum.append((file_rel_path, full_path))

    # Always include skill.json
    files_to_checksum.append(("skill.json", skill_json_path))

    # Include README.md if it exists
    readme_path = skill_path / "README.md"
    if readme_path.exists():
        files_to_checksum.append(("README.md", readme_path))

    # Generate checksums
    print("Generating checksums...")
    checksums_data = {
        "skill": skill_name,
        "version": version,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository": "prompt-security/ClawSec",
        "tag": f"{skill_name}-v{version}",
        "files": {},
    }

    for rel_path, full_path in files_to_checksum:
        filename = Path(rel_path).name
        sha256 = calculate_sha256(full_path)
        size = full_path.stat().st_size

        checksums_data["files"][filename] = {
            "sha256": sha256,
            "size": size,
            "path": rel_path,
            "url": f"https://clawsec.prompt.security/releases/download/{skill_name}-v{version}/{filename}",
        }
        print(f"  {filename}: {sha256[:16]}...")

    # Write checksums.json
    with open(checksums_filename, "w") as f:
        json.dump(checksums_data, f, indent=2)
    print(f"\n[OK] Checksums written to: {checksums_filename}")

    return None, checksums_filename


def main():
    if len(sys.argv) < 2:
        print("Usage: python utils/package_skill.py <path/to/skill-folder> [output-directory]")
        print("\nExample:")
        print("  python utils/package_skill.py skills/prompt-agent")
        print("  python utils/package_skill.py skills/prompt-agent ./dist")
        sys.exit(1)

    skill_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"Generating checksums for: {skill_path}")
    if output_dir:
        print(f"   Output directory: {output_dir}")
    print()

    _, checksums_file = package_skill(skill_path, output_dir)

    if checksums_file:
        print("\n" + "=" * 50)
        print("Checksums generation complete!")
        print(f"  Checksums: {checksums_file}")
        print("=" * 50)
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
