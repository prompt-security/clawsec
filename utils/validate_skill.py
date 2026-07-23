#!/usr/bin/env python3
"""
Skill Validator - Validates a skill folder against the skill.json schema

Usage:
    python utils/validate_skill.py <path/to/skill-folder> [--require-clawsec]

Example:
    python utils/validate_skill.py skills/prompt-agent
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

_CANONICAL_CLAWSEC_NAME_RE = re.compile(
    r"^clawsec-(?:core|suite|drift-guardian)-(?:openclaw|hermes|nanoclaw|picoclaw)$"
)


def _validate_clawsec_metadata(
    skill_path: Path,
    skill_data: dict,
    require_clawsec: bool,
) -> tuple[list[str], list[str], list[str]]:
    """Run the single normalized ClawSec metadata validator when applicable."""
    name = skill_data.get("name")
    has_clawsec = "clawsec" in skill_data
    canonical_name = isinstance(name, str) and _CANONICAL_CLAWSEC_NAME_RE.fullmatch(name)

    if not has_clawsec and not require_clawsec and not canonical_name:
        return (
            [],
            ["LEGACY_INPUT: no normalized clawsec metadata; usable only as migration material"],
            [],
        )

    repository_root = Path(__file__).resolve().parent.parent
    validator_path = repository_root / "scripts" / "ci" / "validate_clawsec_metadata.mjs"
    command = [
        "node",
        str(validator_path),
        "--skill-dir",
        str(skill_path),
        "--json",
    ]
    if require_clawsec:
        command.append("--require-clawsec")

    try:
        completed = subprocess.run(
            command,
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return (
            [f"METADATA_VALIDATOR_UNAVAILABLE /: {exc}"],
            [],
            [],
        )

    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no validator output"
        return (
            [f"METADATA_VALIDATOR_ERROR /: {detail}"],
            [],
            [],
        )

    errors = [
        f"{entry['code']} {entry['path']}: {entry['message']}"
        for entry in result.get("errors", [])
    ]
    warnings = [
        f"{entry['code']} {entry['path']}: {entry['message']}"
        for entry in result.get("warnings", [])
    ]
    notices = []
    if result.get("valid") and result.get("classification") == "canonical":
        notices.append("CONTRACT_VALID: normalized ClawSec metadata v1")
    elif result.get("valid") and result.get("classification") == "legacy":
        notices.append("LEGACY_INPUT: structurally valid legacy package")

    if completed.returncode == 0 and errors:
        errors.append("METADATA_VALIDATOR_ERROR /: validator returned success with errors")
    if completed.returncode != 0 and not errors:
        errors.append("METADATA_VALIDATOR_ERROR /: validator failed without a diagnostic")

    return errors, warnings, notices


def validate_skill(skill_path: str, require_clawsec: bool = False) -> tuple[bool, str]:
    """
    Validate a skill folder.

    Args:
        skill_path: Path to the skill folder

    Returns:
        Tuple of (is_valid, message)
    """
    skill_path = Path(skill_path).resolve()

    # Check skill folder exists
    if not skill_path.exists():
        return False, f"Skill folder not found: {skill_path}"

    if not skill_path.is_dir():
        return False, f"Path is not a directory: {skill_path}"

    # Check skill.json exists
    skill_json_path = skill_path / "skill.json"
    if not skill_json_path.exists():
        return False, "skill.json not found"

    # Parse skill.json
    try:
        with open(skill_json_path) as f:
            skill_data = json.load(f)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON in skill.json: {e}"

    if not isinstance(skill_data, dict):
        return False, "Invalid skill.json: top-level value must be a JSON object"

    errors = []
    warnings = []
    notices = []

    # Validate required fields
    required_fields = ["name", "version", "description", "author", "license"]
    for field in required_fields:
        if field not in skill_data:
            errors.append(f"Missing required field: {field}")

    # Validate name matches folder
    if "name" in skill_data:
        if skill_data["name"] != skill_path.name:
            warnings.append(
                f"skill.json name '{skill_data['name']}' doesn't match folder name '{skill_path.name}'"
            )

    # Validate version format (basic semver check)
    if "version" in skill_data:
        version = skill_data["version"]
        if not isinstance(version, str):
            errors.append(f"Invalid version format: {version} (expected semver)")
        else:
            parts = version.split(".")
            if len(parts) < 2:
                errors.append(f"Invalid version format: {version} (expected semver)")

    # Note: trust field is deprecated - all published skills are verified through the review process

    # Validate SBOM section
    if "sbom" not in skill_data:
        errors.append("sbom section is required")
    else:
        sbom = skill_data["sbom"]
        if not isinstance(sbom, dict):
            errors.append("sbom must be a JSON object")
        elif "files" not in sbom:
            errors.append("sbom.files is required")
        elif not isinstance(sbom["files"], list):
            errors.append("sbom.files must be a JSON array")
        else:
            # Check each SBOM file exists
            for file_entry in sbom["files"]:
                if not isinstance(file_entry, dict):
                    errors.append("sbom.files entry must be a JSON object")
                    continue
                if not isinstance(file_entry.get("path"), str) or not file_entry["path"]:
                    errors.append("sbom.files entry missing 'path' field")
                    continue

                file_path = skill_path / file_entry["path"]
                if not file_path.exists():
                    if file_entry.get("required", True):
                        errors.append(f"Required SBOM file not found: {file_entry['path']}")
                    else:
                        warnings.append(f"Optional SBOM file not found: {file_entry['path']}")

    metadata_errors, metadata_warnings, metadata_notices = _validate_clawsec_metadata(
        skill_path,
        skill_data,
        require_clawsec,
    )
    errors.extend(metadata_errors)
    warnings.extend(metadata_warnings)
    notices.extend(metadata_notices)

    # Validate openclaw section
    if "openclaw" in skill_data:
        openclaw = skill_data["openclaw"]
        if not isinstance(openclaw, dict):
            errors.append("openclaw must be a JSON object")
        else:
            if "emoji" not in openclaw:
                warnings.append("openclaw.emoji is recommended")
            if "category" not in openclaw:
                warnings.append("openclaw.category is recommended")
            triggers = openclaw.get("triggers")
            if not isinstance(triggers, list) or not triggers:
                warnings.append("openclaw.triggers is recommended for discoverability")

    # Check for README.md
    readme_path = skill_path / "README.md"
    if not readme_path.exists():
        warnings.append("README.md is recommended for website display")

    # Build result message
    if errors:
        message = "Validation FAILED:\n"
        message += "\n".join(f"  ERROR: {e}" for e in errors)
        if notices:
            message += "\n\nNotices:\n"
            message += "\n".join(f"  {notice}" for notice in notices)
        if warnings:
            message += "\n\nWarnings:\n"
            message += "\n".join(f"  WARNING: {w}" for w in warnings)
        return False, message

    if warnings:
        message = f"Validation PASSED with {len(warnings)} warning(s):\n"
        if notices:
            message += "\n".join(f"  {notice}" for notice in notices)
            message += "\n"
        message += "\n".join(f"  WARNING: {w}" for w in warnings)
        return True, message

    if notices:
        message = "Validation PASSED:\n"
        message += "\n".join(f"  {notice}" for notice in notices)
        return True, message

    return True, "Validation PASSED - all checks passed"


def main():
    parser = argparse.ArgumentParser(description="Validate a ClawSec skill folder")
    parser.add_argument("skill_path", help="Path to the skill folder")
    parser.add_argument(
        "--require-clawsec",
        action="store_true",
        help="Require normalized ClawSec metadata v1",
    )
    args = parser.parse_args()

    skill_path = args.skill_path
    print(f"Validating skill: {skill_path}")
    print()

    valid, message = validate_skill(skill_path, require_clawsec=args.require_clawsec)

    print(message)
    print()

    if valid:
        print("[OK] Skill is valid")
        sys.exit(0)
    else:
        print("[FAIL] Skill validation failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
