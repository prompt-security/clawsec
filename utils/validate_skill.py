#!/usr/bin/env python3
"""
Skill Validator - Validates a skill folder against the skill.json schema

Usage:
    python utils/validate_skill.py <path/to/skill-folder>

Example:
    python utils/validate_skill.py skills/prompt-agent
"""

import json
import sys
from pathlib import Path


def validate_skill(skill_path: str) -> tuple[bool, str]:
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

    errors = []
    warnings = []

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
        parts = version.split(".")
        if len(parts) < 2:
            errors.append(f"Invalid version format: {version} (expected semver)")

    # Note: trust field is deprecated - all published skills are verified through the review process

    # Validate SBOM section
    if "sbom" not in skill_data:
        errors.append("sbom section is required")
    else:
        sbom = skill_data["sbom"]
        if "files" not in sbom:
            errors.append("sbom.files is required")
        else:
            # Check each SBOM file exists
            for file_entry in sbom["files"]:
                if "path" not in file_entry:
                    errors.append("sbom.files entry missing 'path' field")
                    continue

                file_path = skill_path / file_entry["path"]
                if not file_path.exists():
                    if file_entry.get("required", True):
                        errors.append(f"Required SBOM file not found: {file_entry['path']}")
                    else:
                        warnings.append(f"Optional SBOM file not found: {file_entry['path']}")

    # Validate openclaw section
    if "openclaw" in skill_data:
        openclaw = skill_data["openclaw"]
        if "emoji" not in openclaw:
            warnings.append("openclaw.emoji is recommended")
        if "category" not in openclaw:
            warnings.append("openclaw.category is recommended")
        if "triggers" not in openclaw or len(openclaw.get("triggers", [])) == 0:
            warnings.append("openclaw.triggers is recommended for discoverability")

    # Check for README.md
    readme_path = skill_path / "README.md"
    if not readme_path.exists():
        warnings.append("README.md is recommended for website display")

    # Build result message
    if errors:
        message = "Validation FAILED:\n"
        message += "\n".join(f"  ERROR: {e}" for e in errors)
        if warnings:
            message += "\n\nWarnings:\n"
            message += "\n".join(f"  WARNING: {w}" for w in warnings)
        return False, message

    if warnings:
        message = f"Validation PASSED with {len(warnings)} warning(s):\n"
        message += "\n".join(f"  WARNING: {w}" for w in warnings)
        return True, message

    return True, "Validation PASSED - all checks passed"


def main():
    if len(sys.argv) < 2:
        print("Usage: python utils/validate_skill.py <path/to/skill-folder>")
        print("\nExample:")
        print("  python utils/validate_skill.py skills/prompt-agent")
        sys.exit(1)

    skill_path = sys.argv[1]
    print(f"Validating skill: {skill_path}")
    print()

    valid, message = validate_skill(skill_path)

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
