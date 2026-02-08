#!/usr/bin/env bash
# validate-release-links.sh
# Validates that all links referenced in SKILL.md files and READMEs will be
# available after release based on the skill-release.yml workflow logic.
#
# Usage: ./scripts/validate-release-links.sh [skill-name]
#   If skill-name is provided, only validates that skill
#   Otherwise validates all skills

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SKILLS_DIR="$PROJECT_ROOT/skills"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ERRORS=0
# shellcheck disable=SC2034  # WARNINGS reserved for future use
WARNINGS=0

# Get repo info from git remote
REPO=$(git -C "$PROJECT_ROOT" remote get-url origin 2>/dev/null | sed -E 's|.*github.com[:/]||' | sed 's/.git$//' || echo "prompt-security/ClawSec")
echo -e "${BLUE}Repository: $REPO${NC}"
echo ""

# Function to get files that will be in a release
get_release_assets() {
  local skill_path="$1"
  local skill_name="$2"
  local assets=()
  
  # Files from SBOM
  if [ -f "$skill_path/skill.json" ]; then
    while IFS= read -r file; do
      assets+=("$(basename "$file")")
    done < <(jq -r '.sbom.files[].path // empty' "$skill_path/skill.json" 2>/dev/null)
  fi
  
  # Always included
  assets+=("skill.json")
  assets+=("checksums.json")

  # README if exists
  if [ -f "$skill_path/README.md" ]; then
    assets+=("README.md")
  fi
  
  printf '%s\n' "${assets[@]}" | sort -u
}

# Function to extract expected files from documentation
extract_referenced_files() {
  local file="$1"
  local skill_name="$2"
  
  # Extract filenames from download URLs matching this skill
  grep -oE "releases/(latest/)?download/[^/]+/[^\"'\`\s)]+" "$file" 2>/dev/null | \
    grep -E "/${skill_name}-v|/latest/" | \
    sed -E 's|.*/||' | \
    sort -u || true
}

# Function to extract all referenced files from any download URL
extract_all_referenced_files() {
  local file="$1"
  
  # Extract all filenames from download URLs
  grep -oE "releases/(latest/)?download/[^/]+/[a-zA-Z0-9_.-]+" "$file" 2>/dev/null | \
    sed -E 's|.*/||' | \
    sort -u || true
}

validate_skill() {
  local skill_name="$1"
  local skill_path="$SKILLS_DIR/$skill_name"
  local skill_errors=0
  
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}Validating: ${skill_name}${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  
  # Check skill.json exists
  if [ ! -f "$skill_path/skill.json" ]; then
    echo -e "${RED}  ✗ Missing skill.json${NC}"
    ((ERRORS++))
    return 1
  fi
  
  # Get version from skill.json
  VERSION=$(jq -r '.version // "unknown"' "$skill_path/skill.json")
  echo -e "  Version: $VERSION"
  echo -e "  Tag will be: ${skill_name}-v${VERSION}"
  echo ""
  
  # Get assets that will be created by workflow
  echo -e "${YELLOW}  Assets that will be created:${NC}"
  RELEASE_ASSETS=()
  while IFS= read -r asset; do
    RELEASE_ASSETS+=("$asset")
    echo -e "    ✓ $asset"
  done < <(get_release_assets "$skill_path" "$skill_name")
  echo ""
  
  # Verify SBOM files exist locally
  echo -e "${YELLOW}  Verifying SBOM files exist:${NC}"
  while IFS= read -r file; do
    if [ -f "$skill_path/$file" ]; then
      echo -e "    ${GREEN}✓${NC} $file"
    else
      echo -e "    ${RED}✗ MISSING: $file${NC}"
      ((skill_errors++))
      ((ERRORS++))
    fi
  done < <(jq -r '.sbom.files[].path // empty' "$skill_path/skill.json" 2>/dev/null)
  echo ""
  
  # Check links in SKILL.md
  if [ -f "$skill_path/SKILL.md" ]; then
    echo -e "${YELLOW}  Checking SKILL.md references:${NC}"
    
    # Find files referenced for THIS skill specifically
    while IFS= read -r referenced_file; do
      [ -z "$referenced_file" ] && continue
      
      # Check if this file will be in the release
      found=false
      for asset in "${RELEASE_ASSETS[@]}"; do
        if [ "$asset" = "$referenced_file" ]; then
          found=true
          break
        fi
      done
      
      if [ "$found" = true ]; then
        echo -e "    ${GREEN}✓${NC} $referenced_file (will be available)"
      else
        # Check if it's a reference to another skill's release
        if grep -qE "/${skill_name}-v[0-9]" "$skill_path/SKILL.md" 2>/dev/null || \
           grep -q "/latest/download/$referenced_file" "$skill_path/SKILL.md" 2>/dev/null; then
          echo -e "    ${RED}✗${NC} $referenced_file (NOT in SBOM - won't be released)"
          ((skill_errors++))
          ((ERRORS++))
        fi
      fi
    done < <(extract_all_referenced_files "$skill_path/SKILL.md")
    
  fi
  echo ""
  
  # Check links in README.md
  if [ -f "$skill_path/README.md" ]; then
    echo -e "${YELLOW}  Checking README.md references:${NC}"
    
    while IFS= read -r referenced_file; do
      [ -z "$referenced_file" ] && continue
      
      found=false
      for asset in "${RELEASE_ASSETS[@]}"; do
        if [ "$asset" = "$referenced_file" ]; then
          found=true
          break
        fi
      done
      
      if [ "$found" = true ]; then
        echo -e "    ${GREEN}✓${NC} $referenced_file"
      else
        # Only error if it's referencing THIS skill's release
        if grep -qE "/${skill_name}-v|/latest/download/${referenced_file}" "$skill_path/README.md" 2>/dev/null; then
          echo -e "    ${RED}✗${NC} $referenced_file (NOT in release assets)"
          ((skill_errors++))
          ((ERRORS++))
        fi
      fi
    done < <(extract_all_referenced_files "$skill_path/README.md")
  fi
  echo ""
  
  # Cross-reference check: look for this skill being referenced by OTHER skills
  echo -e "${YELLOW}  Cross-references from other skills:${NC}"
  cross_refs_found=false
  for other_skill_dir in "$SKILLS_DIR"/*/; do
    other_skill=$(basename "$other_skill_dir")
    [ "$other_skill" = "$skill_name" ] && continue
    
    for doc in "$other_skill_dir"/*.md; do
      [ -f "$doc" ] || continue
      
      if grep -qE "/${skill_name}-v" "$doc" 2>/dev/null; then
        echo -e "    → Referenced by ${other_skill}/$(basename "$doc")"
        cross_refs_found=true
      fi
    done
  done
  
  if [ "$cross_refs_found" = false ]; then
    echo -e "    (none found)"
  fi
  echo ""
  
  # Summary for this skill
  if [ $skill_errors -eq 0 ]; then
    echo -e "${GREEN}  ✓ All checks passed for ${skill_name}${NC}"
  else
    echo -e "${RED}  ✗ ${skill_errors} issue(s) found for ${skill_name}${NC}"
  fi
  echo ""
  
  return $skill_errors
}

# Main logic
if [ $# -gt 0 ]; then
  # Validate specific skill
  if [ -d "$SKILLS_DIR/$1" ]; then
    validate_skill "$1"
  else
    echo -e "${RED}Error: Skill '$1' not found in $SKILLS_DIR${NC}"
    exit 1
  fi
else
  # Validate all skills
  echo -e "${BLUE}Scanning all skills in $SKILLS_DIR${NC}"
  echo ""
  
  for skill_dir in "$SKILLS_DIR"/*/; do
    skill_name=$(basename "$skill_dir")
    
    # Skip if no skill.json
    [ -f "$skill_dir/skill.json" ] || continue
    
    validate_skill "$skill_name" || true
  done
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}SUMMARY${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ $ERRORS -eq 0 ]; then
  echo -e "${GREEN}✓ All validations passed!${NC}"
  echo ""
  echo "Release URLs will follow this pattern:"
  echo "  https://github.com/$REPO/releases/download/{skill-name}-v{version}/{file}"
  echo ""
  echo "For 'latest' symlinks:"
  echo "  https://github.com/$REPO/releases/latest/download/{file}"
  echo "  (Note: 'latest' points to the most recent release of ANY skill)"
  exit 0
else
  echo -e "${RED}✗ Found $ERRORS error(s)${NC}"
  echo ""
  echo "Please fix the issues above before tagging a release."
  exit 1
fi
