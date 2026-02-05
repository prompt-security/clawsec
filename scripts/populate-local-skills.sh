#!/bin/bash
# populate-local-skills.sh
# Builds local skills index from skills/ directory for development preview.
# This mirrors the skill-release.yml pipeline exactly - generates real checksums and .skill packages.
#
# Usage: ./scripts/populate-local-skills.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PUBLIC_SKILLS_DIR="$PROJECT_ROOT/public/skills"
DIST_DIR="$PROJECT_ROOT/dist/skills"

echo "=== ClawSec Local Skills Populator ==="
echo "Project root: $PROJECT_ROOT"
echo ""

# Create directories
mkdir -p "$PUBLIC_SKILLS_DIR"
mkdir -p "$DIST_DIR"

# Start building skills index
echo '{"version":"1.0.0","updated":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","skills":[' > "$PUBLIC_SKILLS_DIR/index.json"

FIRST_SKILL=true
SKILL_COUNT=0

echo "=== Discovering Skills ==="

# Process each skill directory
for SKILL_DIR in "$PROJECT_ROOT/skills"/*/; do
  SKILL_NAME=$(basename "$SKILL_DIR")
  SKILL_JSON="$SKILL_DIR/skill.json"
  
  # Skip if no skill.json
  if [ ! -f "$SKILL_JSON" ]; then
    echo "⚠️  Skipping $SKILL_NAME (no skill.json)"
    continue
  fi
  
  echo "Processing: $SKILL_NAME"
  
  # Check if internal skill
  IS_INTERNAL=$(jq -r '.openclaw.internal // false' "$SKILL_JSON")
  if [ "$IS_INTERNAL" = "true" ]; then
    echo "  ⚠️  Skipping internal skill: $SKILL_NAME"
    continue
  fi
  
  VERSION=$(jq -r '.version' "$SKILL_JSON")
  TAG="${SKILL_NAME}-v${VERSION}"
  
  # Create skill directory in public
  mkdir -p "$PUBLIC_SKILLS_DIR/$SKILL_NAME"
  
  # Copy skill.json
  cp "$SKILL_JSON" "$PUBLIC_SKILLS_DIR/$SKILL_NAME/skill.json"
  echo "  ✓ Copied: skill.json"
  
  # Copy README.md if exists
  if [ -f "$SKILL_DIR/README.md" ]; then
    cp "$SKILL_DIR/README.md" "$PUBLIC_SKILLS_DIR/$SKILL_NAME/README.md"
    echo "  ✓ Copied: README.md"
  fi

  # Copy SBOM markdown docs (SKILL.md, HEARTBEAT.md, etc.) for website display
  TEMPFILE=$(mktemp)
  jq -r '.sbom.files[].path' "$SKILL_JSON" > "$TEMPFILE" 2>/dev/null || true

  while IFS= read -r file; do
    [ -z "$file" ] && continue

    case "$file" in
      *.md|*.MD)
        FULL_PATH="$SKILL_DIR/$file"
        if [ -f "$FULL_PATH" ]; then
          cp "$FULL_PATH" "$PUBLIC_SKILLS_DIR/$SKILL_NAME/$(basename "$file")"
          echo "  ✓ Copied: $(basename "$file")"
        fi
        ;;
    esac
  done < "$TEMPFILE"
  rm -f "$TEMPFILE"
  
  # === Generate real checksums from SBOM (mirrors skill-release.yml) ===
  CHECKSUMS_FILE="$PUBLIC_SKILLS_DIR/$SKILL_NAME/checksums.json"
  
  cat > "$CHECKSUMS_FILE" << EOF
{
  "skill": "$SKILL_NAME",
  "version": "$VERSION",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "repository": "prompt-security/ClawSec",
  "tag": "$TAG",
  "files": {
EOF
  
  FIRST_FILE=true
  TEMPFILE=$(mktemp)
  
  # Get files from SBOM
  jq -r '.sbom.files[].path' "$SKILL_JSON" > "$TEMPFILE" 2>/dev/null || echo ""
  
  while IFS= read -r file; do
    [ -z "$file" ] && continue
    FULL_PATH="$SKILL_DIR/$file"
    if [ -f "$FULL_PATH" ]; then
      # macOS uses shasum, Linux uses sha256sum
      if command -v sha256sum &> /dev/null; then
        SHA256=$(sha256sum "$FULL_PATH" | awk '{print $1}')
      else
        SHA256=$(shasum -a 256 "$FULL_PATH" | awk '{print $1}')
      fi
      
      # macOS vs Linux stat
      SIZE=$(stat -f%z "$FULL_PATH" 2>/dev/null || stat -c%s "$FULL_PATH")
      FILENAME=$(basename "$file")
      
      if [ "$FIRST_FILE" = true ]; then
        FIRST_FILE=false
      else
        echo "," >> "$CHECKSUMS_FILE"
      fi
      
      cat >> "$CHECKSUMS_FILE" << FILEENTRY
    "$FILENAME": {
      "sha256": "$SHA256",
      "size": $SIZE,
      "path": "$file",
      "url": "https://clawsec.prompt.security/releases/download/$TAG/$FILENAME"
    }
FILEENTRY
      echo "  ✓ Checksum: $FILENAME ($SHA256)"
    else
      echo "  ⚠️  File not found: $file"
    fi
  done < "$TEMPFILE"
  rm -f "$TEMPFILE"
  
  # Add skill.json checksum
  if command -v sha256sum &> /dev/null; then
    SKILL_JSON_SHA=$(sha256sum "$SKILL_JSON" | awk '{print $1}')
  else
    SKILL_JSON_SHA=$(shasum -a 256 "$SKILL_JSON" | awk '{print $1}')
  fi
  SKILL_JSON_SIZE=$(stat -f%z "$SKILL_JSON" 2>/dev/null || stat -c%s "$SKILL_JSON")
  
  if [ "$FIRST_FILE" = false ]; then
    echo "," >> "$CHECKSUMS_FILE"
  fi
  
  cat >> "$CHECKSUMS_FILE" << SKILLJSON
    "skill.json": {
      "sha256": "$SKILL_JSON_SHA",
      "size": $SKILL_JSON_SIZE,
      "url": "https://clawsec.prompt.security/releases/download/$TAG/skill.json"
    }
SKILLJSON
  
  # === Create .skill package BEFORE closing checksums JSON ===
  SKILL_PACKAGE="$PUBLIC_SKILLS_DIR/$SKILL_NAME/${SKILL_NAME}.skill"
  
  # Get files from SBOM and create zip
  pushd "$SKILL_DIR" > /dev/null
  
  FILES=$(jq -r '.sbom.files[].path' skill.json 2>/dev/null | tr '\n' ' ')
  
  if [ -n "$FILES" ]; then
    # Create zip with SBOM files + skill.json
    zip -r "$SKILL_PACKAGE" $FILES skill.json 2>/dev/null || true
    
    # Add README if exists
    if [ -f README.md ]; then
      zip -u "$SKILL_PACKAGE" README.md 2>/dev/null || true
    fi
    
    if [ -f "$SKILL_PACKAGE" ]; then
      PACKAGE_SIZE=$(stat -f%z "$SKILL_PACKAGE" 2>/dev/null || stat -c%s "$SKILL_PACKAGE")
      echo "  ✓ Created: ${SKILL_NAME}.skill ($(( PACKAGE_SIZE / 1024 ))KB)"
      
      # Add .skill package checksum
      if command -v sha256sum &> /dev/null; then
        SKILL_PACKAGE_SHA=$(sha256sum "$SKILL_PACKAGE" | awk '{print $1}')
      else
        SKILL_PACKAGE_SHA=$(shasum -a 256 "$SKILL_PACKAGE" | awk '{print $1}')
      fi
      
      echo "," >> "$CHECKSUMS_FILE"
      cat >> "$CHECKSUMS_FILE" << SKILLPACKAGE
    "${SKILL_NAME}.skill": {
      "sha256": "$SKILL_PACKAGE_SHA",
      "size": $PACKAGE_SIZE,
      "url": "https://clawsec.prompt.security/releases/download/$TAG/${SKILL_NAME}.skill"
    }
SKILLPACKAGE
      echo "  ✓ Checksum: ${SKILL_NAME}.skill ($SKILL_PACKAGE_SHA)"
    fi
  else
    echo "  ⚠️  No SBOM files, skipping .skill package"
  fi
  
  popd > /dev/null

  # Close checksums JSON
  cat >> "$CHECKSUMS_FILE" << EOF
  }
}
EOF
  
  echo "  ✓ Generated: checksums.json"
  
  # Build skill entry for index
  SKILL_DATA=$(jq -c --arg tag "$TAG" '{
    id: .name,
    name: .name,
    version: .version,
    description: .description,
    emoji: .openclaw.emoji,
    category: .openclaw.category,
    tag: $tag
  }' "$SKILL_JSON")
  
  # Append to index
  if [ "$FIRST_SKILL" = "true" ]; then
    FIRST_SKILL=false
  else
    echo "," >> "$PUBLIC_SKILLS_DIR/index.json"
  fi
  echo "$SKILL_DATA" >> "$PUBLIC_SKILLS_DIR/index.json"
  
  SKILL_COUNT=$((SKILL_COUNT + 1))
  echo "  ✓ Added to index"
  echo ""
done

# Close the JSON array
echo ']}' >> "$PUBLIC_SKILLS_DIR/index.json"

echo "=== Skills Index ==="
jq '.' "$PUBLIC_SKILLS_DIR/index.json"

echo ""
echo "=== Summary ==="
echo "Total skills indexed: $SKILL_COUNT"
echo "Skills directory: $PUBLIC_SKILLS_DIR"
echo ""
ls -la "$PUBLIC_SKILLS_DIR"/*/
echo ""
echo "Run 'npm run dev' to preview the skills catalog."
