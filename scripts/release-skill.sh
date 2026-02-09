#!/bin/bash
# Usage: ./scripts/release-skill.sh <skill-name> <version> [--force-tag]
# Example: ./scripts/release-skill.sh clawsec-feed 1.1.0
#
# This script ensures version consistency by:
# 1. Updating skill.json with the new version
# 2. Updating any hardcoded version URLs in skill.json and SKILL.md
# 3. Committing the changes
# 4. Creating the git tag (only on main/master branch)
#
# Branch-aware workflow:
#   Feature branch: Updates versions, commits, pushes → CI validates build
#   Main branch:    Updates versions, commits, creates tag → push triggers release
#
# Use --force-tag to create a tag even when not on main/master.

set -euo pipefail

# Parse arguments
FORCE_TAG=false
POSITIONAL_ARGS=()

for arg in "$@"; do
  case $arg in
    --force-tag)
      FORCE_TAG=true
      ;;
    *)
      POSITIONAL_ARGS+=("$arg")
      ;;
  esac
done

if [ "${#POSITIONAL_ARGS[@]}" -ne 2 ]; then
  echo "Usage: $0 <skill-name> <version> [--force-tag]"
  echo "Example: $0 clawsec-feed 1.1.0"
  exit 1
fi

SKILL_NAME="${POSITIONAL_ARGS[0]}"
VERSION="${POSITIONAL_ARGS[1]}"
SKILL_PATH="skills/$SKILL_NAME"

# Ensure we're on a branch (not detached HEAD) so release flow works from feature branches
CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
if [ -z "$CURRENT_BRANCH" ]; then
  echo "Error: Detached HEAD detected. Checkout a branch before running release." >&2
  exit 1
fi

# Determine if we're on a release branch (main/master)
IS_RELEASE_BRANCH=false
if [[ "$CURRENT_BRANCH" == "main" || "$CURRENT_BRANCH" == "master" ]]; then
  IS_RELEASE_BRANCH=true
fi

# Security: Validate skill name to prevent path injection
# Only allow lowercase alphanumeric characters and hyphens
if ! [[ "$SKILL_NAME" =~ ^[a-z0-9-]+$ ]]; then
  echo "Error: Invalid skill name. Only lowercase alphanumeric characters and hyphens are allowed."
  echo "Example: clawsec-feed, prompt-agent, clawtributor"
  exit 1
fi

if [ ! -f "$SKILL_PATH/skill.json" ]; then
  echo "Error: $SKILL_PATH/skill.json not found"
  exit 1
fi

# Validate semver format (supports prerelease like 1.0.0-beta1)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$ ]]; then
  echo "Error: Invalid version format. Use semver (e.g., 1.0.0, 1.1.0-beta1)"
  exit 1
fi

TAG="${SKILL_NAME}-v${VERSION}"

# Check for uncommitted changes in skill directory
if ! git diff --quiet "$SKILL_PATH/" 2>/dev/null; then
  echo "Error: $SKILL_PATH/ has uncommitted changes. Please commit or stash them first."
  exit 1
fi

echo "Releasing $SKILL_NAME version $VERSION"
echo "Branch: $CURRENT_BRANCH"
if [[ "$IS_RELEASE_BRANCH" == "true" || "$FORCE_TAG" == "true" ]]; then
  echo "Mode: Full release (will create tag)"
else
  echo "Mode: Prep only (tag deferred until merge to main)"
fi
echo "======================================="

# Create a temporary directory for atomic operations
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Track files that need to be staged
FILES_TO_STAGE=()

# Update version in skill.json
echo "Updating $SKILL_PATH/skill.json version to $VERSION..."
if ! jq --arg v "$VERSION" '.version = $v' "$SKILL_PATH/skill.json" > "$TEMP_DIR/skill.json"; then
  echo "Error: Failed to update version in skill.json"
  exit 1
fi
mv "$TEMP_DIR/skill.json" "$SKILL_PATH/skill.json"
FILES_TO_STAGE+=("$SKILL_PATH/skill.json")

# Update any hardcoded version URLs in skill.json (openclaw.feed_url pattern)
if jq -e '.openclaw.feed_url' "$SKILL_PATH/skill.json" >/dev/null 2>&1; then
  echo "Updating openclaw.feed_url to use tag $TAG..."
  if ! jq --arg tag "$TAG" '.openclaw.feed_url = (.openclaw.feed_url | gsub("/[^/]+-v[0-9.]+(-[a-zA-Z0-9]+)?/"; "/\($tag)/"))' "$SKILL_PATH/skill.json" > "$TEMP_DIR/skill.json"; then
    echo "Error: Failed to update feed_url in skill.json"
    exit 1
  fi
  mv "$TEMP_DIR/skill.json" "$SKILL_PATH/skill.json"
fi

# Update version in SKILL.md frontmatter and ALL hardcoded version URLs (if file exists)
if [ -f "$SKILL_PATH/SKILL.md" ]; then
  echo "Updating $SKILL_PATH/SKILL.md frontmatter version to $VERSION..."

  # Verify version line exists before sed
  if ! grep -qE "^version: " "$SKILL_PATH/SKILL.md"; then
    echo "Error: SKILL.md missing 'version:' line in frontmatter" >&2
    echo "  Expected format: 'version: X.Y.Z' at start of line" >&2
    exit 1
  fi

  # Apply sed and verify substitution occurred
  sed "s/^version: .*/version: $VERSION/" "$SKILL_PATH/SKILL.md" > "$TEMP_DIR/SKILL.md"

  if ! grep -qF "version: $VERSION" "$TEMP_DIR/SKILL.md"; then
    echo "Error: Failed to update version in SKILL.md frontmatter" >&2
    echo "  Target version: $VERSION" >&2
    exit 1
  fi

  echo "  ✓ Version updated to $VERSION"

  echo "Updating hardcoded version URLs in SKILL.md to use tag $TAG..."
  # Replace all hardcoded version URLs: download/SKILLNAME-vX.Y.Z(-prerelease)?/ -> download/TAG/
  # This handles patterns like: download/clawsec-feed-v1.0.0/ or download/prompt-agent-v1.0.0-beta1/
  PATTERN="/download/${SKILL_NAME}-v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?/"

  # Check if pattern exists (warn if not, don't fail - some skills may not self-reference)
  if grep -qE "$PATTERN" "$TEMP_DIR/SKILL.md"; then
    sed -E "s|$PATTERN|/download/${TAG}/|g" "$TEMP_DIR/SKILL.md" > "$TEMP_DIR/SKILL.md.tmp"

    # Verify substitution occurred
    if ! grep -qF "/download/${TAG}/" "$TEMP_DIR/SKILL.md.tmp"; then
      echo "Warning: URL pattern found but substitution may have failed" >&2
    else
      URL_COUNT=$(grep -cF "/download/${TAG}/" "$TEMP_DIR/SKILL.md.tmp")
      echo "  ✓ Updated $URL_COUNT hardcoded URL(s)"
    fi

    mv "$TEMP_DIR/SKILL.md.tmp" "$TEMP_DIR/SKILL.md"
  else
    echo "  ℹ No hardcoded version URLs found (OK if skill doesn't self-reference)"
  fi

  mv "$TEMP_DIR/SKILL.md" "$SKILL_PATH/SKILL.md"
  FILES_TO_STAGE+=("$SKILL_PATH/SKILL.md")
fi

# Update hardcoded version URLs in other markdown files (heartbeat.md, reporting.md, etc.)
for md_file in "$SKILL_PATH"/*.md; do
  if [ -f "$md_file" ] && [ "$md_file" != "$SKILL_PATH/SKILL.md" ]; then
    filename=$(basename "$md_file")
    echo "Updating hardcoded version URLs in $filename..."

    PATTERN="/download/${SKILL_NAME}-v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?/"

    # Check if pattern exists
    if grep -qE "$PATTERN" "$md_file"; then
      sed -E "s|$PATTERN|/download/${TAG}/|g" "$md_file" > "$TEMP_DIR/$filename"

      # Verify substitution occurred
      if ! grep -qF "/download/${TAG}/" "$TEMP_DIR/$filename"; then
        echo "  Warning: URL pattern found but substitution may have failed in $filename" >&2
      else
        URL_COUNT=$(grep -cF "/download/${TAG}/" "$TEMP_DIR/$filename")
        echo "  ✓ Updated $URL_COUNT URL(s) in $filename"
      fi

      mv "$TEMP_DIR/$filename" "$md_file"
      FILES_TO_STAGE+=("$md_file")
    else
      echo "  ℹ No hardcoded version URLs found in $filename (skipping)"
    fi
  fi
done

# Show what changed
echo ""
echo "Changes to $SKILL_PATH/:"
git diff "$SKILL_PATH/" || true
echo ""

# Stage all changed files atomically
echo "Staging changes..."
for file in "${FILES_TO_STAGE[@]}"; do
  git add "$file"
done

# Verify staged changes before committing
MADE_COMMIT=false
if git diff --cached --quiet; then
  echo "Note: Version already at $VERSION — no changes to commit"
  COMMIT_SHA=$(git rev-parse HEAD)
else
  # Commit the version bump
  echo "Committing changes..."
  if ! git commit -m "chore($SKILL_NAME): bump version to $VERSION"; then
    echo "Error: Failed to commit changes"
    exit 1
  fi
  COMMIT_SHA=$(git rev-parse HEAD)
  MADE_COMMIT=true
fi

# Save commit SHA for recovery
echo "Committed: $COMMIT_SHA"

# Create tag only on release branches (or if forced)
if [[ "$IS_RELEASE_BRANCH" == "true" || "$FORCE_TAG" == "true" ]]; then
  # Check if tag already exists (only matters when we're creating one)
  if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Error: Tag $TAG already exists"
    if [[ "$MADE_COMMIT" == "true" ]]; then
      echo "Rolling back version-bump commit..."
      git reset --hard HEAD~1
    fi
    exit 1
  fi

  echo "Creating tag: $TAG"
  if ! git tag -a "$TAG" -m "$SKILL_NAME version $VERSION"; then
    echo "Error: Failed to create tag $TAG" >&2
    echo "" >&2
    echo "The commit has been created but NOT tagged:" >&2
    echo "  Commit: $COMMIT_SHA" >&2
    echo "" >&2
    echo "Recovery options:" >&2
    echo "  1. Fix the issue and tag manually:" >&2
    echo "     git tag -a '$TAG' -m '$SKILL_NAME version $VERSION' $COMMIT_SHA" >&2
    echo "" >&2
    echo "  2. Investigate why tagging failed:" >&2
    echo "     - Check if tag exists: git tag -l '$TAG'" >&2
    echo "     - Check permissions: ls -ld .git/refs/tags" >&2
    echo "" >&2
    echo "  3. To rollback the commit (if desired):" >&2
    echo "     git reset --hard HEAD~1" >&2
    echo "" >&2
    echo "The commit has NOT been pushed. Fix the issue before pushing." >&2
    exit 1
  fi

  echo ""
  echo "Done! To release, push the tag:"
  if [[ "$MADE_COMMIT" == "true" ]]; then
    echo "  git push origin $CURRENT_BRANCH"
  fi
  echo "  git push origin $TAG"
  echo ""
  echo "Or to undo:"
  if [[ "$MADE_COMMIT" == "true" ]]; then
    echo "  git reset --hard HEAD~1 && git tag -d $TAG"
  else
    echo "  git tag -d $TAG"
  fi
else
  # Feature branch: skip tagging, instruct user on next steps
  echo ""
  echo "Done! Version updated and committed (tag deferred)."
  echo ""
  echo "Next steps:"
  echo "  1. Push your branch for CI validation:"
  echo "     git push origin $CURRENT_BRANCH"
  echo ""
  echo "  2. After CI passes and PR is merged to main, create the tag:"
  echo "     git checkout main && git pull"
  echo "     git tag -a '$TAG' $COMMIT_SHA -m '$SKILL_NAME version $VERSION'"
  echo "     git push origin $TAG"
  echo ""
  echo "Or to undo the version bump:"
  echo "  git reset --hard HEAD~1"
fi
