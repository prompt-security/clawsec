#!/bin/bash
# Usage: ./scripts/release-skill.sh <skill-name> <final-version>
# Example: ./scripts/release-skill.sh clawsec-suite 0.2.0
#
# This is a preparation helper. It updates and commits a final version on a
# review branch. It never creates or pushes a tag and never creates a GitHub
# Release. After the reviewed change reaches protected main, use the
# "Create Skill Release Tag" workflow with that exact main commit.

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <skill-name> <final-version>" >&2
  echo "Example: $0 clawsec-suite 0.2.0" >&2
  exit 1
fi

SKILL_NAME="$1"
VERSION="$2"
SKILL_PATH="skills/$SKILL_NAME"
TAG="${SKILL_NAME}-v${VERSION}"

if ! [[ "$SKILL_NAME" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
  echo "Error: skill name must use lowercase alphanumeric kebab-case." >&2
  exit 1
fi

for required_command in git jq node; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "Error: $required_command is required." >&2
    exit 1
  fi
done

CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
if [ -z "$CURRENT_BRANCH" ]; then
  echo "Error: detached HEAD detected. Checkout a review branch first." >&2
  exit 1
fi
if [ "$CURRENT_BRANCH" = "main" ] || [ "$CURRENT_BRANCH" = "master" ]; then
  echo "Error: version preparation must run on a review branch, not protected $CURRENT_BRANCH." >&2
  exit 1
fi

if [ ! -f "$SKILL_PATH/skill.json" ]; then
  echo "Error: $SKILL_PATH/skill.json not found." >&2
  exit 1
fi
if [ ! -f "$SKILL_PATH/SKILL.md" ]; then
  echo "Error: $SKILL_PATH/SKILL.md not found." >&2
  exit 1
fi

# The shared stable policy runs before any source or Git mutation. Beta and RC
# candidates belong to the private lab flow and never enter this helper.
if ! node scripts/ci/stable_tag_policy.mjs --tag "$TAG" >/dev/null; then
  echo "Error: public release preparation requires a strict final SemVer." >&2
  echo "Build beta and RC candidates through the private lab-candidate flow." >&2
  exit 1
fi

INSTALLABLE="$(node scripts/ci/skill_installability.mjs "$SKILL_PATH")"

# Prevent a scoped release commit from silently capturing unrelated staged,
# tracked, or untracked content.
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
  echo "Error: repository must be globally clean before version preparation." >&2
  exit 1
fi

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
FILES_TO_STAGE=()

echo "Preparing $SKILL_NAME version $VERSION on review branch $CURRENT_BRANCH"

if ! jq --arg version "$VERSION" '.version = $version' \
  "$SKILL_PATH/skill.json" > "$TEMP_DIR/skill.json"; then
  echo "Error: failed to update $SKILL_PATH/skill.json." >&2
  exit 1
fi
mv "$TEMP_DIR/skill.json" "$SKILL_PATH/skill.json"
FILES_TO_STAGE+=("$SKILL_PATH/skill.json")

if jq -e '.openclaw.feed_url' "$SKILL_PATH/skill.json" >/dev/null 2>&1; then
  if ! jq --arg tag "$TAG" \
    '.openclaw.feed_url = (.openclaw.feed_url | gsub("/[^/]+-v[0-9.]+(-[a-zA-Z0-9.]+)?/"; "/\($tag)/"))' \
    "$SKILL_PATH/skill.json" > "$TEMP_DIR/skill.json"; then
    echo "Error: failed to update openclaw.feed_url." >&2
    exit 1
  fi
  mv "$TEMP_DIR/skill.json" "$SKILL_PATH/skill.json"
fi

if ! grep -qE '^version: ' "$SKILL_PATH/SKILL.md"; then
  echo "Error: SKILL.md is missing a frontmatter version." >&2
  exit 1
fi
sed "s/^version: .*/version: $VERSION/" \
  "$SKILL_PATH/SKILL.md" > "$TEMP_DIR/SKILL.md"
if ! grep -qF "version: $VERSION" "$TEMP_DIR/SKILL.md"; then
  echo "Error: failed to update SKILL.md frontmatter version." >&2
  exit 1
fi

VERSION_ASSIGNMENT_PATTERN='^VERSION="[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?"$'
if grep -qE "$VERSION_ASSIGNMENT_PATTERN" "$TEMP_DIR/SKILL.md"; then
  sed -E "s|$VERSION_ASSIGNMENT_PATTERN|VERSION=\"$VERSION\"|g" \
    "$TEMP_DIR/SKILL.md" > "$TEMP_DIR/SKILL.md.next"
  mv "$TEMP_DIR/SKILL.md.next" "$TEMP_DIR/SKILL.md"
fi

DOWNLOAD_PATTERN="/download/${SKILL_NAME}-v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?/"
if grep -qE "$DOWNLOAD_PATTERN" "$TEMP_DIR/SKILL.md"; then
  sed -E "s|$DOWNLOAD_PATTERN|/download/${TAG}/|g" \
    "$TEMP_DIR/SKILL.md" > "$TEMP_DIR/SKILL.md.next"
  mv "$TEMP_DIR/SKILL.md.next" "$TEMP_DIR/SKILL.md"
fi
mv "$TEMP_DIR/SKILL.md" "$SKILL_PATH/SKILL.md"
FILES_TO_STAGE+=("$SKILL_PATH/SKILL.md")

for markdown_file in "$SKILL_PATH"/*.md; do
  if [ ! -f "$markdown_file" ] || [ "$markdown_file" = "$SKILL_PATH/SKILL.md" ]; then
    continue
  fi
  if ! grep -qE "$DOWNLOAD_PATTERN" "$markdown_file"; then
    continue
  fi
  filename="$(basename "$markdown_file")"
  sed -E "s|$DOWNLOAD_PATTERN|/download/${TAG}/|g" \
    "$markdown_file" > "$TEMP_DIR/$filename"
  mv "$TEMP_DIR/$filename" "$markdown_file"
  FILES_TO_STAGE+=("$markdown_file")
done

for file in "${FILES_TO_STAGE[@]}"; do
  git add "$file"
done

if git diff --cached --quiet; then
  echo "No version-preparation changes were needed; $SKILL_NAME is already at $VERSION."
else
  git commit -m "chore($SKILL_NAME): bump version to $VERSION"
fi

COMMIT_SHA="$(git rev-parse HEAD)"
echo "Prepared commit: $COMMIT_SHA"

if [ "$INSTALLABLE" = "false" ]; then
  echo "This package is non-installable. Push the review branch for signed denial evidence."
  echo "Do not request a public tag, GitHub Release, store publication, or catalog activation."
  exit 0
fi

echo "Next steps:"
echo "  1. Push $CURRENT_BRANCH and complete its review and CI."
echo "  2. Merge through the protected-main process."
echo "  3. Run 'Create Skill Release Tag' with package $SKILL_NAME, version $VERSION,"
echo "     and the exact resulting protected-main commit."
