---
name: claw-release
version: 0.0.1
description: Release automation for Claw skills and website. Guides through version bumping, tagging, and release verification.
homepage: https://clawsec.prompt.security
metadata: {"openclaw":{"emoji":"🚀","category":"utility","internal":true}}
clawdis:
  emoji: "🚀"
  requires:
    bins: [git, jq, gh]
---

# Claw Release

Internal tool for releasing skills and managing the ClawSec catalog.

**An internal tool by [Prompt Security](https://prompt.security)**

---

## Quick Reference

| Release Type | Command | Tag Format |
|-------------|---------|------------|
| Skill release | `./scripts/release-skill.sh <name> <version>` | `<name>-v<version>` |
| Pre-release | `./scripts/release-skill.sh <name> 1.0.0-beta1` | `<name>-v1.0.0-beta1` |

---

## Release Workflow

### Step 1: Determine Version Type

Ask what changed:
- **Bug fixes only** → Patch (1.0.0 → 1.0.1)
- **New features, backward compatible** → Minor (1.0.0 → 1.1.0)
- **Breaking changes** → Major (1.0.0 → 2.0.0)
- **Testing/unstable** → Pre-release (1.0.0-beta1, 1.0.0-rc1)

### Step 2: Pre-flight Checks

```bash
# Check for uncommitted changes
git status

# Verify skill directory exists
ls skills/<skill-name>/skill.json

# Get current version
jq -r '.version' skills/<skill-name>/skill.json
```

### Step 3: Run Release Script

```bash
./scripts/release-skill.sh <skill-name> <new-version>
```

The script will:
1. Validate version format (semver)
2. Check tag doesn't already exist
3. Update skill.json version
4. Update SKILL.md frontmatter version (if file exists)
5. Update hardcoded version URLs (feed_url)
6. Commit changes
7. Create annotated git tag

### Step 4: Push Release

```bash
git push && git push origin <skill-name>-v<version>
```

### Step 5: Verify Release

After pushing, the CI/CD pipeline will:
1. Validate skill exists
2. Verify version matches skill.json
3. Verify version matches SKILL.md frontmatter (if exists)
4. Generate checksums from SBOM
5. Create .skill package (ZIP)
6. Create GitHub Release
7. Trigger website rebuild (for non-internal skills)

Verify at:
- **GitHub Releases:** `https://github.com/prompt-security/clawsec/releases/tag/<skill-name>-v<version>`
- **GitHub Actions:** Check workflow run status

---

## Undo a Release (Before Push)

If you need to undo before pushing:

```bash
git reset --hard HEAD~1 && git tag -d <skill-name>-v<version>
```

---

## Pre-release Versions

For beta, alpha, or release candidates:

```bash
./scripts/release-skill.sh <skill-name> 1.2.0-beta1
./scripts/release-skill.sh <skill-name> 1.2.0-alpha1
./scripts/release-skill.sh <skill-name> 1.2.0-rc1
```

Pre-releases are automatically marked in GitHub Releases.

---

## Common Issues

| Error | Solution |
|-------|----------|
| `Tag already exists` | Choose a different version number |
| `Version mismatch in CI` | Ensure you used the release script (not manual tagging) |
| `SKILL.md version mismatch` | Ensure you used the release script which updates both skill.json and SKILL.md |
| `Uncommitted changes` | Commit or stash first: `git stash` or `git add . && git commit` |
| `skill.json not found` | Verify skill directory path is correct |

---

## Internal Skills

Skills with `"internal": true` in their `openclaw` section:
- Are released normally via GitHub Releases
- Are NOT shown in the public skills catalog website
- Can still be downloaded directly from release URLs

This skill (`claw-release`) is an internal skill.

---

## Existing Skills

| Skill | Category | Internal |
|-------|----------|----------|
| clawsec-feed | security | No |
| clawtributor | security | No |
| openclaw-audit-watchdog | security | No |
| soul-guardian | security | No |
| claw-release | utility | Yes |

---

## Verification Checklist

After release, confirm:
- [ ] GitHub Release exists with correct tag
- [ ] Release has: skill.json, SKILL.md, checksums.json, .skill package
- [ ] Release is marked as pre-release if applicable
- [ ] GitHub Actions workflow completed successfully
- [ ] Website updated (for non-internal skills only)

---

## License

MIT License - See repository for details.

Built by the [Prompt Security](https://prompt.security) team.
