# Contributing to ClawSec Skills

Thank you for your interest in contributing security skills to the ClawSec ecosystem! This guide will walk you through creating, testing, and submitting new skills.

## Table of Contents

- [Getting Started](#getting-started)
- [Skill Structure](#skill-structure)
- [Creating a New Skill](#creating-a-new-skill)
- [skill.json Reference](#skilljson-reference)
- [Testing Your Skill](#testing-your-skill)
- [Submission Process](#submission-process)
- [Version Bump and Release Flow](#version-bump-and-release-flow)
- [Review Criteria](#review-criteria)
- [After Acceptance](#after-acceptance)
- [Submitting Security Advisories](#submitting-security-advisories)

---

## Getting Started

### 1. Fork the Repository

1. Navigate to the [ClawSec repository](https://github.com/prompt-security/clawsec)
2. Click the "Fork" button in the top-right corner
3. Clone your fork locally:

```bash
git clone https://github.com/YOUR-USERNAME/clawsec.git
cd clawsec
```

### 2. Set Up Your Environment

```bash
# Add upstream remote to sync with main repo
git remote add upstream https://github.com/prompt-security/clawsec.git

# Install dependencies (if any)
npm install

# Create a new branch for your skill
git checkout -b skill/my-new-skill
```

---

## Trust & Verification Model

All skills distributed through ClawSec undergo security review and are hashed for agent verification. Trust is implicit:

- **Backend Verification**: Every skill is validated against checksums, SBOM manifests, and security policies
- **Transparent Security**: SHA256 checksums, and advisory feeds operate automatically
- **Contribution Flow**: Submit skills via PR → maintainer review → approval → release


---

## Skill Structure

Each skill lives in its own directory under `skills/`. Here's the standard structure:

```
skills/
  └── my-skill-name/
      ├── skill.json          # Required: Metadata and SBOM
      ├── SKILL.md            # Required: Main skill documentation
      ├── README.md           # Optional: Additional documentation
      └── scripts/
          ├── # Any supporting scripts your skill needs
```

### Example: Minimal Skill

```
skills/
  └── my-security-scanner/
      ├── skill.json
      └── SKILL.md
```

### Example: Complex Skill

```
skills/
  └── advanced-analyzer/
      ├── skill.json
      ├── SKILL.md
      ├── README.md
      ├── templates/
      │   └── report-template.md
      ├── scripts/
      │   └── action.py
      └── config/
          └── rules.json
```

---

## Creating a New Skill

### Step 1: Create Skill Directory

```bash
mkdir -p skills/my-skill-name
cd skills/my-skill-name
```

### Step 2: Create skill.json

Create `skill.json` with the following structure:

```json
{
  "name": "my-skill-name",
  "version": "0.0.1",
  "description": "Brief description of what your skill does",
  "author": "your-github-username",
  "license": "MIT",
  "homepage": "https://github.com/prompt-security/clawsec",
  "keywords": ["security", "relevant", "tags"],

  "sbom": {
    "files": [
      {
        "path": "SKILL.md",
        "required": true,
        "description": "Main skill documentation"
      }
    ]
  },

  "openclaw": {
    "emoji": "🔒",
    "category": "security",
    "requires": {
      "bins": ["curl", "jq"]
    },
    "triggers": [
      "keyword that activates skill",
      "another trigger phrase",
      "security check"
    ]
  }
}
```

**Important Notes:**
- Start with version `0.0.1` in both `skill.json` and `SKILL.md` frontmatter
- List ALL files your skill needs in the SBOM

### Step 3: Create SKILL.md

This is the main documentation for your skill. Include YAML frontmatter with a `version` that matches `skill.json`:

````markdown
```markdown
---
name: my-skill-name
version: 0.0.1
description: Brief description of what your skill does
metadata: {"openclaw":{"emoji":"🔒","category":"security"}}
---

# My Skill Name

## Overview

Brief description of what this skill does and why it's useful for AI agent security.

## Usage

How to use the skill.

## Features

- Feature 1: Description
- Feature 2: Description
- Feature 3: Description

## Requirements

- Required tools: curl, jq, etc.
- Any system dependencies
- Prerequisites

## Security Considerations

Important security notes about this skill.
```
````

### Step 4: Add Supporting Files

Add any additional files your skill needs (configs, templates, scripts), and **ensure they're listed in skill.json's SBOM**.

---

## skill.json Reference

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Skill identifier (lowercase, hyphens only) |
| `version` | string | Semantic version (0.0.1) |
| `description` | string | Brief description (max 200 chars) |
| `author` | string | Your GitHub username or organization |
| `license` | string | License type (prefer MIT) |
| `homepage` | string | Repository URL |
| `keywords` | array | Searchable tags |
| `sbom` | object | Software Bill of Materials |

### Verification

All skills published through ClawSec are reviewed by Prompt Security staff or designated maintainers before release:

- All published skills undergo security review
- Checksums and SBOM validation ensure integrity
- There is no distinction between "verified" and "community" skills - every skill in the catalog has passed review

### SBOM Structure

The SBOM (Software Bill of Materials) lists all files that are part of your skill:

```json
{
  "sbom": {
    "files": [
      {
        "path": "SKILL.md",
        "required": true,
        "description": "Main skill file"
      },
      {
        "path": "config/rules.json",
        "required": false,
        "description": "Optional configuration rules"
      }
    ]
  }
}
```

**Critical:** Every file your skill uses MUST be listed in the SBOM. This enables:
- Automated checksum generation
- Integrity verification
- Secure distribution

### OpenClaw Integration

The `openclaw` section defines how the skill integrates with Claude Code:

```json
{
  "openclaw": {
    "emoji": "🔒",
    "category": "security",
    "requires": {
      "bins": ["curl", "jq", "git"]
    },
    "triggers": [
      "keyword to activate skill",
      "another trigger phrase"
    ]
  }
}
```

**Categories:** `security`, `monitoring`, `analysis`, `reporting`, `utility`

---

## Testing Your Skill

### 1. Validate JSON Structure

```bash
# Validate skill.json is valid JSON
cat skills/my-skill-name/skill.json | jq .
```

### 2. Verify SBOM Completeness

```bash
# Check all SBOM files exist
cd skills/my-skill-name
for file in $(jq -r '.sbom.files[].path' skill.json); do
  [ -f "$file" ] && echo "✓ $file" || echo "✗ $file MISSING"
done
```

### 3. Test Locally (if applicable)

If your skill includes executable scripts or requires testing:

```bash
# Follow the testing instructions in your SKILL.md
```

### 4. Check for Common Issues

- [ ] All SBOM files exist
- [ ] skill.json is valid JSON
- [ ] Version is `0.0.1` for new skills
- [ ] `skill.json` version matches `SKILL.md` frontmatter version
- [ ] No hardcoded credentials or secrets
- [ ] Trigger phrases are descriptive
- [ ] Required binaries are documented

---

## Submission Process

### 1. Commit Your Changes

```bash
# From the repository root
git add skills/my-skill-name/
git commit -m "feat(skills): add my-skill-name security skill"
```

**Commit Message Format:**
```
feat(skills): add <skill-name> <brief description>

- Key feature 1
- Key feature 2
- Security benefit
```

### 2. Push to Your Fork

```bash
git push origin skill/my-new-skill
```

### 3. Create a Pull Request

1. Go to your fork on GitHub
2. Click "Pull Request"
3. Select your branch (`skill/my-new-skill`)
4. Fill out the PR template:

```markdown
## Skill Contribution: [Skill Name]

### Description
Brief overview of what this skill does.

### Security Benefits
How this skill improves AI agent security.

### Testing Performed
- [ ] JSON validation passed
- [ ] SBOM files verified
- [ ] Local testing completed
- [ ] No secrets or credentials included

### Checklist
- [ ] skill.json is complete
- [ ] SKILL.md documentation is clear
- [ ] All SBOM files are present
- [ ] Version is 0.0.1 (if new skill)

### Additional Notes
Any special considerations for reviewers.
```

---

## Version Bump and Release Flow

This repository uses a branch-first workflow for skill versions:

1. Make skill changes on a branch (`skill/<name>-...`).
2. Keep versions in sync:
   - `skills/<skill>/skill.json` -> `.version`
   - `skills/<skill>/SKILL.md` -> frontmatter `version`
3. For existing skills, you can bump versions on your branch with:

```bash
./scripts/release-skill.sh <skill-name> <new-version>
```

4. Push your branch and open a PR. CI will run:
   - Version parity checks
   - A `release` dry-run (build/validation only, no publish)
5. Do **not** push release tags from PR branches.
   - `scripts/release-skill.sh` creates a local tag. Keep it local during PR review.
   - If you need to remove that local tag: `git tag -d <skill-name>-v<version>`
6. After merge, a maintainer creates and pushes the release tag from `main`:

```bash
git checkout main
git pull --ff-only origin main
git tag -a <skill-name>-v<version> -m "<skill-name> version <version>"
git push origin <skill-name>-v<version>
```

7. Pushing the tag triggers the full release workflow (GitHub release + ClawHub publish).

---

## Review Criteria

Maintainers will review your skill based on:

### Security
- [ ] No malicious code or backdoors
- [ ] No hardcoded credentials
- [ ] Safe command execution (no command injection)
- [ ] Proper input validation
- [ ] No unnecessary privileges required

### Quality
- [ ] Clear documentation
- [ ] Well-structured code
- [ ] Follows naming conventions
- [ ] Complete SBOM
- [ ] Descriptive trigger phrases

### Value
- [ ] Provides clear security benefit
- [ ] Not duplicate of existing skill
- [ ] Useful for AI agent protection
- [ ] Aligns with ClawSec mission

### Technical
- [ ] Valid JSON structure
- [ ] All SBOM files present
- [ ] Correct versioning
- [ ] Proper metadata

---

## After Acceptance

Once your skill is accepted:

1. **Maintainers will:**
   - Review your PR (Prompt Security staff or designated maintainers)
   - Merge your PR after security review
   - Create and push a release tag from merged `main` (`<skill>-v<version>`)
   - Generate checksums and publish to GitHub Releases + ClawHub
   - Update the skills catalog website

2. **You'll be credited:**
   - Listed as the skill author
   - Mentioned in release notes
   - Added to contributors list

3. **Future updates:**
   - Submit PRs with version bumps for improvements
   - Maintainers will handle releases
   - Follow semantic versioning:
     - `1.0.1` - Patch (bug fixes)
     - `1.1.0` - Minor (new features)
     - `2.0.0` - Major (breaking changes)

---

## Questions?

- **Issues:** [GitHub Issues](https://github.com/prompt-security/clawsec/issues)
- **Discussions:** [GitHub Discussions](https://github.com/prompt-security/clawsec/discussions)
- **Security:** For security-sensitive contributions, email security@prompt.security

---

## Example Contribution

Here's a complete example of a minimal skill contribution:

```bash
# Fork and clone
git clone https://github.com/YOUR-USERNAME/clawsec.git
cd clawsec

# Create branch
git checkout -b skill/simple-scanner

# Create skill
mkdir -p skills/simple-scanner
cat > skills/simple-scanner/skill.json << 'EOF'
{
  "name": "simple-scanner",
  "version": "0.0.1",
  "description": "Basic security scanner for AI agents",
  "author": "contributor-name",
  "license": "MIT",
  "homepage": "https://github.com/prompt-security/clawsec",
  "keywords": ["security", "scanner", "basic"],
  "sbom": {
    "files": [
      { "path": "SKILL.md", "required": true, "description": "Scanner documentation" }
    ]
  },
  "openclaw": {
    "emoji": "🔍",
    "category": "security",
    "requires": { "bins": ["curl"] },
    "triggers": ["simple scan", "basic security check"]
  }
}
EOF

cat > skills/simple-scanner/SKILL.md << 'EOF'
---
name: simple-scanner
version: 0.0.1
description: Basic security scanner for AI agents
metadata: {"openclaw":{"emoji":"🔍","category":"security"}}
---

# Simple Scanner

A basic security scanner for AI agents.

## Usage
Run a simple security scan on your agent configuration.

## Features
- Quick security checks
- Minimal dependencies
- Easy to use
EOF

# Validate
cat skills/simple-scanner/skill.json | jq .

# Commit and push
git add skills/simple-scanner/
git commit -m "feat(skills): add simple-scanner security skill

- Provides basic security scanning
- Minimal dependencies
- Easy to use for beginners"
git push origin skill/simple-scanner
```

Then create a pull request on GitHub!

---

## Submitting Security Advisories

Found a prompt injection vector, malicious skill, or security vulnerability affecting AI agents? Help protect the community by submitting a security advisory.

### Advisory Types

| Type | Description | Example |
|------|-------------|---------|
| `prompt_injection` | Detected prompt injection or social engineering | Skill contains hidden instructions to exfiltrate data |
| `vulnerable_skill` | Skill with security vulnerabilities | Skill executes unsanitized user input |
| `tampering_attempt` | Attempt to disable/modify security controls | Instructions to remove ClawSec or ignore security checks |

### How to Submit

#### 1. Open a Security Incident Report

1. Go to [Issues → New Issue](https://github.com/prompt-security/clawsec/issues/new/choose)
2. Select **"Security Incident Report"** template
3. Fill out all required sections:

**Required Fields:**
- **Opener Type** - Are you a human or an AI agent reporting this?
- **Report Type** - What kind of issue is this?
- **Severity** - How severe is the threat?
- **Title** - Brief descriptive title
- **Description** - Detailed explanation of the vulnerability
- **Affected** - Which skill(s) and version(s) are affected
- **Recommended Action** - What should users do?

**Optional but Helpful:**
- Evidence (sanitized payloads, indicators)
- Reporter information (for follow-up questions)

#### 2. Privacy Checklist

Before submitting, ensure you have:
- [ ] Removed all real user data and PII
- [ ] Not included any API keys, credentials, or secrets
- [ ] Sanitized evidence to describe issues abstractly
- [ ] No proprietary or confidential information included

#### 3. Wait for Review

A maintainer will:
1. Review your report for validity and completeness
2. Assess the severity and impact
3. Add the `advisory-approved` label when ready to publish

#### 4. Automatic Publication

Once approved, the [community-advisory workflow](.github/workflows/community-advisory.yml) automatically:
1. Parses your issue content
2. Generates an advisory ID: `CLAW-{YEAR}-{ISSUE_NUMBER}` (e.g., `CLAW-2026-0042`)
3. Adds the advisory to `advisories/feed.json`
4. Comments on your issue confirming publication

### Advisory ID Format

| Source | Format | Example |
|--------|--------|---------|
| NVD CVE | `CVE-YYYY-NNNNN` | `CVE-2026-24763` |
| Community Report | `CLAW-YYYY-NNNN` | `CLAW-2026-0042` |

The `NNNN` in community advisories is your GitHub issue number, zero-padded to 4 digits.

### Example Security Report

```markdown
## Opener Type
- [x] Agent (automated report)

## Report Type
- [x] Vulnerable Skill - Found a skill with security issues

## Severity
- [x] High - Significant security risk, potential for harm

## Title
Data exfiltration via helper-plus skill network calls

## Description
The helper-plus skill was observed sending conversation data to an external
server (suspicious-domain.com) on every invocation. The skill makes
undocumented network calls that transmit full conversation context to a
domain not mentioned in the skill description.

## Affected

### Skill Name
helper-plus

### Skill Version
0.0.1, 1.0.0, 1.0.1

## Recommended Action
Remove helper-plus immediately. Do not use versions 0.0.1, 1.0.0 or 1.0.1.
Wait for a verified patched version.

## Reporter Information (Optional)
**Agent/User Name:** SecurityBot
```

### After Publication

Once your advisory is published:

1. **Agents receive it** - The feed is served from raw GitHub, so agents see it on their next feed check
2. **You're credited** - Your issue is linked in the advisory
3. **Community is protected** - Agents using ClawSec Feed will be alerted

### Questions?

- **General questions:** [GitHub Discussions](https://github.com/prompt-security/clawsec/discussions)
- **Sensitive reports:** Email security@prompt.security for issues too sensitive for public disclosure

---

Thank you for contributing to ClawSec security! 🛡️
