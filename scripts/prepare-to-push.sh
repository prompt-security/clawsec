#!/usr/bin/env bash
#
# prepare-to-push.sh - Run all checks before pushing to ensure CI will pass
#
# Usage: ./scripts/prepare-to-push.sh [--fix]
#
# Options:
#   --fix    Attempt to auto-fix issues where possible
#

set -euo pipefail

# Ensure Homebrew tools are in PATH (macOS)
if [[ -d "/opt/homebrew/bin" ]]; then
  export PATH="/opt/homebrew/bin:$PATH"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track failures
FAILURES=0

# Parse arguments
FIX_MODE=false
if [[ "${1:-}" == "--fix" ]]; then
  FIX_MODE=true
  echo -e "${BLUE}🔧 Running in fix mode - will attempt to auto-fix issues${NC}\n"
fi

# Helper functions
print_header() {
  echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}▶ $1${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_pass() {
  echo -e "${GREEN}✓ $1${NC}"
}

check_fail() {
  echo -e "${RED}✗ $1${NC}"
  FAILURES=$((FAILURES + 1))
}

check_warn() {
  echo -e "${YELLOW}⚠ $1${NC}"
}

check_skip() {
  echo -e "${YELLOW}⊘ $1 (skipped - tool not installed)${NC}"
}

# Change to repo root
cd "$(dirname "$0")/.."
REPO_ROOT=$(pwd)
echo -e "${BLUE}📁 Repository: ${REPO_ROOT}${NC}"

# ============================================================================
# TypeScript / React Checks
# ============================================================================

print_header "TypeScript / React"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
  echo "Installing npm dependencies..."
  npm ci
fi

# ESLint
echo -e "\n${YELLOW}Running ESLint...${NC}"
if $FIX_MODE; then
  if npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --fix; then
    check_pass "ESLint (with auto-fix)"
  else
    check_fail "ESLint found unfixable issues"
  fi
else
  if npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0; then
    check_pass "ESLint"
  else
    check_fail "ESLint found issues (run with --fix to auto-fix)"
  fi
fi

# TypeScript
echo -e "\n${YELLOW}Running TypeScript type check...${NC}"
if npx tsc --noEmit; then
  check_pass "TypeScript type check"
else
  check_fail "TypeScript type errors found"
fi

# Build
echo -e "\n${YELLOW}Running build...${NC}"
if npm run build; then
  check_pass "Vite build"
else
  check_fail "Build failed"
fi

# ============================================================================
# Python Checks
# ============================================================================

print_header "Python"

# Check for Python files
if [ -d "utils" ] && ls utils/*.py 1> /dev/null 2>&1; then
  
  # Ruff
  if command -v ruff &> /dev/null; then
    echo -e "\n${YELLOW}Running Ruff...${NC}"
    if $FIX_MODE; then
      if ruff check utils/ --fix; then
        check_pass "Ruff (with auto-fix)"
      else
        check_fail "Ruff found unfixable issues"
      fi
    else
      if ruff check utils/; then
        check_pass "Ruff"
      else
        check_fail "Ruff found issues (run with --fix to auto-fix)"
      fi
    fi
  else
    check_skip "Ruff"
    echo "  Install with: pip install ruff"
  fi

  # Bandit
  if command -v bandit &> /dev/null; then
    echo -e "\n${YELLOW}Running Bandit security scan...${NC}"
    if bandit -r utils/ -ll; then
      check_pass "Bandit security scan"
    else
      check_fail "Bandit found security issues"
    fi
  else
    check_skip "Bandit"
    echo "  Install with: pip install bandit"
  fi

else
  check_warn "No Python files found in utils/"
fi

# ============================================================================
# Shell Script Checks
# ============================================================================

print_header "Shell Scripts"

if command -v shellcheck &> /dev/null; then
  echo -e "\n${YELLOW}Running ShellCheck...${NC}"
  SHELL_ERRORS=0
  for script in scripts/*.sh; do
    if [ -f "$script" ]; then
      if shellcheck -S warning "$script"; then
        echo -e "  ${GREEN}✓${NC} $script"
      else
        echo -e "  ${RED}✗${NC} $script"
        SHELL_ERRORS=$((SHELL_ERRORS + 1))
      fi
    fi
  done
  if [ $SHELL_ERRORS -eq 0 ]; then
    check_pass "ShellCheck"
  else
    check_fail "ShellCheck found issues in $SHELL_ERRORS file(s)"
  fi
else
  check_skip "ShellCheck"
  echo "  Install with: brew install shellcheck"
fi

# ============================================================================
# Security Scans
# ============================================================================

print_header "Security"

# Trivy FS Scan
if command -v trivy &> /dev/null; then
  echo -e "\n${YELLOW}Running Trivy filesystem scan...${NC}"
  if trivy fs . --severity CRITICAL,HIGH --exit-code 1 --ignore-unfixed; then
    check_pass "Trivy filesystem scan"
  else
    check_fail "Trivy found CRITICAL/HIGH vulnerabilities"
  fi

  echo -e "\n${YELLOW}Running Trivy config scan...${NC}"
  # Suppress info/warnings about missing config files (expected for non-IaC projects)
  if trivy config . --severity CRITICAL,HIGH --exit-code 1 --quiet 2>&1 | grep -v "Supported files for scanner(s) not found"; then
    check_pass "Trivy config scan"
  else
    check_fail "Trivy found CRITICAL/HIGH config issues"
  fi
else
  check_skip "Trivy"
  echo "  Install with: brew install trivy"
fi

# Gitleaks (scans git history to match CI)
if command -v gitleaks &> /dev/null; then
  echo -e "\n${YELLOW}Running Gitleaks secrets scan...${NC}"
  if gitleaks detect --source . --verbose; then
    check_pass "Gitleaks secrets scan"
  else
    check_fail "Gitleaks found potential secrets"
  fi
else
  check_skip "Gitleaks"
  echo "  Install with: brew install gitleaks"
fi

# npm audit (use public registry since private registries like CodeArtifact don't support audit)
echo -e "\n${YELLOW}Running npm audit...${NC}"
if npm audit --audit-level=high --registry=https://registry.npmjs.org; then
  check_pass "npm audit"
else
  check_warn "npm audit found vulnerabilities (run 'npm audit fix')"
fi

# ============================================================================
# Summary
# ============================================================================

print_header "Summary"

if [ $FAILURES -eq 0 ]; then
  echo -e "\n${GREEN}🎉 All checks passed! Ready to push.${NC}\n"
  exit 0
else
  echo -e "\n${RED}❌ $FAILURES check(s) failed. Please fix before pushing.${NC}"
  echo -e "${YELLOW}💡 Tip: Run with --fix to auto-fix some issues${NC}\n"
  exit 1
fi
