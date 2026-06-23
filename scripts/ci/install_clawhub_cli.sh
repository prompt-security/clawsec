#!/usr/bin/env bash
set -euo pipefail

CLI_PREFIX="${CLAWHUB_CLI_PREFIX:-.github/clawhub-cli}"
NPM_REGISTRY="${CLAWHUB_NPM_REGISTRY:-https://registry.npmjs.org}"

npm ci --prefix "$CLI_PREFIX" --registry="$NPM_REGISTRY"

if [ -n "${GITHUB_PATH:-}" ]; then
  workspace="${GITHUB_WORKSPACE:-$(pwd)}"
  echo "${workspace}/${CLI_PREFIX}/node_modules/.bin" >> "$GITHUB_PATH"
fi
