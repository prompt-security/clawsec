#!/usr/bin/env bash
set -euo pipefail

CLI_PREFIX="${CLAWHUB_CLI_PREFIX:-.github/clawhub-cli}"

npm ci --prefix "$CLI_PREFIX"

if [ -n "${GITHUB_PATH:-}" ]; then
  workspace="${GITHUB_WORKSPACE:-$(pwd)}"
  echo "${workspace}/${CLI_PREFIX}/node_modules/.bin" >> "$GITHUB_PATH"
fi
