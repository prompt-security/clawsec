#!/usr/bin/env bash
set -euo pipefail

CLI_PREFIX="${CLAWHUB_CLI_PREFIX:-.github/clawhub-cli}"
CODEARTIFACT_DOMAIN="${CODEARTIFACT_DOMAIN:-prompt-security}"
CODEARTIFACT_DOMAIN_OWNER="${CODEARTIFACT_DOMAIN_OWNER:-443370709039}"
CODEARTIFACT_REPOSITORY="${CODEARTIFACT_REPOSITORY:-npm-proxy}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-north-1}}"

if ! command -v aws >/dev/null 2>&1; then
  echo "::error::aws CLI is required to authenticate npm against CodeArtifact"
  exit 1
fi

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "::error::AWS credentials are required before installing the CodeArtifact-pinned clawhub CLI"
  exit 1
fi

aws codeartifact login \
  --tool npm \
  --domain "$CODEARTIFACT_DOMAIN" \
  --domain-owner "$CODEARTIFACT_DOMAIN_OWNER" \
  --repository "$CODEARTIFACT_REPOSITORY" \
  --region "$AWS_REGION"

npm ci --prefix "$CLI_PREFIX"

if [ -n "${GITHUB_PATH:-}" ]; then
  workspace="${GITHUB_WORKSPACE:-$(pwd)}"
  echo "${workspace}/${CLI_PREFIX}/node_modules/.bin" >> "$GITHUB_PATH"
fi
