---
name: clawsec-scanner
version: 0.0.2
description: Automated vulnerability scanner for agent platforms. Performs dependency scanning (npm audit, pip-audit), multi-database CVE lookup (OSV, NVD, GitHub Advisory), SAST analysis (Semgrep, Bandit), and agent-specific DAST hook execution testing. Use when running security scans, checking for vulnerabilities, auditing dependencies, or finding security issues in agent platforms.
homepage: https://clawsec.prompt.security
clawdis:
  emoji: "🔍"
  requires:
    bins: [node, npm, python3, pip-audit, semgrep, bandit, jq, curl]
---

# ClawSec Scanner

Comprehensive security scanner for agent platforms that automates vulnerability detection across multiple dimensions:

- **Dependency Scanning**: Analyzes npm and Python dependencies using `npm audit` and `pip-audit` with structured JSON output parsing
- **CVE Database Integration**: Queries OSV (primary), NVD 2.0, and GitHub Advisory Database for vulnerability enrichment
- **SAST Analysis**: Static code analysis using Semgrep (JavaScript/TypeScript) and Bandit (Python) to detect hardcoded secrets, command injection, path traversal, and unsafe deserialization
- **DAST Framework**: Agent-specific dynamic analysis with real OpenClaw hook execution harness (malicious input, timeout, output bounds, event mutation safety)
- **Unified Reporting**: Consolidated vulnerability reports with severity classification and remediation guidance
- **Continuous Monitoring**: OpenClaw hook integration for automated periodic scanning

## Unified Reporting

All scan types emit a consistent `ScanReport` JSON schema:

```typescript
{
  scan_id: string;         // UUID
  timestamp: string;       // ISO 8601
  target: string;          // Scanned path
  vulnerabilities: Vulnerability[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  }
}
```

### OpenClaw Integration

Automated continuous monitoring via hook:

- Runs scanner on configurable interval (default: 86400s / 24 hours)
- Triggers on `agent:bootstrap` and `command:new` events
- Posts findings to `event.messages` array with severity summary
- Rate-limited by `CLAWSEC_SCANNER_INTERVAL` environment variable

## Installation

### Prerequisites

Verify required binaries are available:

```bash
# Core runtimes
node --version  # v20+
npm --version
python3 --version  # 3.10+

# Scanning tools
pip-audit --version  # Install: uv pip install pip-audit
semgrep --version    # Install: pip install semgrep OR brew install semgrep
bandit --version     # Install: uv pip install bandit

# Utilities
jq --version
curl --version
```

### Option A: Via clawhub (recommended)

```bash
npx clawhub@latest install clawsec-scanner
```

### Option B: Manual installation with verification

```bash
set -euo pipefail

VERSION="${SKILL_VERSION:?Set SKILL_VERSION (e.g. 0.1.0)}"
INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.openclaw/skills}"
DEST="$INSTALL_ROOT/clawsec-scanner"
BASE="https://github.com/prompt-security/clawsec/releases/download/clawsec-scanner-v${VERSION}"

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Pinned release-signing public key
# Fingerprint (SHA-256 of SPKI DER): 711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8
cat > "$TEMP_DIR/release-signing-public.pem" <<'PEM'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAS7nijfMcUoOBCj4yOXJX+GYGv2pFl2Yaha1P4v5Cm6A=
-----END PUBLIC KEY-----
PEM

ZIP_NAME="clawsec-scanner-v${VERSION}.zip"

# Download release archive + signed checksums
curl -fsSL "$BASE/$ZIP_NAME" -o "$TEMP_DIR/$ZIP_NAME"
curl -fsSL "$BASE/checksums.json" -o "$TEMP_DIR/checksums.json"
curl -fsSL "$BASE/checksums.sig" -o "$TEMP_DIR/checksums.sig"

# Verify checksums manifest signature
openssl base64 -d -A -in "$TEMP_DIR/checksums.sig" -out "$TEMP_DIR/checksums.sig.bin"
if ! openssl pkeyutl -verify \
  -pubin \
  -inkey "$TEMP_DIR/release-signing-public.pem" \
  -sigfile "$TEMP_DIR/checksums.sig.bin" \
  -rawin \
  -in "$TEMP_DIR/checksums.json" >/dev/null 2>&1; then
  echo "ERROR: checksums.json signature verification failed" >&2
  exit 1
fi

EXPECTED_SHA="$(jq -r '.archive.sha256 // empty' "$TEMP_DIR/checksums.json")"
if [ -z "$EXPECTED_SHA" ]; then
  echo "ERROR: checksums.json missing archive.sha256" >&2
  exit 1
fi

ACTUAL_SHA="$(shasum -a 256 "$TEMP_DIR/$ZIP_NAME" | awk '{print $1}')"
if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
  echo "ERROR: Archive checksum mismatch" >&2
  exit 1
fi

echo "Checksums verified. Installing..."

mkdir -p "$INSTALL_ROOT"
rm -rf "$DEST"
unzip -q "$TEMP_DIR/$ZIP_NAME" -d "$INSTALL_ROOT"

chmod 600 "$DEST/skill.json"
find "$DEST" -type f ! -name "skill.json" -exec chmod 644 {} \;

echo "Installed clawsec-scanner v${VERSION} to: $DEST"
echo "Next step: Run a scan or set up continuous monitoring"
```

## Usage

### On-Demand CLI Scanning

```bash
SCANNER_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-scanner"

# Scan all skills with JSON output
"$SCANNER_DIR/scripts/runner.sh" --target ./skills/ --output report.json --format json

# Scan specific directory with human-readable output
"$SCANNER_DIR/scripts/runner.sh" --target ./my-skill/ --format text

# Check available flags
"$SCANNER_DIR/scripts/runner.sh" --help
```

**CLI Flags:**
- `--target <path>`: Directory to scan (required)
- `--output <file>`: Write results to file (optional, defaults to stdout)
- `--format <json|text>`: Output format (default: json)
- `--check`: Verify all required binaries are installed

### OpenClaw Hook Setup (Continuous Monitoring)

Enable automated periodic scanning:

```bash
SCANNER_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-scanner"
node "$SCANNER_DIR/scripts/setup_scanner_hook.mjs"
```

This creates a hook that:
- Scans on `agent:bootstrap` and `command:new` events
- Respects `CLAWSEC_SCANNER_INTERVAL` rate limiting (default: 86400 seconds / 24 hours)
- Posts findings to conversation with severity summary
- Recommends remediation for high/critical vulnerabilities

Restart the OpenClaw gateway after enabling the hook, then run `/new` to trigger an immediate scan.

### Environment Variables

```bash
# Optional - NVD API key to avoid rate limiting (6-second delays without key)
export CLAWSEC_NVD_API_KEY="your-nvd-api-key"

# Optional - GitHub OAuth token for Advisory Database queries
export GITHUB_TOKEN="ghp_your_token_here"

# Optional - Scanner hook interval in seconds (default: 86400 / 24 hours)
export CLAWSEC_SCANNER_INTERVAL="86400"

# Optional - Allow unsigned advisory feed during development (from clawsec-suite)
export CLAWSEC_ALLOW_UNSIGNED_FEED="1"
```

## Architecture

### Modular Design

Each scan type is an independent module that can run standalone or as part of unified scan:

```
scripts/runner.sh              # Orchestration layer
├── scan_dependencies.mjs      # npm audit + pip-audit
├── query_cve_databases.mjs    # OSV/NVD/GitHub API queries
├── sast_analyzer.mjs          # Semgrep + Bandit static analysis
├── dast_runner.mjs            # Dynamic security testing orchestration
└── dast_hook_executor.mjs     # Isolated real hook execution harness

lib/
├── report.mjs                 # Result aggregation and formatting
├── utils.mjs                  # Subprocess exec, JSON parsing, error handling
└── types.ts                   # TypeScript schema definitions

hooks/clawsec-scanner-hook/
├── HOOK.md                    # OpenClaw hook metadata
└── handler.ts                 # Periodic scan trigger
```

### Fail-Open Philosophy

The scanner follows a fail-open philosophy: network failures, missing tools, or malformed JSON produce partial results with warnings rather than hard failures. Critical failures (target path missing, no scanning tools available, concurrent scan detected) exit immediately.

## Troubleshooting

- **"Missing package-lock.json"**: Run `npm install` in target directory to generate lockfile. Scanner continues with other scan types.
- **"NVD API rate limit exceeded"**: Set `CLAWSEC_NVD_API_KEY` environment variable. OSV API is used as primary source with no rate limits.
- **"pip-audit not found"**: Install via `uv pip install pip-audit` or `pip install pip-audit`.
- **"Semgrep binary missing"**: Install via `pip install semgrep` or `brew install semgrep`.
- **"TypeScript hook not executable in DAST harness"**: Install TypeScript (`npm install -D typescript`) or provide `handler.js`/`handler.mjs`.
- **"Concurrent scan detected"**: Wait for running scan or remove `/tmp/clawsec-scanner.lock`.

## Integration with ClawSec Suite

The scanner works standalone or as part of the ClawSec ecosystem:

- **clawsec-suite**: Meta-skill that can install and manage clawsec-scanner
- **clawsec-feed**: Advisory feed for malicious skill detection (complementary)
- **openclaw-audit-watchdog**: Cron-based audit automation (similar pattern)

Install the full ClawSec suite:

```bash
npx clawhub@latest install clawsec-suite
# Then use clawsec-suite to discover and install clawsec-scanner
```

## Security Considerations

### Scanner Security

- No hardcoded secrets in scanner code
- API keys read from environment variables only (never logged or committed)
- Subprocess arguments use arrays to prevent shell injection
- All external tool output parsed with try/catch error handling

### Vulnerability Prioritization

**Critical/High severity findings** should be addressed immediately:
- Known exploits in dependencies (CVSS 9.0+)
- Hardcoded API keys or credentials in code
- Command injection vulnerabilities
- Path traversal without validation

**Medium/Low severity findings** can be addressed in normal sprint cycles:
- Outdated dependencies without known exploits
- Missing security headers
- Weak cryptography usage

**Info findings** are advisory only:
- Deprecated API usage
- Code quality issues flagged by linters

## License

AGPL-3.0-or-later
