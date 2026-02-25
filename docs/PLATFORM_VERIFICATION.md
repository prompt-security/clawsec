# Platform Verification Checklist

Use this checklist to validate portability and path-handling behavior after changes.

## Linux Verification

1. Run core Node tests:
   ```bash
   node skills/clawsec-suite/test/path_resolution.test.mjs
   node skills/clawsec-suite/test/guarded_install.test.mjs
   node skills/clawsec-suite/test/advisory_suppression.test.mjs
   node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
   ```
   Expected: all tests pass.

2. Verify no literal `$HOME` path acceptance:
   ```bash
   CLAWSEC_LOCAL_FEED='\$HOME/advisories/feed.json' \
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
   Expected: exits non-zero with `Unexpanded home token` error.

3. Verify `$HOME` expansion works:
   ```bash
   HOME=/tmp/clawsec-home node skills/clawsec-suite/test/path_resolution.test.mjs
   ```
   Expected: `$HOME` expansion tests pass.

## macOS Verification

1. Run the same Node test suite as Linux.
2. Confirm OpenSSL tooling path assumptions are documented:
   - If using LibreSSL/OpenSSL variations, ensure checks use tested command forms from docs.
3. Verify tilde expansion in config path:
   ```bash
   OPENCLAW_AUDIT_CONFIG=~/.openclaw/security-audit.json \
   node skills/openclaw-audit-watchdog/scripts/load_suppression_config.mjs --enable-suppressions
   ```
   Expected: path resolves correctly (or clear file-not-found error at expanded location).

## Windows Verification (PowerShell)

1. Run Node tests:
   ```powershell
   node skills/clawsec-suite/test/path_resolution.test.mjs
   node skills/clawsec-suite/test/guarded_install.test.mjs
   node skills/clawsec-suite/test/advisory_suppression.test.mjs
   ```
   Expected: all pass.

2. Verify PowerShell env path expansion behavior:
   ```powershell
   $env:CLAWSEC_LOCAL_FEED = '$env:USERPROFILE\advisories\feed.json'
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
   Expected: path token is expanded/normalized or fails with a clear error if target files are missing.

3. Verify escaped literal token rejection:
   ```powershell
   $env:CLAWSEC_LOCAL_FEED = '\$HOME\advisories\feed.json'
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
   Expected: `Unexpanded home token` error; no directory creation with literal `$HOME`.

## Line Endings Sanity

1. Confirm LF policy is present:
   ```bash
   test -f .gitattributes && grep -n "eol=lf" .gitattributes
   ```
   Expected: script/config file patterns enforce LF.

2. After a CRLF-prone checkout, verify scripts still parse:
   ```bash
   bash -n scripts/populate-local-feed.sh
   bash -n scripts/populate-local-skills.sh
   ```
   Expected: no `^M` shebang/parse errors.

## Explicit Bug Check: No Literal `$HOME` Directory Creation

1. Configure a path with a literal/escaped token.
2. Run setup/install command.
3. Verify command fails early with token error.
4. Confirm no `$HOME` segment directory was created under working directories.

Expected outcome: **no directories containing literal `$HOME` are created by supported setup scripts.**
