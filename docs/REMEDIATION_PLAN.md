# Cross-Platform Remediation Plan

## Phase 1: Immediate Risk Closure (Completed)

### Milestones
- Implement explicit home-path expansion + suspicious token rejection in high-risk runtime/install paths.
- Add regression tests for path expansion and escaped-token rejection.
- Add `.gitattributes` LF policy.
- Expand Node lint/type/build CI coverage to Linux/macOS/Windows.
- Update install docs with shell-specific guidance and literal `$HOME` troubleshooting.

### Outcomes
- Literal `$HOME` path propagation bug addressed at source.
- Core advisory/install path config now fails fast on invalid path tokens.

---

## Phase 2: Windows Parity for Critical Workflows (Next)

### Quick wins
- Add PowerShell equivalents for the most-used manual install/check commands in:
  - `skills/clawsec-suite/SKILL.md`
  - `skills/openclaw-audit-watchdog/SKILL.md`
  - `README.md`
- Add a lightweight `scripts/preflight.mjs` to detect missing tools and print OS-specific install hints.

### Milestones
- Native PowerShell instructions for suite setup and advisory hook.
- WSL/Git Bash fallback documented where shell scripts are unavoidable.

---

## Phase 3: Reduce POSIX Shell Surface (Deeper Refactor)

### Refactor targets
- `scripts/populate-local-feed.sh`
- `scripts/populate-local-skills.sh`
- `scripts/release-skill.sh`

### Approach
- Re-implement critical paths in Node/Python to remove dependency on `jq/sed/awk/find/chmod` pipelines.
- Preserve shell wrappers for backward compatibility; route to new cross-platform implementations.

### Migration notes
- Keep old script entrypoints as wrappers for at least one minor release.
- Emit deprecation warnings with exact migration commands.

---

## Phase 4: CI Hardening and Ongoing Verification

### Milestones
- Keep Node matrix (Linux/macOS/Windows) as required check.
- Add targeted Windows smoke tests for install path handling.
- Add macOS check for OpenSSL command compatibility notes where relevant.

### Test strategy
- Local:
  - Run Node test suites that cover path expansion/suppression/install behavior.
  - Run syntax checks for modified scripts.
- CI:
  - Matrix Node checks + guarded installer/suppression/path tests.
  - Linux-only security scans remain, but explicitly marked as Linux-scoped.

---

## Rollout / Release Considerations

- No breaking interface changes introduced in this patch set; behavior is stricter only for invalid/unexpanded path tokens.
- Communicate in release notes:
  - path token validation now enforced
  - how to correct invalid quoted env values
  - where PowerShell examples live
