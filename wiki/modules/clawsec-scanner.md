# Module: ClawSec Scanner

## Responsibilities
- Provide multi-layer vulnerability scanning for OpenClaw-oriented skill repositories.
- Orchestrate dependency, SAST, and DAST engines into a single report contract.
- Execute real OpenClaw hook handlers in an isolated DAST harness to validate runtime security behavior.
- Support periodic scan execution through an OpenClaw hook integration.
- Normalize findings into severity buckets for downstream triage and automation.

## Key Files
- `skills/clawsec-scanner/skill.json`: skill metadata, SBOM paths, trigger phrases.
- `skills/clawsec-scanner/scripts/runner.sh`: main orchestrator for dependency/SAST/DAST scans.
- `skills/clawsec-scanner/scripts/scan_dependencies.mjs`: `npm audit` + `pip-audit` parsing.
- `skills/clawsec-scanner/scripts/sast_analyzer.mjs`: Semgrep and Bandit execution/parsing.
- `skills/clawsec-scanner/scripts/dast_runner.mjs`: hook discovery + real harness DAST evaluation.
- `skills/clawsec-scanner/scripts/dast_hook_executor.mjs`: isolated per-hook runtime executor.
- `skills/clawsec-scanner/hooks/clawsec-scanner-hook/handler.ts`: periodic OpenClaw event hook.
- `skills/clawsec-scanner/lib/report.mjs`: unified report generation and text/JSON formatting.

## Public Interfaces
| Interface | Consumer | Behavior |
| --- | --- | --- |
| `runner.sh` CLI | Operators/automation | Runs all enabled scan engines and emits merged report output. |
| `dast_runner.mjs` CLI | Operators/CI/hooks | Discovers hooks and runs isolated runtime DAST checks. |
| OpenClaw scanner hook default export | OpenClaw runtime | Handles `agent:bootstrap` and `command:new` scanner trigger events. |
| `ScanReport` JSON output | Humans and automation | Provides normalized severity summary + finding list. |

## Inputs and Outputs
Inputs/outputs are summarized in the table below.

| Type | Name | Location | Description |
| --- | --- | --- | --- |
| Input | Scan target path | `--target` CLI arg | Root directory where skills/hooks are scanned. |
| Input | Dependency manifests | `package-lock.json`, `requirements.txt`, `pyproject.toml` | Drives dependency vulnerability checks. |
| Input | Hook metadata and handlers | `**/HOOK.md`, `handler.{js,mjs,cjs,ts}` | DAST harness discovers and executes these handlers. |
| Input | Env configuration | `CLAWSEC_*`, `GITHUB_TOKEN` | Controls engine behavior, severity filtering, and output paths. |
| Output | Unified scan report | stdout or `--output` file | JSON/text report with severity summary and finding details. |
| Output | Runtime hook alerts | OpenClaw `event.messages` | New vulnerability alerts pushed into conversations. |
| Output | Scanner state file | `~/.openclaw/clawsec-scanner-state.json` by default | De-duplication memory for reported finding IDs. |

## Configuration
| Variable | Default | Module Effect |
| --- | --- | --- |
| `CLAWSEC_SCANNER_INTERVAL` | `86400` | Minimum interval between periodic hook-triggered scans. |
| `CLAWSEC_SCANNER_MIN_SEVERITY` | `medium` | Threshold for findings pushed to conversation alerts. |
| `CLAWSEC_SCANNER_FORMAT` | `text` | Hook alert serialization format (`text` or `json`). |
| `CLAWSEC_SKIP_DEPENDENCY_SCAN` | `0` | Disables dependency scanner when set to `1`. |
| `CLAWSEC_SKIP_SAST` | `0` | Disables Semgrep/Bandit scanner when set to `1`. |
| `CLAWSEC_SKIP_DAST` | `0` | Disables runtime hook DAST checks when set to `1`. |
| `CLAWSEC_SKIP_CVE_LOOKUP` | `0` | Disables CVE enrichment stage when set to `1`. |
| `CLAWSEC_DAST_HARNESS` | unset | Internal guard to avoid recursive scans during harness execution. |
| `CLAWSEC_DAST_DISABLE_TYPESCRIPT` | unset | Test/debug switch forcing TypeScript harness coverage fallback mode. |

## DAST Harness Behavior
- Hook discovery walks the target tree for `HOOK.md` and resolves adjacent handler files.
- Each declared event key is executed in a separate Node subprocess via `dast_hook_executor.mjs`.
- Findings are generated from real runtime behavior:
  - Baseline execution crash or timeout.
  - Malicious-input crash or timeout.
  - Output amplification beyond message/character thresholds.
  - Core event identity mutation (`type`, `action`, `sessionKey`).
- Harness capability gaps (for example missing TypeScript compiler for `.ts` handlers) are reported as `info` coverage findings, not high-severity vulnerabilities.

## Example Snippets
```bash
# run scanner end-to-end
bash skills/clawsec-scanner/scripts/runner.sh --target ./skills --format json
```

```bash
# run DAST harness directly
node skills/clawsec-scanner/scripts/dast_runner.mjs --target ./skills --format text --timeout 30000
```

## Tests
| Test File | Focus |
| --- | --- |
| `skills/clawsec-scanner/test/dast_harness.test.mjs` | Real hook execution path, malicious crash detection, TypeScript coverage fallback semantics. |
| `skills/clawsec-scanner/test/reviewer_regressions.test.mjs` | Runner behavior around non-zero DAST exit and merged reporting. |
| `skills/clawsec-scanner/test/dependency_scanner.test.mjs` | Dependency scanner utility/report contracts. |
| `skills/clawsec-scanner/test/sast_engine.test.mjs` | SAST parser/normalization behavior. |
| `skills/clawsec-scanner/test/cve_integration.test.mjs` | OSV/NVD/GitHub enrichment integration checks. |

## Update Notes
- 2026-03-10: Added module page for `clawsec-scanner` and documented the `0.0.2` real OpenClaw DAST harness execution model.

## Source References
- skills/clawsec-scanner/skill.json
- skills/clawsec-scanner/SKILL.md
- skills/clawsec-scanner/CHANGELOG.md
- skills/clawsec-scanner/scripts/runner.sh
- skills/clawsec-scanner/scripts/scan_dependencies.mjs
- skills/clawsec-scanner/scripts/sast_analyzer.mjs
- skills/clawsec-scanner/scripts/dast_runner.mjs
- skills/clawsec-scanner/scripts/dast_hook_executor.mjs
- skills/clawsec-scanner/scripts/setup_scanner_hook.mjs
- skills/clawsec-scanner/hooks/clawsec-scanner-hook/HOOK.md
- skills/clawsec-scanner/hooks/clawsec-scanner-hook/handler.ts
- skills/clawsec-scanner/lib/report.mjs
- skills/clawsec-scanner/lib/utils.mjs
- skills/clawsec-scanner/test/dast_harness.test.mjs
- skills/clawsec-scanner/test/reviewer_regressions.test.mjs
