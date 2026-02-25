# Module: Local Validation and Packaging Tools

## Responsibilities
- Validate skill directory metadata/schema and SBOM file presence before release.
- Generate per-skill checksums manifests for local testing or packaging.
- Provide local data bootstrap scripts that mirror CI behavior for advisories and skills.
- Offer release-link and signing-key consistency checks for maintainers.

## Key Files
- `utils/validate_skill.py`: schema and file existence checks for a skill directory.
- `utils/package_skill.py`: checksum manifest generator with skill pre-validation.
- `scripts/populate-local-skills.sh`: generates local catalog and checksums under `public/skills/`.
- `scripts/populate-local-feed.sh`: pulls NVD data and updates feed copies.
- `scripts/validate-release-links.sh`: verifies docs reference releasable assets.
- `scripts/ci/verify_signing_key_consistency.sh`: verifies key fingerprints across docs/files.

## Public Interfaces
| Tool | Interface | Primary Output |
| --- | --- | --- |
| `validate_skill.py` | `python utils/validate_skill.py <skill-dir>` | Exit code + validation summary with warnings/errors. |
| `package_skill.py` | `python utils/package_skill.py <skill-dir> [out-dir]` | `checksums.json` artifact for skill files. |
| `populate-local-skills.sh` | shell CLI | `public/skills/index.json` and per-skill files/checksums. |
| `populate-local-feed.sh` | shell CLI flags `--days`, `--force` | Updated advisory feeds in repo/skill/public paths. |
| `validate-release-links.sh` | shell CLI optional skill arg | Release-link validation report. |

## Inputs and Outputs
Inputs/outputs are summarized in the table below.

| Type | Name | Location | Description |
| --- | --- | --- | --- |
| Input | Skill metadata and SBOM | `skills/<name>/skill.json` | Enumerates required files and release artifacts. |
| Input | Existing feed state | `advisories/feed.json` | Determines incremental NVD polling start date. |
| Input | Environment tools | `jq`, `curl`, `openssl`, Python runtime | Required execution dependencies. |
| Output | Validation diagnostics | stdout/stderr + exit code | Signals readiness for release/CI. |
| Output | Checksums manifests | `checksums.json` | Integrity data for skill artifacts. |
| Output | Local mirrors | `public/skills/*`, `public/advisories/feed.json` | Makes local web preview match CI outputs. |

## Configuration
| Setting | Location | Purpose |
| --- | --- | --- |
| Ruff/Bandit policy | `pyproject.toml` | Python lint/security baseline. |
| CLI flags (`--days`, `--force`) | `populate-local-feed.sh` | Controls window and overwrite semantics. |
| `OPENCLAW_AUDIT_CONFIG` | suppression loaders in scripts | Chooses suppression config path. |
| `CLAWSEC_*` env vars | installer/hook scripts | Path and verification behavior tuning. |

## Example Snippets
```bash
# validate and package a skill locally
python utils/validate_skill.py skills/clawsec-feed
python utils/package_skill.py skills/clawsec-feed ./dist
```

```bash
# refresh local UI data to mirror CI-generated artifacts
./scripts/populate-local-skills.sh
./scripts/populate-local-feed.sh --days 120
```

## Edge Cases
- Validation allows warnings (for example missing optional files) while still returning success when required fields/files are present.
- NVD poll script handles macOS/Linux differences in `date` and `stat` utilities.
- Release-link validation can detect doc references to files missing from SBOM-derived release assets.
- Path expansion guards reject unexpanded home-token literals to avoid misdirected filesystem writes.

## Tests
| Test/Check | Scope |
| --- | --- |
| `ruff check utils/` | Python style and correctness checks. |
| `bandit -r utils/ -ll` | Python security issue scan. |
| `scripts/prepare-to-push.sh` | Combined local gate across TS/Python/shell/security checks. |
| Skill-local tests | `skills/*/test/*.test.mjs` (targeted invocation) |

## Source References
- utils/validate_skill.py
- utils/package_skill.py
- pyproject.toml
- scripts/populate-local-skills.sh
- scripts/populate-local-feed.sh
- scripts/prepare-to-push.sh
- scripts/validate-release-links.sh
- scripts/ci/verify_signing_key_consistency.sh
- skills/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- skills/clawsec-suite/scripts/guarded_skill_install.mjs
- skills/clawsec-suite/scripts/discover_skill_catalog.mjs
