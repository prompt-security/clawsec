# ClawSec NanoClaw v1-Era Template

> **Status:** Deprecated, historical, and runtime-unverified. This package is retained as migration evidence. It is not a supported NanoClaw adapter and must not be installed into NanoClaw v2.

## Compatibility

- No NanoClaw runtime version is advertised as supported. The package has not passed an end-to-end harness test against a pinned upstream release.
- NanoClaw v2 is incompatible with this template.
- NanoClaw v2 uses a Node.js host, per-session `inbound.db` and `outbound.db` transport, additive code-carrying skills, and current host registration surfaces.
- This template assumes retired v1-era message-file IPC, paths, scheduling, and source reach-ins.

NanoClaw has no reviewed direct Agent Skills CLI target; do not substitute `--agent openclaw` or another unrelated target.

Read the [historical integration record](./INSTALL.md) for the known limitations. It is not an installation procedure.

## Why It Is Unverified

The bundled MCP modules declare `server`, `writeIpcFile`, `TASKS_DIR`, and `groupFolder` as ambient identifiers. Importing an ES module does not make module-local variables from the importer visible to the imported module. The historical instructions therefore do not provide a working registration boundary.

Other retained assumptions also differ from the official v1 and v2 trees:

- The old restart instructions referenced Docker Compose even though the reviewed v1 trees use host services and a separate container build step.
- Several host services use container-side paths.
- The historical group, task, and message-file paths do not represent NanoClaw v2's database model.
- The package has no tested apply, update, remove, rollback, or recovery transaction.

Unit tests cover isolated ClawSec helper invariants. They do not prove that NanoClaw loads or executes this package.

## Preserved Evidence

The source remains available for migration analysis and future test fixtures:

- Advisory matching and feed-signature helpers.
- Historical MCP declarations and message-file handlers.
- Historical package-signature and integrity components.
- v1-era path and policy assumptions that future migration checks must detect.

Do not interpret preserved source as an available protection or installation path.

## Replacement Direction

Current NanoClaw support will be implemented as separate v2-native packages:

- `clawsec-core-nanoclaw`
- `clawsec-suite-nanoclaw`
- `clawsec-drift-guardian-nanoclaw`

None is available merely because its name appears here. Each package must use NanoClaw v2's additive skill workflow, include complete apply and removal behavior, and pass remote harness acceptance before it can claim support.

## Official NanoClaw References

- [NanoClaw architecture](https://docs.nanoclaw.dev/concepts/architecture)
- [NanoClaw v2 skills](https://docs.nanoclaw.dev/extend/overview)
- [Migrate from NanoClaw v1](https://docs.nanoclaw.dev/migrate-from-v1)

## Security Reporting

Report ClawSec issues through the repository's security policy. For NanoClaw behavior, verify findings against a pinned upstream source revision and the current official documentation.
