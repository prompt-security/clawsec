---
name: clawsec-nanoclaw
version: 0.0.11
description: Use when auditing or migrating historical ClawSec artifacts from a NanoClaw v1-era fork; this package is an unverified template with no supported runtime range, must not be installed, and is incompatible with NanoClaw v2
---

# Audit the Historical ClawSec NanoClaw Template

Treat this package as migration evidence only.

## Stop Gate

- Do not install, import, or activate the bundled TypeScript.
- Do not claim that any NanoClaw version is supported by this package.
- Do not use the package as evidence of NanoClaw v2 support.
- Do not copy v1-era paths, message-file handlers, scheduler examples, or service commands into v2.
- Do not treat isolated unit tests as a harness acceptance result.

NanoClaw has no reviewed direct Agent Skills CLI target; do not substitute `--agent openclaw` or another unrelated target.

Read the [historical integration record](./INSTALL.md) before assessing an existing deployment. It documents why the former integration procedure is not runnable as written.

## Compatibility Result

Return these conclusions when asked whether this package can be installed:

- Status: historical, unverified v1-era template.
- Supported NanoClaw range: none asserted.
- NanoClaw v2: incompatible.
- Installation recommendation: do not install.
- Successor status: prove availability from the current published release and its acceptance evidence; do not infer it from a roadmap, directory, branch, pull request, or version label.

## Why the Runtime Is Not Qualified

The MCP modules use ambient declarations for `server`, `writeIpcFile`, `TASKS_DIR`, and `groupFolder`. Those declarations satisfy TypeScript but create no runtime binding. Importing the modules cannot access module-local identifiers from NanoClaw's runner.

The remaining source also leaves `glob` and `writeResponse` without runtime implementations and uses CommonJS `__dirname` in an ES module. It preserves unqualified assumptions about host/container paths, message-file IPC, group state, scheduling, restart behavior, and writable state. No pinned NanoClaw checkout has passed a complete apply, run, remove, and rollback test for this package.

## Allowed Uses

Use the package only to:

- Identify historical ClawSec files in a customized NanoClaw v1-era checkout.
- Compare those files with the operator's actual fork and service configuration.
- Produce a read-only migration inventory.
- Preserve source as test-vector input for future migration tooling.
- Explain why the old integration must not be copied into NanoClaw v2.

Do not modify or remove an operator's existing deployment without an explicit reviewed plan and rollback path.

## Migration Inventory

Record evidence without executing the package:

1. Pin the exact NanoClaw source commit and record its reported version.
2. Locate every copied ClawSec file and every source reach-in.
3. Locate service, task, hook, database, cache, and integrity state owned by the old customization.
4. Record file digests, permissions, ownership, and whether each path is host-side or container-side.
5. Record any active process or scheduler that imports or invokes the historical code.
6. Identify conflicts with NanoClaw v2's additive skill workflow and two-database host/container boundary.
7. Propose disable, migration, and rollback steps without executing them.

If current authorization does not permit access to live logs, record runtime execution evidence as unknown. Do not infer success or inactivity from missing evidence.

## Preserved Source Boundaries

- `mcp-tools/` contains historical declarations, not a supported registration API.
- `host-services/` contains unqualified v1-era host integration attempts.
- `guardian/` contains a historical integrity implementation, not the future NanoClaw drift guardian.
- `lib/` contains isolated helpers that may inform common contracts only after independent review.
- `advisories/feed-signing-public.pem` is a feed-verification key and is not release-installation authority.

## Future v2 Requirements

A supported NanoClaw package must be implemented separately. Require it to:

- Target a pinned NanoClaw v2 range and current official architecture.
- Use an explicit registration API or reviewed additive reach-in with a failing-when-removed integration test.
- Keep authoritative trust and receipts on the host, outside agent-controlled state.
- Provide idempotent apply, update, removal, resume, and rollback behavior.
- Ship `REMOVE.md` whenever apply leaves state.
- Run NanoClaw host build/tests and Bun tests for any agent-runner change.
- Pass the remote lab and release lifecycle before any support claim.

The v2 architecture statements above reflect official upstream material observed on 2026-07-22. Reverify the current documentation and source revision before making a migration or support decision.

## References

- [NanoClaw architecture](https://docs.nanoclaw.dev/concepts/architecture)
- [NanoClaw v2 skills](https://docs.nanoclaw.dev/extend/overview)
- [Migrate from NanoClaw v1](https://docs.nanoclaw.dev/migrate-from-v1)
