# Historical NanoClaw Integration Record

> **Do not install this package.** This file preserves the failed assumptions of an earlier NanoClaw v1-era integration template. It is not an installation guide.

## Classification

- Package: `clawsec-nanoclaw`
- Version: `0.0.11`
- Status: historical and unverified
- Supported NanoClaw versions: none asserted
- NanoClaw v2: incompatible
- Runtime activation: prohibited until a separate implementation passes its own acceptance suite

NanoClaw has no reviewed direct Agent Skills CLI target; do not substitute an OpenClaw or another unrelated target.

## Why the Former Procedure Was Withdrawn

The previous procedure instructed operators to copy modules into a NanoClaw checkout and import them from the agent runner. That does not establish a working module boundary.

The files under `mcp-tools/` declare these identifiers without importing or receiving them:

- `server`
- `writeIpcFile`
- `TASKS_DIR`
- `groupFolder`

TypeScript `declare` statements emit no JavaScript. ES modules also do not inherit lexical variables from their importers. Importing these files therefore cannot bind the identifiers that their top-level registration and handlers use.

Additional retained assumptions were not qualified against an upstream runtime:

- `guardian/integrity-monitor.ts` declares a `glob` namespace but imports or receives no runtime implementation, so `glob.sync` is unbound.
- `host-services/ipc-handlers.ts` declares `writeResponse` but imports or implements no such function.
- `host-services/skill-signature-handler.ts` uses CommonJS `__dirname` in an ES module without defining an equivalent ESM path.
- Docker Compose restart commands did not match the reviewed v1 service model.
- Some host services hard-code paths that belong to the container view.
- Group, task, cache, result, and integrity paths are not bound to one verified NanoClaw layout.
- The host IPC wrapper is incomplete and has no end-to-end response-path test.
- No apply, update, removal, interruption-recovery, or rollback transaction was tested.

The old commands and code snippets were removed so an agent cannot mistake them for a supported installation path.

## NanoClaw v2 Boundary

NanoClaw v2 is a ground-up rewrite. Current official documentation describes:

- A Node.js host and one container per active session.
- Per-session `inbound.db` and `outbound.db` files with opposite writer ownership.
- Additive code-carrying skills executed by a coding harness.
- Skills that copy reviewed files, append explicit registration imports, pin dependencies, run integration tests, and provide `REMOVE.md` when state is left behind.
- Scheduled tasks managed by current host surfaces rather than the retired v1 `schedule_task` MCP example.

These upstream facts were observed on 2026-07-22. Reverify the current official documentation and source revision before relying on them for a migration decision.

This package instead preserves v1-era message-file IPC, runner reach-ins, and path assumptions. Do not translate them by changing path strings.

## Existing Fork Assessment

If an operator already has a historical customization, perform a read-only assessment:

1. Record the exact NanoClaw commit and local modifications.
2. Locate every ClawSec file, import, service, task, cache, baseline, and result path.
3. Determine whether any process actually loads the modules and capture its logs without restarting it.
4. Record file digests, ownership, permissions, host/container location, and dependencies.
5. Identify how to disable the customization without deleting state.
6. Prepare rollback and migration steps for operator review.

If current authorization does not permit access to live logs, record runtime execution evidence as unknown. Do not infer that the customization works or is inactive.

Do not run the historical setup or removal instructions from an older release. Do not mutate the deployment merely to test whether the integration works.

## Qualification Required for Any Replacement

A new NanoClaw package must be developed separately and must provide:

- A declared, pinned NanoClaw v2 support range.
- A complete additive apply plan with exact preimages and postimages.
- An explicit registration boundary; no ambient globals.
- Integration tests that fail when required wiring is absent.
- Correct host/container path ownership and database-writer invariants.
- Idempotent apply, update, resume, remove, and rollback behavior.
- `REMOVE.md` for every persistent change.
- Remote harness acceptance using the exact copied candidate bytes.
- Signed qualification and installation receipts before stable release.

Treat a successor as available only when the current published release and its acceptance evidence prove that status. A roadmap entry, source directory, branch, pull request, or version-shaped label is not availability evidence.

## Official References

- [NanoClaw architecture](https://docs.nanoclaw.dev/concepts/architecture)
- [NanoClaw v2 skills](https://docs.nanoclaw.dev/extend/overview)
- [Writing NanoClaw skills](https://docs.nanoclaw.dev/extend/writing-skills)
- [Migrate from NanoClaw v1](https://docs.nanoclaw.dev/migrate-from-v1)
