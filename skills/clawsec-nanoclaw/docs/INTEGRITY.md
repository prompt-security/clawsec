# Historical NanoClaw Integrity Component Record

> **Status:** Deprecated and runtime-unverified. This v1-era source is migration evidence, not an active integrity guardian. It is incompatible with NanoClaw v2.

## Do Not Activate

Do not copy the files under `guardian/` or `host-services/` into a NanoClaw deployment. Do not enable automatic restoration from this package. It has no supported NanoClaw runtime range and has not passed a pinned harness acceptance test.

## Why the Old Policy Is Not a Valid Posture Model

The retained policy and documentation mix host and container namespaces and include obsolete or nonexistent paths:

- `/workspace/project/data/registered_groups.json` is not the active v1 group database.
- `/workspace/project/host/**/*.ts` does not map to the official v1 host source tree.
- `/workspace/group/CLAUDE.md` is a container-side path presented to a host monitor.
- `/workspace/project/data/soul-guardian` is another container-side path used as host state.
- `/workspace/ipc` represents the retired v1 message-file transport, not NanoClaw v2's two-database session boundary.

Because the monitored objects are not derived from a verified checkout and scope, a successful local hash comparison would not prove NanoClaw posture integrity.

## Security Limits

- A hash chain can detect internal sequence changes relative to its chosen first record; it does not independently authenticate that first record.
- A locally generated baseline is not trustworthy merely because later hashes match it.
- Automatic restoration can destroy legitimate changes and must remain off unless a future guardian authenticates its baseline and obtains explicit operator approval.
- The historical code has no verified registration, scheduler, service, disable, removal, or rollback path.
- ClawSec installs no schedule. Any refresh or integrity cadence in a v1-era fork is an operator-owned customization.

## Preserved Files

- `guardian/integrity-monitor.ts` — historical implementation input for future tests.
- `guardian/policy.json` — inventory of obsolete path assumptions that migration tooling should detect.
- `host-services/integrity-handler.ts` — historical message-file handler.
- `mcp-tools/integrity-tools.ts` — historical ambient-global MCP declarations.

Their presence is not capability evidence.

## Future Drift Guardian Requirements

Implement `clawsec-drift-guardian-nanoclaw` as a separate NanoClaw v2-native package. Require it to:

- Derive posture from a pinned, supported v2 checkout and explicit host scope.
- Keep authoritative baselines and receipts outside agent-controlled paths.
- Authenticate the baseline before comparing drift.
- Default to read-only detection.
- Disclose every persistent path and keep restoration opt-in.
- Provide idempotent apply, disable, remove, resume, and rollback behavior.
- Ship `REMOVE.md` whenever it leaves state.
- Test every host registration reach-in and database ownership boundary.
- Pass remote harness acceptance before claiming availability.

## References

- [NanoClaw architecture](https://docs.nanoclaw.dev/concepts/architecture)
- [NanoClaw security model](https://docs.nanoclaw.dev/concepts/security)
- [Migrate from NanoClaw v1](https://docs.nanoclaw.dev/migrate-from-v1)
