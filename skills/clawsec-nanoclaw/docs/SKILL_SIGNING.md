# Historical NanoClaw Signature Component Record

> **Status:** Deprecated and runtime-unverified. This v1-era source is migration evidence, not a supported package-verification workflow. It is incompatible with NanoClaw v2.

## Do Not Use It to Authorize Installation

Do not copy or activate the historical verifier. A valid signature proves only that bytes match the selected key and signed input. It does not prove code safety, current catalog authorization, advisory clearance, or operator approval.

The bundled MCP and host integration has not passed an end-to-end NanoClaw test. Its machine-readable `install` recommendation must not be treated as installation authority.

## Trust-Domain Mismatch

The historical handler expects a detached `<archive>.sig` and defaults to the embedded advisory-feed public key. That is not the current ClawSec release contract.

ClawSec release artifacts use a signed `checksums.json` manifest whose authenticated archive digest binds the release ZIP. Release verification also requires a pinned release trust root, exact package identity and version, safe archive validation, and an installation receipt. The advisory-feed key and release-manifest trust domain must not be treated as interchangeable.

No supported ClawSec publisher flow creates the detached archive signatures expected by this legacy handler.

## Runtime Limitations

- The MCP module depends on ambient identifiers that imports do not bind at runtime.
- The host verifier uses unqualified v1-era path assumptions.
- The historical host response path is incomplete.
- The ESM integration and key-path resolution were never proven in a composed upstream build.
- No pinned NanoClaw checkout passed request, response, rejection, cleanup, or removal tests.
- The documentation defines no supported key-rotation or multi-key transition protocol.

## Isolated Invariants Preserved in Source

The retained code and unit tests still provide review input for narrow properties:

- Reject caller-supplied public-key overrides.
- Reject unsigned bypass requests.
- Bound package and signature paths before reading them.
- Verify an Ed25519 signature with a configured key.
- Return evidence to a caller rather than extracting a package.

These isolated properties do not make the NanoClaw integration operational.

## Publisher Workflow

This package defines no publisher key-generation, signing, distribution, or rotation workflow. Do not generate a local key, sign an arbitrary archive, and expect ClawSec or NanoClaw to authorize it.

Use the ClawSec release pipeline only after the relevant package has passed the private lifecycle and promotion gates. Production release keys must never be copied to a harness lab or agent-controlled path.

## Future Ownership

The future `clawsec-core-nanoclaw` package, not a guardian or suite, must own deterministic release verification. Require it to:

- Authenticate pinned root metadata and the exact release manifest.
- Verify the canonical archive digest and package identity.
- Reject unsafe archive entries before writing.
- Install the exact verified bytes through a NanoClaw v2-native transaction.
- Record scope, origin, preimages, postimages, signer, and result in a receipt.
- Keep trust roots and authoritative receipts on the host.
- Separate advisory-feed verification from release-installation authorization.
- Fail closed on unknown keys, identities, versions, paths, or partial state.

## Preserved Files

- `mcp-tools/signature-verification.ts`
- `host-services/skill-signature-handler.ts`
- `lib/signatures.ts`
- `advisories/feed-signing-public.pem`

Treat them as historical/test-vector input only.

## References

- [NanoClaw architecture](https://docs.nanoclaw.dev/concepts/architecture)
- [NanoClaw v2 skills](https://docs.nanoclaw.dev/extend/overview)
- [ClawSec security and signing runbook](../../../wiki/security-signing-runbook.md)
