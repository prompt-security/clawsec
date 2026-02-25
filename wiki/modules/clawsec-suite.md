# Module: ClawSec Suite Core

## Responsibilities
- Act as the main skill-of-skills security bundle for OpenClaw-style agents.
- Verify advisory feed authenticity (Ed25519 signatures and optional checksum manifests).
- Detect advisory matches against installed skills and emit actionable runtime alerts.
- Enforce two-step confirmation for risky skill installations.

## Key Files
- `skills/clawsec-suite/skill.json`: suite metadata, embedded components, catalog defaults.
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`: runtime event handler.
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs`: signed feed loading/parsing.
- `skills/clawsec-suite/hooks/.../lib/matching.ts`: advisory-to-skill matching logic.
- `skills/clawsec-suite/hooks/.../lib/state.ts`: scan state persistence.
- `skills/clawsec-suite/hooks/.../lib/suppression.mjs`: allowlist-based suppression loader.
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`: advisory-gated installer wrapper.
- `skills/clawsec-suite/scripts/discover_skill_catalog.mjs`: remote/fallback catalog discovery.

## Public Interfaces
| Interface | Consumer | Behavior |
| --- | --- | --- |
| Hook handler default export | OpenClaw hook runtime | Handles `agent:bootstrap` and `command:new` events. |
| `guarded_skill_install.mjs` CLI | Operators/automation | Blocks on advisory matches unless `--confirm-advisory`. |
| `discover_skill_catalog.mjs` CLI | Suite docs/automation | Lists installable skills with fallback metadata. |
| `feed.mjs` functions | Suite scripts and tests | Feed load, signature verification, checksum manifest checks. |
| Exit code contract | External wrappers | `42` indicates explicit second confirmation required. |

## Inputs and Outputs
Inputs/outputs are summarized in the table below.

| Type | Name | Location | Description |
| --- | --- | --- | --- |
| Input | Advisory feed + signatures | Remote URLs or local `advisories/` files | Risk intelligence source for hook and installer. |
| Input | Installed skill metadata | Skill directories under install root | Matcher compares installed versions to advisory affected specs. |
| Input | Suppression config | `OPENCLAW_AUDIT_CONFIG` or default config paths | Selective suppression by check and skill name. |
| Output | Runtime alert messages | Hook event `messages[]` | Advisories and recommended user actions. |
| Output | Persistent state | `~/.openclaw/clawsec-suite-feed-state.json` | De-dup alerts, track scan windows. |
| Output | CLI gating exit codes | Installer process status | Ensures deliberate user confirmation on risk. |

## Configuration
| Variable | Default | Module Effect |
| --- | --- | --- |
| `CLAWSEC_FEED_URL` | Hosted advisory URL | Chooses primary remote feed endpoint. |
| `CLAWSEC_LOCAL_FEED*` vars | Suite-local advisories directory | Configures local signed fallback artifacts. |
| `CLAWSEC_FEED_PUBLIC_KEY` | `advisories/feed-signing-public.pem` | Verification key path. |
| `CLAWSEC_ALLOW_UNSIGNED_FEED` | `0` | Enables temporary migration bypass mode. |
| `CLAWSEC_VERIFY_CHECKSUM_MANIFEST` | `1` | Enables checksum manifest verification layer. |
| `CLAWSEC_HOOK_INTERVAL_SECONDS` | `300` | Controls event-driven scan throttling. |

## Example Snippets
```ts
// hook only handles selected events
function shouldHandleEvent(event: HookEvent): boolean {
  const eventName = toEventName(event);
  return eventName === 'agent:bootstrap' || eventName === 'command:new';
}
```

```js
// guarded installer confirmation contract
if (matches.length > 0 && !args.confirmAdvisory) {
  process.stdout.write('Re-run with --confirm-advisory to proceed.\n');
  process.exit(EXIT_CONFIRM_REQUIRED); // 42
}
```

## Edge Cases
- Missing/malformed feed signatures force remote rejection and local fallback attempts.
- Ambiguous checksum manifest basename collisions are treated as errors.
- Unknown skill versions are treated conservatively in version matching logic.
- Suppression is disabled unless config includes the pipeline sentinel (`enabledFor`).
- Invalid environment path tokens are rejected to avoid accidental literal path usage.

## Tests
| Test File | Focus |
| --- | --- |
| `skills/clawsec-suite/test/feed_verification.test.mjs` | Signature/checksum verification and fail-closed behavior. |
| `skills/clawsec-suite/test/guarded_install.test.mjs` | Confirmation gating and match semantics. |
| `skills/clawsec-suite/test/path_resolution.test.mjs` | Home/path expansion and invalid token handling. |
| `skills/clawsec-suite/test/advisory_suppression.test.mjs` | Suppression config parsing and matching. |
| `skills/clawsec-suite/test/skill_catalog_discovery.test.mjs` | Remote index and fallback merge behavior. |

## Source References
- skills/clawsec-suite/skill.json
- skills/clawsec-suite/SKILL.md
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/matching.ts
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/state.ts
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/suppression.mjs
- skills/clawsec-suite/hooks/clawsec-advisory-guardian/lib/version.mjs
- skills/clawsec-suite/scripts/guarded_skill_install.mjs
- skills/clawsec-suite/scripts/discover_skill_catalog.mjs
- skills/clawsec-suite/test/feed_verification.test.mjs
- skills/clawsec-suite/test/guarded_install.test.mjs
- skills/clawsec-suite/test/path_resolution.test.mjs
