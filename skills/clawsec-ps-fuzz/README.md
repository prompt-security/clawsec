# ClawSec ps-fuzz

`clawsec-ps-fuzz` is a public, standalone, harness-neutral workflow for an authorized agent to provision a pinned Prompt Security `ps-fuzz` release and run reviewed direct-model fuzz tests. It is not a hook, proxy, scheduler, or platform runtime integration.

## Install

Vercel Skills / OpenClaw:

```bash
npx skills add prompt-security/clawsec --skill clawsec-ps-fuzz -a openclaw -y
```

Codex:

```bash
npx skills add prompt-security/clawsec --skill clawsec-ps-fuzz -a codex -y
```

ClawHub environments can use the following when this skill's released package is available in that registry; this repository command does not claim it has already been published there:

```bash
npx clawhub@latest install clawsec-ps-fuzz
```

## Safe scope

- Python 3.9+, `venv`, and `pip` are needed. Source provisioning also needs `git`.
- The reviewed provider scope is static: `open_ai` (including OpenAI-compatible base URLs) and `ollama`. There is no generic agent HTTP adapter, MCP execution, tool invocation, or arbitrary endpoint adapter.
- Preflight is ungated and makes no writes or network calls. Provision and run each require a fresh authorization ID and their own confirmation flag.
- The wrapper copies the system prompt only into a temporary workspace. Upstream configuration and `.env` discovery are isolated from the project. It never creates, changes, prints, or persists `.env` files.
- Reports contain redacted aggregate outcomes only. The wrapper exposes no debug mode and no custom benchmark option.

## Credential boundary

Provider credentials are inherited only from the calling environment. For any `open_ai` provider or embedding role, preflight reports its presence as `OPENAI_API_KEY`; if it reports false, do not run until the harness/operator's existing secure environment-injection mechanism provides it. Native ollama mode has no credential environment requirement. This skill does not define or install a credential mechanism. Never put a credential in argv, URL, `.env`, report, or authorization ID.

## Operator flow

Run `python3 scripts/ps_fuzz_runner.py --help` from the installed skill directory. First inspect the local prerequisites without creating state:

```bash
python3 scripts/ps_fuzz_runner.py preflight --source wheel \
  --target-provider open_ai --target-model gpt-4o-mini \
  --attack-provider open_ai --attack-model gpt-4o-mini \
  --tests '["system_prompt_stealer"]' --attempts 1 --threads 1
```

For an authorized provision, choose an external base and use the dedicated leaf exactly as shown. `--state-root` is required for provision and run, but not preflight. Wheel mode verifies the release hash before installation; source mode clones only the pinned commit and builds inside this state root.

```bash
python3 scripts/ps_fuzz_runner.py provision \
  --confirm-authorized-provision --authorization-id AUTH-2026-001 \
  --state-root /secure/agent-state/clawsec-ps-fuzz --source wheel
```

For an active test, obtain a fresh authorization. Select the provider/model roles, an exact JSON test list, positive attempts/threads, a regular prompt file, and a new external output directory. Provider calls can consume tokens and incur charges.

```bash
python3 scripts/ps_fuzz_runner.py run \
  --confirm-authorized-test --authorization-id AUTH-2026-002 \
  --state-root /secure/agent-state/clawsec-ps-fuzz \
  --system-prompt-file /secure/inputs/system-prompt.txt \
  --target-provider open_ai --target-model gpt-4o-mini \
  --attack-provider open_ai --attack-model gpt-4o-mini \
  --tests '["system_prompt_stealer"]' --attempts 1 --threads 1 \
  --output-dir /secure/reports/ps-fuzz-2026-08-18
```

Use `--source source` only where `git` is available. The manifest, source commit, wheel hash, dependency lock, capability snapshot, and tests are one reviewed unit: a future ps-fuzz update must change and review all of them together.

## Endpoint and RAG boundaries

Base URLs must be syntactically safe and separately approved. With the same upstream provider on both roles, ps-fuzz's provider-wide base-URL flag means a custom target URL requires both `--approved-target-url` and `--approved-attack-url`, with matching `--target-base-url` and `--attack-base-url` values. Do not pass credentials in URLs.

`rag_poisoning` requires `--embedding-provider` and `--embedding-model`; it is a synthetic local Chroma demonstration only. It is not evidence about real retrieval, ingestion, filtering, a production vector store, agent tools, or persistence. This skill performs no real vector-store mutation, persistence, remediation, or scheduled scanning.

Known upstream caveat: `custom benchmark` support is intentionally excluded, and upstream aggregate totals may include its registered selector despite this wrapper passing only the requested reviewed selectors. Compare report provenance and requested tests before interpreting totals.

## Provenance

The package pins upstream `ps-fuzz` tag `v2.1.0`, commit `a04982f58fe6c99b08df12a69e967368c96ef9f4`, and the release wheel SHA-256 `953d6d87605335e03f7701204abc2702247dc3627cdb3e48ca7ed52c2c66e3e8`. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and `resources/upstream.json`.
