---
name: clawsec-ps-fuzz
version: 0.1.0
description: Approval-gated, harness-neutral provisioning and redacted direct-model fuzzing with pinned ps-fuzz v2.1.0.
homepage: https://clawsec.prompt.security/
metadata: {"openclaw":{"emoji":"🧪","category":"security"}}
---

# ClawSec ps-fuzz

Use this skill only for an explicitly authorized local fuzz test against a direct model provider. It is portable shell/Python guidance for OpenClaw, NanoClaw, Hermes, PicoClaw, Codex, and other harnesses that can execute approved local commands. It adds no hook, proxy, scheduler, persistence service, or platform runtime integration.

## Install

Vercel Skills / OpenClaw:

```bash
npx skills add prompt-security/clawsec --skill clawsec-ps-fuzz -a openclaw -y
```

Codex:

```bash
npx skills add prompt-security/clawsec --skill clawsec-ps-fuzz -a codex -y
```

ClawHub environments may use this command once the released package is present in that registry; do not represent it as already published:

```bash
npx clawhub@latest install clawsec-ps-fuzz
```

## Authorization and prerequisites

- Require an explicit user authorization ID for provisioning and a fresh authorization ID for every active run.
- `preflight` is deliberately ungated: it only checks local Python/`venv`/`pip`, selected reviewed capabilities, and credential presence. It makes no writes and no network calls.
- Python 3.9+, `venv`, and `pip` are required. `--source source` additionally requires `git`.
- Do not use this skill where the harness cannot run approved local commands; provide the preflight guidance instead.

The capability snapshot intentionally permits only static reviewed `open_ai` (including OpenAI-compatible endpoints) and `ollama` direct-model modes. There is no generic agent HTTP adapter, MCP execution, tool invocation, arbitrary agent API, real vector-store adapter, remediation, persistence, or scheduled scanning.

### Credential boundary

Provider credentials are inherited only from the calling environment. For any `open_ai` provider or embedding role, preflight reports its presence as `OPENAI_API_KEY`; if it reports false, do not run until the harness/operator's existing secure environment-injection mechanism provides it. Native ollama mode has no credential environment requirement. This skill does not define or install a credential mechanism. Never put a credential in argv, URL, `.env`, report, or authorization ID.

## Workflow

Run from the installed skill directory. The credential boundary above applies to every command.

### 1. Inspect without side effects

```bash
python3 scripts/ps_fuzz_runner.py preflight --source wheel \
  --target-provider open_ai --target-model gpt-4o-mini \
  --attack-provider open_ai --attack-model gpt-4o-mini \
  --tests '["system_prompt_stealer"]' --attempts 1 --threads 1
```

### 2. Provision only after confirmation

Choose a caller-owned external base. `--state-root` is required for provision and run, but not preflight. The state path must end in the dedicated `clawsec-ps-fuzz` leaf; it cannot be the checkout or a general temporary directory.

```bash
python3 scripts/ps_fuzz_runner.py provision \
  --confirm-authorized-provision --authorization-id AUTH-2026-001 \
  --state-root /secure/agent-state/clawsec-ps-fuzz --source wheel
```

`wheel` downloads only the pinned GitHub release asset, checks its SHA-256, installs it without dependency resolution, then applies the reviewed hash lock. `source` clones only the pinned commit into isolated state, verifies `HEAD`, and builds a wheel there; it never builds from the user's checkout.

### 3. Run only after a fresh confirmation

Before executing, present the exact target/attack provider and model, approved origins, tests, attempts, threads, and token-cost warning. Use a regular, nonempty system-prompt file and a new external output directory.

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

The wrapper writes only redacted `run.json` and a Markdown summary to the selected output directory. It copies the system prompt into a temporary workspace, uses temporary `HOME`/XDG paths, and prevents upstream persistent configuration and `.env` discovery from touching the user project. It does not create, edit, print, or persist `.env`; do not enable debug logging or a custom benchmark.

## Custom URLs and RAG disclosure

The wrapper rejects malformed URLs, embedded credentials, and an unapproved origin. For OpenAI-compatible or Ollama base URLs, supply the exact matching approved URL. When target and attack use the same provider, upstream uses a provider-wide base-URL flag, so a custom target URL still needs both separately approved target and attack URLs:

```bash
--target-base-url https://models.example.test/v1 \
--approved-target-url https://models.example.test/v1 \
--attack-base-url https://models.example.test/v1 \
--approved-attack-url https://models.example.test/v1
```

For `rag_poisoning`, add `--embedding-provider` and `--embedding-model` (and an approved matching embedding base URL when needed). This is a synthetic local Chroma demonstration only—not evidence about the user's real retrieval, ingestion, filtering, vector store, agent tools, or persistence. It performs no real vector-store mutation, persistence, remediation, or scheduling.

Only the reviewed exact upstream selectors in `resources/capabilities-v2.1.0.json` may be used. The wrapper offers no debug mode and intentionally excludes `custom benchmark`; upstream aggregates can nevertheless include its registered selector, so interpret aggregate totals alongside the requested-test list.

## Upstream refresh policy

Do not follow `latest`. A ps-fuzz update requires an explicit ClawSec review that updates the upstream manifest, pinned commit, release-wheel hash, dependency lock, capability snapshot, and direct tests together. See [README.md](README.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for pinned provenance.
