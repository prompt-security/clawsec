# Optional pinned local Gemma smoke

Use this workflow only as a local, text-only connectivity, authorization-gate, isolation, and report-redaction smoke before authorizing a real endpoint. It is not a meaningful security assessment. Complete the signed install and approved provisioning flow in `../SKILL.md` first.

The shell examples below are for macOS/Linux. The wrapper itself still requires the reviewed CPython 3.9–3.11/native-wheel platform boundary documented in `../SKILL.md`.

## 1. Review, confirm, and verify the model

Show the operator all of these values and obtain an explicit confirmation **before downloading**:

- Model: `google/gemma-4-E2B-it` (instruction-tuned, not `google/gemma-4-E2B`)
- Repository: `ggml-org/gemma-4-E2B-it-GGUF`
- Immutable revision: `b4243c156154b6dca9324415f8c7ccc098b4aed1`
- File: `gemma-4-E2B-it-Q4_0.gguf`
- Size: `2,841,481,184` bytes (about 2.84 GB)
- SHA-256: `8e30dff3ac4c8434c49a7036fa15564bdbb6044e42bf04550bf1a096ad7e6a52`
- Immutable URL: `https://huggingface.co/ggml-org/gemma-4-E2B-it-GGUF/resolve/b4243c156154b6dca9324415f8c7ccc098b4aed1/gemma-4-E2B-it-Q4_0.gguf`
- License: Apache-2.0

After confirmation, download only that immutable URL to a `.partial` file. Verify both the exact size and SHA-256 before publishing it. Never follow `main` or `latest`. The same-directory hard-link step below is an atomic no-replace publication: unlike a plain `mv`, it fails if a final file raced into place. Removing the verified partial name completes the publication without overwriting an existing final path.

```bash
# local-smoke-download
set -euo pipefail
umask 077

MODEL_DIR=/secure/models/gemma-4-E2B-it
MODEL_FILE="$MODEL_DIR/gemma-4-E2B-it-Q4_0.gguf"
MODEL_PARTIAL="$MODEL_FILE.partial"

fail() {
  printf 'local smoke download blocked: %s\n' "$1" >&2
  exit 1
}

[[ ! -L "$MODEL_DIR" ]] || fail 'model directory is a symlink'
mkdir -p "$MODEL_DIR"
[[ -d "$MODEL_DIR" && ! -L "$MODEL_DIR" ]] || fail 'model directory is not a regular directory'
[[ ! -e "$MODEL_FILE" && ! -L "$MODEL_FILE" ]] || fail 'final model path already exists'
[[ ! -e "$MODEL_PARTIAL" && ! -L "$MODEL_PARTIAL" ]] || fail 'partial model path already exists'

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$MODEL_PARTIAL" \
  'https://huggingface.co/ggml-org/gemma-4-E2B-it-GGUF/resolve/b4243c156154b6dca9324415f8c7ccc098b4aed1/gemma-4-E2B-it-Q4_0.gguf'

verify_model_file() {
  local candidate="$1"
  [[ -f "$candidate" && ! -L "$candidate" ]] || fail 'model is not a regular non-symlink file'
  [[ "$(wc -c < "$candidate" | tr -d ' ')" == '2841481184' ]] || fail 'model size mismatch'
  printf '%s  %s\n' \
    '8e30dff3ac4c8434c49a7036fa15564bdbb6044e42bf04550bf1a096ad7e6a52' \
    "$candidate" | shasum -a 256 -c -
}

verify_model_file "$MODEL_PARTIAL"
ln "$MODEL_PARTIAL" "$MODEL_FILE"
[[ "$MODEL_PARTIAL" -ef "$MODEL_FILE" ]] || fail 'no-replace publication was not the verified file'
unlink "$MODEL_PARTIAL"
[[ ! -e "$MODEL_PARTIAL" && ! -L "$MODEL_PARTIAL" ]] || fail 'partial name remains after publication'
verify_model_file "$MODEL_FILE"
printf 'local smoke model published and re-verified\n'
```

If any step fails, the shell exits immediately. Do not load a remaining `.partial` or final file unless the complete block prints the publication confirmation.

## 2. Run an operator-controlled loopback server

Install and manage `llama-server` yourself. This skill does not download, install, update, daemonize, background, or stop it, and it does not pin a llama.cpp version. The single block below probes the installed executable, verifies the final model again, and starts the foreground server only if every preceding check succeeds. `--reasoning-budget` is optional: the Bash array includes `--reasoning-budget 0` only when this same help output lists it.

```bash
# local-smoke-server
set -euo pipefail

MODEL_FILE=/secure/models/gemma-4-E2B-it/gemma-4-E2B-it-Q4_0.gguf

fail() {
  printf 'local smoke server blocked: %s\n' "$1" >&2
  exit 1
}

LLAMA_HELP="$(llama-server --help)"
has_llama_flag() {
  printf '%s\n' "$LLAMA_HELP" | grep -Eq -- "(^|[[:space:],])${1}([=[:space:],]|$)"
}
for FLAG in --model --alias --host --port --ctx-size --parallel --no-mmproj --no-webui --log-disable --offline --no-slots --no-cache-prompt; do
  has_llama_flag "$FLAG" || fail "required llama-server flag is missing: $FLAG"
done
[[ -f "$MODEL_FILE" && ! -L "$MODEL_FILE" ]] || fail 'model is not a regular non-symlink file'
[[ "$(wc -c < "$MODEL_FILE" | tr -d ' ')" == '2841481184' ]] || fail 'model size mismatch'
printf '%s  %s\n' \
  '8e30dff3ac4c8434c49a7036fa15564bdbb6044e42bf04550bf1a096ad7e6a52' \
  "$MODEL_FILE" | shasum -a 256 -c -

LLAMA_COMMAND=(
  llama-server
  --model "$MODEL_FILE"
  --alias psfuzz-local
  --host 127.0.0.1
  --port 8081
  --ctx-size 8192
  --parallel 1
  --no-mmproj
  --no-webui
  --log-disable
  --offline
  --no-slots
  --no-cache-prompt
)
if has_llama_flag --reasoning-budget; then
  LLAMA_COMMAND+=(--reasoning-budget 0)
fi
exec "${LLAMA_COMMAND[@]}"
```

Do not enable tools, agent mode, MCP servers or proxies, slot persistence, model URL/repository download flags, TLS credential files, prompt logs, `tee`, or a `0.0.0.0` bind.

Loopback prevents remote-host access but does not authenticate or isolate other local processes on the same machine. `--offline` disables llama-server's supported online model behavior; it is not an operating-system network sandbox. Use host firewall/sandbox controls if local-process or broader egress isolation is required.

The supplied Qwen3-VL sample is not the default because its `0.0.0.0` bind exposes an unauthenticated endpoint, `tee` persists potentially sensitive traffic, and an F16 8B model plus projector with 32K context and two slots is unnecessarily heavy for a text-only smoke. It also lacks an immutable repository revision and artifact hash. An existing user-supplied server remains usable only after applying the same loopback and no-log controls.

## 3. Check readiness, then optionally make one harmless completion

Require `GET http://127.0.0.1:8081/health` to return HTTP 200 with exactly `{"status":"ok"}`. Require `GET http://127.0.0.1:8081/v1/models` to return exactly one model whose ID is `psfuzz-local`. The following check makes no completion:

```bash
python3 - <<'PY'
import json
import urllib.request

MAX_JSON_BYTES = 65536

def get_json(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        if response.status != 200:
            raise SystemExit("local smoke readiness failed")
        raw = response.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise SystemExit("local smoke readiness response is too large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit("local smoke readiness response is invalid") from None
    if not isinstance(value, dict):
        raise SystemExit("local smoke readiness response is not an object")
    return value

if get_json("http://127.0.0.1:8081/health") != {"status": "ok"}:
    raise SystemExit("local smoke health response is invalid")
models = get_json("http://127.0.0.1:8081/v1/models").get("data")
if (
    not isinstance(models, list)
    or len(models) != 1
    or not isinstance(models[0], dict)
    or models[0].get("id") != "psfuzz-local"
):
    raise SystemExit("local smoke model alias is invalid")
print("local smoke readiness passed")
PY
```

Only after a separate explicit approval, send at most one harmless chat completion to validate the OpenAI-compatible response shape. This one request has a 60-second timeout, uses no tools and no streaming, and has no retry loop. It keeps the response in memory only, validates it, discards it, and prints no response body:

```bash
python3 - <<'PY'
import json
import urllib.request

MAX_JSON_BYTES = 1048576

request = urllib.request.Request(
    "http://127.0.0.1:8081/v1/chat/completions",
    data=json.dumps({
        "model": "psfuzz-local",
        "messages": [{"role": "user", "content": "Reply with a short greeting."}],
        "max_tokens": 16,
        "stream": False,
    }).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=60) as response:
    if response.status != 200:
        raise SystemExit("local completion failed")
    raw = response.read(MAX_JSON_BYTES + 1)
if len(raw) > MAX_JSON_BYTES:
    raise SystemExit("local completion response is too large")
try:
    body = json.loads(raw.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit("local completion response is invalid") from None
if not isinstance(body, dict):
    raise SystemExit("local completion response is not an object")
choices = body.get("choices")
valid_shape = (
    isinstance(choices, list)
    and bool(choices)
    and isinstance(choices[0], dict)
    and isinstance(choices[0].get("message", {}).get("content"), str)
)
body = None
choices = None
if not valid_shape:
    raise SystemExit("local completion response shape is invalid")
print("local completion shape passed; response discarded")
PY
```

## 4. Preflight and run the wrapper

The exact placeholder `local-loopback-no-auth` is not a real credential. Use it only in the process environment for this unauthenticated loopback smoke so the OpenAI client path is satisfied. Never put it in `.env`, argv, a URL, a report, or a persistent shell configuration.

Preflight both roles against the exact same approved loopback URL:

```bash
OPENAI_API_KEY=local-loopback-no-auth python3 scripts/ps_fuzz_runner.py preflight \
  --source wheel \
  --target-provider open_ai --target-model psfuzz-local \
  --attack-provider open_ai --attack-model psfuzz-local \
  --target-base-url http://127.0.0.1:8081/v1 \
  --approved-target-url http://127.0.0.1:8081/v1 \
  --attack-base-url http://127.0.0.1:8081/v1 \
  --approved-attack-url http://127.0.0.1:8081/v1 \
  --tests '["system_prompt_stealer"]'
```

Preflight is an offline configuration preview; it does not call the server or replace the readiness checks above. Attempts, threads, and attack temperature are run-only controls and are intentionally omitted from this preview. The active run remains separately confirmation-gated.

After checking that preview and obtaining a fresh authorization, run one attempt against the packaged synthetic prompt and a new output directory:

```bash
OPENAI_API_KEY=local-loopback-no-auth python3 scripts/ps_fuzz_runner.py run \
  --confirm-authorized-test --authorization-id AUTH-LOCAL-SMOKE-001 \
  --state-root /secure/agent-state/clawsec-ps-fuzz \
  --system-prompt-file resources/local-smoke-system-prompt.txt \
  --target-provider open_ai --target-model psfuzz-local \
  --attack-provider open_ai --attack-model psfuzz-local \
  --target-base-url http://127.0.0.1:8081/v1 \
  --approved-target-url http://127.0.0.1:8081/v1 \
  --attack-base-url http://127.0.0.1:8081/v1 \
  --approved-attack-url http://127.0.0.1:8081/v1 \
  --tests '["system_prompt_stealer"]' \
  --attempts 1 --threads 1 --attack-temperature 0.2 \
  --output-dir /secure/reports/ps-fuzz-local-smoke-001
```

Using the same small model for target and attack validates only transport, authorization gates, isolation, and redacted reports. It may under-generate attacks and must not be interpreted as a meaningful security assessment. Obtain a fresh authorization before switching to any real endpoint.

Do not include `rag_poisoning` in this first smoke. It needs a separate embedding-capable model/server at a separately approved URL and exercises only ps-fuzz's temporary synthetic Chroma corpus. It does not exercise the user's retrieval, ingestion, filtering, production vector store, agent tools, or persistence.
