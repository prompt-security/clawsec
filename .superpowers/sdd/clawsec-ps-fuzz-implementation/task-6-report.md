# Task 6 report: optional pinned local Gemma smoke

## Scope and constraints

This task adds documentation and authenticated package resources only. It does
not add a runtime helper or second runner. No command in implementation or test
downloaded the 2,841,481,184-byte model, contacted a provider/server, or
installed, updated, started, stopped, daemonized, or backgrounded
`llama-server`.

Before editing, I read the Task 6 brief, repository `AGENTS.md`, current package
README/SKILL/metadata/changelog/notices, all three package test files, the
signed-install provenance brief and documentation, the pinned upstream and
capability manifests, and the Task 4 reviewed runtime boundary. The documented
runtime now matches that reviewed boundary: CPython 3.9 through 3.11 on Windows
AMD64; glibc 2.28+ Linux x86_64/aarch64; or macOS 14+ arm64.

## RED: missing local-smoke resources and SBOM closure

I first changed only `test/test_package_contract.py`. The new contract pins the
entire local model manifest, the harmless prompt, the two direct SKILL links,
and the complete SBOM file set.

Command:

```text
python3 skills/clawsec-ps-fuzz/test/test_package_contract.py
```

Output:

```text
...E.F.
======================================================================
ERROR: test_local_smoke_resources_are_pinned_safe_and_packaged (__main__.PackageContractTests.test_local_smoke_resources_are_pinned_safe_and_packaged)
Changing the reviewed local model identity or omitting its resources must fail this test.
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/Users/david.abutbul/.codex/worktrees/1ad5/clawsec/skills/clawsec-ps-fuzz/test/test_package_contract.py", line 156, in test_local_smoke_resources_are_pinned_safe_and_packaged
    (SKILL_ROOT / "resources" / "local-smoke-model.json").read_text(encoding="utf-8")
FileNotFoundError: [Errno 2] No such file or directory: '/Users/david.abutbul/.codex/worktrees/1ad5/clawsec/skills/clawsec-ps-fuzz/resources/local-smoke-model.json'

======================================================================
FAIL: test_sbom_is_a_complete_package_closure (__main__.PackageContractTests.test_sbom_is_a_complete_package_closure)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/Users/david.abutbul/.codex/worktrees/1ad5/clawsec/skills/clawsec-ps-fuzz/test/test_package_contract.py", line 57, in test_sbom_is_a_complete_package_closure
    self.assertEqual(sbom_paths, EXPECTED_ARTIFACTS)
AssertionError: Items in the second set but not the first:
'resources/local-smoke-system-prompt.txt'
'resources/local-smoke.md'
'resources/local-smoke-model.json'

----------------------------------------------------------------------
Ran 7 tests in 0.008s

FAILED (failures=1, errors=1)
```

The failures were the intended missing-resource and unauthenticated-SBOM
failures, not a test syntax or fixture error.

## GREEN: minimal implementation

I added the exact immutable Gemma manifest, harmless synthetic prompt, and one
directly linked guide. I then added those resources to the package SBOM and
updated README, SKILL, changelog, and third-party attribution. No package code
or runtime behavior changed.

Command:

```text
python3 skills/clawsec-ps-fuzz/test/test_package_contract.py
```

Output:

```text
.......
----------------------------------------------------------------------
Ran 7 tests in 0.006s

OK
```

## Verification

All tests were offline. The local-smoke contract only parses package files; the
runner and installer suites use fake commands/downloads or local generated
fixtures and made no model/provider/server calls.

Commands and results:

```text
python3 skills/clawsec-ps-fuzz/test/test_package_contract.py
.......
----------------------------------------------------------------------
Ran 7 tests in 0.006s

OK

python3 skills/clawsec-ps-fuzz/test/test_ps_fuzz_runner.py
----------------------------------------------------------------------
Ran 45 tests in 0.540s

OK

python3 skills/clawsec-ps-fuzz/test/test_verified_install.py
----------------------------------------------------------------------
Ran 26 tests in 1.802s

OK

python3 -m py_compile skills/clawsec-ps-fuzz/test/test_package_contract.py skills/clawsec-ps-fuzz/scripts/ps_fuzz_runner.py skills/clawsec-ps-fuzz/scripts/verified_install.py
(no output; exit 0)

python3 utils/validate_skill.py skills/clawsec-ps-fuzz
Validating skill: skills/clawsec-ps-fuzz

Validation PASSED - all checks passed

[OK] Skill is valid

node scripts/test-skill-install-docs.mjs
(no output; exit 0)

node scripts/ci/validate_skill_install_docs.mjs --skills skills/clawsec-ps-fuzz --agent-types-file scripts/test-skill-install-docs.mjs
npx skills install docs OK for clawsec-ps-fuzz: -a openclaw

node scripts/test-skill-release-workflow.mjs
(no output; exit 0)

node scripts/test-skill-tag-release-simulation.mjs
(no output; exit 0)

python3 -c 'import pathlib,re; text=pathlib.Path("skills/clawsec-ps-fuzz/resources/local-smoke.md").read_text(); snippets=re.findall(r"python3 - <<.PY.\n(.*?)\nPY", text, re.S); assert len(snippets)==2, len(snippets); [compile(s, "local-smoke.md", "exec") for s in snippets]; print("local smoke Python snippets compile: 2")'
local smoke Python snippets compile: 2

python3 -c 'import pathlib,re,subprocess; text=pathlib.Path("skills/clawsec-ps-fuzz/resources/local-smoke.md").read_text(); snippets=re.findall(r"```bash\n(.*?)\n```", text, re.S); assert len(snippets)==7, len(snippets); [subprocess.run(["bash", "-n"], input=s, text=True, check=True) for s in snippets]; print("local smoke shell snippets parse: 7")'
local smoke shell snippets parse: 7

git diff --check
(no output; exit 0)
```

The focused total is 78 passing Python tests (7 package/local-smoke, 45 runner,
26 signed installer), plus all requested validation/release simulations.

## Changed files

- `.superpowers/sdd/clawsec-ps-fuzz-implementation/task-6-report.md`
- `skills/clawsec-ps-fuzz/CHANGELOG.md`
- `skills/clawsec-ps-fuzz/README.md`
- `skills/clawsec-ps-fuzz/SKILL.md`
- `skills/clawsec-ps-fuzz/THIRD_PARTY_NOTICES.md`
- `skills/clawsec-ps-fuzz/resources/local-smoke-model.json`
- `skills/clawsec-ps-fuzz/resources/local-smoke-system-prompt.txt`
- `skills/clawsec-ps-fuzz/resources/local-smoke.md`
- `skills/clawsec-ps-fuzz/skill.json`
- `skills/clawsec-ps-fuzz/test/test_package_contract.py`

## Self-review

- The manifest uses `google/gemma-4-E2B-it`, the exact GGUF repository,
  immutable revision, Q4_0 filename/URL, SHA-256, 2,841,481,184-byte size,
  Apache-2.0 license, `psfuzz-local` alias, and loopback base URL from the brief.
- The download flow requires explicit confirmation, writes `.partial`, verifies
  exact size and hash, and renames only after both checks. It never follows
  `main` or `latest`.
- `llama-server` remains entirely operator controlled. The guide requires
  `--help` feature probing, makes no llama.cpp version-pin claim, uses the
  loopback/no-log/offline/minimal server shape, disables slots and prompt-cache
  reuse, and conditionally includes `--reasoning-budget 0` only when supported.
- The download refuses existing/symlinked final and partial leaves; the final
  regular file is size/hash checked again immediately before server launch.
- The guide states that loopback remains reachable to other local processes and
  that `--offline` is not an operating-system network sandbox.
- The guide explains why the Qwen3-VL/F16/projector/32K/two-slot sample is too
  heavy and why `0.0.0.0`, `tee`, and unpinned artifacts are unsafe defaults.
- Readiness requires bounded timeouts, HTTP 200, parsed JSON, and exact
  health/model-alias semantics. The only optional completion is separately
  approved, harmless, at most one, non-streaming, tool-free, without a retry
  loop, shape checked, not printed, and discarded in memory.
- Preflight and run use `open_ai`/`psfuzz-local` for both roles, all four exact
  loopback base/approval flags, one `system_prompt_stealer` attempt/thread,
  attack temperature 0.2, the packaged prompt, and a new output directory.
- `local-loopback-no-auth` appears as a documented non-secret placeholder and
  is supplied only as a per-process environment assignment. The guide forbids
  `.env`, argv, URL, report, and persistent-shell placement.
- Interpretation is limited to transport, authorization gates, isolation, and
  redacted reports. The guide warns about attack under-generation and requires
  fresh authorization for a real endpoint.
- The first smoke excludes `rag_poisoning`; the separate embedding server/URL
  and temporary synthetic Chroma limitation retain every required non-claim.
- The verified-install guidance and signed publisher trust ordering remain
  unchanged. The package SBOM now authenticates all three smoke resources, so
  signed release manifests cover them through the existing release pipeline.

## Concerns and forward-test handoff

The required context-free fresh-agent documentation forward test cannot be
self-dispatched because Task 6 explicitly forbids spawning subagents/reviewers
and assigns independent review to the controller. The finished package is ready
for the controller to give only the installed skill to a fresh agent and ask it
to set up a safe local first run. That forward test should confirm the agent
requires confirmation before the immutable download, verifies before rename,
probes local server flags, stays on loopback without logs, performs readiness
checks before at most one approved completion, uses the exact wrapper shape,
and refuses to interpret this smoke as a security assessment.

No other concerns.

## Fix round 1: fail-closed executable local-smoke flows

Independent review found that the original download and pre-launch examples
used guard commands without strict shell failure semantics. A failed guard,
size check, or hash pipeline could therefore continue to `mv` or launch, and
plain `mv` could overwrite a final path raced into place. Review also required
one combined help/verification/launch block, a quoted Bash array for the
optional reasoning flags, executable offline behavior tests, and removal of
run-only controls from the preflight preview.

This section supersedes the initial self-review statement that the old `mv`
flow safely renamed the artifact.

### RED

I first added `test/test_local_smoke.py` and added that intended path to the
package-closure expectation. No guide or SBOM implementation changed before
these runs.

Commands:

```text
python3 skills/clawsec-ps-fuzz/test/test_local_smoke.py
python3 skills/clawsec-ps-fuzz/test/test_package_contract.py
```

Relevant complete result:

```text
test_download_failures_never_publish_or_overwrite ... FAIL
test_download_publishes_no_replace_and_reverifies_final ... FAIL
test_failed_prelaunch_checks_never_start_server ... FAIL
test_preflight_example_omits_run_only_attempt_controls ... FAIL
test_server_launch_uses_safe_flags_and_optional_reasoning_array ... FAIL

FAIL: test_download_failures_never_publish_or_overwrite
AssertionError: expected one # local-smoke-download shell block, found 0

FAIL: test_download_publishes_no_replace_and_reverifies_final
AssertionError: expected one # local-smoke-download shell block, found 0

FAIL: test_failed_prelaunch_checks_never_start_server
AssertionError: expected one # local-smoke-server shell block, found 0

FAIL: test_preflight_example_omits_run_only_attempt_controls
AssertionError: '--attempts' unexpectedly found in the preflight block

FAIL: test_server_launch_uses_safe_flags_and_optional_reasoning_array
AssertionError: expected one # local-smoke-server shell block, found 0

----------------------------------------------------------------------
Ran 5 tests in 0.011s

FAILED (failures=6)

.....F.
======================================================================
FAIL: test_sbom_is_a_complete_package_closure
AssertionError: Items in the second set but not the first:
'test/test_local_smoke.py'

----------------------------------------------------------------------
Ran 7 tests in 0.006s

FAILED (failures=1)
```

These were the intended failures: the guide lacked executable marked strict
blocks, the preflight example still included run-only controls, and the SBOM
did not authenticate the new offline test.

### GREEN iteration and Bash 3.2 correction

The first implementation added strict blocks and the SBOM entry. Four behavior
tests passed, but the success case caught a real macOS Bash 3.2 issue rather
than being weakened:

```text
test_download_failures_never_publish_or_overwrite ... ok
test_download_publishes_no_replace_and_reverifies_final ... ok
test_failed_prelaunch_checks_never_start_server ... ok
test_preflight_example_omits_run_only_attempt_controls ... ok
test_server_launch_uses_safe_flags_and_optional_reasoning_array ... FAIL

FAIL: test_server_launch_uses_safe_flags_and_optional_reasoning_array (reasoning=False)
AssertionError: 1 != 0 : /bin/bash: line 29: LLAMA_REASONING_FLAGS[@]: unbound variable

----------------------------------------------------------------------
Ran 5 tests in 3.136s

FAILED (failures=1)
```

With `set -u`, Bash 3.2 can reject a quoted expansion of an empty array. I kept
the test unchanged and replaced the empty optional array with one nonempty
`LLAMA_COMMAND` array. The optional `--reasoning-budget 0` pair is appended only
when the exact help probe supports it, and the entire command is executed with
`exec "${LLAMA_COMMAND[@]}"`.

Final focused GREEN:

```text
python3 skills/clawsec-ps-fuzz/test/test_local_smoke.py

test_download_failures_never_publish_or_overwrite ... ok
test_download_publishes_no_replace_and_reverifies_final ... ok
test_failed_prelaunch_checks_never_start_server ... ok
test_preflight_example_omits_run_only_attempt_controls ... ok
test_server_launch_uses_safe_flags_and_optional_reasoning_array ... ok

----------------------------------------------------------------------
Ran 5 tests in 2.428s

OK
```

### Fix-round verification

All behavior tests use temporary files and fake `curl`, `shasum`, and
`llama-server` executables. They make no network call, do not download a model,
and never start a real server or provider request.

```text
python3 skills/clawsec-ps-fuzz/test/test_local_smoke.py
Ran 5 tests in 3.716s
OK

python3 skills/clawsec-ps-fuzz/test/test_package_contract.py
Ran 7 tests in 0.018s
OK

python3 skills/clawsec-ps-fuzz/test/test_ps_fuzz_runner.py
Ran 45 tests in 0.741s
OK

python3 skills/clawsec-ps-fuzz/test/test_verified_install.py
Ran 26 tests in 2.062s
OK

python3 -m py_compile skills/clawsec-ps-fuzz/test/test_local_smoke.py skills/clawsec-ps-fuzz/test/test_package_contract.py skills/clawsec-ps-fuzz/scripts/ps_fuzz_runner.py skills/clawsec-ps-fuzz/scripts/verified_install.py
(no output; exit 0)

python3 utils/validate_skill.py skills/clawsec-ps-fuzz
Validation PASSED - all checks passed
[OK] Skill is valid

node scripts/ci/validate_skill_install_docs.mjs --skills skills/clawsec-ps-fuzz --agent-types-file scripts/test-skill-install-docs.mjs
npx skills install docs OK for clawsec-ps-fuzz: -a openclaw

node scripts/test-skill-install-docs.mjs
(no output; exit 0)

node scripts/test-skill-release-workflow.mjs
(no output; exit 0)

node scripts/test-skill-tag-release-simulation.mjs
(no output; exit 0)

python3 -c 'import pathlib,re; text=pathlib.Path("skills/clawsec-ps-fuzz/resources/local-smoke.md").read_text(); snippets=re.findall(r"python3 - <<.PY.\n(.*?)\nPY", text, re.S); assert len(snippets)==2, len(snippets); [compile(s, "local-smoke.md", "exec") for s in snippets]; print("local smoke Python snippets compile: 2")'
local smoke Python snippets compile: 2

python3 -c 'import pathlib,re,subprocess; text=pathlib.Path("skills/clawsec-ps-fuzz/resources/local-smoke.md").read_text(); snippets=re.findall(r"```bash\n(.*?)\n```", text, re.S); assert len(snippets)==6, len(snippets); [subprocess.run(["bash", "-n"], input=s, text=True, check=True) for s in snippets]; print("local smoke shell snippets parse: 6")'
local smoke shell snippets parse: 6

python3 -c 'import pathlib,re,subprocess; text=pathlib.Path("skills/clawsec-ps-fuzz/resources/local-smoke.md").read_text(); blocks=re.findall(r"```bash\n(.*?)\n```", text, re.S); results=[subprocess.run(["shellcheck","-s","bash","-"],input=block,text=True,capture_output=True) for block in blocks]; assert all(result.returncode == 0 for result in results), [(result.stdout,result.stderr) for result in results if result.returncode]; print(f"shellcheck blocks passed: {len(blocks)}")'
shellcheck blocks passed: 6

git diff --check
(no output; exit 0)
```

The focused total is now 83 passing Python tests (5 executable local smoke, 7
package contract, 45 runner, and 26 signed installer), plus all documentation,
release, syntax, and static-shell validation gates.

### Fix-round self-review

- Both executable flows begin with `set -euo pipefail` and use explicit guards.
- Download guard, wrong-size, and first-hash failures never create the final
  path. A fake race creates a final path after verification; atomic same-dir
  hard-link publication fails without overwriting it and retains the partial.
- Successful publication proves the final and partial names referenced the same
  inode, unlinks the partial name, proves it is gone, and rechecks final type,
  size, and hash before printing the only success confirmation.
- The guide warns that a remaining partial or final is not usable unless the
  complete publication confirmation printed.
- Help probing, final model verification, array construction, and foreground
  launch are one block. Failed flag, size, or hash checks may run `--help` but
  never execute the fake launch path.
- The nonempty command array prevents Bash 3.2 empty-array/unbound behavior,
  quotes every expansion, and ignores hostile ambient `MODEL_FILE` and optional
  flag variables. `--no-slots` and `--no-cache-prompt` remain mandatory.
- Preflight retains both exact `open_ai`/`psfuzz-local` roles, selectors, and all
  four base/approval URLs while omitting attempts, threads, and temperature.
  The active run retains attempts 1, threads 1, and temperature 0.2 exactly.
- Readiness and optional-completion parsing now cap response bytes, decode UTF-8
  and JSON explicitly, and require top-level objects; model entry type is
  checked before reading the exact alias.
- `test/test_local_smoke.py` is authenticated through the package SBOM and is
  handled by the existing release test-file exclusion policy in simulation.

Changed fix-round files:

- `.superpowers/sdd/clawsec-ps-fuzz-implementation/task-6-report.md`
- `skills/clawsec-ps-fuzz/resources/local-smoke.md`
- `skills/clawsec-ps-fuzz/skill.json`
- `skills/clawsec-ps-fuzz/test/test_local_smoke.py`
- `skills/clawsec-ps-fuzz/test/test_package_contract.py`

Concern remains only the controller-owned context-free fresh-agent forward
test, which the task explicitly schedules after this fix. No model/server or
provider smoke was performed, by design.
