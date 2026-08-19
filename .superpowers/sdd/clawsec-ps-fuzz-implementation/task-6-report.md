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
