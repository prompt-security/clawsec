# Task 5 report: standalone signed-release verification

## Supplied no-guidance baseline

The controller supplied the already-run first-install baseline: a fresh agent
read the candidate `SKILL.md` first, found only the upstream `ps-fuzz` pins and
no publisher authentication, and correctly concluded that `clawsec-suite` was
neither required nor sufficient for candidate attestation.

That baseline established the missing publisher-trust and trust-ordering
guidance before this task changed the candidate package.

## RED: verifier behavior

I added the offline signed-release behavior suite before adding the verifier.
The suite's production change was the new `scripts/verified_install.py`
interface and its fail-closed verification/install behavior.

Command:

```text
python3 skills/clawsec-ps-fuzz/test/test_verified_install.py
```

Observed output (exit 1):

```text
Traceback (most recent call last):
  File "skills/clawsec-ps-fuzz/test/test_verified_install.py", line 28, in <module>
    SPEC.loader.exec_module(verifier)
  File "<frozen importlib._bootstrap_external>", line 950, in get_data
FileNotFoundError: [Errno 2] No such file or directory:
'skills/clawsec-ps-fuzz/scripts/verified_install.py'
```

This was the expected missing-feature failure. The initial suite covered the
confirmation gate, canonical key, tampered signature, duplicate manifest keys,
exact signed identity, archive size/hash, fetch order, unsafe ZIP paths and
types, resource limits, SBOM closure, payload hashes, extraction re-hash,
existing-destination preservation, and successful atomic installation.

## First GREEN and adversarial expansion

After the minimal verifier implementation, the initial behavior suite passed:

```text
python3 skills/clawsec-ps-fuzz/test/test_verified_install.py
Ran 17 tests in 1.134s
OK
```

The adversarial pass then expanded direct coverage for:

- Ed25519 SPKI shape and exactly 64 decoded signature bytes.
- Nested duplicate keys, NaN, bool-as-int, and oversized manifest sizes.
- Canonical version validation before URL interpolation or any fetch.
- Encrypted and unsupported-compression ZIP members.
- File/directory prefix, casefold, Unicode normalization, Windows reserved
  name, trailing-dot/space, and alternate-data-stream collisions.
- The exact release workflow's test-path exclusion categories.
- No-clobber publication when the destination is an existing empty directory.

Expanded GREEN output:

```text
python3 skills/clawsec-ps-fuzz/test/test_verified_install.py
Ran 24 tests in 1.686s
OK
```

All fixtures are generated locally. The tests use a real system OpenSSL
Ed25519 key/signature flow, inject opaque release downloads, perform no network
request, do not execute archive content, and never read candidate `SKILL.md` as
instructions.

## RED: package and documentation contract

Before changing documentation or SBOM metadata, I updated the package contract
to require the verifier, its direct test, and the first-install trust boundary.

Command:

```text
python3 skills/clawsec-ps-fuzz/test/test_package_contract.py
```

Observed output (exit 1):

```text
.FF..F.
FAIL test_first_install_trust_ordering_is_explicit (filename='SKILL.md')
AssertionError: 'out-of-band trusted ClawSec' not found
FAIL test_first_install_trust_ordering_is_explicit (filename='README.md')
AssertionError: 'out-of-band trusted ClawSec' not found
FAIL test_sbom_is_a_complete_package_closure
missing: scripts/verified_install.py, test/test_verified_install.py
Ran 6 tests
FAILED (failures=3)
```

After the documentation and SBOM changes:

```text
python3 skills/clawsec-ps-fuzz/test/test_package_contract.py
Ran 6 tests in 0.005s
OK
```

The docs now require an out-of-band trusted verifier source, explicitly deny
self-authentication by a candidate `SKILL.md`, verifier, or candidate key, name
the key as an Ed25519 public key, pin the canonical fingerprint, identify
`checksums.json` as the signed release manifest and `skill.json` as package
metadata/SBOM, deny a `skills.json` trust manifest, state that the suite is
optional and insufficient for candidate attestation, and label `npx skills`
and ClawHub as convenience paths without this local attestation.

## Verification order and implementation review

The verifier enforces this order:

1. Canonicalize the explicit version, refuse an existing destination, and
   download only bounded opaque `checksums.json`, `checksums.sig`, and
   `signing-public.pem` bytes from the fixed tag URL.
2. Parse the key with OpenSSL, require the Ed25519 SPKI encoding, and compare
   its SPKI-DER SHA-256 against the pinned canonical fingerprint.
3. Strictly base64-decode a 64-byte signature and use OpenSSL to verify the
   exact raw manifest bytes before JSON parsing.
4. Reject duplicate/non-finite JSON and enforce exact repository, skill,
   version, tag, archive filename, URL, hashes, and bounded integer sizes.
5. Fetch the archive only after authenticated identity validation, with the
   authenticated size as the byte limit, then verify exact size and SHA-256.
6. Inspect every ZIP entry before extraction, allowing safe directory entries
   and rejecting path, type, encryption, compression, collision, count, size,
   total-size, and ratio hazards.
7. Read only `skill.json` as inert data, derive SBOM-minus-tests plus
   `skill.json`, require exact regular-file closure, and verify every payload
   file against the signed manifest.
8. Stream each member into a fresh controlled staging directory, recheck size
   and SHA-256 while writing, and publish with a platform no-replace atomic
   rename.

OpenSSL runs without a shell, with a minimal environment, captured output, and
a timeout. The downloader requests identity encoding, uses timeouts, rejects
HTTP downgrade/unexpected redirect hosts, and enforces both declared and read
byte bounds. Public failures use fixed labels; downloaded bytes, failed
manifest values, subprocess output, OS details, and user paths are never
reported.

The repository canonical-key fingerprint was independently checked:

```text
openssl pkey -pubin -in clawsec-signing-public.pem -outform DER | shasum -a 256
711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8  -
```

## Final GREEN evidence

Commands and observed results:

```text
python3 skills/clawsec-ps-fuzz/test/test_package_contract.py
Ran 6 tests in 0.006s
OK

python3 skills/clawsec-ps-fuzz/test/test_verified_install.py
Ran 24 tests in 1.714s
OK

python3 skills/clawsec-ps-fuzz/test/test_ps_fuzz_runner.py
Ran 45 tests in 0.533s
OK

python3 -m py_compile \
  skills/clawsec-ps-fuzz/scripts/verified_install.py \
  skills/clawsec-ps-fuzz/test/test_verified_install.py
exit 0

python3 utils/validate_skill.py skills/clawsec-ps-fuzz
Validation PASSED - all checks passed
[OK] Skill is valid

git diff --check
exit 0
```

The 45 existing runner tests provide the regression evidence that Task 4's
runtime/native-wheel support matrix, dependency lock, authorization ordering,
redaction, URL approvals, and isolated state behavior were not changed.

`ruff` was not installed on this host (`zsh: command not found: ruff`), so it
could not be added as supplemental lint evidence. It was not one of Task 5's
required gates; syntax compilation, focused tests, skill validation, and diff
checking are recorded above.

## Changed files

```text
.superpowers/sdd/clawsec-ps-fuzz-implementation/task-5-report.md
skills/clawsec-ps-fuzz/CHANGELOG.md
skills/clawsec-ps-fuzz/README.md
skills/clawsec-ps-fuzz/SKILL.md
skills/clawsec-ps-fuzz/scripts/verified_install.py
skills/clawsec-ps-fuzz/skill.json
skills/clawsec-ps-fuzz/test/test_package_contract.py
skills/clawsec-ps-fuzz/test/test_verified_install.py
```

No release workflow, suite catalog, runner, upstream manifest, capability
snapshot, or dependency-lock file was changed.

## Self-review and concerns

The implementation checks external signed-manifest assets structurally but
correctly derives ZIP closure only from SBOM-minus-tests plus `skill.json`;
external-only trust documents in `manifest.files` do not become required ZIP
members. Safe directory entries are allowed, while archive regular files must
match the authenticated package closure exactly.

The no-replace atomic publish uses `renamex_np(RENAME_EXCL)` on macOS,
`renameat2(RENAME_NOREPLACE)` on Linux, and documented non-replacing
`os.rename` behavior on Windows. Other platforms now fail closed without
attempting a rename; there is no check-then-rename publication fallback.

Per the task instruction not to spawn subagents or reviewers, I did not run a
fresh-agent documentation forward test myself. The deterministic documentation
contract is green, and the controller must supply the required independent
fresh-agent forward test/review.

## Fix round 1: portable no-clobber and exact test exclusion

Independent review found two gaps: the unsupported-POSIX fallback could race
between `lexists()` and `os.rename()`, and the local test-path predicate treated
leaf paths named `test`, `tests`, or `__tests__` as excluded even though the
release workflow excludes those names only when they are directory segments
with a following slash. The same round added direct NUL/original-filename ZIP
coverage.

### RED

I added three focused regressions before changing production behavior.

Command:

```text
python3 skills/clawsec-ps-fuzz/test/test_verified_install.py \
  VerifiedInstallTests.test_atomic_publish_fails_closed_without_a_known_no_replace_primitive \
  VerifiedInstallTests.test_release_test_exclusion_policy_matches_packaging_workflow \
  VerifiedInstallTests.test_nul_truncated_zip_original_name_is_rejected
```

Observed output (exit 1):

```text
FAIL test_atomic_publish_fails_closed_without_a_known_no_replace_primitive
AssertionError: VerifiedInstallError not raised

FAIL test_release_test_exclusion_policy_matches_packaging_workflow
AssertionError: True is not false

FAIL test_nul_truncated_zip_original_name_is_rejected
expected: release archive layout is unsafe
actual:   release payload does not match package SBOM

Ran 3 tests in 0.109s
FAILED (failures=3)
```

The forced-fallback test patches the platform to an unsupported POSIX value,
requires the stable `atomic no-replace is unavailable` error, asserts that
`os.rename` is never called, and confirms staging remains unpublished. The
policy boundary test includes leaf `test`, `tests`, `__tests__`, and their
nested leaf equivalents while excluding files below those directories. The
NUL test creates real ZIP bytes whose central/local original filename contains
a NUL but whose `ZipInfo.filename` is truncated by Python.

### GREEN

Production changes:

- macOS and Linux still use their native atomic no-replace primitives.
- Windows alone uses its documented non-replacing `os.rename` behavior.
- An unknown platform or missing native primitive returns a stable fail-closed
  error and never calls a racy generic rename fallback.
- The test exclusion predicate now applies directory-name matching to
  `parts[:-1]`, exactly preserving regular leaf files named `test`, `tests`, or
  `__tests__` while retaining all workflow basename patterns.
- ZIP inspection rejects NUL-truncated `orig_filename` metadata before trusting
  the sanitized `filename` property.
- Both install guides document the supported atomic-publish platforms and the
  fail-closed behavior elsewhere.

Focused GREEN output:

```text
Ran 3 tests in 0.077s
OK
```

Full fix-round verification:

```text
python3 skills/clawsec-ps-fuzz/test/test_verified_install.py
Ran 26 tests in 1.661s
OK

python3 skills/clawsec-ps-fuzz/test/test_package_contract.py
Ran 6 tests in 0.005s
OK

python3 skills/clawsec-ps-fuzz/test/test_ps_fuzz_runner.py
Ran 45 tests in 0.409s
OK

python3 -m py_compile \
  skills/clawsec-ps-fuzz/scripts/verified_install.py \
  skills/clawsec-ps-fuzz/test/test_verified_install.py
exit 0

python3 utils/validate_skill.py skills/clawsec-ps-fuzz
Validation PASSED - all checks passed
[OK] Skill is valid

node scripts/test-skill-release-workflow.mjs
exit 0

git diff --check
exit 0
```

### Fix-round self-review and concern

The unsupported-platform branch cannot reach `os.rename`; the regression
checks that directly. Known-platform missing-symbol cases also fail closed.
Existing-destination tests remain green on the native macOS no-replace path.
The predicate now matches the workflow's slash-sensitive directory patterns
and its basename patterns without widening either category. NUL rejection uses
`orig_filename` specifically so Python's safety truncation cannot hide archive
metadata from inspection.

No release workflow, suite catalog, runner, lock, or release schema changed.
The controller-owned fresh-agent documentation forward test remains the only
outstanding external check; this fix round intentionally did not perform it.
