import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const fixtureRoot = await mkdtemp(path.join(tmpdir(), "clawsec-release-script-installability-"));
const skillDir = path.join(fixtureRoot, "skills", "retired-skill");
const scriptsDir = path.join(fixtureRoot, "scripts");
const ciDir = path.join(scriptsDir, "ci");
const releasePolicyDir = path.join(fixtureRoot, "contracts", "release-policy");
const fakeBinDir = path.join(fixtureRoot, "fake-bin");
const ghAttemptPath = path.join(fixtureRoot, "gh-attempted");
const childPath = `${fakeBinDir}:${path.dirname(process.execPath)}:${process.env.PATH ?? ""}`;

function run(command, args, extraEnv = {}) {
  return spawnSync(command, args, {
    cwd: fixtureRoot,
    encoding: "utf8",
    env: { ...process.env, PATH: childPath, ...extraEnv },
  });
}

function runGit(...args) {
  const result = run("git", args);
  assert.equal(
    result.status,
    0,
    `git ${args.join(" ")} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  return result.stdout.trim();
}

try {
  await Promise.all([
    mkdir(skillDir, { recursive: true }),
    mkdir(ciDir, { recursive: true }),
    mkdir(releasePolicyDir, { recursive: true }),
    mkdir(fakeBinDir, { recursive: true }),
  ]);
  await Promise.all([
    cp("scripts/release-skill.sh", path.join(scriptsDir, "release-skill.sh")),
    cp("scripts/ci/skill_installability.mjs", path.join(ciDir, "skill_installability.mjs")),
    cp("scripts/ci/stable_tag_policy.mjs", path.join(ciDir, "stable_tag_policy.mjs")),
    cp("scripts/ci/lifecycle_semver.mjs", path.join(ciDir, "lifecycle_semver.mjs")),
    cp(
      "contracts/release-policy/legacy-prereleases-v1.json",
      path.join(releasePolicyDir, "legacy-prereleases-v1.json"),
    ),
    writeFile(
      path.join(skillDir, "skill.json"),
      `${JSON.stringify({
        name: "retired-skill",
        version: "0.0.1",
        installable: false,
      }, null, 2)}\n`,
    ),
    writeFile(
      path.join(skillDir, "SKILL.md"),
      "---\nname: retired-skill\nversion: 0.0.1\n---\n\n# Retired skill\n",
    ),
    writeFile(
      path.join(skillDir, "CHANGELOG.md"),
      "# Changelog\n\n## [0.0.2] - 2026-07-22\n\n- Test release.\n",
    ),
    mkdir(path.join(fixtureRoot, "skills", "broken-skill"), { recursive: true }),
    writeFile(
      path.join(fakeBinDir, "gh"),
      `#!/bin/sh\nprintf attempted > "${ghAttemptPath}"\nexit 0\n`,
    ),
    writeFile(
      path.join(fakeBinDir, "mv"),
      "#!/bin/sh\n/bin/mv \"$@\"\n" +
        "if [ -n \"${CLAWSEC_TEST_SIGNAL_AFTER_APPLY:-}\" ] && " +
        "[ \"${2:-}\" = \"skills/retired-skill/skill.json\" ]; then\n" +
        "  kill \"-$CLAWSEC_TEST_SIGNAL_AFTER_APPLY\" \"$PPID\"\nfi\n",
    ),
  ]);
  await Promise.all([
    writeFile(
      path.join(fixtureRoot, "skills", "broken-skill", "skill.json"),
      `${JSON.stringify({
        name: "broken-skill",
        version: "0.0.1",
        installable: false,
      }, null, 2)}\n`,
    ),
    writeFile(
      path.join(fixtureRoot, "skills", "broken-skill", "SKILL.md"),
      "---\nname: broken-skill\n---\n\n# Broken skill\n",
    ),
    writeFile(
      path.join(fixtureRoot, "skills", "broken-skill", "CHANGELOG.md"),
      "# Changelog\n\n## [0.0.2] - 2026-07-22\n\n- Test release.\n",
    ),
  ]);
  await Promise.all([
    chmod(path.join(fakeBinDir, "gh"), 0o700),
    chmod(path.join(fakeBinDir, "mv"), 0o700),
  ]);

  runGit("init", "--initial-branch=main");
  runGit("config", "user.name", "ClawSec Test");
  runGit("config", "user.email", "clawsec-test@example.invalid");
  runGit("config", "commit.gpgsign", "false");
  runGit("config", "tag.gpgsign", "false");
  runGit("add", ".");
  runGit("commit", "-m", "test fixture");

  const mainHead = runGit("rev-parse", "HEAD");
  const fullRelease = run("bash", ["scripts/release-skill.sh", "retired-skill", "0.0.2"]);
  assert.equal(fullRelease.status, 1, "main-branch version preparation must fail");
  assert.match(fullRelease.stderr, /must run on a review branch, not protected main/);
  assert.equal(runGit("rev-parse", "HEAD"), mainHead, "denial must happen before commit creation");
  assert.equal(runGit("status", "--short"), "", "denial must happen before file mutation or staging");
  assert.equal(runGit("tag", "--list"), "", "denial must happen before tag creation");
  assert.equal(existsSync(ghAttemptPath), false, "denial must happen before GitHub release creation");

  runGit("switch", "-c", "review/non-installable");
  const malformedHead = runGit("rev-parse", "HEAD");
  const malformedPrep = run("bash", ["scripts/release-skill.sh", "broken-skill", "0.0.2"]);
  assert.equal(malformedPrep.status, 1, "invalid metadata must fail before applying any file");
  assert.match(malformedPrep.stderr, /SKILL\.md is missing a frontmatter version/);
  assert.equal(runGit("rev-parse", "HEAD"), malformedHead);
  assert.equal(runGit("status", "--short"), "", "pre-apply failure must preserve a clean tree");
  const brokenSkill = JSON.parse(
    await readFile(path.join(fixtureRoot, "skills", "broken-skill", "skill.json"), "utf8"),
  );
  assert.equal(brokenSkill.version, "0.0.1", "pre-apply failure must preserve original metadata");

  for (const [signal, expectedStatus] of [
    ["HUP", 129],
    ["INT", 130],
    ["TERM", 143],
  ]) {
    const signalFailureHead = runGit("rev-parse", "HEAD");
    const signalFailure = run(
      "bash",
      ["scripts/release-skill.sh", "retired-skill", "0.0.2"],
      { CLAWSEC_TEST_SIGNAL_AFTER_APPLY: signal },
    );
    assert.equal(
      signalFailure.status,
      expectedStatus,
      `${signal} during apply must exit with the signal status`,
    );
    assert.match(signalFailure.stderr, /restoring the original clean tree/);
    assert.equal(runGit("rev-parse", "HEAD"), signalFailureHead, `${signal} must not move HEAD`);
    assert.equal(runGit("status", "--short"), "", `${signal} must restore index and worktree`);
    const signalRolledBackSkill = JSON.parse(
      await readFile(path.join(skillDir, "skill.json"), "utf8"),
    );
    assert.equal(
      signalRolledBackSkill.version,
      "0.0.1",
      `${signal} must restore original metadata`,
    );
  }

  const preCommitHook = path.join(fixtureRoot, ".git", "hooks", "pre-commit");
  await writeFile(
    preCommitHook,
    "#!/bin/sh\nif [ \"${CLAWSEC_TEST_FAIL_COMMIT:-}\" = \"1\" ]; then\n" +
      "  echo 'injected commit failure' >&2\n  exit 1\nfi\n",
  );
  await chmod(preCommitHook, 0o700);
  const commitFailureHead = runGit("rev-parse", "HEAD");
  const commitFailure = run(
    "bash",
    ["scripts/release-skill.sh", "retired-skill", "0.0.2"],
    { CLAWSEC_TEST_FAIL_COMMIT: "1" },
  );
  assert.equal(commitFailure.status, 1, "commit-hook failure must fail version preparation");
  assert.match(commitFailure.stderr, /injected commit failure/);
  assert.match(commitFailure.stderr, /restoring the original clean tree/);
  assert.equal(runGit("rev-parse", "HEAD"), commitFailureHead, "failed commit must not move HEAD");
  assert.equal(runGit("status", "--short"), "", "failed commit must restore index and worktree");
  const rolledBackSkill = JSON.parse(await readFile(path.join(skillDir, "skill.json"), "utf8"));
  assert.equal(rolledBackSkill.version, "0.0.1", "failed commit must restore original version");

  const prepOnly = run("bash", ["scripts/release-skill.sh", "retired-skill", "0.0.2"]);
  assert.equal(
    prepOnly.status,
    0,
    `review-only version preparation failed\nstdout:\n${prepOnly.stdout}\nstderr:\n${prepOnly.stderr}`,
  );
  assert.match(prepOnly.stdout, /signed denial evidence/);
  assert.match(
    prepOnly.stdout,
    /Do not request a public tag, GitHub Release, store publication, or catalog activation/,
  );
  assert.equal(runGit("tag", "--list"), "", "review-only preparation must not create a tag");
  assert.equal(existsSync(ghAttemptPath), false, "review-only preparation must not create a release");
  assert.equal(runGit("status", "--short"), "", "review-only preparation must leave a clean commit");
  const preparedSkill = JSON.parse(await readFile(path.join(skillDir, "skill.json"), "utf8"));
  assert.equal(preparedSkill.version, "0.0.2");

  process.stdout.write("Skill release script installability tests passed.\n");
} finally {
  await rm(fixtureRoot, { recursive: true, force: true });
}
