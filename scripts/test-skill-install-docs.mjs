import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const validator = "scripts/ci/validate_skill_install_docs.mjs";
const workflow = await readFile(".github/workflows/skill-release.yml", "utf8");
const tempRoot = await mkdtemp(path.join(tmpdir(), "clawsec-install-docs-"));
const agentTypesPath = path.join(tempRoot, "vercel-types.ts");

function runValidator(args) {
  return spawnSync(
    process.execPath,
    [validator, "--root", tempRoot, "--agent-types-file", agentTypesPath, ...args],
    {
      encoding: "utf8",
    },
  );
}

async function writeSkill({ name, metadata, readme, skillMd, installMd }) {
  const skillDir = path.join(tempRoot, "skills", name);
  const releaseMetadata = installMd !== undefined && metadata.sbom === undefined
    ? {
        ...metadata,
        sbom: {
          files: [{ path: "INSTALL.md", required: true, description: "Native installation guide" }],
        },
      }
    : metadata;
  await mkdir(skillDir, { recursive: true });
  await writeFile(
    path.join(skillDir, "skill.json"),
    JSON.stringify(
      {
        name,
        version: "1.0.0",
        description: `${name} test skill`,
        license: "AGPL-3.0-or-later",
        ...releaseMetadata,
      },
      null,
      2,
    ),
  );
  await writeFile(path.join(skillDir, "README.md"), readme);
  await writeFile(path.join(skillDir, "SKILL.md"), skillMd);
  if (installMd !== undefined) {
    await writeFile(path.join(skillDir, "INSTALL.md"), installMd);
  }
}

try {
  await writeFile(
    agentTypesPath,
    "export type AgentType = | 'codex' | 'hermes-agent' | 'openclaw' | 'universal';\n",
  );

  await writeSkill({
    name: "hermes-example",
    metadata: { hermes: { category: "security" } },
    readme: "# Hermes Example\n\n## Installation\n\nMissing the Skills CLI command.\n",
    skillMd: "---\nname: hermes-example\nversion: 1.0.0\n---\n\n## Installation\n\nMissing the Skills CLI command.\n",
  });

  const missingHermes = runValidator(["--skills", "skills/hermes-example"]);
  assert.equal(missingHermes.status, 1, "missing Hermes install docs must fail validation");
  assert.match(
    missingHermes.stderr,
    /npx skills add prompt-security\/clawsec --skill hermes-example -a hermes-agent -y/,
    "Hermes skills must require the hermes-agent installer target",
  );

  await writeSkill({
    name: "hermes-example",
    metadata: { hermes: { category: "security" } },
    readme:
      "# Hermes Example\n\n## Vercel Skills Installation\n\n```bash\nnpx skills add prompt-security/clawsec --skill hermes-example -a hermes-agent -y\n```\n",
    skillMd:
      "---\nname: hermes-example\nversion: 1.0.0\n---\n\n## Vercel Skills Installation\n\n```bash\nnpx skills add prompt-security/clawsec --skill hermes-example -a hermes-agent -y\n```\n",
  });

  const validHermes = runValidator(["--skills", "skills/hermes-example"]);
  assert.equal(
    validHermes.status,
    0,
    `valid Hermes install docs should pass\nstdout:\n${validHermes.stdout}\nstderr:\n${validHermes.stderr}`,
  );

  await writeSkill({
    name: "hermes-env-prefix",
    metadata: { hermes: { category: "security" } },
    readme:
      "# Hermes Environment Prefix\n\n```bash\nNODE_OPTIONS=--require=./evil.js npx skills add prompt-security/clawsec --skill hermes-env-prefix -a hermes-agent -y\n```\n",
    skillMd:
      "---\nname: hermes-env-prefix\nversion: 1.0.0\n---\n\n```bash\nNODE_OPTIONS=--require=./evil.js npx skills add prompt-security/clawsec --skill hermes-env-prefix -a hermes-agent -y\n```\n",
  });
  const environmentPrefix = runValidator(["--skills", "skills/hermes-env-prefix"]);
  assert.equal(environmentPrefix.status, 1, "environment assignments must not prefix an approved command");
  assert.match(environmentPrefix.stderr, /no wrapper, environment assignment/);

  for (const [label, wrappedCommand] of [
    ["sudo", "sudo npx skills add prompt-security/clawsec --skill hermes-wrapped-sudo -a hermes-agent -y"],
    ["env", "env npx skills add prompt-security/clawsec --skill hermes-wrapped-env -a hermes-agent -y"],
    ["command", "command npx skills add prompt-security/clawsec --skill hermes-wrapped-command -a hermes-agent -y"],
    [
      "shell",
      "bash -c 'npx skills add prompt-security/clawsec --skill hermes-wrapped-shell -a hermes-agent -y'",
    ],
  ]) {
    const name = `hermes-wrapped-${label}`;
    const canonical = `npx skills add prompt-security/clawsec --skill ${name} -a hermes-agent -y`;
    await writeSkill({
      name,
      metadata: { hermes: { category: "security" } },
      readme: `# Wrapped Hermes Command\n\n\`\`\`bash\n${canonical}\n${wrappedCommand}\n\`\`\`\n`,
      skillMd: `---\nname: ${name}\nversion: 1.0.0\n---\n\n\`\`\`bash\n${canonical}\n${wrappedCommand}\n\`\`\`\n`,
    });
    const wrapped = runValidator(["--skills", `skills/${name}`]);
    assert.equal(wrapped.status, 1, `${label} wrapped commands must fail even beside a canonical command`);
    assert.match(wrapped.stderr, /no wrapper, environment assignment/);
  }

  await writeSkill({
    name: "hermes-example",
    metadata: { hermes: { category: "security" } },
    readme:
      "# Hermes Example\n\n```bash\nnpx skills add prompt-security/clawsec-evil --skill hermes-example-evil -a hermes-agent-evil --yes-please\n# npx skills add prompt-security/clawsec --skill hermes-example -a hermes-agent -y\n```\n",
    skillMd:
      "---\nname: hermes-example\nversion: 1.0.0\n---\n\n```bash\nnpx skills add prompt-security/clawsec-evil --skill hermes-example-evil -a hermes-agent-evil --yes-please\n# npx skills add prompt-security/clawsec --skill hermes-example -a hermes-agent -y\n```\n",
  });
  const suffixAndCommentBypass = runValidator(["--skills", "skills/hermes-example"]);
  assert.equal(suffixAndCommentBypass.status, 1, "suffixes and commented commands must not satisfy validation");
  assert.match(suffixAndCommentBypass.stderr, /hermes-example -a hermes-agent -y/);

  await writeSkill({
    name: "hermes-example",
    metadata: { hermes: { category: "security" } },
    readme:
      "# Hermes Example\n\n```bash\nnpx skills add prompt-security/clawsec \\\n  --skill hermes-example \\\n  --agent hermes-agent \\\n  --yes\n```\n",
    skillMd:
      "---\nname: hermes-example\nversion: 1.0.0\n---\n\n```bash\nnpx skills add prompt-security/clawsec \\\n  --skill hermes-example \\\n  --agent hermes-agent \\\n  --yes\n```\n",
  });
  const multilineHermes = runValidator(["--skills", "skills/hermes-example"]);
  assert.equal(multilineHermes.status, 0, `canonical multiline commands should pass\n${multilineHermes.stderr}`);

  await writeSkill({
    name: "hermes-example",
    metadata: { hermes: { category: "security" } },
    readme:
      "# Hermes Example\n\n```bash\nnpx skills add prompt-security/clawsec --skill hermes-example --agent hermes-agent --agent openclaw -y\n```\n",
    skillMd:
      "---\nname: hermes-example\nversion: 1.0.0\n---\n\n```bash\nnpx skills add prompt-security/clawsec --skill hermes-example --agent hermes-agent --agent openclaw -y\n```\n",
  });
  const duplicateAgent = runValidator(["--skills", "skills/hermes-example"]);
  assert.equal(duplicateAgent.status, 1, "duplicate agent options must fail closed");
  assert.match(duplicateAgent.stderr, /reviewed command grammar with exactly one --skill/);

  await writeSkill({
    name: "hermes-example",
    metadata: { hermes: { category: "security" } },
    readme:
      "# Hermes Example\n\n```bash\nnpx skills add prompt-security/clawsec --skill hermes-example -a hermes-agent -y ; echo unsafe\n```\n",
    skillMd:
      "---\nname: hermes-example\nversion: 1.0.0\n---\n\n```bash\nnpx skills add prompt-security/clawsec --skill hermes-example -a hermes-agent -y ; echo unsafe\n```\n",
  });
  const shellControlOperator = runValidator(["--skills", "skills/hermes-example"]);
  assert.equal(shellControlOperator.status, 1, "shell control operators must fail closed");
  assert.match(shellControlOperator.stderr, /no executable shell syntax or extra tokens/);

  for (const [label, suffix] of [
    ["command-substitution", '"$(printf unsafe)"'],
    ["backticks", '"`printf unsafe`"'],
    ["redirection", ">proof.txt"],
    ["extra-positional", "unexpected"],
  ]) {
    const name = `hermes-unsafe-${label}`;
    const command = `npx skills add prompt-security/clawsec --skill ${name} -a hermes-agent -y ${suffix}`;
    await writeSkill({
      name,
      metadata: { hermes: { category: "security" } },
      readme: `# Unsafe Hermes Example\n\n\`\`\`bash\n${command}\n\`\`\`\n`,
      skillMd: `---\nname: ${name}\nversion: 1.0.0\n---\n\n\`\`\`bash\n${command}\n\`\`\`\n`,
    });
    const unsafeCommand = runValidator(["--skills", `skills/${name}`]);
    assert.equal(unsafeCommand.status, 1, `${label} syntax must fail closed`);
    assert.match(unsafeCommand.stderr, /no executable shell syntax or extra tokens/);
  }

  await writeSkill({
    name: "hermes-comment-example",
    metadata: { hermes: { category: "security" } },
    readme:
      "# Hermes Comment Example\n\n<!-- npx skills add prompt-security/clawsec --skill hermes-comment-example -a hermes-agent -y -->\n",
    skillMd:
      "---\nname: hermes-comment-example\nversion: 1.0.0\n---\n\n<!-- npx skills add prompt-security/clawsec --skill hermes-comment-example -a hermes-agent -y -->\n",
  });
  const hiddenHermesCommand = runValidator(["--skills", "skills/hermes-comment-example"]);
  assert.equal(hiddenHermesCommand.status, 1, "HTML-comment-only commands must not satisfy validation");
  assert.match(hiddenHermesCommand.stderr, /hermes-comment-example -a hermes-agent -y/);

  await writeSkill({
    name: "codex-example",
    metadata: { platform: "codex" },
    readme:
      "# Codex Example\n\n## Vercel Skills Installation\n\n```bash\nnpx skills add prompt-security/clawsec --skill codex-example -a openclaw -y\n```\n",
    skillMd:
      "---\nname: codex-example\nversion: 1.0.0\n---\n\n## Vercel Skills Installation\n\n```bash\nnpx skills add prompt-security/clawsec --skill codex-example -a openclaw -y\n```\n",
  });

  const wrongExactTarget = runValidator(["--skills", "skills/codex-example"]);
  assert.equal(wrongExactTarget.status, 1, "exact AgentType matches must use their matched target");
  assert.match(
    wrongExactTarget.stderr,
    /npx skills add prompt-security\/clawsec --skill codex-example -a codex -y/,
    "Exact AgentType matches must not fall back to openclaw",
  );

  await writeSkill({
    name: "nanoclaw-example",
    metadata: { platform: "nanoclaw", nanoclaw: { category: "security" } },
    readme:
      "# NanoClaw Example\n\n## Vercel Skills Installation\n\n```bash\nnpx skills add https://github.com/evil/fork --skill nanoclaw-example -a openclaw -y\n```\n",
    skillMd:
      "---\nname: nanoclaw-example\nversion: 1.0.0\n---\n\n## Vercel Skills Installation\n\n```bash\nnpx skills add https://github.com/evil/fork --skill nanoclaw-example -a openclaw -y\n```\n",
  });

  const wrongNanoTarget = runValidator(["--skills", "skills/nanoclaw-example"]);
  assert.equal(wrongNanoTarget.status, 1, "NanoClaw docs must fail when they claim any unrelated agent target");
  assert.match(
    wrongNanoTarget.stderr,
    /Unsupported npx skills install command[\s\S]*nanoclaw has no reviewed direct AgentType target/,
    "NanoClaw must not silently fall back to an OpenClaw or Hermes target",
  );

  await writeSkill({
    name: "nanoclaw-unterminated-quote",
    metadata: { platform: "nanoclaw" },
    readme:
      "# NanoClaw Unterminated Quote\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n\nnpx skills add prompt-security/clawsec --skill nanoclaw-unterminated-quote --agent \"openclaw --yes",
    skillMd:
      "---\nname: nanoclaw-unterminated-quote\nversion: 1.0.0\n---\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n\nnpx skills add prompt-security/clawsec --skill nanoclaw-unterminated-quote --agent \"openclaw --yes",
    installMd: "# Native installation\n",
  });
  const unterminatedQuote = runValidator(["--skills", "skills/nanoclaw-unterminated-quote"]);
  assert.equal(unterminatedQuote.status, 1, "an unterminated quoted install candidate must fail closed");
  assert.match(unterminatedQuote.stderr, /Invalid npx skills install command/);

  await writeSkill({
    name: "nanoclaw-trailing-continuation",
    metadata: { platform: "nanoclaw" },
    readme:
      "# NanoClaw Trailing Continuation\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n\nnpx skills add prompt-security/clawsec --skill nanoclaw-trailing-continuation --agent openclaw --yes \\",
    skillMd:
      "---\nname: nanoclaw-trailing-continuation\nversion: 1.0.0\n---\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n\nnpx skills add prompt-security/clawsec --skill nanoclaw-trailing-continuation --agent openclaw --yes \\",
    installMd: "# Native installation\n",
  });
  const trailingContinuation = runValidator(["--skills", "skills/nanoclaw-trailing-continuation"]);
  assert.equal(trailingContinuation.status, 1, "a trailing continuation install candidate must fail closed");
  assert.match(trailingContinuation.stderr, /Invalid npx skills install command/);

  await writeSkill({
    name: "nanoclaw-example",
    metadata: { platform: "nanoclaw", nanoclaw: { category: "security" } },
    readme:
      "# NanoClaw Example\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    skillMd:
      "---\nname: nanoclaw-example\nversion: 1.0.0\n---\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    installMd: "# Native installation\n",
  });

  const nativeNano = runValidator(["--skills", "skills/nanoclaw-example"]);
  assert.equal(
    nativeNano.status,
    0,
    `NanoClaw docs without a fabricated direct target should pass\nstdout:\n${nativeNano.stdout}\nstderr:\n${nativeNano.stderr}`,
  );
  assert.match(nativeNano.stdout, /not applicable[\s\S]*nanoclaw/);

  await writeSkill({
    name: "nanoclaw-wrapped-command",
    metadata: { platform: "nanoclaw" },
    readme:
      "# Unsupported Wrapped Command\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n\n```bash\nsudo npx skills add prompt-security/clawsec --skill nanoclaw-wrapped-command -a openclaw -y\n```\n",
    skillMd:
      "---\nname: nanoclaw-wrapped-command\nversion: 1.0.0\n---\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n\n```bash\nsudo npx skills add prompt-security/clawsec --skill nanoclaw-wrapped-command -a openclaw -y\n```\n",
    installMd: "# Native installation\n",
  });
  const unsupportedWrappedCommand = runValidator(["--skills", "skills/nanoclaw-wrapped-command"]);
  assert.equal(unsupportedWrappedCommand.status, 1, "unsupported harness docs must reject wrapped commands");
  assert.match(unsupportedWrappedCommand.stderr, /no wrapper, environment assignment/);

  await writeSkill({
    name: "native-wrong-harness-statement",
    metadata: { platform: "nanoclaw" },
    readme:
      "# Wrong Harness Statement\n\nPicoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    skillMd:
      "---\nname: native-wrong-harness-statement\nversion: 1.0.0\n---\n\nPicoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    installMd: "# Native installation\n",
  });
  const wrongHarnessStatement = runValidator(["--skills", "skills/native-wrong-harness-statement"]);
  assert.equal(wrongHarnessStatement.status, 1, "a no-target statement must name the unsupported harness");
  assert.match(wrongHarnessStatement.stderr, /Missing explicit no-direct-target statement[\s\S]*nanoclaw/);

  await writeSkill({
    name: "mixed-harness-claim",
    metadata: { platform: "nanoclaw" },
    readme:
      "# Mixed Harness Claim\n\nNanoClaw supports a direct target. PicoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    skillMd:
      "---\nname: mixed-harness-claim\nversion: 1.0.0\n---\n\nNanoClaw supports a direct target. PicoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    installMd: "# Native installation\n",
  });
  const mixedHarnessClaim = runValidator(["--skills", "skills/mixed-harness-claim"]);
  assert.equal(mixedHarnessClaim.status, 1, "a nearby statement about another harness must not cross-bind");
  assert.match(mixedHarnessClaim.stderr, /Missing explicit no-direct-target statement[\s\S]*nanoclaw/);

  await writeSkill({
    name: "nanoclaw-unpackaged-guide",
    metadata: { platform: "nanoclaw", sbom: { files: [] } },
    readme:
      "# Unpackaged Native Guide\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    skillMd:
      "---\nname: nanoclaw-unpackaged-guide\nversion: 1.0.0\n---\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    installMd: "# Native installation\n",
  });
  const unpackagedNativeGuide = runValidator(["--skills", "skills/nanoclaw-unpackaged-guide"]);
  assert.equal(unpackagedNativeGuide.status, 1, "native install guides must be included in release SBOM files");
  assert.match(unpackagedNativeGuide.stderr, /omitted from skill\.json sbom\.files[\s\S]*INSTALL\.md/);

  await writeSkill({
    name: "nanoclaw-filtered-guide",
    metadata: {
      platform: "nanoclaw",
      sbom: {
        files: [{ path: "tests/INSTALL.md", required: true, description: "Filtered test guide" }],
      },
    },
    readme:
      "# Filtered Native Guide\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./tests/INSTALL.md).\n",
    skillMd:
      "---\nname: nanoclaw-filtered-guide\nversion: 1.0.0\n---\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./tests/INSTALL.md).\n",
  });
  const filteredGuideRoot = path.join(tempRoot, "skills", "nanoclaw-filtered-guide", "tests");
  await mkdir(filteredGuideRoot);
  await writeFile(path.join(filteredGuideRoot, "INSTALL.md"), "# Filtered native installation\n");
  const filteredNativeGuide = runValidator(["--skills", "skills/nanoclaw-filtered-guide"]);
  assert.equal(filteredNativeGuide.status, 1, "release-filtered test paths must not count as packaged guides");
  assert.match(filteredNativeGuide.stderr, /omitted from skill\.json sbom\.files[\s\S]*tests\/INSTALL\.md/);

  await writeSkill({
    name: "nanoclaw-comment-example",
    metadata: { platform: "nanoclaw", nanoclaw: { category: "security" } },
    readme:
      "# NanoClaw Comment Example\n\n<!-- NanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md). -->\n",
    skillMd:
      "---\nname: nanoclaw-comment-example\nversion: 1.0.0\n---\n\n<!-- NanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md). -->\n",
    installMd: "# Native installation\n",
  });
  const hiddenNanoRequirements = runValidator(["--skills", "skills/nanoclaw-comment-example"]);
  assert.equal(hiddenNanoRequirements.status, 1, "HTML-comment-only native guidance must not satisfy validation");
  assert.match(hiddenNanoRequirements.stderr, /Missing explicit no-direct-target statement/);
  assert.match(hiddenNanoRequirements.stderr, /Missing local harness-native installation reference/);

  await writeSkill({
    name: "nanoclaw-directory-reference",
    metadata: { platform: "nanoclaw" },
    readme:
      "# NanoClaw Directory Reference\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    skillMd:
      "---\nname: nanoclaw-directory-reference\nversion: 1.0.0\n---\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
  });
  await mkdir(path.join(tempRoot, "skills", "nanoclaw-directory-reference", "INSTALL.md"));
  const directoryReference = runValidator(["--skills", "skills/nanoclaw-directory-reference"]);
  assert.equal(directoryReference.status, 1, "a directory must not count as a native install document");
  assert.match(directoryReference.stderr, /Missing local harness-native installation reference/);

  const outsideInstallPath = path.join(tempRoot, "outside-native-install.md");
  await writeFile(outsideInstallPath, "# Outside native installation\n");
  await writeSkill({
    name: "nanoclaw-symlink-reference",
    metadata: { platform: "nanoclaw" },
    readme:
      "# NanoClaw Symlink Reference\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    skillMd:
      "---\nname: nanoclaw-symlink-reference\nversion: 1.0.0\n---\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
  });
  await symlink(
    outsideInstallPath,
    path.join(tempRoot, "skills", "nanoclaw-symlink-reference", "INSTALL.md"),
  );
  const symlinkReference = runValidator(["--skills", "skills/nanoclaw-symlink-reference"]);
  assert.equal(symlinkReference.status, 1, "an escaping symlink must not count as a native install document");
  assert.match(symlinkReference.stderr, /Missing local harness-native installation reference/);

  await writeSkill({
    name: "picoclaw-example",
    metadata: { platform: "picoclaw", picoclaw: { category: "security" } },
    readme:
      "# PicoClaw Example\n\n```bash\nnpx skills add prompt-security/clawsec --skill picoclaw-example -a openclaw -y\n```\n",
    skillMd:
      "---\nname: picoclaw-example\nversion: 1.0.0\n---\n\n```bash\nnpx skills add prompt-security/clawsec --skill picoclaw-example -a openclaw -y\n```\n",
  });
  const wrongPicoTarget = runValidator(["--skills", "skills/picoclaw-example"]);
  assert.equal(wrongPicoTarget.status, 1, "PicoClaw must not inherit an OpenClaw installer target");
  assert.match(wrongPicoTarget.stderr, /picoclaw has no reviewed direct AgentType target/);

  await writeSkill({
    name: "multi-example",
    metadata: { platforms: ["openclaw", "nanoclaw", "hermes", "picoclaw"] },
    readme:
      "# Multi Example\n\nNanoClaw and PicoClaw have no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n\n```bash\nnpx skills add prompt-security/clawsec --skill multi-example -a openclaw -y\n```\n",
    skillMd:
      "---\nname: multi-example\nversion: 1.0.0\n---\n\nNanoClaw and PicoClaw have no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n\n```bash\nnpx skills add prompt-security/clawsec --skill multi-example -a openclaw -y\n```\n",
    installMd: "# Native installation\n",
  });
  const missingMultiTarget = runValidator(["--skills", "skills/multi-example"]);
  assert.equal(missingMultiTarget.status, 1, "multi-platform docs must cover every reviewed direct target");
  assert.match(missingMultiTarget.stderr, /multi-example -a hermes-agent -y/);

  await writeSkill({
    name: "multi-no-native-example",
    metadata: { platforms: ["openclaw", "nanoclaw", "hermes"] },
    readme:
      "# Multi No Native Example\n\nNanoClaw has no reviewed direct Agent Skills target.\n\n```bash\nnpx skills add prompt-security/clawsec --skill multi-no-native-example -a openclaw -y\nnpx skills add prompt-security/clawsec --skill multi-no-native-example -a hermes-agent -y\n```\n",
    skillMd:
      "---\nname: multi-no-native-example\nversion: 1.0.0\n---\n\nNanoClaw has no reviewed direct Agent Skills target.\n\n```bash\nnpx skills add prompt-security/clawsec --skill multi-no-native-example -a openclaw -y\nnpx skills add prompt-security/clawsec --skill multi-no-native-example -a hermes-agent -y\n```\n",
  });
  const mixedMissingNativeReference = runValidator(["--skills", "skills/multi-no-native-example"]);
  assert.equal(mixedMissingNativeReference.status, 1, "mixed-platform docs must link a native install guide");
  assert.match(mixedMissingNativeReference.stderr, /Missing local harness-native installation reference/);

  await writeSkill({
    name: "multi-example",
    metadata: { platforms: ["openclaw", "nanoclaw", "hermes", "picoclaw"] },
    readme:
      "# Multi Example\n\nNanoClaw and PicoClaw have no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n\n```bash\nnpx skills add prompt-security/clawsec --skill multi-example -a openclaw -y\nnpx skills add prompt-security/clawsec --skill multi-example -a hermes-agent -y\n```\n",
    skillMd:
      "---\nname: multi-example\nversion: 1.0.0\n---\n\nNanoClaw and PicoClaw have no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n\n```bash\nnpx skills add prompt-security/clawsec --skill multi-example -a openclaw -y\nnpx skills add prompt-security/clawsec --skill multi-example -a hermes-agent -y\n```\n",
    installMd: "# Native installation\n",
  });
  const validMulti = runValidator(["--skills", "skills/multi-example"]);
  assert.equal(validMulti.status, 0, `valid multi-target docs should pass\n${validMulti.stderr}`);
  assert.match(validMulti.stdout, /-a hermes-agent, -a openclaw; no direct target for nanoclaw, picoclaw/);

  await writeSkill({
    name: "missing-platform",
    metadata: {},
    readme: "# Missing Platform\n",
    skillMd: "---\nname: missing-platform\nversion: 1.0.0\n---\n",
  });
  const missingPlatform = runValidator(["--skills", "skills/missing-platform"]);
  assert.equal(missingPlatform.status, 1, "platform metadata is required for installer policy");
  assert.match(missingPlatform.stderr, /Skill metadata does not declare a platform/);

  await rm(path.join(tempRoot, "skills", "nanoclaw-example", "README.md"));
  const missingNativeDoc = runValidator(["--skills", "skills/nanoclaw-example"]);
  assert.equal(missingNativeDoc.status, 1, "not-applicable skills must still ship both documentation files");
  assert.match(missingNativeDoc.stderr, /Missing required install documentation file/);

  await writeFile(
    agentTypesPath,
    "export type AgentType = | 'codex' | 'hermes-agent' | 'nanoclaw' | 'openclaw' | 'universal';\n",
  );
  await writeSkill({
    name: "nanoclaw-example",
    metadata: { platform: "nanoclaw" },
    readme:
      "# NanoClaw Example\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    skillMd:
      "---\nname: nanoclaw-example\nversion: 1.0.0\n---\n\nNanoClaw has no reviewed direct Agent Skills target. Use the [native installation guide](./INSTALL.md).\n",
    installMd: "# Native installation\n",
  });
  const unreviewedUpstreamNano = runValidator(["--skills", "skills/nanoclaw-example"]);
  assert.equal(unreviewedUpstreamNano.status, 0, "an upstream AgentType must not auto-activate an unreviewed harness mapping");
  assert.match(unreviewedUpstreamNano.stdout, /not applicable[\s\S]*nanoclaw/);

  await writeFile(
    agentTypesPath,
    "export type AgentType = | 'codex' | 'future-agent' | 'hermes-agent' | 'openclaw' | 'universal';\n",
  );
  await writeSkill({
    name: "future-example",
    metadata: { platform: "future-agent" },
    readme: "# Future Example\n",
    skillMd: "---\nname: future-example\nversion: 1.0.0\n---\n",
  });
  const unreviewedFutureTarget = runValidator(["--skills", "skills/future-example"]);
  assert.equal(unreviewedFutureTarget.status, 1, "upstream additions must not authorize new platform mappings");
  assert.match(unreviewedFutureTarget.stderr, /Unknown platform without a reviewed npx skills target: future-agent/);

  await writeFile(
    agentTypesPath,
    "export type AgentType = | 'codex' | 'openclaw' | 'universal';\n",
  );
  const missingConfiguredHermes = runValidator(["--skills", "skills/hermes-example"]);
  assert.equal(missingConfiguredHermes.status, 1, "a missing reviewed upstream target must fail closed");
  assert.match(missingConfiguredHermes.stderr, /Configured npx skills target hermes-agent for hermes is unavailable/);

  assert.match(
    workflow,
    /Validate npx skills install docs/,
    "Skill release workflow must run the install-doc validator",
  );
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}
