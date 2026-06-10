import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

async function writeSkill({ name, metadata, readme, skillMd }) {
  const skillDir = path.join(tempRoot, "skills", name);
  await mkdir(skillDir, { recursive: true });
  await writeFile(
    path.join(skillDir, "skill.json"),
    JSON.stringify(
      {
        name,
        version: "1.0.0",
        description: `${name} test skill`,
        license: "AGPL-3.0-or-later",
        ...metadata,
      },
      null,
      2,
    ),
  );
  await writeFile(path.join(skillDir, "README.md"), readme);
  await writeFile(path.join(skillDir, "SKILL.md"), skillMd);
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
      "# NanoClaw Example\n\n## Vercel Skills Installation\n\n```bash\nnpx skills add prompt-security/clawsec --skill nanoclaw-example -a hermes-agent -y\n```\n",
    skillMd:
      "---\nname: nanoclaw-example\nversion: 1.0.0\n---\n\n## Vercel Skills Installation\n\n```bash\nnpx skills add prompt-security/clawsec --skill nanoclaw-example -a hermes-agent -y\n```\n",
  });

  const wrongNanoTarget = runValidator(["--skills", "skills/nanoclaw-example"]);
  assert.equal(wrongNanoTarget.status, 1, "NanoClaw docs must fail when they use the Hermes target");
  assert.match(
    wrongNanoTarget.stderr,
    /npx skills add prompt-security\/clawsec --skill nanoclaw-example -a openclaw -y/,
    "NanoClaw skills must install through the openclaw target",
  );

  await writeSkill({
    name: "nanoclaw-example",
    metadata: { platform: "nanoclaw", nanoclaw: { category: "security" } },
    readme:
      "# NanoClaw Example\n\n## Vercel Skills Installation\n\n```bash\nnpx skills add prompt-security/clawsec --skill nanoclaw-example -a openclaw -y\n```\n",
    skillMd:
      "---\nname: nanoclaw-example\nversion: 1.0.0\n---\n\n## Vercel Skills Installation\n\n```bash\nnpx skills add prompt-security/clawsec --skill nanoclaw-example -a openclaw -y\n```\n",
  });

  const validNano = runValidator(["--skills", "skills/nanoclaw-example"]);
  assert.equal(
    validNano.status,
    0,
    `valid NanoClaw install docs should pass\nstdout:\n${validNano.stdout}\nstderr:\n${validNano.stderr}`,
  );

  assert.match(
    workflow,
    /Validate npx skills install docs/,
    "Skill release workflow must run the install-doc validator",
  );
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}
