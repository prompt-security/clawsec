#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const PLATFORM_KEYS = ["openclaw", "nanoclaw", "hermes", "picoclaw"];
const KNOWN_AGENT_TYPES = new Set(["codex", "hermes-agent", "openclaw", "universal"]);
const PLATFORM_AGENT_ALIASES = new Map([["hermes", "hermes-agent"]]);

function usage() {
  return [
    "Usage: node scripts/ci/generate_skill_release_trust_packet.mjs <skill-dir> <output-dir> [options]",
    "",
    "Options:",
    "  --repository <owner/repo>  Source repository used in install instructions",
    "  --tag <tag>                Release tag for this skill",
    "  --source-ref <ref>         Source ref for npx skills examples",
  ].join("\n");
}

function parseArgs(argv) {
  const positional = [];
  const options = {
    repository: "prompt-security/clawsec",
    tag: "",
    sourceRef: "main",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--repository") {
      options.repository = argv[++i];
    } else if (token === "--tag") {
      options.tag = argv[++i];
    } else if (token === "--source-ref") {
      options.sourceRef = argv[++i];
    } else if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
    } else if (token.startsWith("--")) {
      throw new Error(`Unknown option: ${token}`);
    } else {
      positional.push(token);
    }
  }

  if (positional.length !== 2) {
    throw new Error(usage());
  }

  return {
    skillDir: positional[0],
    outputDir: positional[1],
    ...options,
  };
}

function parseFrontmatter(markdown) {
  if (!markdown.startsWith("---\n")) {
    return {};
  }

  const end = markdown.indexOf("\n---", 4);
  if (end === -1) {
    return {};
  }

  const result = {};
  const frontmatter = markdown.slice(4, end).split("\n");
  for (const line of frontmatter) {
    const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (match) {
      result[match[1]] = match[2].replace(/^["']|["']$/g, "").trim();
    }
  }
  return result;
}

function asArray(value) {
  if (Array.isArray(value)) {
    return value.filter((item) => item !== null && item !== undefined).map(String);
  }
  if (typeof value === "string" && value.trim()) {
    return [value.trim()];
  }
  return [];
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function detectPlatform(skill) {
  for (const key of PLATFORM_KEYS) {
    if (skill[key] && typeof skill[key] === "object") {
      return key;
    }
  }
  return skill.platform || "agent-skills";
}

function collectDeclaredPlatforms(skill) {
  const platforms = new Set();
  if (typeof skill.platform === "string" && skill.platform.trim()) {
    platforms.add(skill.platform.trim());
  }
  if (Array.isArray(skill.platforms)) {
    for (const platform of skill.platforms) {
      if (typeof platform === "string" && platform.trim()) {
        platforms.add(platform.trim());
      }
    }
  }
  for (const key of PLATFORM_KEYS) {
    if (skill[key] && typeof skill[key] === "object") {
      platforms.add(key);
    }
  }
  return [...platforms];
}

function installAgentForSkill(skill) {
  const platforms = collectDeclaredPlatforms(skill);
  if (platforms.length === 0) {
    return "openclaw";
  }

  const matchedAgents = new Set();
  let allPlatformsMatched = true;
  for (const platform of platforms) {
    const candidate = PLATFORM_AGENT_ALIASES.get(platform) || platform;
    if (KNOWN_AGENT_TYPES.has(candidate)) {
      matchedAgents.add(candidate);
    } else {
      allPlatformsMatched = false;
    }
  }

  if (allPlatformsMatched && matchedAgents.size === 1) {
    return [...matchedAgents][0];
  }

  return "openclaw";
}

function platformMetadata(skill, platform) {
  const direct = skill[platform];
  return direct && typeof direct === "object" ? direct : {};
}

function collectRequiredBinaries(metadata) {
  const requires = metadata.requires && typeof metadata.requires === "object" ? metadata.requires : {};
  const bins = asArray(requires.bins);

  for (const [key, value] of Object.entries(requires)) {
    if (key !== "bins" && typeof value === "string") {
      bins.push(key);
    }
  }

  return unique(bins);
}

function collectOptionalBinaries(metadata) {
  return unique([
    ...asArray(metadata.runtime?.optional_bins),
    ...asArray(metadata.runtime?.optionalBins),
  ]);
}

function collectRequiredEnv(metadata) {
  const requires = metadata.requires && typeof metadata.requires === "object" ? metadata.requires : {};
  return unique([
    ...asArray(requires.env),
    ...asArray(metadata.runtime?.required_env),
    ...asArray(metadata.runtime?.requiredEnv),
  ]);
}

function collectOptionalEnv(metadata) {
  return unique([
    ...asArray(metadata.runtime?.optional_env),
    ...asArray(metadata.runtime?.optionalEnv),
  ]);
}

function stringifyCapabilities(skill, metadata) {
  const capabilities = metadata.capabilities ?? skill.capabilities ?? {};
  if (Array.isArray(capabilities)) {
    return capabilities;
  }
  if (capabilities && typeof capabilities === "object") {
    return Object.entries(capabilities).map(([key, value]) => `${key}: ${String(value)}`);
  }
  if (typeof capabilities === "string") {
    return [capabilities];
  }
  return [];
}

function requireField(skill, fieldName) {
  if (!skill[fieldName] || typeof skill[fieldName] !== "string" || !skill[fieldName].trim()) {
    throw new Error(`skill.json missing required trust-packet field: ${fieldName}`);
  }
  return skill[fieldName].trim();
}

function codeBlock(command) {
  return ["```bash", command, "```"].join("\n");
}

function buildPermissions({ skill, metadata, platform, generatedAt }) {
  const execution = metadata.execution && typeof metadata.execution === "object" ? metadata.execution : {};
  const permissions = {
    schema_version: "1",
    generated_at: generatedAt,
    skill: skill.name,
    version: skill.version,
    platform,
    required_binaries: collectRequiredBinaries(metadata),
    optional_binaries: collectOptionalBinaries(metadata),
    required_env: collectRequiredEnv(metadata),
    optional_env: collectOptionalEnv(metadata),
    network_egress: execution.network_egress || "Not declared in skill metadata.",
    persistence: execution.persistence || "Not declared in skill metadata.",
    automatic_execution: typeof execution.always === "boolean" ? execution.always : "Not declared in skill metadata.",
    capabilities: stringifyCapabilities(skill, metadata),
    operator_review: asArray(metadata.operator_review),
  };

  return permissions;
}

function buildSkillCard({ skill, frontmatter, permissions, repository, tag, sourceRef }) {
  const homepage = skill.homepage || frontmatter.homepage || `https://github.com/${repository}`;
  const supportRef = `${repository}@${tag || sourceRef}`;
  const licenseRef = `https://github.com/${repository}/blob/${tag || sourceRef}/LICENSE`;
  const outputTypes = ["Markdown instructions", "release artifact files"];
  if (permissions.capabilities.length > 0) {
    outputTypes.push("local security findings or status reports");
  }

  return `# Skill Card

## Description

The \`${skill.name}\` skill provides this capability: ${skill.description}

This skill is intended for operator-reviewed security workflows, not unattended production mutation without the review steps declared in the skill instructions.

## Owner

prompt-security

## License/Terms of Use

${skill.license}

License reference: ${licenseRef}

Project homepage: ${homepage}

## Use Case

Use this skill for ${permissions.platform} workflows where an agent or operator needs the capability described in \`${skill.name}\`.

## Deployment Geography for Use

Global, subject to the operator's local compliance, network, and data-handling requirements.

## Known Risks and Mitigations

Risk: The skill may run commands, inspect local files, install hooks, or fetch remote security metadata depending on the workflow.

Mitigation: Review \`permissions.json\`, \`SKILL.md\`, and the signed \`checksums.json\` before enabling the skill. Keep high-impact actions approval-gated.

Risk: Security findings and remediation guidance can be incomplete or wrong.

Mitigation: Treat output as operator guidance. Review proposed removals, installs, configuration changes, and reports before acting.

## References

- Source release: ${supportRef}
- Skill instructions: SKILL.md
- Permission summary: permissions.json
- SkillSpector scan: skillspector-report.md
- Signed release manifest: checksums.json and checksums.sig

## Skill Output

Output type(s): ${outputTypes.join(", ")}

Output format: Markdown, JSON, shell commands, or local files as documented by the skill.

Output parameters: See \`SKILL.md\`, \`permissions.json\`, and release checksums for exact files and side effects.

Other properties: Release assets are covered by signed SHA-256 checksums.

## Skill Version

${skill.version}${tag ? ` (${tag})` : ""}

## Ethical Considerations

Use this skill only on systems, agents, repositories, and workspaces where you have authorization. Review generated security reports before sharing them because they may contain operational details.
`;
}

function buildInstallDoc({ skill, repository, tag, sourceRef }) {
  const refSuffix = sourceRef && sourceRef !== "main" ? `#${sourceRef}` : "";
  const source = `${repository}${refSuffix}`;
  const releaseUrl = tag ? `https://github.com/${repository}/releases/tag/${tag}` : `https://github.com/${repository}`;
  const agent = installAgentForSkill(skill);

  return `# Install and Update ${skill.name}

## Install With Agent Skills CLI

Harness-aware global install:

${codeBlock(`npx skills add ${source} --skill ${skill.name} --agent ${agent} --global --yes`)}

Project-local install for compatible agents:

${codeBlock(`npx skills add ${source} --skill ${skill.name} --yes`)}

## Update

Update this skill when installed through the Skills CLI:

${codeBlock(`npx skills update ${skill.name}`)}

List installed skills:

${codeBlock("npx skills list")}

## Verify Release Artifact

When installing from a GitHub release instead of the Skills CLI, download the archive, \`checksums.json\`, \`checksums.sig\`, and \`signing-public.pem\` from:

${releaseUrl}

Verify \`checksums.json\` before trusting the archive or standalone files.
`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const skillDir = path.resolve(args.skillDir);
  const outputDir = path.resolve(args.outputDir);

  const skillJsonPath = path.join(skillDir, "skill.json");
  const skillMdPath = path.join(skillDir, "SKILL.md");
  const [skillJsonRaw, skillMdRaw] = await Promise.all([
    readFile(skillJsonPath, "utf8"),
    readFile(skillMdPath, "utf8"),
  ]);

  const skill = JSON.parse(skillJsonRaw);
  const frontmatter = parseFrontmatter(skillMdRaw);
  skill.name = requireField(skill, "name");
  skill.version = requireField(skill, "version");
  skill.description = requireField(skill, "description");
  skill.license = requireField(skill, "license");

  const platform = detectPlatform(skill);
  const metadata = platformMetadata(skill, platform);
  const generatedAt = new Date().toISOString();
  const permissions = buildPermissions({ skill, metadata, platform, generatedAt });

  await mkdir(outputDir, { recursive: true });
  await Promise.all([
    writeFile(
      path.join(outputDir, "permissions.json"),
      `${JSON.stringify(permissions, null, 2)}\n`,
    ),
    writeFile(
      path.join(outputDir, "skill-card.md"),
      buildSkillCard({
        skill,
        frontmatter,
        permissions,
        repository: args.repository,
        tag: args.tag,
        sourceRef: args.sourceRef,
      }),
    ),
    writeFile(
      path.join(outputDir, "install.md"),
      buildInstallDoc({
        skill,
        repository: args.repository,
        tag: args.tag,
        sourceRef: args.sourceRef,
      }),
    ),
  ]);

  console.log(`Generated release trust packet for ${skill.name} in ${outputDir}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
