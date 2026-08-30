#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { resolveSkillInstallability } from "./skill_installability.mjs";
import { PLATFORM_KEYS, resolveDirectSkillsCliTargets } from "./skill_platforms.mjs";

const KNOWN_AGENT_TYPES = new Set(["codex", "hermes-agent", "openclaw", "universal"]);
const RELEASE_SIGNING_KEY_SHA256 = "711424e4535f84093fefb024cd1ca4ec87439e53907b305b79a631d5befba9c8";
const RELEASE_VERIFIER_URL = new URL("./verify_skill_release_bundle.py", import.meta.url);

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

function validateReleaseIdentity(skill, tag) {
  if (!tag) {
    return;
  }

  const expectedTag = `${skill.name}-v${skill.version}`;
  if (tag !== expectedTag) {
    throw new Error(`Release tag ${tag} does not match skill identity ${expectedTag}`);
  }
}

function codeBlock(command) {
  return ["```bash", command, "```"].join("\n");
}

function buildPermissions({ skill, metadata, platform, generatedAt, installable }) {
  if (!installable) {
    return {
      schema_version: "1",
      generated_at: generatedAt,
      skill: skill.name,
      version: skill.version,
      platform: "not-applicable",
      installable: false,
      required_binaries: [],
      optional_binaries: [],
      required_env: [],
      optional_env: [],
      network_egress: "Not applicable: package is non-installable.",
      persistence: "Not applicable: package is non-installable.",
      automatic_execution: "Not applicable: package is non-installable.",
      capabilities: [],
      operator_review: ["Limit use to read-only historical review or migration planning."],
    };
  }

  const execution = metadata.execution && typeof metadata.execution === "object" ? metadata.execution : {};
  const permissions = {
    schema_version: "1",
    generated_at: generatedAt,
    skill: skill.name,
    version: skill.version,
    platform,
    installable: true,
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
  const isInstallable = skill.installable !== false;
  const outputTypes = isInstallable
    ? ["Markdown instructions", "release artifact files"]
    : ["Historical and migration documentation", "signed denial evidence"];
  if (isInstallable && permissions.capabilities.length > 0) {
    outputTypes.push("local security findings or status reports");
  }

  const description = isInstallable
    ? `The \`${skill.name}\` skill provides this capability: ${skill.description}

This skill is intended for operator-reviewed security workflows, not unattended production mutation without the review steps declared in the skill instructions.`
    : `The \`${skill.name}\` package declares \`installable: false\`: ${skill.description}

It is retained only as immutable historical, migration, or test-vector evidence. It has no supported execution or activation path.`;
  const useCase = isInstallable
    ? `Use this skill for ${permissions.platform} workflows where an agent or operator needs the capability described in \`${skill.name}\`.`
    : `Use this package only for read-only historical review or migration planning. Do not install, activate, execute, or substitute another harness target.`;
  const risks = isInstallable
    ? `Risk: The skill may run commands, inspect local files, install hooks, or fetch remote security metadata depending on the workflow.

Mitigation: Review \`permissions.json\`, \`SKILL.md\`, and the signed \`checksums.json\` before enabling the skill. Keep high-impact actions approval-gated.

Risk: Security findings and remediation guidance can be incomplete or wrong.

Mitigation: Treat output as operator guidance. Review proposed removals, installs, configuration changes, and reports before acting.`
    : `Risk: Historical material may be mistaken for a supported integration.

Mitigation: Enforce \`installable: false\`, emit no installation commands, and do not execute preserved source. \`SKILL.md\` may provide migration context, but it is not installation authority.`;
  const outputFormat = isInstallable
    ? "Markdown, JSON, shell commands, or local files as documented by the skill."
    : "Read-only Markdown and JSON evidence; no runtime output is authorized.";

  return `# Skill Card

## Description

${description}

## Owner

prompt-security

## License/Terms of Use

${skill.license}

License reference: ${licenseRef}

Project homepage: ${homepage}

## Use Case

${useCase}

## Deployment Geography for Use

Global, subject to the operator's local compliance, network, and data-handling requirements.

## Known Risks and Mitigations

${risks}

## References

- Source release: ${supportRef}
- Skill instructions: SKILL.md
- Permission summary: permissions.json
- SkillSpector scan: skillspector-report.md
- Signed release manifest: checksums.json and checksums.sig

## Skill Output

Output type(s): ${outputTypes.join(", ")}

Output format: ${outputFormat}

Output parameters: See \`SKILL.md\`, \`permissions.json\`, and release checksums for exact files and side effects.

Other properties: Release assets are covered by signed SHA-256 checksums.

## Skill Version

${skill.version}${tag ? ` (${tag})` : ""}

## Ethical Considerations

${isInstallable
    ? "Use this skill only on systems, agents, repositories, and workspaces where you have authorization. Review generated security reports before sharing them because they may contain operational details."
    : "Preserve operator data and history. Keep assessment read-only unless a separate reviewed migration plan explicitly authorizes a change."}
`;
}

function buildInstallDoc({ skill, repository, tag, sourceRef }) {
  const releaseUrl = tag ? `https://github.com/${repository}/releases/tag/${tag}` : `https://github.com/${repository}`;

  if (skill.installable === false) {
    return `# Installation Unavailable for ${skill.name}

This package declares \`installable: false\` in signed package metadata. It may be retained as immutable historical, migration, or test-vector evidence, but it has no supported installation or activation path.

Do not install, extract into a harness skill directory, activate, execute, or substitute another harness target. \`SKILL.md\` may provide status and migration context, but it cannot override this denial.

Reference identifier only: ${releaseUrl}.
`;
  }

  const refSuffix = sourceRef && sourceRef !== "main" ? `#${sourceRef}` : "";
  const source = `${repository}${refSuffix}`;
  const archiveName = `${skill.name}-v${skill.version}.zip`;
  const releaseAssetBase = tag ? `https://github.com/${repository}/releases/download/${tag}` : "";
  const resolution = resolveDirectSkillsCliTargets(skill, KNOWN_AGENT_TYPES);
  if (resolution.status === "error") {
    throw new Error(`Cannot generate install instructions for ${skill.name}: ${resolution.errors.join(" ")}`);
  }

  const secureInstallSection = tag
    ? `## Secure Path: Verify the Canonical Release Before Installation

The signed release archive is the only installation artifact this packet binds cryptographically. Confirm the pinned signing-key fingerprint through an independent trusted channel before first use; this packet cannot bootstrap trust in its own key.

${codeBlock(`set -euo pipefail
VERIFY_DIR="$(mktemp -d)"
cd "$VERIFY_DIR"
SKILL="${skill.name}"
VERSION="${skill.version}"
TAG="${tag}"
ARCHIVE="${archiveName}"
BASE_URL="${releaseAssetBase}"
EXPECTED_KEY_SHA256="${RELEASE_SIGNING_KEY_SHA256}"

curl -fSLO "$BASE_URL/$ARCHIVE"
curl -fSLO "$BASE_URL/checksums.json"
curl -fSLO "$BASE_URL/checksums.sig"
curl -fSLO "$BASE_URL/signing-public.pem"
curl -fSLO "$BASE_URL/verify_skill_release_bundle.py"

ACTUAL_KEY_SHA256="$(openssl pkey -pubin -in signing-public.pem -outform DER | openssl dgst -sha256 | awk '{print $NF}')"
test "$EXPECTED_KEY_SHA256" = "$ACTUAL_KEY_SHA256"
openssl base64 -d -A -in checksums.sig -out checksums.sig.bin
openssl pkeyutl -verify -rawin -pubin -inkey signing-public.pem -sigfile checksums.sig.bin -in checksums.json

EXPECTED_VERIFIER_SHA="$(jq -r '.files["verify_skill_release_bundle.py"].sha256 // empty' checksums.json)"
ACTUAL_VERIFIER_SHA="$(openssl dgst -sha256 verify_skill_release_bundle.py | awk '{print $NF}')"
EXPECTED_VERIFIER_SIZE="$(jq -r '.files["verify_skill_release_bundle.py"].size // empty' checksums.json)"
ACTUAL_VERIFIER_SIZE="$(wc -c < verify_skill_release_bundle.py | tr -d ' ')"
test -n "$EXPECTED_VERIFIER_SHA"
test "$EXPECTED_VERIFIER_SHA" = "$ACTUAL_VERIFIER_SHA"
test "$EXPECTED_VERIFIER_SIZE" = "$ACTUAL_VERIFIER_SIZE"

python3 verify_skill_release_bundle.py \
  --release-dir "$VERIFY_DIR" \
  --output-dir "$VERIFY_DIR/verified" \
  --skill "$SKILL" \
  --version "$VERSION" \
  --tag "$TAG" \
  --spki-sha256 "$EXPECTED_KEY_SHA256" \
  --openssl openssl`)}

Integrate only the verified extracted \`${skill.name}/\` directory. Follow its harness-native installation instructions before enabling hooks, persistence, or automatic execution. Release page: ${releaseUrl}.`
    : `## Secure Path: Exact Release Tag Required

This packet has no exact release tag, so it cannot render an executable secure-install procedure. Generate it with \`--tag\`, then verify the signed canonical archive before installation. Repository: ${releaseUrl}.`;

  let skillsCliSection;
  if (resolution.status === "not_applicable") {
    const unsupportedSubject = resolution.unsupportedPlatforms.join(" and ");
    const unsupportedVerb = resolution.unsupportedPlatforms.length === 1 ? "has" : "have";
    skillsCliSection = `## Harness-Native Integration

Not applicable. ${unsupportedSubject} ${unsupportedVerb} no reviewed direct Vercel Agent Skills target. Do not substitute an OpenClaw or other unrelated agent target.

Follow \`SKILL.md\` and a harness-native installation document from the verified extracted archive above.`;
  } else {
    const commands = resolution.agents
      .map((agent) => codeBlock(`npx skills add ${source} --skill ${skill.name} --agent ${agent} --yes`))
      .join("\n\n");
    let unsupportedNotice = "";
    if (resolution.unsupportedPlatforms.length > 0) {
      const unsupportedSubject = resolution.unsupportedPlatforms.join(" and ");
      const unsupportedVerb = resolution.unsupportedPlatforms.length === 1 ? "has" : "have";
      unsupportedNotice = `\n\nThese commands cover only the direct targets above. ${unsupportedSubject} ${unsupportedVerb} no reviewed direct Agent Skills target.`;
    }

    skillsCliSection = `## Optional Compatibility-Only Agent Skills CLI Check

These commands test reviewed direct-target compatibility in a disposable project. They resolve repository source; their installed tree is not byte-bound to the signed release archive or its manifest.

${commands}${unsupportedNotice}

Do not treat the resolver output as a verified installation, do not promote it from staging, and do not run the CLI's mutable update operation on a verified install. This packet emits no installed-tree parity procedure; use the verified canonical release archive above for a trusted installation. Direct-target compatibility also does not grant catalog authorization.`;
  }

  return `# Verify and Install ${skill.name}

${secureInstallSection}

${skillsCliSection}
`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const skillDir = path.resolve(args.skillDir);
  const outputDir = path.resolve(args.outputDir);

  const skillJsonPath = path.join(skillDir, "skill.json");
  const skillMdPath = path.join(skillDir, "SKILL.md");
  const [skillJsonRaw, skillMdRaw, releaseVerifier] = await Promise.all([
    readFile(skillJsonPath, "utf8"),
    readFile(skillMdPath, "utf8"),
    readFile(RELEASE_VERIFIER_URL, "utf8"),
  ]);

  const skill = JSON.parse(skillJsonRaw);
  const frontmatter = parseFrontmatter(skillMdRaw);
  skill.name = requireField(skill, "name");
  skill.version = requireField(skill, "version");
  skill.description = requireField(skill, "description");
  skill.license = requireField(skill, "license");
  const { installable } = resolveSkillInstallability(skill);
  validateReleaseIdentity(skill, args.tag);

  const platform = installable ? detectPlatform(skill) : "not-applicable";
  const metadata = installable ? platformMetadata(skill, platform) : {};
  const generatedAt = new Date().toISOString();
  const permissions = buildPermissions({ skill, metadata, platform, generatedAt, installable });

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
    writeFile(
      path.join(outputDir, "verify_skill_release_bundle.py"),
      releaseVerifier,
    ),
  ]);

  console.log(`Generated release trust packet for ${skill.name} in ${outputDir}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
