import { pathToFileURL } from "node:url";

import {
  parseAffectedSpecifier,
  parseVersionSpec,
} from "../../skills/hermes-attestation-guardian/lib/semver.mjs";

export const PROTECTED_ADVISORY_COMPONENTS = Object.freeze([
  Object.freeze({ slug: "openclaw", label: "OpenClaw" }),
  Object.freeze({ slug: "nanoclaw", label: "NanoClaw" }),
  Object.freeze({ slug: "hermes", label: "Hermes" }),
  Object.freeze({ slug: "picoclaw", label: "Picoclaw" }),
  Object.freeze({ slug: "openshell", label: "OpenShell" }),
  Object.freeze({ slug: "nemoclaw", label: "NemoClaw" }),
]);

const EMPTY_SCOPE_VALUES = new Set(["*", "all", "any", "n/a", "na", "none", "unknown", "unspecified"]);
const PACKAGE_NAME_PATTERN = /^(?:[a-z0-9][a-z0-9._-]*|@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*)$/;

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function cleanSectionValue(value) {
  return value
    .replace(/<!--[\s\S]*?-->/g, "")
    .split("\n")
    .map((line) => line.trim())
    .find(Boolean) || "";
}

function extractSection(issueBody, headings) {
  const lines = issueBody.split(/\r?\n/);

  for (const heading of headings) {
    const headingPattern = new RegExp(`^###\\s+${escapeRegExp(heading)}\\s*$`, "i");
    const start = lines.findIndex((line) => headingPattern.test(line.trim()));
    if (start === -1) continue;

    const sectionLines = [];
    for (let index = start + 1; index < lines.length; index += 1) {
      if (/^#{2,3}\s+/.test(lines[index]) || /^---\s*$/.test(lines[index])) break;
      sectionLines.push(lines[index]);
    }

    const value = cleanSectionValue(sectionLines.join("\n"));
    if (value) return value;
  }

  return "";
}

function checked(issueBody, label) {
  const pattern = new RegExp(
    `^\\s*-\\s*\\[[xX]\\]\\s*${escapeRegExp(label)}(?:\\s|\\(|$)`,
    "m",
  );
  return pattern.test(issueBody);
}

function parseLegacyOtherPlatform(issueBody) {
  const match = issueBody.match(
    /^\s*-\s*\[[xX]\]\s*Other:\s*([^\n<]+?)\s*(?:<!--.*)?$/im,
  );
  if (!match) return null;

  const slug = match[1]
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");

  if (!slug) return null;
  if (!PROTECTED_ADVISORY_COMPONENTS.some((component) => component.slug === slug)) {
    throw new Error(
      `Other platform "${match[1].trim()}" is not a protected advisory component. `
      + "Select an explicit protected component; distribution channels such as ClawHub are not platforms.",
    );
  }
  return slug;
}

function normalizeComponentName(rawName) {
  const name = rawName.trim();
  const knownComponent = PROTECTED_ADVISORY_COMPONENTS.find(
    ({ label, slug }) => slug === name.toLowerCase() || label.toLowerCase() === name.toLowerCase(),
  );
  if (knownComponent) return knownComponent.slug;

  if (!PACKAGE_NAME_PATTERN.test(name)) {
    throw new Error(
      "Component or skill name must be a lowercase package name or scoped package such as @scope/name",
    );
  }
  return name;
}

export function parseCommunityAdvisoryScope(issueBody) {
  if (typeof issueBody !== "string") {
    throw new TypeError("Issue body must be a string");
  }

  const rawComponentName = extractSection(issueBody, ["Component or Skill Name", "Skill Name"]);
  const rawVersionScope = extractSection(issueBody, ["Affected Version Scope", "Skill Version"]);

  if (!rawComponentName) {
    throw new Error("Component or skill name is required; unscoped advisories must not be published");
  }
  if (/^clawhub(?:\.ai)?$/i.test(rawComponentName)) {
    throw new Error("ClawHub is a distribution channel, not a protected advisory component");
  }
  const componentName = normalizeComponentName(rawComponentName);
  if (!rawVersionScope || EMPTY_SCOPE_VALUES.has(rawVersionScope.toLowerCase())) {
    throw new Error("An explicit affected version or version range is required; wildcard scope must not be published");
  }
  const parsedVersionScope = parseVersionSpec(rawVersionScope);
  if (!parsedVersionScope.supported || parsedVersionScope.normalized === "*") {
    throw new Error(`Unsupported affected version or range: ${rawVersionScope}`);
  }
  const versionScope = parsedVersionScope.normalized;

  const affectedSelector = `${componentName}@${versionScope}`;
  const parsedSelector = parseAffectedSpecifier(affectedSelector);
  if (
    !parsedSelector
    || parsedSelector.name !== componentName
    || parsedSelector.versionSpec !== versionScope
  ) {
    throw new Error("Component name and version range do not form an unambiguous affected selector");
  }

  const platforms = PROTECTED_ADVISORY_COMPONENTS
    .filter(({ label }) => checked(issueBody, label))
    .map(({ slug }) => slug);
  const legacyOther = parseLegacyOtherPlatform(issueBody);
  if (legacyOther) platforms.push(legacyOther);

  const uniquePlatforms = [...new Set(platforms)];
  if (uniquePlatforms.length === 0) {
    throw new Error("At least one explicit protected component is required; platform defaults must not be inferred");
  }

  return {
    componentName,
    versionScope,
    affected: [affectedSelector],
    platforms: uniquePlatforms,
  };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    const result = parseCommunityAdvisoryScope(process.env.ISSUE_BODY || "");
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    console.error(`Community advisory scope invalid: ${error.message}`);
    process.exitCode = 1;
  }
}
