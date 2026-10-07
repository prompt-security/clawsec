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
const SINGLE_SELECT_FIELDS = Object.freeze({
  openerType: Object.freeze({
    heading: "Opener Type",
    options: Object.freeze([
      Object.freeze({ label: "Human", value: "human" }),
      Object.freeze({ label: "Agent", value: "agent" }),
    ]),
  }),
  reportType: Object.freeze({
    heading: "Report Type",
    options: Object.freeze([
      Object.freeze({ label: "Malicious Prompt", value: "prompt_injection" }),
      Object.freeze({ label: "Vulnerable Skill", value: "vulnerable_skill" }),
      Object.freeze({ label: "Tampering Attempt", value: "tampering_attempt" }),
    ]),
  }),
  severity: Object.freeze({
    heading: "Severity",
    options: Object.freeze([
      Object.freeze({ label: "Critical", value: "critical" }),
      Object.freeze({ label: "High", value: "high" }),
      Object.freeze({ label: "Medium", value: "medium" }),
      Object.freeze({ label: "Low", value: "low" }),
    ]),
  }),
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function cleanSectionValue(value) {
  return value
    .split("\n")
    .map((line) => line.trim())
    .find(Boolean) || "";
}

function cleanMultilineSectionValue(value) {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}

function stripHtmlComments(value) {
  return value.replace(/<!--[\s\S]*?(?:-->|$)/g, (comment) => (
    comment.replace(/[^\r\n]/g, " ")
  ));
}

function stripNonFormMarkdown(value) {
  const lines = stripHtmlComments(value).split(/\r?\n/);
  let fence = null;

  return lines.map((line) => {
    if (fence) {
      const closingFence = new RegExp(`^ {0,3}${escapeRegExp(fence.marker)}{${fence.length},}\\s*$`);
      if (closingFence.test(line)) fence = null;
      return "";
    }

    const openingFence = line.match(/^ {0,3}(`{3,}|~{3,})/);
    if (openingFence) {
      fence = {
        marker: openingFence[1][0],
        length: openingFence[1].length,
      };
      return "";
    }

    if (/^(?: {4,}|\t)/.test(line)) return "";
    return line;
  }).join("\n");
}

function extractSectionBody(issueBody, headings, fieldName = headings[0]?.text) {
  const lines = issueBody.split(/\r?\n/);
  const matches = [];

  for (let index = 0; index < lines.length; index += 1) {
    const candidate = lines[index].trim();
    if (headings.some(({ level, text }) => (
      new RegExp(`^#{${level}}\\s+${escapeRegExp(text)}\\s*$`, "i").test(candidate)
    ))) {
      matches.push(index);
    }
  }

  if (matches.length > 1) {
    throw new Error(`${fieldName} section must appear exactly once`);
  }
  if (matches.length === 0) return "";

  const sectionLines = [];
  for (let index = matches[0] + 1; index < lines.length; index += 1) {
    const candidateBoundary = lines[index].trim();
    if (/^#{1,6}\s+/.test(candidateBoundary) || /^---\s*$/.test(candidateBoundary)) break;
    sectionLines.push(lines[index]);
  }

  return sectionLines.join("\n");
}

function extractSection(issueBody, headings, fieldName) {
  return cleanSectionValue(extractSectionBody(issueBody, headings, fieldName));
}

function checked(issueBody, label) {
  const pattern = new RegExp(
    `^\\s*-\\s*\\[[xX]\\]\\s*${escapeRegExp(label)}(?:\\s|\\(|$)`,
    "m",
  );
  return pattern.test(issueBody);
}

function parseSingleSelect(formBody, { heading, options }) {
  const sectionBody = extractSectionBody(
    formBody,
    [{ level: 2, text: heading }],
    heading,
  );
  if (!sectionBody) {
    throw new Error(`${heading} section is required`);
  }

  const checkedLines = sectionBody
    .split(/\r?\n/)
    .map((line) => line.match(/^\s*-\s*\[[xX]\]\s*(.*?)\s*$/)?.[1] || null)
    .filter(Boolean);

  if (checkedLines.length !== 1) {
    throw new Error(`${heading} must have exactly one checked value`);
  }

  const selectedLine = checkedLines[0];
  const selected = options.find(({ label }) => (
    new RegExp(`^${escapeRegExp(label)}(?:\\s*(?:[-–—]\\s+.+|\\(.+\\)))?$`, "i")
      .test(selectedLine)
  ));
  if (!selected) {
    throw new Error(`${heading} has an invalid checked value`);
  }
  return selected.value;
}

function requireMeaningfulSection(formBody, heading) {
  const value = cleanMultilineSectionValue(extractSectionBody(
    formBody,
    [{ level: 2, text: heading }],
    heading,
  ));
  if (!/[\p{L}\p{N}]/u.test(value)) {
    throw new Error(`${heading} is required`);
  }
  return value;
}

function parseReporterName(formBody) {
  const reporterSection = extractSectionBody(
    formBody,
    [{ level: 2, text: "Reporter Information (Optional)" }],
    "Reporter Information",
  );
  if (!reporterSection) return "";

  const lines = reporterSection.split(/\r?\n/);
  const markerIndexes = lines.flatMap((line, index) => (
    /^\s*\*\*Agent\/User Name:\*\*/i.test(line) ? [index] : []
  ));
  if (markerIndexes.length > 1) {
    throw new Error("Agent/User Name field must appear at most once");
  }
  if (markerIndexes.length === 0) return "";

  const markerIndex = markerIndexes[0];
  const inlineValue = lines[markerIndex]
    .replace(/^\s*\*\*Agent\/User Name:\*\*/i, "")
    .trim();
  if (inlineValue) return inlineValue;

  for (let index = markerIndex + 1; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (/^\*\*Contact:\*\*/i.test(line)) break;
    if (line) return line;
  }
  return "";
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

  const formBody = stripNonFormMarkdown(issueBody);
  return parseScopeFromFormBody(formBody);
}

function parseScopeFromFormBody(formBody) {
  const rawComponentName = extractSection(
    formBody,
    [
      { level: 3, text: "Component or Skill Name" },
      { level: 3, text: "Skill Name" },
    ],
    "Component or Skill Name",
  );
  const rawVersionScope = extractSection(
    formBody,
    [
      { level: 3, text: "Affected Version Scope" },
      { level: 3, text: "Skill Version" },
    ],
    "Affected Version Scope",
  );

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

  const protectedComponentsSection = extractSectionBody(
    formBody,
    [
      { level: 3, text: "Protected Components" },
      { level: 3, text: "Platforms" },
    ],
    "Protected Components",
  );
  const platforms = PROTECTED_ADVISORY_COMPONENTS
    .filter(({ label }) => checked(protectedComponentsSection, label))
    .map(({ slug }) => slug);
  const legacyOther = parseLegacyOtherPlatform(protectedComponentsSection);
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

export function parseCommunityAdvisoryForm(issueBody) {
  if (typeof issueBody !== "string") {
    throw new TypeError("Issue body must be a string");
  }

  const formBody = stripNonFormMarkdown(issueBody);
  const scope = parseScopeFromFormBody(formBody);

  return {
    openerType: parseSingleSelect(formBody, SINGLE_SELECT_FIELDS.openerType),
    reportType: parseSingleSelect(formBody, SINGLE_SELECT_FIELDS.reportType),
    severity: parseSingleSelect(formBody, SINGLE_SELECT_FIELDS.severity),
    title: requireMeaningfulSection(formBody, "Title"),
    description: requireMeaningfulSection(formBody, "Description"),
    action: requireMeaningfulSection(formBody, "Recommended Action"),
    reporterName: parseReporterName(formBody),
    ...scope,
  };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    const result = parseCommunityAdvisoryForm(process.env.ISSUE_BODY || "");
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    console.error(`Community advisory form invalid: ${error.message}`);
    process.exitCode = 1;
  }
}
