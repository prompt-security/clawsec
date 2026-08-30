export const PLATFORM_KEYS = Object.freeze(["openclaw", "nanoclaw", "hermes", "picoclaw"]);

// This reviewed map answers only whether the Vercel Skills CLI has a direct
// target for a declared platform. It does not grant release-channel eligibility.
// A null value is an explicit, fail-closed "no direct target" decision.
const PLATFORM_AGENT_TARGETS = new Map([
  ["codex", "codex"],
  ["openclaw", "openclaw"],
  ["hermes", "hermes-agent"],
  ["nanoclaw", null],
  ["picoclaw", null],
]);

function asStringArray(value) {
  if (Array.isArray(value)) {
    return value.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim());
  }
  if (typeof value === "string" && value.trim()) {
    return [value.trim()];
  }
  return [];
}

export function collectDeclaredPlatforms(skill) {
  const platforms = new Set([
    ...asStringArray(skill.platform),
    ...asStringArray(skill.platforms),
  ]);

  for (const key of PLATFORM_KEYS) {
    if (skill[key] && typeof skill[key] === "object") {
      platforms.add(key);
    }
  }

  return [...platforms];
}

export function resolveDirectSkillsCliTargets(skill, agentTypes) {
  const platforms = collectDeclaredPlatforms(skill);
  if (platforms.length === 0) {
    return {
      status: "error",
      agents: [],
      unsupportedPlatforms: [],
      errors: ["Skill metadata does not declare a platform."],
    };
  }

  const matchedAgents = new Set();
  const unsupportedPlatforms = new Set();
  const errors = [];

  for (const platform of platforms) {
    if (PLATFORM_AGENT_TARGETS.has(platform)) {
      const target = PLATFORM_AGENT_TARGETS.get(platform);
      if (target === null) {
        unsupportedPlatforms.add(platform);
      } else if (agentTypes.has(target)) {
        matchedAgents.add(target);
      } else {
        errors.push(`Configured npx skills target ${target} for ${platform} is unavailable.`);
      }
      continue;
    }

    errors.push(`Unknown platform without a reviewed npx skills target: ${platform}.`);
  }

  const agents = [...matchedAgents].sort();
  const unsupported = [...unsupportedPlatforms].sort();
  if (errors.length > 0) {
    return {
      status: "error",
      agents,
      unsupportedPlatforms: unsupported,
      errors,
    };
  }

  return {
    status: agents.length > 0 ? "required" : "not_applicable",
    agents,
    unsupportedPlatforms: unsupported,
    errors: [],
  };
}

export function installAgentForSkill(skill, agentTypes) {
  const resolution = resolveDirectSkillsCliTargets(skill, agentTypes);
  if (resolution.status === "error") {
    throw new Error(resolution.errors.join(" "));
  }
  if (resolution.agents.length !== 1 || resolution.unsupportedPlatforms.length > 0) {
    throw new Error("Skill does not resolve to exactly one reviewed npx skills target.");
  }
  return resolution.agents[0];
}
