export const PLATFORM_KEYS = Object.freeze(["openclaw", "nanoclaw", "hermes", "picoclaw"]);

const PLATFORM_AGENT_ALIASES = new Map([["hermes", "hermes-agent"]]);

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

export function installAgentForSkill(skill, agentTypes, fallback = "openclaw") {
  const platforms = collectDeclaredPlatforms(skill);
  if (platforms.length === 0) {
    return fallback;
  }

  const matchedAgents = new Set();
  let allPlatformsMatched = true;
  for (const platform of platforms) {
    const candidate = PLATFORM_AGENT_ALIASES.get(platform) || platform;
    if (agentTypes.has(candidate)) {
      matchedAgents.add(candidate);
    } else {
      allPlatformsMatched = false;
    }
  }

  if (allPlatformsMatched && matchedAgents.size === 1) {
    return [...matchedAgents][0];
  }

  return fallback;
}
