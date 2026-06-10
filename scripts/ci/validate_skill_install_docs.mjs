#!/usr/bin/env node
import { readFile, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import https from "node:https";
import path from "node:path";

const DEFAULT_REPOSITORY = "prompt-security/clawsec";
const DEFAULT_AGENT_TYPES_URL = "https://raw.githubusercontent.com/vercel-labs/skills/main/src/types.ts";
const DOC_FILENAMES = ["README.md", "SKILL.md"];
const KNOWN_PLATFORM_KEYS = ["openclaw", "nanoclaw", "picoclaw", "hermes"];
const PLATFORM_AGENT_ALIASES = new Map([["hermes", "hermes-agent"]]);

function usage() {
  return [
    "Usage: node scripts/ci/validate_skill_install_docs.mjs [options]",
    "",
    "Options:",
    "  --root <dir>              Repository root. Defaults to current working directory.",
    "  --repository <owner/repo> Expected npx skills source. Defaults to prompt-security/clawsec.",
    "  --base <sha>              Base ref for changed-skill detection.",
    "  --head <sha>              Head ref for changed-skill detection.",
    "  --skills <dir[,dir...]>   Skill directories to validate.",
    "  --all                     Validate every skill directory with skill.json.",
    "  --agent-types-file <path> Read Vercel AgentType source from a local file.",
    "  --agent-types-url <url>   Read Vercel AgentType source from a URL.",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    root: process.cwd(),
    repository: DEFAULT_REPOSITORY,
    base: process.env.BASE_SHA || "",
    head: process.env.HEAD_SHA || "",
    skillDirs: [],
    all: false,
    agentTypesFile: "",
    agentTypesUrl: DEFAULT_AGENT_TYPES_URL,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--root") {
      options.root = argv[++i];
    } else if (token === "--repository") {
      options.repository = argv[++i];
    } else if (token === "--base") {
      options.base = argv[++i];
    } else if (token === "--head") {
      options.head = argv[++i];
    } else if (token === "--skills") {
      options.skillDirs.push(...argv[++i].split(",").map((item) => item.trim()).filter(Boolean));
    } else if (token === "--all") {
      options.all = true;
    } else if (token === "--agent-types-file") {
      options.agentTypesFile = argv[++i];
    } else if (token === "--agent-types-url") {
      options.agentTypesUrl = argv[++i];
    } else if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${token}\n${usage()}`);
    }
  }

  return {
    ...options,
    root: path.resolve(options.root),
  };
}

function fetchText(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (response) => {
        if (response.statusCode !== 200) {
          reject(new Error(`Failed to fetch ${url}: HTTP ${response.statusCode}`));
          response.resume();
          return;
        }

        response.setEncoding("utf8");
        let body = "";
        response.on("data", (chunk) => {
          body += chunk;
        });
        response.on("end", () => resolve(body));
      })
      .on("error", reject);
  });
}

async function readAgentTypeSource(options) {
  if (options.agentTypesFile) {
    return readFile(path.resolve(options.agentTypesFile), "utf8");
  }

  return fetchText(options.agentTypesUrl);
}

function parseAgentTypes(source) {
  const match = source.match(/export\s+type\s+AgentType\s*=\s*([\s\S]*?);/);
  if (!match) {
    throw new Error("Could not find export type AgentType in Vercel skills type source.");
  }

  const agents = new Set();
  const agentTypeBody = match[1];
  for (const agentMatch of agentTypeBody.matchAll(/['"]([^'"]+)['"]/g)) {
    agents.add(agentMatch[1]);
  }

  if (agents.size === 0) {
    throw new Error("Vercel AgentType list was empty.");
  }

  return agents;
}

async function listAllSkillDirs(root) {
  const skillsRoot = path.join(root, "skills");
  const entries = await readdir(skillsRoot, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => `skills/${entry.name}`)
    .filter((skillDir) => existsSync(path.join(root, skillDir, "skill.json")))
    .sort();
}

function changedSkillDirs({ root, base, head }) {
  if (!base || !head) {
    throw new Error("Provide --skills, --all, or both --base and --head for changed-skill detection.");
  }

  const result = spawnSync(
    "git",
    [
      "-C",
      root,
      "diff",
      "--name-only",
      `${base}...${head}`,
      "--",
      "skills/*/**",
      ":(exclude)skills/*/test/**",
      ":(exclude)skills/*/tests/**",
    ],
    { encoding: "utf8" },
  );

  if (result.status !== 0) {
    throw new Error(`git diff failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  }

  return [
    ...new Set(
      result.stdout
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
        .map((filePath) => filePath.split("/").slice(0, 2).join("/"))
        .filter((skillDir) => /^skills\/[^/]+$/.test(skillDir)),
    ),
  ].sort();
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
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

  for (const key of KNOWN_PLATFORM_KEYS) {
    if (skill[key] && typeof skill[key] === "object") {
      platforms.add(key);
    }
  }

  return [...platforms];
}

function agentForSkill(skill, agentTypes) {
  const platforms = collectDeclaredPlatforms(skill);
  if (platforms.length === 0) {
    return "openclaw";
  }

  const matchedAgents = new Set();
  let allPlatformsMatched = true;

  for (const platform of platforms) {
    const aliasedPlatform = PLATFORM_AGENT_ALIASES.get(platform) || platform;
    if (agentTypes.has(aliasedPlatform)) {
      matchedAgents.add(aliasedPlatform);
    } else {
      allPlatformsMatched = false;
    }
  }

  if (allPlatformsMatched && matchedAgents.size === 1) {
    return [...matchedAgents][0];
  }

  return "openclaw";
}

function hasRequiredCommand(markdown, { repository, skillName, agent }) {
  return markdown
    .split("\n")
    .map((line) => line.replace(/\s+/g, " ").trim())
    .filter((line) => line.includes("npx skills add"))
    .some((line) => {
      return (
        line.includes(`npx skills add ${repository}`) &&
        line.includes(`--skill ${skillName}`) &&
        (line.includes(`-a ${agent}`) || line.includes(`--agent ${agent}`)) &&
        (line.includes(" -y") || line.includes(" --yes"))
      );
    });
}

async function validateSkill({ root, skillDir, repository, agentTypes }) {
  const skillJsonPath = path.join(root, skillDir, "skill.json");
  const skill = await readJson(skillJsonPath);
  const skillName = skill.name || path.basename(skillDir);
  const agent = agentForSkill(skill, agentTypes);
  const command = `npx skills add ${repository} --skill ${skillName} -a ${agent} -y`;
  const failures = [];

  for (const filename of DOC_FILENAMES) {
    const docPath = path.join(root, skillDir, filename);
    if (!existsSync(docPath)) {
      failures.push(`Missing required install documentation file: ${path.join(skillDir, filename)}`);
      continue;
    }

    const markdown = await readFile(docPath, "utf8");
    if (!hasRequiredCommand(markdown, { repository, skillName, agent })) {
      failures.push(`Missing required npx skills install command in ${path.join(skillDir, filename)}: ${command}`);
    }
  }

  return {
    skillDir,
    skillName,
    agent,
    failures,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const agentTypes = parseAgentTypes(await readAgentTypeSource(options));
  let skillDirs = options.skillDirs;

  if (options.all) {
    skillDirs = await listAllSkillDirs(options.root);
  } else if (skillDirs.length === 0) {
    skillDirs = changedSkillDirs(options);
  }

  if (skillDirs.length === 0) {
    console.log("No skill install docs to validate.");
    return;
  }

  const results = [];
  for (const skillDir of skillDirs) {
    const skillJsonPath = path.join(options.root, skillDir, "skill.json");
    if (!existsSync(skillJsonPath)) {
      console.log(`Skipping removed skill directory: ${skillDir}`);
      continue;
    }

    results.push(
      await validateSkill({
        root: options.root,
        skillDir,
        repository: options.repository,
        agentTypes,
      }),
    );
  }

  const failures = results.flatMap((result) => result.failures);
  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(`::error::${failure}`);
    }
    throw new Error(`Found ${failures.length} npx skills install documentation issue(s).`);
  }

  for (const result of results) {
    console.log(`npx skills install docs OK for ${result.skillName}: -a ${result.agent}`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
