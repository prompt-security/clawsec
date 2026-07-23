#!/usr/bin/env node
import { readFile, readdir } from "node:fs/promises";
import { existsSync, lstatSync, realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import https from "node:https";
import path from "node:path";
import { inspectNonInstallableMarkdown } from "./noninstallable_public_installer_policy.mjs";
import { isTestReleasePath } from "./release_path_policy.mjs";
import { resolveSkillInstallability } from "./skill_installability.mjs";
import { resolveDirectSkillsCliTargets } from "./skill_platforms.mjs";

const DEFAULT_REPOSITORY = "prompt-security/clawsec";
const DEFAULT_AGENT_TYPES_URL = "https://raw.githubusercontent.com/vercel-labs/skills/main/src/types.ts";
const DOC_FILENAMES = ["README.md", "SKILL.md"];
const NON_INSTALLABLE_DOC_PROLOGUE =
  "This skill is intentionally non-installable. Do not publish or install it through public skill channels.";
const NO_DIRECT_TARGET_PATTERN = /no\s+(?:reviewed\s+)?direct[\s\S]{0,80}(?:Agent Skills|Skills CLI)[\s\S]{0,40}target/i;

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
      ":(exclude)skills/clawsec-feed/advisories/feed.json",
      ":(exclude)skills/clawsec-feed/advisories/feed.json.sig",
      ":(exclude)skills/clawsec-suite/advisories/feed.json",
      ":(exclude)skills/clawsec-suite/advisories/feed.json.sig",
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

function logicalShellLines(markdown) {
  const lines = [];
  let current = "";
  let awaitingContinuation = false;

  for (const rawLine of markdown.split("\n")) {
    const line = rawLine.trim();
    current = current ? `${current} ${line}` : line.replace(/^\$\s+/, "");
    if (current.endsWith("\\")) {
      current = current.slice(0, -1).trimEnd();
      awaitingContinuation = true;
      continue;
    }
    if (current) {
      lines.push({ text: current, malformedContinuation: false });
    }
    current = "";
    awaitingContinuation = false;
  }

  if (current) {
    lines.push({ text: current, malformedContinuation: awaitingContinuation });
  }
  return lines;
}

function stripHtmlComments(markdown) {
  return markdown.replace(/<!--[\s\S]*?(?:-->|$)/g, "");
}

function hasOnlySupportedYamlCharacters(value) {
  return [...value].every((character) => {
    const codePoint = character.codePointAt(0);
    return (
      (codePoint >= 0x20 && codePoint <= 0x7e) ||
      codePoint === 0x85 ||
      (codePoint >= 0xa0 && codePoint <= 0xd7ff) ||
      (codePoint >= 0xe000 && codePoint <= 0xfffd) ||
      (codePoint >= 0x10000 && codePoint <= 0x10ffff)
    );
  });
}

function isSupportedFrontmatterScalar(scalar) {
  if (!scalar || !hasOnlySupportedYamlCharacters(scalar) || /[<>{}]/.test(scalar)) {
    return false;
  }
  if (/^"(?:[^"\\]|\\["\\/bfnrt]|\\u[0-9A-Fa-f]{4})*"$/.test(scalar)) {
    return true;
  }
  if (/^'(?:[^']|'')*'$/.test(scalar)) {
    return true;
  }
  if (/^\[(?:[A-Za-z0-9_.+/-]+(?:,\s*[A-Za-z0-9_.+/-]+)*)?\]$/.test(scalar)) {
    return true;
  }
  const disallowedPlainScalarStart = "-?:,[]#&*!|>'\"%@`";
  return (
    !disallowedPlainScalarStart.includes(scalar[0]) &&
    !scalar.includes("[") &&
    !scalar.includes("]") &&
    !/(?:^|\s)#/.test(scalar) &&
    !/:(?:\s|,|$)/.test(scalar)
  );
}

function frontmatterBodyStart(lines) {
  if (!/^--- *$/.test(lines[0] || "")) {
    return 0;
  }

  const closingIndex = lines.findIndex(
    (line, index) => index > 0 && /^--- *$/.test(line),
  );
  if (closingIndex === -1) {
    return null;
  }

  const indentationLevels = [0];
  const keysByLevel = [new Set()];
  let previousIndent = 0;
  let previousOpensMapping = false;
  let sawEntry = false;

  for (const rawLine of lines.slice(1, closingIndex)) {
    if (/^ *$/.test(rawLine)) {
      continue;
    }
    if (!hasOnlySupportedYamlCharacters(rawLine)) {
      return null;
    }

    const entry = rawLine.match(/^( *)([A-Za-z_][A-Za-z0-9_-]*):(?: +(.*))?$/);
    if (!entry) {
      return null;
    }

    const indent = entry[1].length;
    const value = (entry[3] || "").replace(/ +$/, "");
    if (indent % 2 !== 0 || (!sawEntry && indent !== 0)) {
      return null;
    }

    if (sawEntry && indent > previousIndent) {
      if (!previousOpensMapping || indent !== previousIndent + 2) {
        return null;
      }
      indentationLevels.push(indent);
      keysByLevel.push(new Set());
    } else if (sawEntry && indent < previousIndent) {
      if (previousOpensMapping) {
        return null;
      }
      while (indentationLevels.at(-1) > indent) {
        indentationLevels.pop();
        keysByLevel.pop();
      }
      if (indentationLevels.at(-1) !== indent) {
        return null;
      }
    } else if (sawEntry && previousOpensMapping) {
      return null;
    }

    if (keysByLevel.at(-1).has(entry[2])) {
      return null;
    }
    keysByLevel.at(-1).add(entry[2]);

    previousIndent = indent;
    previousOpensMapping = value === "";
    if (!previousOpensMapping && !isSupportedFrontmatterScalar(value)) {
      return null;
    }
    sawEntry = true;
  }

  return sawEntry && !previousOpensMapping ? closingIndex + 1 : null;
}

function hasNonInstallableDocPrologue(markdown) {
  const lines = markdown
    .replace(/^\uFEFF/, "")
    .replace(/\r\n?/g, "\n")
    .split("\n");
  let lineIndex = frontmatterBodyStart(lines);
  if (lineIndex === null) {
    return false;
  }

  while (lineIndex < lines.length && /^ *$/.test(lines[lineIndex])) {
    lineIndex += 1;
  }

  return lines[lineIndex]?.replace(/ +$/, "") === NON_INSTALLABLE_DOC_PROLOGUE;
}

function tokenizeShellLine(line) {
  const tokens = [];
  let current = "";
  let quote = "";
  let escaped = false;
  let hasUnsafeShellSyntax = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) {
        quote = "";
      } else {
        if (quote === '"' && (char === "`" || (char === "$" && line[index + 1] === "("))) {
          hasUnsafeShellSyntax = true;
        }
        current += char;
      }
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "#" && current === "") {
      break;
    }
    if (
      char === ";" ||
      char === "|" ||
      char === "&" ||
      char === "<" ||
      char === ">" ||
      char === "`" ||
      (char === "$" && line[index + 1] === "(")
    ) {
      hasUnsafeShellSyntax = true;
    }
    if (/\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }

  if (current) {
    tokens.push(current);
  }
  return {
    tokens,
    hasUnsafeShellSyntax,
    malformed: Boolean(escaped || quote),
  };
}

function parseCommandOptions(tokens, start) {
  const skillValues = [];
  const agentValues = [];
  const unexpectedTokens = [];
  let yesCount = 0;
  let globalCount = 0;

  for (let index = start + 4; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token === "--skill") {
      skillValues.push(tokens[index + 1] || "");
      index += 1;
      continue;
    }
    if (token.startsWith("--skill=")) {
      skillValues.push(token.slice("--skill=".length));
      continue;
    }
    if (token === "-a" || token === "--agent") {
      agentValues.push(tokens[index + 1] || "");
      index += 1;
      continue;
    }
    if (token.startsWith("-a=") || token.startsWith("--agent=")) {
      agentValues.push(token.slice(token.indexOf("=") + 1));
      continue;
    }
    if (token === "-y" || token === "--yes") {
      yesCount += 1;
      continue;
    }
    if (token === "-g" || token === "--global") {
      globalCount += 1;
      continue;
    }
    unexpectedTokens.push(token);
  }

  return { skillValues, agentValues, yesCount, globalCount, unexpectedTokens };
}

function parseSkillsAddCommands(markdown) {
  const commands = [];
  for (const { text: line, malformedContinuation } of logicalShellLines(markdown)) {
    const { tokens, hasUnsafeShellSyntax, malformed } = tokenizeShellLine(line);
    const start = 0;
    if (tokens[start] !== "npx" || tokens[start + 1] !== "skills" || tokens[start + 2] !== "add") {
      if (/\bnpx\s+skills\s+add(?:\s|$)/.test(line)) {
        commands.push({
          source: "",
          skill: "",
          skillValues: [],
          agent: "",
          agentValues: [],
          yes: false,
          malformed: true,
          valid: false,
        });
      }
      continue;
    }

    const { skillValues, agentValues, yesCount, globalCount, unexpectedTokens } = parseCommandOptions(tokens, start);
    const malformedCommand = malformed || malformedContinuation;
    commands.push({
      source: tokens[start + 3] || "",
      skill: skillValues[0] || "",
      skillValues,
      agent: agentValues[0] || "",
      agentValues,
      yes: yesCount === 1,
      malformed: malformedCommand,
      valid: (
        !malformedCommand &&
        !hasUnsafeShellSyntax &&
        skillValues.length === 1 &&
        agentValues.length === 1 &&
        yesCount === 1 &&
        globalCount <= 1 &&
        unexpectedTokens.length === 0
      ),
    });
  }
  return commands;
}

function hasRequiredCommand(commands, { repository, skillName, agent }) {
  return commands.some((command) => (
    command.valid &&
    command.source === repository &&
    command.skill === skillName &&
    command.agent === agent &&
    command.yes
  ));
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hasPlatformNoDirectTargetStatement(markdown, platform) {
  const platformPattern = escapeRegExp(platform);
  const noTargetPattern = NO_DIRECT_TARGET_PATTERN.source;
  const subjectStatement = new RegExp(
    `(?:^|[^A-Za-z0-9])${platformPattern}` +
    `(?:(?:\\s+and\\s+[A-Za-z0-9._+-]+)+|\\s*,\\s*which)?` +
    `\\s+(?:has|have)\\s+${noTargetPattern}`,
    "i",
  );
  const reverseStatement = new RegExp(
    `${noTargetPattern}\\s+(?:exists?\\s+)?(?:for|in)\\s+` +
    `(?:the\\s+)?${platformPattern}(?:$|[^A-Za-z0-9])`,
    "i",
  );
  return markdown
    .split(/\n+|(?<=[.!?;])\s+/)
    .map((statement) => statement.replace(/\s+/g, " ").trim())
    .some((statement) => subjectStatement.test(statement) || reverseStatement.test(statement));
}

function packagedSkillFiles(skill) {
  const files = new Set();
  for (const entry of skill.sbom?.files || []) {
    const candidate = typeof entry === "string" ? entry : entry?.path;
    if (typeof candidate !== "string" || !candidate.trim()) {
      continue;
    }
    const normalized = candidate.replaceAll("\\", "/").replace(/^\.\//, "");
    if (!isTestReleasePath(normalized)) {
      files.add(normalized);
    }
  }
  return files;
}

function hasUnsafePackagePathCharacter(value) {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0);
    return (
      codePoint < 0x20 ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      codePoint === 0x2028 ||
      codePoint === 0x2029
    );
  });
}

function localInstallReferences(markdown, { docPath, skillRoot }) {
  const references = [];
  for (const match of markdown.matchAll(/\[([^\]]+)\]\(([^)]+)\)/g)) {
    const label = match[1];
    const href = match[2].trim().replace(/^<|>$/g, "");
    if (!/(?:install|setup|integration)/i.test(`${label} ${href}`) || /^[a-z]+:/i.test(href)) {
      continue;
    }

    const relativeTarget = href.split(/[?#]/, 1)[0];
    const target = path.resolve(path.dirname(docPath), relativeTarget);
    const skillPrefix = `${skillRoot}${path.sep}`;
    if (target === docPath || !target.startsWith(skillPrefix) || !/\.md$/i.test(target)) {
      continue;
    }

    try {
      const targetStat = lstatSync(target);
      const realSkillRoot = realpathSync(skillRoot);
      const realTarget = realpathSync(target);
      if (
        targetStat.isFile() &&
        realTarget.startsWith(`${realSkillRoot}${path.sep}`)
      ) {
        references.push(path.relative(realSkillRoot, realTarget).split(path.sep).join("/"));
      }
    } catch {
      // Broken links and unreadable targets do not prove a native install path.
    }
  }
  return [...new Set(references)];
}

async function validateNonInstallableMarkdown({ docPath, displayPath, requirePrologue }) {
  const failures = [];
  const inspection = inspectNonInstallableMarkdown(await readFile(docPath));
  if (
    requirePrologue &&
    inspection.markdown !== null &&
    !hasNonInstallableDocPrologue(inspection.markdown)
  ) {
    failures.push(
      `Missing required non-installable document prologue in ${displayPath}: ` +
      NON_INSTALLABLE_DOC_PROLOGUE,
    );
  }
  for (const issue of inspection.issues) {
    failures.push(`Invalid non-installable documentation in ${displayPath}: ${issue}.`);
  }
  return failures;
}

async function validateSkill({ root, skillDir, repository, getAgentTypes }) {
  const skillJsonPath = path.join(root, skillDir, "skill.json");
  const skill = await readJson(skillJsonPath);
  const skillName = skill.name || path.basename(skillDir);
  const installability = resolveSkillInstallability(skill, skillJsonPath);
  const resolution = installability.installable
    ? resolveDirectSkillsCliTargets(skill, await getAgentTypes())
    : null;
  const failures = [];
  const skillRoot = path.join(root, skillDir);
  const packagedFiles = packagedSkillFiles(skill);

  for (const error of resolution?.errors || []) {
    failures.push(`Invalid npx skills target policy for ${skillDir}: ${error}`);
  }

  for (const filename of DOC_FILENAMES) {
    const docPath = path.join(root, skillDir, filename);
    let docStat;
    try {
      docStat = lstatSync(docPath);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        failures.push(
          `Unable to inspect required install documentation file: ${path.join(skillDir, filename)}`,
        );
        continue;
      }
      failures.push(`Missing required install documentation file: ${path.join(skillDir, filename)}`);
      continue;
    }

    if (!docStat.isFile()) {
      failures.push(
        `Required install documentation path is not a regular file: ${path.join(skillDir, filename)}`,
      );
      continue;
    }

    if (!installability.installable) {
      failures.push(...await validateNonInstallableMarkdown({
        docPath,
        displayPath: path.join(skillDir, filename),
        requirePrologue: true,
      }));
      continue;
    }

    const rawMarkdown = await readFile(docPath, "utf8");
    const markdown = stripHtmlComments(rawMarkdown);
    const commands = parseSkillsAddCommands(markdown);
    const commandsForSkill = commands.filter((command) => command.skillValues.includes(skillName));
    const malformedCommands = commands.filter(
      (command) => command.malformed &&
        (command.skillValues.length === 0 || command.skillValues.includes(skillName)),
    );

    if (malformedCommands.length > 0) {
      failures.push(
        `Invalid npx skills install command in ${path.join(skillDir, filename)}: ` +
        "the command must be standalone, use the exact reviewed grammar, and have no wrapper, " +
        "environment assignment, malformed quoting, or trailing line continuation.",
      );
    }

    const missingNoTargetPlatforms = resolution.unsupportedPlatforms.filter(
      (platform) => !hasPlatformNoDirectTargetStatement(markdown, platform),
    );
    if (missingNoTargetPlatforms.length > 0) {
      failures.push(
        `Missing explicit no-direct-target statement in ${path.join(skillDir, filename)} for ` +
        `${missingNoTargetPlatforms.join(", ")}.`,
      );
    }

    if (resolution.status === "not_applicable" && commandsForSkill.length > 0) {
      failures.push(
        `Unsupported npx skills install command in ${path.join(skillDir, filename)}: ` +
        `${resolution.unsupportedPlatforms.join(", ")} has no reviewed direct AgentType target.`,
      );
    }

    if (resolution.unsupportedPlatforms.length > 0) {
      const nativeReferences = localInstallReferences(markdown, { docPath, skillRoot });
      if (nativeReferences.length === 0) {
        failures.push(
          `Missing local harness-native installation reference in ${path.join(skillDir, filename)}.`,
        );
      } else if (!nativeReferences.some((reference) => packagedFiles.has(reference))) {
        failures.push(
          `Harness-native installation reference is omitted from skill.json sbom.files in ` +
          `${path.join(skillDir, filename)}: ${nativeReferences.join(", ")}.`,
        );
      }
    }

    if (resolution.status !== "required") {
      continue;
    }

    if (commandsForSkill.some((command) => !command.valid && !command.malformed)) {
      failures.push(
        `Invalid npx skills install command in ${path.join(skillDir, filename)}: ` +
        "use only the reviewed command grammar with exactly one --skill, one --agent/-a, one --yes/-y, " +
        "at most one --global/-g, and no executable shell syntax or extra tokens.",
      );
    }

    for (const command of commandsForSkill.filter((candidate) => candidate.valid)) {
      if (!resolution.agents.includes(command.agent)) {
        failures.push(
          `Unreviewed npx skills target in ${path.join(skillDir, filename)}: ${command.agent || "(missing)"}.`,
        );
      }
    }

    for (const agent of resolution.agents) {
      if (!hasRequiredCommand(commands, { repository, skillName, agent })) {
        const command = `npx skills add ${repository} --skill ${skillName} -a ${agent} -y`;
        failures.push(`Missing required npx skills install command in ${path.join(skillDir, filename)}: ${command}`);
      }
    }
  }

  if (!installability.installable) {
    for (const filename of packagedFiles) {
      if (hasUnsafePackagePathCharacter(filename)) {
        failures.push(
          `Unsafe package-visible path for ${skillDir}: control characters are not allowed.`,
        );
        continue;
      }
      if (/\.mdx$/i.test(filename)) {
        failures.push(
          `Unsupported package-visible MDX path for non-installable skill ${skillDir}: ${filename}.`,
        );
        continue;
      }
      if (!/\.md$/i.test(filename) || DOC_FILENAMES.includes(filename)) {
        continue;
      }

      const docPath = path.resolve(skillRoot, filename.split("/").join(path.sep));
      const skillPrefix = `${path.resolve(skillRoot)}${path.sep}`;
      const displayPath = `${skillDir}/${filename}`;
      if (!docPath.startsWith(skillPrefix)) {
        failures.push(`Unsafe package-visible Markdown path for ${skillDir}: ${filename}.`);
        continue;
      }

      let docStat;
      try {
        docStat = lstatSync(docPath);
      } catch (error) {
        if (error?.code === "ENOENT") {
          continue;
        }
        failures.push(`Unable to inspect package-visible Markdown file: ${displayPath}`);
        continue;
      }
      if (!docStat.isFile()) {
        failures.push(`Package-visible Markdown path is not a regular file: ${displayPath}`);
        continue;
      }

      failures.push(...await validateNonInstallableMarkdown({
        docPath,
        displayPath,
        requirePrologue: false,
      }));
    }
  }

  return {
    skillDir,
    skillName,
    installability,
    resolution,
    failures,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  let agentTypesPromise;
  const getAgentTypes = () => {
    agentTypesPromise ??= readAgentTypeSource(options).then(parseAgentTypes);
    return agentTypesPromise;
  };
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
        getAgentTypes,
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
    if (!result.installability.installable) {
      console.log(
        `Public install docs not applicable for ${result.skillName}: ` +
        'skill.json declares "installable": false',
      );
      continue;
    }

    if (result.resolution.status === "not_applicable") {
      console.log(
        `npx skills install docs not applicable for ${result.skillName}: ` +
        `no reviewed direct AgentType for ${result.resolution.unsupportedPlatforms.join(", ")}`,
      );
      continue;
    }

    const targets = result.resolution.agents.map((agent) => `-a ${agent}`).join(", ");
    const unsupported = result.resolution.unsupportedPlatforms.length > 0
      ? `; no direct target for ${result.resolution.unsupportedPlatforms.join(", ")}`
      : "";
    console.log(`npx skills install docs OK for ${result.skillName}: ${targets}${unsupported}`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
