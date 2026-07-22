export const SKILLS_INDEX_PATH = "/skills/index.json";

const RESULT_FIELDS = [
  "state",
  "reason",
  "record",
  "skillData",
  "checksums",
  "doc",
  "view",
];

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOwn(value, field) {
  return Object.prototype.hasOwnProperty.call(value, field);
}

function requireNonEmptyString(value, field, source) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${source} field "${field}" must be a non-empty string`);
  }
  return value;
}

function validateOptionalInstallable(value, source) {
  if (hasOwn(value, "installable") && typeof value.installable !== "boolean") {
    throw new Error(`${source} field "installable" must be a boolean when present`);
  }
}

function isProbablyHtmlDocument(text) {
  const start = text.trimStart().slice(0, 200).toLowerCase();
  return start.startsWith("<!doctype html") || start.startsWith("<html");
}

function responseContentType(response) {
  return response?.headers?.get?.("content-type") ?? "";
}

function isHtmlResponse(response, text) {
  return responseContentType(response).toLowerCase().includes("text/html")
    || isProbablyHtmlDocument(text);
}

function isAbortError(error) {
  return error !== null
    && typeof error === "object"
    && "name" in error
    && error.name === "AbortError";
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function buildResult({
  state,
  reason,
  record = null,
  skillData = null,
  checksums = null,
  doc = null,
}) {
  const result = {
    state,
    reason,
    record,
    skillData,
    checksums,
    doc,
    view: getSkillLifecycleView(state),
  };

  // Keep the public result stable even if this helper is refactored later.
  if (Object.keys(result).some((field, index) => field !== RESULT_FIELDS[index])) {
    throw new Error("Internal lifecycle result shape mismatch");
  }

  return result;
}

function blocked(reason, fields = {}) {
  return buildResult({ state: "blocked", reason, ...fields });
}

function historical(reason, fields = {}) {
  return buildResult({ state: "historical", reason, ...fields });
}

function validateIndexRecord(record, index) {
  const source = `Skills index record ${index}`;
  if (!isObject(record)) {
    throw new Error(`${source} must be an object`);
  }

  for (const field of ["id", "name", "version", "description", "emoji", "category", "tag"]) {
    requireNonEmptyString(record[field], field, source);
  }

  if (record.id !== record.name) {
    throw new Error(`${source} field "id" must exactly match "name"`);
  }

  const expectedTag = `${record.name}-v${record.version}`;
  if (record.tag !== expectedTag) {
    throw new Error(`${source} field "tag" must be "${expectedTag}"`);
  }

  if (hasOwn(record, "platforms")) {
    if (!Array.isArray(record.platforms) || record.platforms.some((platform) => typeof platform !== "string")) {
      throw new Error(`${source} field "platforms" must be an array of strings when present`);
    }
  }

  validateOptionalInstallable(record, source);

  return {
    ...record,
    ...(Array.isArray(record.platforms) ? { platforms: [...record.platforms] } : {}),
  };
}

export function parseSkillsIndex(raw) {
  if (typeof raw !== "string") {
    throw new Error("Skills index must be JSON text");
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Skills index contains invalid JSON");
  }

  if (!isObject(parsed)) {
    throw new Error("Skills index root must be an object");
  }
  if (!Array.isArray(parsed.skills)) {
    throw new Error('Skills index field "skills" must be an array');
  }

  const seenIds = new Set();
  const seenNames = new Set();
  const skills = parsed.skills.map((record, index) => {
    const validated = validateIndexRecord(record, index);
    if (seenIds.has(validated.id)) {
      throw new Error(`Skills index contains duplicate id "${validated.id}"`);
    }
    if (seenNames.has(validated.name)) {
      throw new Error(`Skills index contains duplicate name "${validated.name}"`);
    }
    seenIds.add(validated.id);
    seenNames.add(validated.name);
    return validated;
  });

  return { ...parsed, skills };
}

export async function loadSkillsIndex(fetchImpl, { signal } = {}) {
  if (typeof fetchImpl !== "function") {
    throw new Error("A fetch implementation is required");
  }

  const response = await fetchImpl(SKILLS_INDEX_PATH, {
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response?.ok) {
    const status = Number.isInteger(response?.status) ? ` (HTTP ${response.status})` : "";
    throw new Error(`Skills index is unavailable${status}`);
  }

  const raw = await response.text();
  if (!raw.trim()) {
    throw new Error("Skills index response is empty");
  }
  if (isHtmlResponse(response, raw)) {
    throw new Error("Skills index response is HTML, not JSON");
  }

  return parseSkillsIndex(raw);
}

function parseSkillData(raw) {
  let skill;
  try {
    skill = JSON.parse(raw);
  } catch {
    throw new Error("Skill metadata contains invalid JSON");
  }

  if (!isObject(skill)) {
    throw new Error("Skill metadata root must be an object");
  }
  requireNonEmptyString(skill.name, "name", "Skill metadata");
  requireNonEmptyString(skill.version, "version", "Skill metadata");
  validateOptionalInstallable(skill, "Skill metadata");
  if (hasOwn(skill, "tag")) {
    requireNonEmptyString(skill.tag, "tag", "Skill metadata");
  }
  return skill;
}

function validateDetailIdentity(skillId, record, skillData) {
  if (record.id !== skillId || record.name !== skillId) {
    throw new Error("Catalog route identity does not match the requested skill");
  }
  if (skillData.name !== record.name) {
    throw new Error("Skill metadata name does not match the catalog record");
  }
  if (skillData.version !== record.version) {
    throw new Error("Skill metadata version does not match the catalog record");
  }

  const detailTag = hasOwn(skillData, "tag")
    ? skillData.tag
    : `${skillData.name}-v${skillData.version}`;
  if (detailTag !== record.tag) {
    throw new Error("Skill metadata tag does not match the catalog record");
  }
}

async function fetchRequiredSkillData(fetchImpl, url, signal) {
  const response = await fetchImpl(url, {
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response?.ok) {
    const status = Number.isInteger(response?.status) ? ` (HTTP ${response.status})` : "";
    throw new Error(`Skill metadata is unavailable${status}`);
  }

  const raw = await response.text();
  if (!raw.trim()) {
    throw new Error("Skill metadata response is empty");
  }
  if (isHtmlResponse(response, raw)) {
    throw new Error("Skill metadata response is HTML, not JSON");
  }
  return parseSkillData(raw);
}

async function fetchOptionalChecksums(fetchImpl, url, signal, expectedRecord) {
  try {
    const response = await fetchImpl(url, {
      headers: { Accept: "application/json" },
      signal,
    });
    if (!response?.ok) return null;

    const raw = await response.text();
    if (!raw.trim() || isHtmlResponse(response, raw)) return null;

    const parsed = JSON.parse(raw);
    if (
      !isObject(parsed)
      || parsed.skill !== expectedRecord.name
      || parsed.version !== expectedRecord.version
      || parsed.tag !== expectedRecord.tag
      || !isObject(parsed.files)
    ) {
      return null;
    }

    for (const [filename, file] of Object.entries(parsed.files)) {
      if (
        !filename
        || !isObject(file)
        || typeof file.sha256 !== "string"
        || !file.sha256.trim()
        || typeof file.size !== "number"
        || !Number.isFinite(file.size)
        || file.size < 0
        || (hasOwn(file, "path") && typeof file.path !== "string")
        || (hasOwn(file, "url") && typeof file.url !== "string")
      ) {
        return null;
      }
    }

    return parsed;
  } catch (error) {
    if (isAbortError(error)) throw error;
    return null;
  }
}

async function fetchOptionalDoc(fetchImpl, url, filename, signal) {
  try {
    const response = await fetchImpl(url, {
      headers: { Accept: "text/plain" },
      signal,
    });
    if (!response?.ok) return null;

    const raw = await response.text();
    if (!raw.trim() || isHtmlResponse(response, raw)) return null;
    return { filename, content: raw.trim() };
  } catch (error) {
    if (isAbortError(error)) throw error;
    return null;
  }
}

export function getSkillLifecycleView(state) {
  if (!new Set(["installable", "historical", "blocked"]).has(state)) {
    throw new Error(`Unknown skill lifecycle state: ${state}`);
  }

  const installable = state === "installable";
  return {
    canInstall: installable,
    showCopyControls: installable,
    showPlatforms: installable,
    showTriggers: installable,
    showDocumentation: installable,
    historicalEvidence: state === "historical",
  };
}

export async function loadSkillDetailData(fetchImpl, skillId, { signal } = {}) {
  let index;
  try {
    index = await loadSkillsIndex(fetchImpl, { signal });
  } catch (error) {
    if (isAbortError(error)) throw error;
    return blocked(`Unable to verify catalog lifecycle: ${errorMessage(error)}`);
  }

  if (typeof skillId !== "string" || !skillId.trim()) {
    return blocked("The requested skill identity is missing");
  }

  const record = index.skills.find((candidate) => candidate.id === skillId);
  if (!record) {
    return blocked("The requested skill is not present in the verified catalog index");
  }

  if (record.installable === false) {
    return historical("The catalog marks this skill as historical and non-installable", { record });
  }

  const encodedSkillId = encodeURIComponent(skillId);
  const skillJsonUrl = `/skills/${encodedSkillId}/skill.json`;
  let skillData;
  try {
    skillData = await fetchRequiredSkillData(fetchImpl, skillJsonUrl, signal);
    validateDetailIdentity(skillId, record, skillData);
  } catch (error) {
    if (isAbortError(error)) throw error;
    return blocked(`Unable to verify skill metadata: ${errorMessage(error)}`, { record });
  }

  if (skillData.installable === false) {
    return historical("The skill metadata marks this release as historical and non-installable", {
      record,
      skillData,
    });
  }

  const checksums = await fetchOptionalChecksums(
    fetchImpl,
    `/skills/${encodedSkillId}/checksums.json`,
    signal,
    record,
  );

  let doc = await fetchOptionalDoc(
    fetchImpl,
    `/skills/${encodedSkillId}/README.md`,
    "README.md",
    signal,
  );
  if (!doc) {
    doc = await fetchOptionalDoc(
      fetchImpl,
      `/skills/${encodedSkillId}/SKILL.md`,
      "SKILL.md",
      signal,
    );
  }

  return buildResult({
    state: "installable",
    reason: "Catalog and skill metadata allow the installation experience",
    record,
    skillData,
    checksums,
    doc,
  });
}
