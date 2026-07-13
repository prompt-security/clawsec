import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isCpeAffectedSpecifier, parseAffectedSpecifier, parseVersionSpec } from "./semver.mjs";

const PINNED_FEED_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAS7nijfMcUoOBCj4yOXJX+GYGv2pFl2Yaha1P4v5Cm6A=
-----END PUBLIC KEY-----
`;

const DEFAULT_REMOTE_FEED_URL = "https://clawsec.prompt.security/advisories/feed.json";
const STATE_FILE_BASENAME = "feed-verification-state.json";
const CACHED_FEED_BASENAME = "feed.json";

function isObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function toBool(value, fallback = false) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === "boolean") return value;
  const norm = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on", "enabled"].includes(norm)) return true;
  if (["0", "false", "no", "off", "disabled"].includes(norm)) return false;
  return fallback;
}

function readJsonFileMaybe(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function detectHermesConfig(hermesHome) {
  const candidates = [path.join(hermesHome, "config.json"), path.join(hermesHome, "gateway", "config.json")];
  for (const candidate of candidates) {
    try {
      const parsed = readJsonFileMaybe(candidate);
      if (parsed && typeof parsed === "object") {
        return parsed;
      }
    } catch {
      // Ignore malformed local config here; feed verification should remain independently operable.
    }
  }
  return {};
}

function configValue(config, key) {
  const fromRoot = config?.advisory_feed?.[key];
  if (fromRoot !== undefined && fromRoot !== null) return fromRoot;
  const fromSecurity = config?.security?.advisory_feed?.[key];
  if (fromSecurity !== undefined && fromSecurity !== null) return fromSecurity;
  return undefined;
}

function readEnv(name) {
  const proc = globalThis?.process;
  const envBag = proc && typeof proc === "object" ? proc["env"] : undefined;
  return envBag ? envBag[name] : undefined;
}

function envOrConfigString(name, config, configKey, fallback) {
  const envValue = readEnv(name);
  if (typeof envValue === "string" && envValue.trim()) {
    return envValue.trim();
  }
  const cfgValue = configValue(config, configKey);
  if (typeof cfgValue === "string" && cfgValue.trim()) {
    return cfgValue.trim();
  }
  return fallback;
}

function envOrConfigBool(name, config, configKey, fallback) {
  const envValue = readEnv(name);
  if (typeof envValue === "string") {
    return toBool(envValue, fallback);
  }
  const cfgValue = configValue(config, configKey);
  if (cfgValue !== undefined) {
    return toBool(cfgValue, fallback);
  }
  return fallback;
}

function resolveUserPath(rawPath, fallback, hermesHome) {
  const picked = String(rawPath || fallback || "").trim();
  if (!picked) return "";
  if (picked === "~") return os.homedir();
  if (picked.startsWith("~/")) return path.join(os.homedir(), picked.slice(2));
  if (picked.startsWith("$HERMES_HOME/")) return path.join(hermesHome, picked.slice("$HERMES_HOME/".length));
  return path.resolve(picked);
}

function isPathInside(childPath, parentPath) {
  const child = path.resolve(childPath);
  const parent = path.resolve(parentPath);
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function nearestExistingAncestorWithinRoot(targetPath, rootPath) {
  const root = path.resolve(rootPath);
  let candidate = path.resolve(targetPath);

  while (isPathInside(candidate, root)) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    const parent = path.dirname(candidate);
    if (parent === candidate) {
      break;
    }
    candidate = parent;
  }

  return null;
}

function nearestExistingAncestor(inputPath) {
  let candidate = path.resolve(inputPath);
  while (!fs.existsSync(candidate)) {
    const parent = path.dirname(candidate);
    if (parent === candidate) {
      return candidate;
    }
    candidate = parent;
  }
  return candidate;
}

function safeRealpath(inputPath) {
  return fs.realpathSync.native ? fs.realpathSync.native(inputPath) : fs.realpathSync(inputPath);
}

function realpathWithMissingTail(inputPath) {
  const resolved = path.resolve(inputPath);
  const ancestor = nearestExistingAncestor(resolved);
  const ancestorReal = safeRealpath(ancestor);
  const rel = path.relative(ancestor, resolved);
  return rel ? path.join(ancestorReal, rel) : ancestorReal;
}

function confineToHermesHome(candidatePath, hermesHome, label) {
  const root = path.resolve(hermesHome);
  const resolved = path.resolve(String(candidatePath || ""));

  if (!isPathInside(resolved, root)) {
    throw new Error(`${label} must stay under ${root}`);
  }

  const rootReal = realpathWithMissingTail(root);
  const nearestAncestor = nearestExistingAncestorWithinRoot(resolved, root);
  if (nearestAncestor) {
    const nearestAncestorReal = safeRealpath(nearestAncestor);
    if (!isPathInside(nearestAncestorReal, rootReal)) {
      throw new Error(`${label} must stay under ${rootReal}`);
    }
  }

  if (fs.existsSync(resolved) && fs.lstatSync(resolved).isSymbolicLink()) {
    throw new Error(`${label} must not be a symlink: ${resolved}`);
  }

  return resolved;
}

function sha256Hex(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function decodeSignature(signatureRaw) {
  const trimmed = String(signatureRaw || "").trim();
  if (!trimmed) return null;

  let encoded = trimmed;
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (isObject(parsed) && typeof parsed.signature === "string") {
        encoded = parsed.signature;
      }
    } catch {
      return null;
    }
  }

  const normalized = encoded.replace(/\s+/g, "");
  if (!normalized) return null;

  try {
    return Buffer.from(normalized, "base64");
  } catch {
    return null;
  }
}

export function verifySignedPayload(payloadRaw, signatureRaw, publicKeyPem) {
  const signature = decodeSignature(signatureRaw);
  if (!signature) return false;

  const keyPem = String(publicKeyPem || "").trim();
  if (!keyPem) return false;

  try {
    const publicKey = crypto.createPublicKey(keyPem);
    return crypto.verify(null, Buffer.from(payloadRaw, "utf8"), publicKey, signature);
  } catch {
    return false;
  }
}

function extractSha256(value) {
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    return /^[a-f0-9]{64}$/.test(normalized) ? normalized : null;
  }
  if (isObject(value) && typeof value.sha256 === "string") {
    const normalized = value.sha256.trim().toLowerCase();
    return /^[a-f0-9]{64}$/.test(normalized) ? normalized : null;
  }
  return null;
}

function parseChecksumsManifest(manifestRaw) {
  let parsed;
  try {
    parsed = JSON.parse(manifestRaw);
  } catch {
    throw new Error("checksum manifest is not valid JSON");
  }

  if (!isObject(parsed)) {
    throw new Error("checksum manifest must be an object");
  }

  const algorithm = String(parsed.algorithm || "sha256").trim().toLowerCase();
  if (algorithm !== "sha256") {
    throw new Error(`unsupported checksum algorithm: ${algorithm || "(empty)"}`);
  }

  if (!isObject(parsed.files)) {
    throw new Error("checksum manifest missing files object");
  }

  const files = {};
  for (const [name, value] of Object.entries(parsed.files)) {
    const key = String(name || "").trim();
    if (!key) continue;
    const digest = extractSha256(value);
    if (!digest) {
      throw new Error(`invalid checksum digest for ${key}`);
    }
    files[key] = digest;
  }

  if (Object.keys(files).length === 0) {
    throw new Error("checksum manifest has no usable digest entries");
  }

  return { files };
}

function normalizeChecksumEntryName(entryName) {
  return String(entryName || "")
    .trim()
    .replace(/\\/g, "/")
    .replace(/^(?:\.\/)+/, "")
    .replace(/^\/+/, "");
}

function resolveChecksumManifestEntry(files, entryName) {
  const normalizedEntry = normalizeChecksumEntryName(entryName);
  if (!normalizedEntry) return null;

  const candidates = [
    normalizedEntry,
    path.posix.basename(normalizedEntry),
    `advisories/${path.posix.basename(normalizedEntry)}`,
  ].filter((candidate, index, all) => candidate && all.indexOf(candidate) === index);

  for (const candidate of candidates) {
    if (Object.prototype.hasOwnProperty.call(files, candidate)) {
      return { key: candidate, digest: files[candidate] };
    }
  }

  const basename = path.posix.basename(normalizedEntry);
  if (!basename) return null;

  const matches = Object.entries(files).filter(([key]) => path.posix.basename(normalizeChecksumEntryName(key)) === basename);
  if (matches.length > 1) {
    throw new Error(`checksum manifest entry is ambiguous for ${entryName}`);
  }
  if (matches.length === 1) {
    const [key, digest] = matches[0];
    return { key, digest };
  }

  return null;
}

function verifyChecksumEntry(manifest, entryName, contentRaw) {
  const resolved = resolveChecksumManifestEntry(manifest.files, entryName);
  if (!resolved) {
    throw new Error(`checksum manifest missing required entry: ${entryName}`);
  }
  const actual = sha256Hex(contentRaw);
  if (actual !== resolved.digest) {
    throw new Error(`checksum mismatch for ${entryName} (manifest key: ${resolved.key})`);
  }
  return resolved;
}

function safeBasename(urlOrPath, fallback) {
  try {
    const parsed = new URL(urlOrPath);
    const parts = parsed.pathname.split("/").filter(Boolean);
    return parts.length > 0 ? parts[parts.length - 1] : fallback;
  } catch {
    const normalized = String(urlOrPath || "").trim();
    const base = path.basename(normalized);
    return base || fallback;
  }
}

async function fetchTextRequired(url) {
  const controller = new globalThis.AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), 10000);
  try {
    const response = await globalThis.fetch(url, {
      method: "GET",
      signal: controller.signal,
      headers: { accept: "application/json,text/plain;q=0.9,*/*;q=0.8" },
    });
    if (!response.ok) {
      throw new Error(`failed to fetch ${url} (http ${response.status})`);
    }
    return await response.text();
  } catch (error) {
    throw new Error(`failed to fetch ${url}: ${error?.message || String(error)}`);
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

async function fetchTextOptional(url) {
  const controller = new globalThis.AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), 10000);
  try {
    const response = await globalThis.fetch(url, {
      method: "GET",
      signal: controller.signal,
      headers: { accept: "application/json,text/plain;q=0.9,*/*;q=0.8" },
    });
    if (!response.ok) {
      if (response.status === 404) return null;
      throw new Error(`failed to fetch ${url} (http ${response.status})`);
    }
    return await response.text();
  } catch (error) {
    if (String(error?.name || "") === "AbortError") {
      throw new Error(`failed to fetch ${url}: request timed out`);
    }
    throw new Error(`failed to fetch ${url}: ${error?.message || String(error)}`);
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

export function isValidFeedPayload(raw) {
  if (!isObject(raw)) return false;
  if (typeof raw.version !== "string" || !raw.version.trim()) return false;
  if (!Array.isArray(raw.advisories)) return false;

  for (const advisory of raw.advisories) {
    if (!isObject(advisory)) return false;
    if (typeof advisory.id !== "string" || !advisory.id.trim()) return false;
    if (typeof advisory.severity !== "string" || !advisory.severity.trim()) return false;
    if (!Array.isArray(advisory.affected)) return false;
    for (const entry of advisory.affected) {
      if (typeof entry !== "string" || !entry.trim()) return false;
      // The consolidated feed intentionally preserves NVD CPE metadata. Hermes
      // package matching cannot act on CPEs, but valid CPE 2.3 entries must not
      // invalidate an otherwise trusted feed.
      if (isCpeAffectedSpecifier(entry)) continue;
      const parsed = parseAffectedSpecifier(entry);
      if (!parsed || !parsed.name) return false;
      if (!parseVersionSpec(parsed.versionSpec).supported) return false;
    }
  }

  return true;
}

export function detectHermesHome() {
  const envHome = String(readEnv("HERMES_HOME") || "").trim();
  return envHome || path.join(os.homedir(), ".hermes");
}

export function advisorySecurityRoot(hermesHome = detectHermesHome()) {
  return path.join(path.resolve(hermesHome), "security", "advisories");
}

export function defaultFeedStatePath(hermesHome = detectHermesHome()) {
  return path.join(advisorySecurityRoot(hermesHome), STATE_FILE_BASENAME);
}

export function defaultCachedFeedPath(hermesHome = detectHermesHome()) {
  return path.join(advisorySecurityRoot(hermesHome), CACHED_FEED_BASENAME);
}

export function defaultChecksumsUrl(feedUrl) {
  try {
    return new URL("checksums.json", feedUrl).toString();
  } catch {
    const fallbackBase = String(feedUrl || "").replace(/\/?[^/]*$/, "");
    return `${fallbackBase}/checksums.json`;
  }
}

export function resolveFeedConfig(overrides = {}) {
  const hermesHome = detectHermesHome();
  const config = detectHermesConfig(hermesHome);
  const advisoryRoot = advisorySecurityRoot(hermesHome);

  const cachedFeedPath = confineToHermesHome(
    resolveUserPath(
      overrides.cachedFeedPath
        ?? envOrConfigString("HERMES_ADVISORY_CACHED_FEED", config, "cached_feed_path", path.join(advisoryRoot, CACHED_FEED_BASENAME)),
      path.join(advisoryRoot, CACHED_FEED_BASENAME),
      hermesHome,
    ),
    hermesHome,
    "cached feed path",
  );

  const feedUrl = String(
    overrides.feedUrl
      ?? envOrConfigString("HERMES_ADVISORY_FEED_URL", config, "url", DEFAULT_REMOTE_FEED_URL),
  ).trim();

  const signatureUrl = String(
    overrides.signatureUrl
      ?? envOrConfigString("HERMES_ADVISORY_FEED_SIG_URL", config, "signature_url", `${feedUrl}.sig`),
  ).trim();

  const checksumsUrl = String(
    overrides.checksumsUrl
      ?? envOrConfigString("HERMES_ADVISORY_FEED_CHECKSUMS_URL", config, "checksums_url", defaultChecksumsUrl(feedUrl)),
  ).trim();

  const checksumsSignatureUrl = String(
    overrides.checksumsSignatureUrl
      ?? envOrConfigString("HERMES_ADVISORY_FEED_CHECKSUMS_SIG_URL", config, "checksums_signature_url", `${checksumsUrl}.sig`),
  ).trim();

  const source = String(
    overrides.source
      ?? envOrConfigString("HERMES_ADVISORY_FEED_SOURCE", config, "source", "auto"),
  ).trim().toLowerCase();

  const allowUnsigned = overrides.allowUnsigned ?? envOrConfigBool("HERMES_ADVISORY_ALLOW_UNSIGNED_FEED", config, "allow_unsigned", false);
  const verifyChecksumManifest = overrides.verifyChecksumManifest
    ?? envOrConfigBool("HERMES_ADVISORY_VERIFY_CHECKSUM_MANIFEST", config, "verify_checksum_manifest", true);

  const localFeedPath = resolveUserPath(
    overrides.localFeedPath
      ?? envOrConfigString("HERMES_LOCAL_ADVISORY_FEED", config, "local_path", cachedFeedPath),
    cachedFeedPath,
    hermesHome,
  );
  const localSignaturePath = resolveUserPath(
    overrides.localSignaturePath
      ?? envOrConfigString("HERMES_LOCAL_ADVISORY_FEED_SIG", config, "local_signature_path", `${localFeedPath}.sig`),
    `${localFeedPath}.sig`,
    hermesHome,
  );
  const localChecksumsPath = resolveUserPath(
    overrides.localChecksumsPath
      ?? envOrConfigString(
        "HERMES_LOCAL_ADVISORY_FEED_CHECKSUMS",
        config,
        "local_checksums_path",
        path.join(path.dirname(localFeedPath), "checksums.json"),
      ),
    path.join(path.dirname(localFeedPath), "checksums.json"),
    hermesHome,
  );
  const localChecksumsSignaturePath = resolveUserPath(
    overrides.localChecksumsSignaturePath
      ?? envOrConfigString("HERMES_LOCAL_ADVISORY_FEED_CHECKSUMS_SIG", config, "local_checksums_signature_path", `${localChecksumsPath}.sig`),
    `${localChecksumsPath}.sig`,
    hermesHome,
  );

  const publicKeyPathRaw = overrides.publicKeyPath
    ?? envOrConfigString("HERMES_ADVISORY_FEED_PUBLIC_KEY", config, "public_key_path", "");
  const publicKeyPath = publicKeyPathRaw ? resolveUserPath(publicKeyPathRaw, "", hermesHome) : "";

  const statePath = confineToHermesHome(
    resolveUserPath(
      overrides.statePath
        ?? envOrConfigString("HERMES_ADVISORY_FEED_STATE_PATH", config, "state_path", path.join(advisoryRoot, STATE_FILE_BASENAME)),
      path.join(advisoryRoot, STATE_FILE_BASENAME),
      hermesHome,
    ),
    hermesHome,
    "advisory state path",
  );

  return {
    hermesHome,
    advisoryRoot,
    source: ["remote", "local", "auto"].includes(source) ? source : "auto",
    feedUrl,
    signatureUrl,
    checksumsUrl,
    checksumsSignatureUrl,
    localFeedPath,
    localSignaturePath,
    localChecksumsPath,
    localChecksumsSignaturePath,
    publicKeyPath,
    publicKeyPem: overrides.publicKeyPem || "",
    allowUnsigned: allowUnsigned === true,
    verifyChecksumManifest: verifyChecksumManifest !== false,
    statePath,
    cachedFeedPath,
  };
}

function readPublicKeyPem(config) {
  if (config.allowUnsigned) return "";
  if (config.publicKeyPem && config.publicKeyPem.trim()) {
    return config.publicKeyPem;
  }
  if (config.publicKeyPath) {
    if (!fs.existsSync(config.publicKeyPath)) {
      throw new Error(`pinned feed public key not found: ${config.publicKeyPath}`);
    }
    return fs.readFileSync(config.publicKeyPath, "utf8");
  }
  return PINNED_FEED_PUBLIC_KEY_PEM;
}

export function loadFeedVerificationState(statePath = defaultFeedStatePath()) {
  if (!fs.existsSync(statePath)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(statePath, "utf8"));
    if (!isObject(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function getFeedVerificationStatus({ statePath = defaultFeedStatePath() } = {}) {
  const state = loadFeedVerificationState(statePath);
  const status = String(state?.status || "").trim().toLowerCase();
  if (["verified", "unverified"].includes(status)) {
    return {
      status,
      available: true,
      checked_at: state.checked_at || null,
      state_path: statePath,
      source: state.source || null,
    };
  }

  return {
    status: "unknown",
    available: false,
    checked_at: null,
    state_path: statePath,
    source: null,
  };
}

function writeTextAtomic(filePath, content, writeOptions = {}) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = path.join(
    path.dirname(filePath),
    `${path.basename(filePath)}.tmp-${process.pid}-${Date.now()}-${crypto.randomUUID()}`,
  );
  let renamed = false;
  try {
    fs.writeFileSync(tempPath, content, { encoding: "utf8", ...writeOptions });
    fs.renameSync(tempPath, filePath);
    renamed = true;
  } finally {
    if (!renamed && fs.existsSync(tempPath)) {
      try {
        fs.unlinkSync(tempPath);
      } catch {
        // Best-effort cleanup for interrupted atomic writes.
      }
    }
  }
}

function writeJsonAtomic(filePath, value) {
  writeTextAtomic(filePath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function parseAndValidateFeed(feedRaw, sourceLabel) {
  let payload;
  try {
    payload = JSON.parse(feedRaw);
  } catch (error) {
    throw new Error(`invalid advisory feed JSON (${sourceLabel}): ${error?.message || String(error)}`);
  }

  if (!isValidFeedPayload(payload)) {
    throw new Error(`invalid advisory feed format (${sourceLabel})`);
  }

  return payload;
}

function assertSignedPayload(payloadRaw, signatureRaw, keyPem, failureMessage) {
  if (!verifySignedPayload(payloadRaw, signatureRaw, keyPem)) {
    throw new Error(failureMessage);
  }
}

function assertCompleteChecksumManifestArtifacts(hasManifest, hasManifestSignature) {
  if (!hasManifest || !hasManifestSignature) {
    throw new Error("checksum manifest artifacts are required when checksum verification is enabled");
  }
}

function verifyChecksumManifestBundle({
  checksumsRaw,
  checksumsSignatureRaw,
  keyPem,
  checksumsLocation,
  feedEntry,
  signatureEntry,
  feedRaw,
  signatureRaw,
}) {
  assertSignedPayload(
    checksumsRaw,
    checksumsSignatureRaw,
    keyPem,
    `checksum manifest signature verification failed: ${checksumsLocation}`,
  );

  const manifest = parseChecksumsManifest(checksumsRaw);
  verifyChecksumEntry(manifest, feedEntry, feedRaw);
  verifyChecksumEntry(manifest, signatureEntry, signatureRaw);
}

function verifySignedFeedArtifacts({
  feedRaw,
  signatureRaw,
  keyPem,
  signatureFailureMessage,
  verifyChecksumManifest,
  checksumsRaw,
  checksumsSignatureRaw,
  checksumsLocation,
  feedEntry,
  signatureEntry,
}) {
  assertSignedPayload(feedRaw, signatureRaw, keyPem, signatureFailureMessage);

  if (!verifyChecksumManifest) {
    return false;
  }

  const hasChecksums = checksumsRaw !== null;
  const hasChecksumsSignature = checksumsSignatureRaw !== null;
  assertCompleteChecksumManifestArtifacts(hasChecksums, hasChecksumsSignature);

  verifyChecksumManifestBundle({
    checksumsRaw,
    checksumsSignatureRaw,
    keyPem,
    checksumsLocation,
    feedEntry,
    signatureEntry,
    feedRaw,
    signatureRaw,
  });
  return true;
}

export async function loadLocalFeed(config) {
  const feedRaw = fs.readFileSync(config.localFeedPath, "utf8");
  const keyPem = readPublicKeyPem(config);
  const result = {
    source: "local",
    location: config.localFeedPath,
    checksums_verified: false,
    unsigned_bypass: config.allowUnsigned,
  };

  if (!config.allowUnsigned) {
    if (!fs.existsSync(config.localSignaturePath)) {
      throw new Error(`missing local feed signature: ${config.localSignaturePath}`);
    }

    const signatureRaw = fs.readFileSync(config.localSignaturePath, "utf8");
    const hasChecksums = config.verifyChecksumManifest && fs.existsSync(config.localChecksumsPath);
    const hasChecksumsSignature = config.verifyChecksumManifest && fs.existsSync(config.localChecksumsSignaturePath);
    const checksumsRaw = hasChecksums ? fs.readFileSync(config.localChecksumsPath, "utf8") : null;
    const checksumsSignatureRaw = hasChecksumsSignature ? fs.readFileSync(config.localChecksumsSignaturePath, "utf8") : null;
    result.checksums_verified = verifySignedFeedArtifacts({
      feedRaw,
      signatureRaw,
      keyPem,
      signatureFailureMessage: `local feed signature verification failed: ${config.localFeedPath}`,
      verifyChecksumManifest: config.verifyChecksumManifest,
      checksumsRaw,
      checksumsSignatureRaw,
      checksumsLocation: config.localChecksumsPath,
      feedEntry: path.basename(config.localFeedPath),
      signatureEntry: path.basename(config.localSignaturePath),
    });
  }

  const payload = parseAndValidateFeed(feedRaw, config.localFeedPath);
  return {
    payload,
    feedRaw,
    verification: result,
  };
}

export async function loadRemoteFeed(config) {
  const feedRaw = await fetchTextRequired(config.feedUrl);
  const keyPem = readPublicKeyPem(config);
  const result = {
    source: "remote",
    location: config.feedUrl,
    checksums_verified: false,
    unsigned_bypass: config.allowUnsigned,
  };

  if (!config.allowUnsigned) {
    const signatureRaw = await fetchTextRequired(config.signatureUrl);
    const checksumsRaw = config.verifyChecksumManifest ? await fetchTextOptional(config.checksumsUrl) : null;
    const checksumsSignatureRaw = config.verifyChecksumManifest ? await fetchTextOptional(config.checksumsSignatureUrl) : null;
    const feedEntry = safeBasename(config.feedUrl, "feed.json");
    result.checksums_verified = verifySignedFeedArtifacts({
      feedRaw,
      signatureRaw,
      keyPem,
      signatureFailureMessage: `remote feed signature verification failed: ${config.feedUrl}`,
      verifyChecksumManifest: config.verifyChecksumManifest,
      checksumsRaw,
      checksumsSignatureRaw,
      checksumsLocation: config.checksumsUrl,
      feedEntry,
      signatureEntry: safeBasename(config.signatureUrl, `${feedEntry}.sig`),
    });
  }

  const payload = parseAndValidateFeed(feedRaw, config.feedUrl);
  return {
    payload,
    feedRaw,
    verification: result,
  };
}

function buildState({ status, source, config, verification = {}, payload = null, error = null }) {
  return {
    schema_version: "1",
    checked_at: new Date().toISOString(),
    status,
    source,
    allow_unsigned_bypass: config.allowUnsigned,
    verify_checksum_manifest: config.verifyChecksumManifest,
    advisory_count: Array.isArray(payload?.advisories) ? payload.advisories.length : 0,
    feed_version: payload?.version || null,
    feed_updated: payload?.updated || null,
    cached_feed_path: config.cachedFeedPath,
    ...verification,
    error: error ? String(error) : null,
  };
}

export async function refreshAdvisoryFeed(overrides = {}) {
  const config = resolveFeedConfig(overrides);
  const attemptedErrors = [];

  const tryLoadRemote = async () => {
    const loaded = await loadRemoteFeed(config);
    return { ...loaded, source: "remote" };
  };

  const tryLoadLocal = async () => {
    const loaded = await loadLocalFeed(config);
    return { ...loaded, source: "local" };
  };

  let loaded = null;

  if (config.source === "remote") {
    loaded = await tryLoadRemote();
  } else if (config.source === "local") {
    loaded = await tryLoadLocal();
  } else {
    try {
      loaded = await tryLoadRemote();
    } catch (error) {
      attemptedErrors.push(`remote: ${error?.message || String(error)}`);
      loaded = await tryLoadLocal();
    }
  }

  try {
    writeTextAtomic(config.cachedFeedPath, `${loaded.feedRaw.trimEnd()}\n`);

    const state = buildState({
      status: config.allowUnsigned ? "unverified" : "verified",
      source: loaded.source,
      config,
      verification: loaded.verification,
      payload: loaded.payload,
      error: attemptedErrors.length > 0 ? attemptedErrors.join(" | ") : null,
    });
    writeJsonAtomic(config.statePath, state);

    return {
      status: state.status,
      source: loaded.source,
      statePath: config.statePath,
      cachedFeedPath: config.cachedFeedPath,
      advisoryCount: state.advisory_count,
      feedVersion: state.feed_version,
      attemptedErrors,
    };
  } catch (error) {
    const state = buildState({
      status: "unverified",
      source: loaded?.source || config.source,
      config,
      verification: loaded?.verification,
      payload: loaded?.payload,
      error: error?.message || String(error),
    });
    writeJsonAtomic(config.statePath, state);
    throw error;
  }
}

export function recordUnverifiedFeedState(error, overrides = {}) {
  const config = resolveFeedConfig(overrides);
  const state = buildState({
    status: "unverified",
    source: config.source,
    config,
    verification: {},
    payload: null,
    error,
  });
  writeJsonAtomic(config.statePath, state);
  return state;
}
