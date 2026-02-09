import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { isObject } from "./utils.mjs";

/**
 * @param {string} rawSpecifier
 * @returns {{ name: string; versionSpec: string } | null}
 */
export function parseAffectedSpecifier(rawSpecifier) {
  const specifier = String(rawSpecifier ?? "").trim();
  if (!specifier) return null;

  const atIndex = specifier.lastIndexOf("@");
  if (atIndex <= 0) {
    return { name: specifier, versionSpec: "*" };
  }

  return {
    name: specifier.slice(0, atIndex),
    versionSpec: specifier.slice(atIndex + 1),
  };
}

/**
 * @param {unknown} raw
 * @returns {raw is import("./types.ts").FeedPayload}
 */
export function isValidFeedPayload(raw) {
  if (!isObject(raw)) return false;
  if (typeof raw.version !== "string" || !raw.version.trim()) return false;
  if (!Array.isArray(raw.advisories)) return false;

  for (const advisory of raw.advisories) {
    if (!isObject(advisory)) return false;
    if (typeof advisory.id !== "string" || !advisory.id.trim()) return false;
    if (typeof advisory.severity !== "string" || !advisory.severity.trim()) return false;
    if (!Array.isArray(advisory.affected)) return false;
    if (!advisory.affected.every((entry) => typeof entry === "string" && entry.trim())) return false;
  }

  return true;
}

/**
 * @param {string} signatureRaw
 * @returns {Buffer | null}
 */
function decodeSignature(signatureRaw) {
  const trimmed = String(signatureRaw ?? "").trim();
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

/**
 * @param {string} payloadRaw
 * @param {string} signatureRaw
 * @param {string} publicKeyPem
 * @returns {boolean}
 */
export function verifySignedPayload(payloadRaw, signatureRaw, publicKeyPem) {
  const signature = decodeSignature(signatureRaw);
  if (!signature) return false;

  const keyPem = String(publicKeyPem ?? "").trim();
  if (!keyPem) return false;

  try {
    const publicKey = crypto.createPublicKey(keyPem);
    return crypto.verify(null, Buffer.from(payloadRaw, "utf8"), publicKey, signature);
  } catch {
    return false;
  }
}

/**
 * @param {string | Buffer} content
 * @returns {string}
 */
function sha256Hex(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

/**
 * @param {unknown} value
 * @returns {string | null}
 */
function extractSha256Value(value) {
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

/**
 * @param {string} manifestRaw
 * @returns {{ schemaVersion: string; algorithm: string; files: Record<string, string> }}
 */
function parseChecksumsManifest(manifestRaw) {
  let parsed;
  try {
    parsed = JSON.parse(manifestRaw);
  } catch {
    throw new Error("Checksum manifest is not valid JSON");
  }

  if (!isObject(parsed)) {
    throw new Error("Checksum manifest must be an object");
  }

  const algorithmRaw = typeof parsed.algorithm === "string" ? parsed.algorithm.trim().toLowerCase() : "sha256";
  if (algorithmRaw !== "sha256") {
    throw new Error(`Unsupported checksum manifest algorithm: ${algorithmRaw || "(empty)"}`);
  }

  const schemaVersion = typeof parsed.schema_version === "string" ? parsed.schema_version.trim() : "";
  if (!schemaVersion) {
    throw new Error("Checksum manifest missing schema_version");
  }

  if (!isObject(parsed.files)) {
    throw new Error("Checksum manifest missing files object");
  }

  const files = /** @type {Record<string, string>} */ ({});
  for (const [key, value] of Object.entries(parsed.files)) {
    if (!String(key).trim()) continue;
    const digest = extractSha256Value(value);
    if (!digest) {
      throw new Error(`Invalid checksum digest entry for ${key}`);
    }
    files[key] = digest;
  }

  if (Object.keys(files).length === 0) {
    throw new Error("Checksum manifest has no usable file digests");
  }

  return {
    schemaVersion,
    algorithm: algorithmRaw,
    files,
  };
}

/**
 * @param {{ files: Record<string, string> }} manifest
 * @param {Record<string, string | Buffer>} expectedEntries
 */
function verifyChecksums(manifest, expectedEntries) {
  for (const [entryName, entryContent] of Object.entries(expectedEntries)) {
    if (!entryName) continue;

    const expectedDigest = manifest.files[entryName];
    if (!expectedDigest) {
      throw new Error(`Checksum manifest missing required entry: ${entryName}`);
    }

    const actualDigest = sha256Hex(entryContent);
    if (actualDigest !== expectedDigest) {
      throw new Error(`Checksum mismatch for ${entryName}`);
    }
  }
}

/**
 * @param {string} feedUrl
 * @returns {string}
 */
export function defaultChecksumsUrl(feedUrl) {
  try {
    return new URL("checksums.json", feedUrl).toString();
  } catch {
    const fallbackBase = String(feedUrl ?? "").replace(/\/?[^/]*$/, "");
    return `${fallbackBase}/checksums.json`;
  }
}

/**
 * @param {Function} fetchFn
 * @param {string} targetUrl
 * @returns {Promise<string | null>}
 */
async function fetchText(fetchFn, targetUrl) {
  const controller = new globalThis.AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetchFn(targetUrl, {
      method: "GET",
      signal: controller.signal,
      headers: { accept: "application/json,text/plain;q=0.9,*/*;q=0.8" },
    });
    if (!response.ok) return null;
    return await response.text();
  } catch {
    return null;
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

/**
 * @param {string} feedPath
 * @param {{
 *   signaturePath?: string;
 *   checksumsPath?: string;
 *   checksumsSignaturePath?: string;
 *   publicKeyPem?: string;
 *   checksumsPublicKeyPem?: string;
 *   allowUnsigned?: boolean;
 *   verifyChecksumManifest?: boolean;
 *   checksumFeedEntry?: string;
 *   checksumSignatureEntry?: string;
 *   checksumPublicKeyEntry?: string;
 * }} [options]
 * @returns {Promise<import("./types.ts").FeedPayload>}
 */
export async function loadLocalFeed(feedPath, options = {}) {
  const signaturePath = options.signaturePath ?? `${feedPath}.sig`;
  const checksumsPath = options.checksumsPath ?? path.join(path.dirname(feedPath), "checksums.json");
  const checksumsSignaturePath = options.checksumsSignaturePath ?? `${checksumsPath}.sig`;
  const publicKeyPem = String(options.publicKeyPem ?? "");
  const checksumsPublicKeyPem = String(options.checksumsPublicKeyPem ?? publicKeyPem);
  const allowUnsigned = options.allowUnsigned === true;
  const verifyChecksumManifest = options.verifyChecksumManifest !== false;

  const payloadRaw = await fs.readFile(feedPath, "utf8");

  if (!allowUnsigned) {
    const signatureRaw = await fs.readFile(signaturePath, "utf8");
    if (!verifySignedPayload(payloadRaw, signatureRaw, publicKeyPem)) {
      throw new Error(`Feed signature verification failed for local feed: ${feedPath}`);
    }

    if (verifyChecksumManifest) {
      const checksumsRaw = await fs.readFile(checksumsPath, "utf8");
      const checksumsSignatureRaw = await fs.readFile(checksumsSignaturePath, "utf8");

      if (!verifySignedPayload(checksumsRaw, checksumsSignatureRaw, checksumsPublicKeyPem)) {
        throw new Error(`Checksum manifest signature verification failed: ${checksumsPath}`);
      }

      const checksumsManifest = parseChecksumsManifest(checksumsRaw);
      const checksumFeedEntry = options.checksumFeedEntry ?? path.basename(feedPath);
      const checksumSignatureEntry = options.checksumSignatureEntry ?? path.basename(signaturePath);
      const expectedEntries = /** @type {Record<string, string>} */ ({
        [checksumFeedEntry]: payloadRaw,
        [checksumSignatureEntry]: signatureRaw,
      });

      if (options.checksumPublicKeyEntry) {
        expectedEntries[options.checksumPublicKeyEntry] = publicKeyPem;
      }

      verifyChecksums(checksumsManifest, expectedEntries);
    }
  }

  const payload = JSON.parse(payloadRaw);
  if (!isValidFeedPayload(payload)) {
    throw new Error(`Invalid advisory feed format: ${feedPath}`);
  }
  return payload;
}

/**
 * @param {string} feedUrl
 * @param {{
 *   signatureUrl?: string;
 *   checksumsUrl?: string;
 *   checksumsSignatureUrl?: string;
 *   publicKeyPem?: string;
 *   checksumsPublicKeyPem?: string;
 *   allowUnsigned?: boolean;
 *   verifyChecksumManifest?: boolean;
 *   checksumFeedEntry?: string;
 *   checksumSignatureEntry?: string;
 * }} [options]
 * @returns {Promise<import("./types.ts").FeedPayload | null>}
 */
export async function loadRemoteFeed(feedUrl, options = {}) {
  const fetchFn = /** @type {{ fetch?: Function }} */ (globalThis).fetch;
  if (typeof fetchFn !== "function") return null;

  const signatureUrl = options.signatureUrl ?? `${feedUrl}.sig`;
  const checksumsUrl = options.checksumsUrl ?? defaultChecksumsUrl(feedUrl);
  const checksumsSignatureUrl = options.checksumsSignatureUrl ?? `${checksumsUrl}.sig`;
  const publicKeyPem = String(options.publicKeyPem ?? "");
  const checksumsPublicKeyPem = String(options.checksumsPublicKeyPem ?? publicKeyPem);
  const allowUnsigned = options.allowUnsigned === true;
  const verifyChecksumManifest = options.verifyChecksumManifest !== false;

  const payloadRaw = await fetchText(fetchFn, feedUrl);
  if (!payloadRaw) return null;

  if (!allowUnsigned) {
    const signatureRaw = await fetchText(fetchFn, signatureUrl);
    if (!signatureRaw) return null;

    if (!verifySignedPayload(payloadRaw, signatureRaw, publicKeyPem)) {
      return null;
    }

    if (verifyChecksumManifest) {
      const checksumsRaw = await fetchText(fetchFn, checksumsUrl);
      const checksumsSignatureRaw = await fetchText(fetchFn, checksumsSignatureUrl);
      if (!checksumsRaw || !checksumsSignatureRaw) return null;

      if (!verifySignedPayload(checksumsRaw, checksumsSignatureRaw, checksumsPublicKeyPem)) {
        return null;
      }

      const checksumsManifest = parseChecksumsManifest(checksumsRaw);
      const checksumFeedEntry = options.checksumFeedEntry ?? "feed.json";
      const checksumSignatureEntry = options.checksumSignatureEntry ?? "feed.json.sig";
      verifyChecksums(checksumsManifest, {
        [checksumFeedEntry]: payloadRaw,
        [checksumSignatureEntry]: signatureRaw,
      });
    }
  }

  try {
    const payload = JSON.parse(payloadRaw);
    if (!isValidFeedPayload(payload)) return null;
    return payload;
  } catch {
    return null;
  }
}
