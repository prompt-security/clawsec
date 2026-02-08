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
  if (!Array.isArray(raw.advisories)) return false;
  return true;
}

/**
 * @param {string} feedUrl
 * @returns {Promise<import("./types.ts").FeedPayload | null>}
 */
export async function loadRemoteFeed(feedUrl) {
  const fetchFn = /** @type {{ fetch?: Function }} */ (globalThis).fetch;
  if (typeof fetchFn !== "function") return null;

  const controller = new globalThis.AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetchFn(feedUrl, {
      method: "GET",
      signal: controller.signal,
      headers: { accept: "application/json" },
    });

    if (!response.ok) return null;
    const payload = await response.json();
    if (!isValidFeedPayload(payload)) return null;
    return payload;
  } catch {
    return null;
  } finally {
    globalThis.clearTimeout(timeout);
  }
}
