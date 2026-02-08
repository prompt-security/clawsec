/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
export function isObject(value) {
  return typeof value === "object" && value !== null;
}

/**
 * @param {string} value
 * @returns {string}
 */
export function normalizeSkillName(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

/**
 * @param {string[]} values
 * @returns {string[]}
 */
export function uniqueStrings(values) {
  return Array.from(new Set(values));
}
