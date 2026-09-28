import { uniqueStrings } from "./utils.mjs";

/**
 * Return every stable identifier carried by an advisory, in canonical-first
 * order. Keeping aliases here lets consumers treat a GHSA that later matures
 * into a CVE as the same advisory.
 *
 * @param {{ id?: unknown, cve_id?: unknown, ghsa_id?: unknown, ghsa_ids?: unknown, aliases?: unknown }} advisory
 * @returns {string[]}
 */
export function advisoryIdentifiers(advisory) {
  const ghsaIds = Array.isArray(advisory?.ghsa_ids) ? advisory.ghsa_ids : [];
  const aliases = Array.isArray(advisory?.aliases) ? advisory.aliases : [];
  return uniqueStrings(
    [advisory?.id, advisory?.cve_id, advisory?.ghsa_id, ...ghsaIds, ...aliases]
      .filter((value) => typeof value === "string")
      .map((value) => value.trim())
      .filter(Boolean),
  );
}
