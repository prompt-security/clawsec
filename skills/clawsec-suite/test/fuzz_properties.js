import assert from "node:assert/strict";
import path from "node:path";
import fc from "fast-check";
import { parseAffectedSpecifier } from "../hooks/clawsec-advisory-guardian/lib/feed.mjs";
import { normalizeSkillName, resolveConfiguredPath, uniqueStrings } from "../hooks/clawsec-advisory-guardian/lib/utils.mjs";

const SAFE_SEGMENT = fc
  .array(fc.constantFrom(...("abcdefghijklmnopqrstuvwxyz0123456789-_")), { minLength: 1, maxLength: 24 })
  .map((chars) => chars.join(""));

/**
 * Runs property-based fuzz checks for advisory parsing and utility behavior.
 */
export function runFuzzProperties() {
  fc.assert(
    fc.property(fc.string(), (raw) => {
      const expected = String(raw ?? "")
        .trim()
        .toLowerCase();
      assert.equal(normalizeSkillName(raw), expected);
    }),
    { numRuns: 300 },
  );

  fc.assert(
    fc.property(fc.array(fc.string(), { maxLength: 40 }), (values) => {
      const deduped = uniqueStrings(values);
      assert.deepEqual(deduped, Array.from(new Set(values)));
    }),
    { numRuns: 200 },
  );

  fc.assert(
    fc.property(fc.string(), fc.string(), (left, right) => {
      const rawSpecifier = `${left}@${right}`;
      const specifier = rawSpecifier.trim();
      const parsed = parseAffectedSpecifier(rawSpecifier);
      assert.ok(parsed !== null);

      const atIndex = specifier.lastIndexOf("@");
      if (atIndex <= 0) {
        assert.equal(parsed.name, specifier);
        assert.equal(parsed.versionSpec, "*");
      } else {
        assert.equal(parsed.name, specifier.slice(0, atIndex));
        assert.equal(parsed.versionSpec, specifier.slice(atIndex + 1));
      }
    }),
    { numRuns: 300 },
  );

  fc.assert(
    fc.property(SAFE_SEGMENT, (suffix) => {
      const fallback = `/tmp/clawsec-suite/${suffix}`;
      const resolved = resolveConfiguredPath(`\\$HOME/${suffix}`, fallback, {
        label: "FUZZ_PATH",
      });
      assert.equal(resolved, path.normalize(fallback));
    }),
    { numRuns: 200 },
  );
}
