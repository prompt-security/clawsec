import assert from "node:assert/strict";
import { resolveClawHubSlug } from "./ci/resolve_clawhub_slug.mjs";
import { collectDeclaredPlatforms, installAgentForSkill } from "./ci/skill_platforms.mjs";

const cases = [
  ["openclaw-traffic-guardian", ["openclaw"], "clawsec-openclaw-traffic-guardian"],
  ["openclaw-audit-watchdog", ["openclaw"], "clawsec-openclaw-audit-watchdog"],
  ["soul-guardian", ["openclaw"], "clawsec-openclaw-soul-guardian"],
  ["hermes-attestation-guardian", ["hermes"], "clawsec-hermes-attestation-guardian"],
  ["hermes-traffic-guardian", ["hermes"], "clawsec-hermes-traffic-guardian"],
  ["nanoclaw-traffic-guardian", ["nanoclaw"], "clawsec-nanoclaw-traffic-guardian"],
  ["picoclaw-security-guardian", ["picoclaw"], "clawsec-picoclaw-security-guardian"],
  ["picoclaw-self-pen-testing", ["picoclaw"], "clawsec-picoclaw-self-pen-testing"],
  ["picoclaw-traffic-guardian", ["picoclaw"], "clawsec-picoclaw-traffic-guardian"],
  ["clawtributor", ["openclaw", "nanoclaw", "hermes", "picoclaw"], "clawsec-clawtributor"],
  ["clawsec-feed", ["openclaw"], "clawsec-feed"],
  ["clawsec-suite", ["openclaw"], "clawsec"],
];

for (const [name, platforms, expected] of cases) {
  assert.equal(resolveClawHubSlug({ name, platforms }), expected, `${name} should map to ${expected}`);
  assert.equal(resolveClawHubSlug({ name }), expected, `${name} should map to ${expected} without metadata`);
}

assert.throws(
  () => resolveClawHubSlug({ name: "../openclaw-traffic-guardian", platforms: ["openclaw"] }),
  /Invalid skill name/,
  "unsafe skill names must be rejected",
);

assert.deepEqual(
  collectDeclaredPlatforms({
    platform: "openclaw",
    platforms: ["hermes", "openclaw", ""],
    picoclaw: { requires: {} },
  }),
  ["openclaw", "hermes", "picoclaw"],
  "declared platform parsing should combine legacy fields, arrays, and platform metadata keys",
);

assert.equal(
  installAgentForSkill({ platform: "hermes" }, new Set(["codex", "hermes-agent", "openclaw"])),
  "hermes-agent",
  "install agent selection should reuse platform aliases",
);
