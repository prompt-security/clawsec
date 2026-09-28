import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  PROTECTED_ADVISORY_COMPONENTS,
  parseCommunityAdvisoryScope,
} from "./ci/community_advisory_scope.mjs";

const communityWorkflow = readFileSync(
  new URL("../.github/workflows/community-advisory.yml", import.meta.url),
  "utf8",
);

test("community workflow uses strict parsing and validates the complete feed", () => {
  assert.match(communityWorkflow, /node scripts\/ci\/community_advisory_scope\.mjs/);
  assert.match(communityWorkflow, /node scripts\/ci\/validate_advisory_feed\.mjs tmp_feed\.json/);
  assert.doesNotMatch(communityWorkflow, /PLATFORMS='\["openclaw","nanoclaw"\]'/);
  assert.doesNotMatch(communityWorkflow, /\[\$name\]/);
});

test("recognizes every protected advisory component without treating ClawHub as a platform", () => {
  assert.deepEqual(
    PROTECTED_ADVISORY_COMPONENTS.map(({ slug }) => slug),
    ["openclaw", "nanoclaw", "hermes", "picoclaw", "openshell", "nemoclaw"],
  );

  const result = parseCommunityAdvisoryScope(`
### Component or Skill Name
cross-runtime-skill

### Affected Version Scope
>=1.0.0 <1.2.3

### Protected Components
- [x] OpenClaw (agent runtime)
- [x] OpenShell (sandbox runtime)
- [x] NemoClaw (agent stack)
`);

  assert.deepEqual(result, {
    componentName: "cross-runtime-skill",
    versionScope: ">=1.0.0 <1.2.3",
    affected: ["cross-runtime-skill@>=1.0.0 <1.2.3"],
    platforms: ["openclaw", "openshell", "nemoclaw"],
  });
});

test("preserves legacy issue headings when every scope is explicit", () => {
  const result = parseCommunityAdvisoryScope(`
### Skill Name
legacy-skill

### Skill Version
1.2.3

### Platforms
- [ ] OpenClaw
- [x] Other: Hermes
`);

  assert.deepEqual(result.affected, ["legacy-skill@1.2.3"]);
  assert.deepEqual(result.platforms, ["hermes"]);
});

test("accepts scoped package names and consumer-supported comparator ranges", () => {
  const result = parseCommunityAdvisoryScope(`
### Component or Skill Name
@openclaw/voice-call

### Affected Version Scope
>= 2026.1.0, < 2026.2.0

### Protected Components
- [x] OpenClaw (agent runtime)
`);

  assert.equal(result.componentName, "@openclaw/voice-call");
  assert.equal(result.versionScope, ">= 2026.1.0 < 2026.2.0");
  assert.deepEqual(result.affected, ["@openclaw/voice-call@>= 2026.1.0 < 2026.2.0"]);
});

test("canonicalizes known component display names", () => {
  const result = parseCommunityAdvisoryScope(`
### Component or Skill Name
OpenShell

### Affected Version Scope
<=0.0.33

### Protected Components
- [x] OpenShell (sandbox runtime)
`);

  assert.equal(result.componentName, "openshell");
  assert.deepEqual(result.affected, ["openshell@<=0.0.33"]);
});

test("rejects absent and wildcard product scopes instead of inventing defaults", () => {
  assert.throws(
    () => parseCommunityAdvisoryScope(`
### Component or Skill Name

### Affected Version Scope
1.2.3

- [x] OpenClaw
`),
    /name is required/,
  );

  assert.throws(
    () => parseCommunityAdvisoryScope(`
### Component or Skill Name
openclaw

### Affected Version Scope
*

- [x] OpenClaw
`),
    /explicit affected version/,
  );
});

test("rejects ambiguous package names and malformed version ranges", () => {
  const body = (name, version) => `
### Component or Skill Name
${name}

### Affected Version Scope
${version}

### Protected Components
- [x] OpenClaw (agent runtime)
`;

  for (const invalidName of ["bad package", "package@embedded", "@scope", "@Scope/package"]) {
    assert.throws(
      () => parseCommunityAdvisoryScope(body(invalidName, "1.2.3")),
      /lowercase package name or scoped package/,
      invalidName,
    );
  }

  for (const invalidRange of ["banana", ">=1.2.3 <", "1.2.3 || 2.0.0"]) {
    assert.throws(
      () => parseCommunityAdvisoryScope(body("valid-package", invalidRange)),
      /Unsupported affected version or range/,
      invalidRange,
    );
  }
});

test("rejects absent protected components and ClawHub as an Other platform", () => {
  const scopedBody = `
### Component or Skill Name
example-skill

### Affected Version Scope
<2.0.0

### Protected Components
`;

  assert.throws(() => parseCommunityAdvisoryScope(scopedBody), /explicit protected component/);
  assert.throws(
    () => parseCommunityAdvisoryScope(`${scopedBody}- [x] Other: ClawHub`),
    /ClawHub are not platforms/,
  );
  assert.throws(
    () => parseCommunityAdvisoryScope(`
### Component or Skill Name
ClawHub

### Affected Version Scope
<2.0.0

- [x] OpenClaw
`),
    /distribution channel/,
  );
});
