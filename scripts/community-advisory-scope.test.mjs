import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  PROTECTED_ADVISORY_COMPONENTS,
  parseCommunityAdvisoryForm,
  parseCommunityAdvisoryScope,
} from "./ci/community_advisory_scope.mjs";

const communityWorkflow = readFileSync(
  new URL("../.github/workflows/community-advisory.yml", import.meta.url),
  "utf8",
);

test("community workflow uses strict parsing and validates the complete feed", () => {
  assert.match(communityWorkflow, /node scripts\/ci\/community_advisory_scope\.mjs/);
  assert.match(communityWorkflow, /OPENER_TYPE=\$\(jq -r '\.openerType'/);
  assert.match(communityWorkflow, /REPORT_TYPE=\$\(jq -r '\.reportType'/);
  assert.match(communityWorkflow, /SEVERITY=\$\(jq -r '\.severity'/);
  assert.match(communityWorkflow, /node scripts\/ci\/validate_advisory_feed\.mjs tmp_feed\.json/);
  assert.match(
    communityWorkflow,
    /GH_TOKEN: \$\{\{ github\.token \}\}[\s\S]*validate_advisory_feed\.mjs tmp_feed\.json\n\s+node scripts\/ci\/verify_advisory_consumer_releases\.mjs tmp_feed\.json[\s\S]*mv tmp_feed\.json "\$FEED_PATH"/,
    "Community advisories must pass the shared consumer release gate before replacing the canonical feed",
  );
  assert.match(
    communityWorkflow,
    /published: \$published,\n\s+updated: \$published,/,
    "Community advisories must record a valid per-advisory update timestamp before strict validation",
  );
  assert.doesNotMatch(communityWorkflow, /PLATFORMS='\["openclaw","nanoclaw"\]'/);
  assert.doesNotMatch(communityWorkflow, /\[\$name\]/);
  assert.doesNotMatch(communityWorkflow, /grep -q '\\\[x\\\]/);
  assert.doesNotMatch(communityWorkflow, /TITLE=\$\(echo "\$ISSUE_BODY"/);
});

function validCommunityForm() {
  return `
## Opener Type
- [x] Human
- [ ] Agent (automated report)

---

## Report Type
- [ ] Malicious Prompt - Detected prompt injection or social engineering attempt
- [x] Vulnerable Skill - Found a skill with security issues
- [ ] Tampering Attempt - Observed attempt to disable/modify ClawSec

## Severity
- [ ] Critical - Active exploitation, data exfiltration, complete bypass
- [ ] High - Significant security risk, potential for harm
- [ ] Medium - Security concern that should be addressed
- [x] Low - Minor issue, best practice violation

---

## Title
A scoped advisory

## Description
The affected release executes untrusted input.

---

## Affected

### Component or Skill Name
example-skill

### Affected Version Scope
<2.0.0

### Protected Components
- [x] OpenClaw (agent runtime)
- [ ] OpenShell (sandbox runtime)

---

## Recommended Action
Upgrade to version 2.0.0 or later.

---

## Reporter Information (Optional)

**Agent/User Name:** Security Bot
**Contact:** security@example.invalid
`;
}

test("parses security-relevant form fields from their exact sections", () => {
  assert.deepEqual(parseCommunityAdvisoryForm(validCommunityForm()), {
    openerType: "human",
    reportType: "vulnerable_skill",
    severity: "low",
    title: "A scoped advisory",
    description: "The affected release executes untrusted input.",
    action: "Upgrade to version 2.0.0 or later.",
    reporterName: "Security Bot",
    componentName: "example-skill",
    versionScope: "<2.0.0",
    affected: ["example-skill@<2.0.0"],
    platforms: ["openclaw"],
  });
});

test("ignores checkbox and heading spoofs in comments and fenced code", () => {
  const spoofed = validCommunityForm()
    .replace("## Opener Type", `<!--
## Opener Type
- [x] Agent (automated report)
-->
## Opener Type`)
    .replace("## Report Type", `\`\`\`markdown
## Report Type
- [x] Malicious Prompt - spoof
\`\`\`
## Report Type`)
    .replace("## Severity", `~~~markdown
## Severity
- [x] Critical - spoof
~~~
## Severity`)
    .replace("## Title", `\`\`\`markdown
## Title
Spoofed title
\`\`\`
## Title`)
    .replace("## Reporter Information (Optional)", `<!--
## Reporter Information (Optional)
**Agent/User Name:** Spoofed Reporter
-->
## Reporter Information (Optional)`);

  const result = parseCommunityAdvisoryForm(spoofed);
  assert.equal(result.openerType, "human");
  assert.equal(result.reportType, "vulnerable_skill");
  assert.equal(result.severity, "low");
  assert.equal(result.title, "A scoped advisory");
  assert.equal(result.reporterName, "Security Bot");
});

test("rejects zero, multiple, and unknown single-select values", () => {
  const noOpener = validCommunityForm().replace("- [x] Human", "- [ ] Human");
  assert.throws(() => parseCommunityAdvisoryForm(noOpener), /Opener Type must have exactly one/);

  const multipleReports = validCommunityForm()
    .replace("- [ ] Malicious Prompt", "- [x] Malicious Prompt");
  assert.throws(() => parseCommunityAdvisoryForm(multipleReports), /Report Type must have exactly one/);

  const multipleSeverities = validCommunityForm()
    .replace("- [ ] Critical", "- [x] Critical");
  assert.throws(() => parseCommunityAdvisoryForm(multipleSeverities), /Severity must have exactly one/);

  const unknownSeverity = validCommunityForm()
    .replace("- [x] Low - Minor issue, best practice violation", "- [x] Informational");
  assert.throws(() => parseCommunityAdvisoryForm(unknownSeverity), /Severity has an invalid checked value/);
});

test("rejects duplicate real form sections but ignores duplicate headings inside fences", () => {
  const duplicateSeverity = validCommunityForm().replace(
    "## Severity",
    "## Severity\n- [x] High - duplicate\n\n## Severity",
  );
  assert.throws(() => parseCommunityAdvisoryForm(duplicateSeverity), /Severity section must appear exactly once/);

  const fencedDuplicate = validCommunityForm().replace(
    "## Description",
    "```markdown\n## Description\nSpoofed\n```\n\n## Description",
  );
  assert.equal(
    parseCommunityAdvisoryForm(fencedDuplicate).description,
    "The affected release executes untrusted input.",
  );
});

test("requires meaningful title, description, and recommended action", () => {
  const cases = [
    ["A scoped advisory", "<!-- omitted -->", /Title is required/],
    ["The affected release executes untrusted input.", "<!-- omitted -->", /Description is required/],
    ["Upgrade to version 2.0.0 or later.", "<!-- omitted -->", /Recommended Action is required/],
  ];

  for (const [value, replacement, expected] of cases) {
    assert.throws(
      () => parseCommunityAdvisoryForm(validCommunityForm().replace(value, replacement)),
      expected,
    );
  }
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

test("ignores protected-component checkbox text outside its form section", () => {
  assert.throws(
    () => parseCommunityAdvisoryScope(`
### Component or Skill Name
example-skill

### Affected Version Scope
<2.0.0

### Evidence
\`\`\`markdown
- [x] OpenClaw (agent runtime)
\`\`\`

### Protected Components
- [ ] OpenClaw (agent runtime)
`),
    /explicit protected component/,
  );
});

test("ignores fake protected-component sections inside fenced code and comments", () => {
  const contaminants = [
    `\`\`\`markdown
### Protected Components
- [x] OpenClaw (agent runtime)
\`\`\``,
    `<!--
### Protected Components
- [x] OpenClaw (agent runtime)
-->`,
  ];

  for (const contaminant of contaminants) {
    assert.throws(
      () => parseCommunityAdvisoryScope(`
### Component or Skill Name
example-skill

### Affected Version Scope
<2.0.0

${contaminant}

### Protected Components
- [ ] OpenClaw (agent runtime)
`),
      /explicit protected component/,
      contaminant,
    );
  }
});

test("ignores fake protected-component sections inside tilde fences", () => {
  assert.throws(
    () => parseCommunityAdvisoryScope(`
### Component or Skill Name
example-skill

### Affected Version Scope
<2.0.0

~~~markdown
### Protected Components
- [x] OpenClaw (agent runtime)
~~~

### Protected Components
- [ ] OpenClaw (agent runtime)
`),
    /explicit protected component/,
  );
});

test("ignores fake protected-component sections inside four-space indented code", () => {
  assert.throws(
    () => parseCommunityAdvisoryScope(`
### Component or Skill Name
example-skill

### Affected Version Scope
<2.0.0

    ### Protected Components
    - [x] OpenClaw (agent runtime)

### Protected Components
- [ ] OpenClaw (agent runtime)
`),
    /explicit protected component/,
  );
});

test("ends the protected-component section at an indented Markdown heading", () => {
  assert.throws(
    () => parseCommunityAdvisoryScope(`
### Component or Skill Name
example-skill

### Affected Version Scope
<2.0.0

### Protected Components
- [ ] OpenClaw (agent runtime)

   ### Evidence
- [x] OpenClaw (agent runtime)
`),
    /explicit protected component/,
  );
});

test("ends the protected-component section at any later ATX heading level", () => {
  assert.throws(
    () => parseCommunityAdvisoryScope(`
### Component or Skill Name
example-skill

### Affected Version Scope
<2.0.0

### Protected Components
- [ ] OpenClaw (agent runtime)

#### Evidence
- [x] OpenClaw (agent runtime)
`),
    /explicit protected component/,
  );
});
