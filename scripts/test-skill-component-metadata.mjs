import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  validateClawsecMetadata,
  validateComponentRef,
} from "./ci/validate_clawsec_metadata.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const fixtureRoot = path.join(
  repositoryRoot,
  "contracts/fixtures/component-metadata-v1/valid",
);
const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "clawsec-component-metadata-"));

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

async function materializeSkill(skill, label, { omitFiles = [] } = {}) {
  const skillDir = path.join(temporaryRoot, label);
  await mkdir(skillDir, { recursive: true });
  await writeFile(
    path.join(skillDir, "skill.json"),
    `${JSON.stringify(skill, null, 2)}\n`,
    "utf8",
  );

  const sbomFiles = Array.isArray(skill.sbom?.files) ? skill.sbom.files : [];
  for (const entry of sbomFiles) {
    if (omitFiles.includes(entry.path)) continue;
    const filePath = path.join(skillDir, entry.path);
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, `fixture ${entry.path}\n`, "utf8");
  }
  return skillDir;
}

function expectCode(result, expectedCode, label) {
  assert.equal(result.valid, false, `${label} must fail`);
  assert(
    result.errors.some((entry) => entry.code === expectedCode),
    `${label} must report ${expectedCode}; got ${JSON.stringify(result.errors)}`,
  );
}

function runPythonValidator(skillDir, extraArgs = []) {
  return spawnSync(
    "python3",
    [
      path.join(repositoryRoot, "utils/validate_skill.py"),
      skillDir,
      ...extraArgs,
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        PYTHONDONTWRITEBYTECODE: "1",
      },
    },
  );
}

function runPythonPackager(skillDir, outputDir) {
  return spawnSync(
    "python3",
    [
      path.join(repositoryRoot, "utils/package_skill.py"),
      skillDir,
      outputDir,
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        PYTHONDONTWRITEBYTECODE: "1",
      },
    },
  );
}

try {
  const fixtureFiles = (await readdir(fixtureRoot))
    .filter((fileName) => fileName.endsWith(".json"))
    .sort();
  const fixtures = new Map();

  for (const fileName of fixtureFiles) {
    const skill = await readJson(path.join(fixtureRoot, fileName));
    fixtures.set(fileName, skill);
    const skillDir = await materializeSkill(skill, `valid-${fileName.replace(".json", "")}`);
    const result = validateClawsecMetadata({
      skill,
      skillDir,
      requireClawsec: true,
    });
    assert.deepEqual(result.errors, [], `${fileName} semantic errors`);
    assert.equal(result.classification, "canonical", `${fileName} classification`);
    assert.equal(result.valid, true, `${fileName} validity`);

    const pythonResult = runPythonValidator(skillDir, ["--require-clawsec"]);
    assert.equal(
      pythonResult.status,
      0,
      `${fileName} Python validator failed:\n${pythonResult.stdout}\n${pythonResult.stderr}`,
    );
    assert.match(pythonResult.stdout, /CONTRACT_VALID/);

    const componentRef = {
      schema: "clawsec.component-ref/v1",
      name: skill.name,
      version: skill.version,
      harness: skill.clawsec.supported_harness.name,
      role: skill.clawsec.role,
      metadata_digest: `sha256:${"0".repeat(64)}`,
    };
    if (skill.clawsec.family) componentRef.family = skill.clawsec.family;
    assert.equal(validateComponentRef(componentRef).valid, true, `${fileName} component ref`);
  }

  const coreOpenclaw = fixtures.get("core-openclaw.json");
  const suiteHermes = fixtures.get("suite-hermes.json");
  const driftPicoclaw = fixtures.get("drift-picoclaw.json");
  const coreNanoclaw = fixtures.get("core-nanoclaw-v2.json");

  const invalidCases = [
    {
      name: "platform-harness-mismatch",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.platform = "hermes";
      },
      code: "PLATFORM_HARNESS_MISMATCH",
    },
    {
      name: "plural-platform-mismatch",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.platforms = ["hermes"];
      },
      code: "PLATFORM_DECLARATION_AMBIGUOUS",
    },
    {
      name: "extra-harness-block",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.hermes = {};
      },
      code: "HARNESS_METADATA_BLOCK_AMBIGUOUS",
    },
    {
      name: "missing-harness-block",
      base: coreOpenclaw,
      mutate: (skill) => {
        delete skill.openclaw;
      },
      code: "HARNESS_METADATA_BLOCK_MISSING",
    },
    {
      name: "canonical-name-mismatch",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.name = "clawsec-suite-openclaw";
      },
      code: "CANONICAL_NAME_MISMATCH",
    },
    {
      name: "invalid-package-version",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.version = "0.1.0rc1";
      },
      code: "PACKAGE_VERSION_INVALID",
    },
    {
      name: "sbom-nonobject",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.sbom = 1;
      },
      code: "METADATA_SCHEMA_INVALID",
    },
    {
      name: "sbom-files-nonarray",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.sbom.files = 1;
      },
      code: "METADATA_SCHEMA_INVALID",
    },
    {
      name: "invalid-range-bound",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.supported_harness.minimum_version = "v1.0.0";
      },
      code: "VERSION_RANGE_INVALID",
    },
    {
      name: "reversed-range",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.supported_harness.minimum_version = "2.0.0";
        skill.clawsec.supported_harness.maximum_version_exclusive = "1.0.0";
      },
      code: "VERSION_RANGE_INVALID",
    },
    {
      name: "unbounded-range",
      base: coreOpenclaw,
      mutate: (skill) => {
        delete skill.clawsec.supported_harness.maximum_version_exclusive;
      },
      code: "METADATA_SCHEMA_INVALID",
    },
    {
      name: "unsorted-capabilities",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.provides.reverse();
      },
      code: "ARRAY_NOT_SORTED",
    },
    {
      name: "unknown-capability",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.provides.push("core.unknown");
        skill.clawsec.provides.sort();
      },
      code: "UNKNOWN_CAPABILITY",
    },
    {
      name: "wrong-role-capability",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.provides = ["suite.status"];
      },
      code: "CAPABILITY_ROLE_MISMATCH",
    },
    {
      name: "stable-capability-missing",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.maturity = "stable";
        skill.clawsec.provides = skill.clawsec.provides.slice(1);
      },
      code: "STABLE_CAPABILITY_MISSING",
    },
    {
      name: "core-protocol-missing",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.management_protocol_provides = [];
      },
      code: "MANAGEMENT_PROTOCOL_INVALID",
    },
    {
      name: "core-depends-on-guardian",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.runtime_requires = [{
          name: "clawsec-drift-guardian-openclaw",
          minimum_version: "0.1.0",
          maximum_version_exclusive: "1.0.0",
        }];
      },
      code: "CORE_PACKAGE_DEPENDENCY_FORBIDDEN",
    },
    {
      name: "core-arbitrary-package-dependency",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.install_requires = [{
          name: "unrelated-package",
          minimum_version: "1.0.0",
          maximum_version_exclusive: "2.0.0",
        }];
      },
      code: "CORE_PACKAGE_DEPENDENCY_FORBIDDEN",
    },
    {
      name: "suite-core-runtime-missing",
      base: suiteHermes,
      mutate: (skill) => {
        skill.clawsec.runtime_requires = [];
      },
      code: "SUITE_CORE_RUNTIME_REQUIRED",
    },
    {
      name: "suite-cross-harness-core",
      base: suiteHermes,
      mutate: (skill) => {
        skill.clawsec.runtime_requires[0].name = "clawsec-core-openclaw";
      },
      code: "CROSS_HARNESS_DEPENDENCY",
    },
    {
      name: "suite-runtime-guardian-extra",
      base: suiteHermes,
      mutate: (skill) => {
        skill.clawsec.runtime_requires.push({
          name: "clawsec-drift-guardian-hermes",
          minimum_version: "0.1.0",
          maximum_version_exclusive: "1.0.0",
        });
        skill.clawsec.runtime_requires.sort((left, right) => left.name.localeCompare(right.name));
      },
      code: "SUITE_CORE_RUNTIME_REQUIRED",
    },
    {
      name: "guardian-runtime-coupling",
      base: driftPicoclaw,
      mutate: (skill) => {
        skill.clawsec.runtime_requires = [{
          name: "clawsec-core-picoclaw",
          minimum_version: "0.1.0",
          maximum_version_exclusive: "1.0.0",
        }];
      },
      code: "GUARDIAN_PACKAGE_DEPENDENCY_FORBIDDEN",
    },
    {
      name: "guardian-install-coupling",
      base: driftPicoclaw,
      mutate: (skill) => {
        skill.clawsec.install_requires = [{
          name: "clawsec-core-picoclaw",
          minimum_version: "0.1.0",
          maximum_version_exclusive: "1.0.0",
        }];
      },
      code: "GUARDIAN_PACKAGE_DEPENDENCY_FORBIDDEN",
    },
    {
      name: "self-dependency",
      base: suiteHermes,
      mutate: (skill) => {
        skill.clawsec.install_requires = [{
          name: "clawsec-suite-hermes",
          minimum_version: "0.1.0",
          maximum_version_exclusive: "1.0.0",
        }];
      },
      code: "SELF_DEPENDENCY",
    },
    {
      name: "duplicate-dependency-name",
      base: suiteHermes,
      mutate: (skill) => {
        skill.clawsec.runtime_requires.push({
          name: "clawsec-core-hermes",
          minimum_version: "1.0.0",
          maximum_version_exclusive: "2.0.0",
        });
      },
      code: "DUPLICATE_DEPENDENCY",
    },
    {
      name: "legacy-self-reference",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.legacy_names = ["clawsec-core-openclaw"];
      },
      code: "LEGACY_NAME_SELF_REFERENCE",
    },
    {
      name: "guardian-family-missing",
      base: driftPicoclaw,
      mutate: (skill) => {
        delete skill.clawsec.family;
      },
      code: "METADATA_SCHEMA_INVALID",
    },
    {
      name: "lifecycle-used-as-maturity",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.maturity = "rc";
      },
      code: "METADATA_SCHEMA_INVALID",
    },
    {
      name: "nanoclaw-native-missing",
      base: coreNanoclaw,
      mutate: (skill) => {
        delete skill.clawsec.native;
      },
      code: "NANOCLAW_NATIVE_REQUIRED",
    },
    {
      name: "nanoclaw-v1-range",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.clawsec.supported_harness.minimum_version = "1.0.0";
        skill.clawsec.supported_harness.maximum_version_exclusive = "2.0.0";
      },
      code: "NANOCLAW_V2_RANGE_REQUIRED",
    },
    {
      name: "nanoclaw-malformed-range",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.clawsec.supported_harness.minimum_version = "v2.1.17";
      },
      code: "VERSION_RANGE_INVALID",
    },
    {
      name: "nanoclaw-core-operational-category",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.clawsec.native.category = "operational";
      },
      code: "NANOCLAW_NATIVE_CATEGORY_INVALID",
    },
    {
      name: "nanoclaw-operational-suite-leaves-state",
      base: fixtures.get("suite-nanoclaw-v2.json"),
      mutate: (skill) => {
        skill.clawsec.native.apply_leaves_state = true;
      },
      code: "NANOCLAW_OPERATIONAL_STATE_FORBIDDEN",
    },
    {
      name: "nanoclaw-wrong-safe-location",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.clawsec.native.install_location = ".claude/skills/clawsec-suite-nanoclaw";
      },
      code: "NANOCLAW_LOCATION_INVALID",
    },
    {
      name: "nanoclaw-path-traversal",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.clawsec.native.install_location = ".claude/skills/../clawsec-core-nanoclaw";
      },
      code: "METADATA_SCHEMA_INVALID",
    },
    {
      name: "nanoclaw-core-denies-state",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.clawsec.native.apply_leaves_state = false;
      },
      code: "NANOCLAW_STATEFUL_PROFILE_REQUIRED",
    },
    {
      name: "nanoclaw-stateful-without-remove",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.clawsec.native.remove_document_required = false;
      },
      code: "NANOCLAW_REMOVE_DOCUMENT_REQUIRED",
    },
    {
      name: "nanoclaw-remove-not-in-sbom",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.sbom.files = skill.sbom.files.filter((entry) => entry.path !== "REMOVE.md");
      },
      code: "NANOCLAW_REMOVE_DOCUMENT_NOT_IN_SBOM",
    },
    {
      name: "nanoclaw-remove-file-missing",
      base: coreNanoclaw,
      mutate: () => {},
      omitFiles: ["REMOVE.md"],
      code: "NANOCLAW_REMOVE_DOCUMENT_MISSING",
    },
    {
      name: "nanoclaw-v1-metadata-marker",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.nanoclaw.integration = {
          ipc: "/workspace/ipc/request.json",
        };
      },
      code: "METADATA_SCHEMA_INVALID",
    },
    {
      name: "nanoclaw-decomposed-v1-metadata",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.nanoclaw.integration = {
          root: "/workspace",
          channel: "ipc",
          legacy_group_file: "registered_groups",
          suffix: ".json",
        };
      },
      code: "METADATA_SCHEMA_INVALID",
    },
    {
      name: "native-metadata-on-openclaw",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.clawsec.native = clone(coreNanoclaw.clawsec.native);
        skill.clawsec.native.install_location = ".claude/skills/clawsec-core-openclaw";
      },
      code: "NATIVE_METADATA_FORBIDDEN",
    },
  ];

  for (const invalidCase of invalidCases) {
    const skill = clone(invalidCase.base);
    invalidCase.mutate(skill);
    const skillDir = await materializeSkill(skill, `invalid-${invalidCase.name}`, {
      omitFiles: invalidCase.omitFiles,
    });
    const result = validateClawsecMetadata({
      skill,
      skillDir,
      requireClawsec: true,
    });
    expectCode(result, invalidCase.code, invalidCase.name);
  }

  const stableVocabulary = clone(coreOpenclaw);
  stableVocabulary.clawsec.maturity = "stable";
  const stableVocabularyDir = await materializeSkill(
    stableVocabulary,
    "stable-maturity-vocabulary",
  );
  const stableVocabularyResult = validateClawsecMetadata({
    skill: stableVocabulary,
    skillDir: stableVocabularyDir,
    requireClawsec: true,
  });
  assert.equal(stableVocabularyResult.valid, true);
  assert(
    stableVocabularyResult.warnings.some(
      (entry) => entry.code === "STABLE_MATURITY_REQUIRES_CONFORMANCE",
    ),
  );

  const deprecatedVocabulary = clone(coreOpenclaw);
  deprecatedVocabulary.clawsec.maturity = "deprecated";
  const deprecatedVocabularyDir = await materializeSkill(
    deprecatedVocabulary,
    "deprecated-maturity-vocabulary",
  );
  const deprecatedVocabularyResult = validateClawsecMetadata({
    skill: deprecatedVocabulary,
    skillDir: deprecatedVocabularyDir,
    requireClawsec: true,
  });
  assert.equal(deprecatedVocabularyResult.valid, true);
  assert(
    deprecatedVocabularyResult.warnings.some(
      (entry) => entry.code === "DEPRECATED_MATURITY_REQUIRES_SUCCESSOR",
    ),
  );

  const recurringAdvisoryCapability = clone(suiteHermes);
  recurringAdvisoryCapability.clawsec.provides.push(
    "suite.recurring-advisory-verification",
  );
  recurringAdvisoryCapability.clawsec.provides.sort();
  const recurringAdvisoryCapabilityDir = await materializeSkill(
    recurringAdvisoryCapability,
    "optional-recurring-advisory-capability",
  );
  const recurringAdvisoryCapabilityResult = validateClawsecMetadata({
    skill: recurringAdvisoryCapability,
    skillDir: recurringAdvisoryCapabilityDir,
    requireClawsec: true,
  });
  assert.equal(recurringAdvisoryCapabilityResult.valid, true);

  const stableSuiteWithoutRecurring = clone(suiteHermes);
  stableSuiteWithoutRecurring.clawsec.maturity = "stable";
  const stableSuiteWithoutRecurringDir = await materializeSkill(
    stableSuiteWithoutRecurring,
    "stable-suite-without-optional-recurring-advisory-capability",
  );
  const stableSuiteWithoutRecurringResult = validateClawsecMetadata({
    skill: stableSuiteWithoutRecurring,
    skillDir: stableSuiteWithoutRecurringDir,
    requireClawsec: true,
  });
  assert.equal(stableSuiteWithoutRecurringResult.valid, true);

  const legacySkill = {
    name: "legacy-fixture",
    version: "0.0.1",
    description: "Legacy validation fixture.",
    author: "prompt-security",
    license: "AGPL-3.0-or-later",
    sbom: {
      files: [{
        path: "SKILL.md",
        required: true,
      }],
    },
  };
  const legacyDir = await materializeSkill(legacySkill, "legacy-input");
  const legacyResult = validateClawsecMetadata({
    skill: legacySkill,
    skillDir: legacyDir,
  });
  assert.equal(legacyResult.valid, true);
  assert.equal(legacyResult.classification, "legacy");
  assert.equal(legacyResult.warnings[0].code, "LEGACY_INPUT");

  const legacyPython = runPythonValidator(legacyDir);
  assert.equal(legacyPython.status, 0, legacyPython.stderr);
  assert.match(legacyPython.stdout, /LEGACY_INPUT/);

  const strictLegacyPython = runPythonValidator(legacyDir, ["--require-clawsec"]);
  assert.equal(strictLegacyPython.status, 1);
  assert.match(strictLegacyPython.stdout, /MISSING_CLAWSEC_METADATA/);

  const missingCanonical = clone(legacySkill);
  missingCanonical.name = "clawsec-core-openclaw";
  missingCanonical.platform = "openclaw";
  missingCanonical.openclaw = {};
  const missingCanonicalDir = await materializeSkill(
    missingCanonical,
    "canonical-metadata-missing",
  );
  const missingCanonicalPython = runPythonValidator(missingCanonicalDir);
  assert.equal(missingCanonicalPython.status, 1);
  assert.match(missingCanonicalPython.stdout, /MISSING_CLAWSEC_METADATA/);

  const nonObjectDir = path.join(temporaryRoot, "non-object-skill-json");
  await mkdir(nonObjectDir, { recursive: true });
  await writeFile(path.join(nonObjectDir, "skill.json"), "[]\n", "utf8");
  const nonObjectPython = runPythonValidator(nonObjectDir);
  assert.equal(nonObjectPython.status, 1);
  assert.match(nonObjectPython.stdout, /top-level value must be a JSON object/);

  const numericVersion = clone(coreOpenclaw);
  numericVersion.version = 1;
  const numericVersionDir = await materializeSkill(
    numericVersion,
    "numeric-version",
  );
  const numericVersionPython = runPythonValidator(
    numericVersionDir,
    ["--require-clawsec"],
  );
  assert.equal(numericVersionPython.status, 1);
  assert.match(numericVersionPython.stdout, /METADATA_SCHEMA_INVALID/);
  assert.doesNotMatch(numericVersionPython.stderr, /Traceback/);

  const numericVersionPackage = runPythonPackager(
    numericVersionDir,
    path.join(temporaryRoot, "numeric-version-package-output"),
  );
  assert.equal(numericVersionPackage.status, 1);
  assert.match(numericVersionPackage.stdout, /METADATA_SCHEMA_INVALID/);
  assert.doesNotMatch(numericVersionPackage.stderr, /Traceback/);

  const nonObjectOpenclaw = clone(coreOpenclaw);
  nonObjectOpenclaw.openclaw = 1;
  const nonObjectOpenclawDir = await materializeSkill(
    nonObjectOpenclaw,
    "non-object-openclaw",
  );
  const nonObjectOpenclawPython = runPythonValidator(
    nonObjectOpenclawDir,
    ["--require-clawsec"],
  );
  assert.equal(nonObjectOpenclawPython.status, 1);
  assert.match(nonObjectOpenclawPython.stdout, /METADATA_SCHEMA_INVALID/);
  assert.doesNotMatch(nonObjectOpenclawPython.stderr, /Traceback/);

  const nonObjectOpenclawPackage = runPythonPackager(
    nonObjectOpenclawDir,
    path.join(temporaryRoot, "non-object-openclaw-package-output"),
  );
  assert.equal(nonObjectOpenclawPackage.status, 1);
  assert.match(nonObjectOpenclawPackage.stdout, /METADATA_SCHEMA_INVALID/);
  assert.doesNotMatch(nonObjectOpenclawPackage.stderr, /Traceback/);

  const malformedSbomCases = [
    {
      label: "sbom-nonobject-entrypoints",
      base: coreOpenclaw,
      mutate: (skill) => {
        skill.sbom = 1;
      },
    },
    {
      label: "sbom-files-nonarray-entrypoints",
      base: coreNanoclaw,
      mutate: (skill) => {
        skill.sbom.files = 1;
      },
    },
  ];
  for (const malformedCase of malformedSbomCases) {
    const malformedSkill = clone(malformedCase.base);
    malformedCase.mutate(malformedSkill);
    const malformedDir = await materializeSkill(
      malformedSkill,
      malformedCase.label,
    );
    const malformedPython = runPythonValidator(
      malformedDir,
      ["--require-clawsec"],
    );
    assert.equal(malformedPython.status, 1);
    assert.match(malformedPython.stdout, /METADATA_SCHEMA_INVALID/);
    assert.doesNotMatch(malformedPython.stderr, /Traceback/);

    const malformedPackage = runPythonPackager(
      malformedDir,
      path.join(temporaryRoot, `${malformedCase.label}-package-output`),
    );
    assert.equal(malformedPackage.status, 1);
    assert.match(malformedPackage.stdout, /METADATA_SCHEMA_INVALID/);
    assert.doesNotMatch(malformedPackage.stderr, /Traceback/);
  }

  const validCoreDir = path.join(temporaryRoot, "valid-core-openclaw");
  const packageOutput = path.join(temporaryRoot, "package-output");
  const packageResult = runPythonPackager(validCoreDir, packageOutput);
  assert.equal(
    packageResult.status,
    0,
    `canonical package validation failed:\n${packageResult.stdout}\n${packageResult.stderr}`,
  );
  assert.match(packageResult.stdout, /CONTRACT_VALID/);

  const invalidComponentRef = {
    schema: "clawsec.component-ref/v1",
    name: "clawsec-core-hermes",
    version: "0.1.0",
    harness: "hermes",
    role: "core",
    metadata_digest: "sha256:not-a-digest",
  };
  expectCode(
    validateComponentRef(invalidComponentRef),
    "COMPONENT_REF_SCHEMA_INVALID",
    "component-ref-digest",
  );

  const mismatchedComponentRef = {
    schema: "clawsec.component-ref/v1",
    name: "clawsec-core-openclaw",
    version: "0.1.0",
    harness: "hermes",
    role: "core",
    metadata_digest: `sha256:${"f".repeat(64)}`,
  };
  expectCode(
    validateComponentRef(mismatchedComponentRef),
    "COMPONENT_REF_IDENTITY_MISMATCH",
    "component-ref-identity",
  );

  process.stdout.write(
    `component metadata contract: ${fixtureFiles.length} valid fixtures, `
      + `${invalidCases.length} invalid fixtures, legacy/strict/package/component-ref checks passed\n`,
  );
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
