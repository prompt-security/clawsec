import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { patchClawhubTrustExtensions } from "./ci/patch_clawhub_trust_extensions.mjs";
import {
  collectClawhubPackageFiles,
  verifyClawhubClientSelection,
} from "./ci/clawhub_release_package.mjs";

const tempRoot = await mkdtemp(path.join(os.tmpdir(), "clawhub-trust-extensions-"));

try {
  const schemaDir = path.join(tempRoot, "node_modules", "clawhub", "dist", "schema");
  const schemaPath = path.join(schemaDir, "textFiles.js");
  const skillsPath = path.join(tempRoot, "node_modules", "clawhub", "dist", "skills.js");
  await mkdir(schemaDir, { recursive: true });
  await writeFile(path.join(tempRoot, "node_modules", "clawhub", "package.json"), '{"type":"module"}\n');
  await writeFile(
    schemaPath,
    [
      "const RAW_TEXT_FILE_EXTENSIONS = [",
      "    'md',",
      "    'json',",
      "];",
      "export const TEXT_FILE_EXTENSIONS = RAW_TEXT_FILE_EXTENSIONS;",
      "export const TEXT_FILE_EXTENSION_SET = new Set(TEXT_FILE_EXTENSIONS);",
      "",
    ].join("\n"),
  );
  await writeFile(
    skillsPath,
    [
      "const ext = relPath.split('.').at(-1)?.toLowerCase() ?? '';",
      "const contentType = mime.getType(relPath) ?? 'text/plain';",
      "",
    ].join("\n"),
  );

  const first = await patchClawhubTrustExtensions(tempRoot);
  assert.equal(first.patched, true);
  const patchedSource = await readFile(schemaPath, "utf8");
  const patchedSkillsSource = await readFile(skillsPath, "utf8");
  assert.match(patchedSource, /'pem',/);
  assert.match(patchedSource, /'sig',/);
  assert.match(
    patchedSkillsSource,
    /\["pem","sig"\]\.includes\(ext\) \? "text\/plain"/,
    "The patched client must upload trust extensions as text/plain",
  );

  const second = await patchClawhubTrustExtensions(tempRoot);
  assert.equal(second.patched, false, "ClawHub extension patch must be idempotent");
  assert.equal(await readFile(schemaPath, "utf8"), patchedSource);
  assert.equal(await readFile(skillsPath, "utf8"), patchedSkillsSource);

  const schema = await import(`${pathToFileURL(schemaPath).href}?test=${Date.now()}`);
  assert.equal(schema.TEXT_FILE_EXTENSION_SET.has("pem"), true);
  assert.equal(schema.TEXT_FILE_EXTENSION_SET.has("sig"), true);

  const packageDir = path.join(tempRoot, "package");
  await mkdir(path.join(packageDir, "lib"), { recursive: true });
  await writeFile(
    path.join(packageDir, "skill.json"),
    `${JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      sbom: { files: [{ path: "lib/.gitkeep", required: false }] },
    })}\n`,
  );
  await writeFile(path.join(packageDir, "SKILL.md"), "# Fixture\n");
  await writeFile(path.join(packageDir, "signature.sig"), "c2lnbmF0dXJl\n");
  await writeFile(path.join(packageDir, "key.pem"), "public-key\n");
  await writeFile(path.join(packageDir, "lib", ".gitkeep"), "");

  const publishableFiles = await collectClawhubPackageFiles(packageDir);
  assert.deepEqual(
    [...publishableFiles.keys()].sort(),
    ["SKILL.md", "key.pem", "signature.sig", "skill.json"],
    "Only an SBOM-declared optional .gitkeep placeholder may be omitted from ClawHub parity",
  );

  await writeFile(path.join(packageDir, "runtime.bin"), "required binary\n");
  await assert.rejects(
    collectClawhubPackageFiles(packageDir),
    /would omit non-placeholder package file: runtime\.bin/,
  );
  await rm(path.join(packageDir, "runtime.bin"));

  await writeFile(path.join(packageDir, "test_scanner_fixture.py"), "raise AssertionError\n");
  await assert.rejects(
    collectClawhubPackageFiles(packageDir),
    /must not contain test-only file: test_scanner_fixture\.py/,
    "ClawHub package preparation must reject test-named files before upload",
  );
  await rm(path.join(packageDir, "test_scanner_fixture.py"));

  await mkdir(path.join(packageDir, "tests"));
  await writeFile(path.join(packageDir, "tests", "scanner-fixture.md"), "# Test fixture\n");
  await assert.rejects(
    collectClawhubPackageFiles(packageDir),
    /must not contain test-only file: tests\/scanner-fixture\.md/,
    "ClawHub package preparation must reject files in test directories before upload",
  );
  await rm(path.join(packageDir, "tests"), { recursive: true });

  const installedClientSource = path.resolve(".github", "clawhub-cli");
  const installedSkillsModule = path.join(
    installedClientSource,
    "node_modules",
    "clawhub",
    "dist",
    "skills.js",
  );
  if (existsSync(installedSkillsModule)) {
    const mimeFailureCopy = path.join(tempRoot, "mime-failure-clawhub-client");
    await cp(installedClientSource, mimeFailureCopy, { recursive: true });
    await patchClawhubTrustExtensions(mimeFailureCopy);
    await cp(
      installedSkillsModule,
      path.join(mimeFailureCopy, "node_modules", "clawhub", "dist", "skills.js"),
    );
    await assert.rejects(
      verifyClawhubClientSelection({
        packageDir,
        cliPrefix: mimeFailureCopy,
      }),
      /non-text MIME type: application\//,
      "The release simulation must reproduce ClawHub's rejection of non-text trust MIME types",
    );

    const installedClientCopy = path.join(tempRoot, "installed-clawhub-client");
    await cp(installedClientSource, installedClientCopy, { recursive: true });
    await patchClawhubTrustExtensions(installedClientCopy);
    const installedSkills = await import(
      `${pathToFileURL(path.join(installedClientCopy, "node_modules", "clawhub", "dist", "skills.js")).href}?mime=${Date.now()}`
    );
    const trustFiles = (await installedSkills.listTextFiles(packageDir))
      .filter((entry) => /\.(?:pem|sig)$/.test(entry.relPath));
    assert.deepEqual(
      trustFiles
        .map((entry) => ({ path: entry.relPath, contentType: entry.contentType }))
        .sort((left, right) => left.path.localeCompare(right.path)),
      [
        { path: "key.pem", contentType: "text/plain" },
        { path: "signature.sig", contentType: "text/plain" },
      ],
      "The patched pinned ClawHub client must send trust files as text/plain",
    );
    assert.deepEqual(
      await verifyClawhubClientSelection({
        packageDir,
        cliPrefix: installedClientCopy,
      }),
      { files: publishableFiles.size },
      "The patched pinned ClawHub client must select every expected trust file",
    );
  }
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}

console.log("ClawHub trust-extension patch tests passed");
