import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const homepagePath = new URL("../pages/Home.tsx", import.meta.url);
const indexPath = new URL("../index.html", import.meta.url);
const homepage = await readFile(homepagePath, "utf8");
const indexHtml = await readFile(indexPath, "utf8");

const suiteInstallCommand = "npx skills add prompt-security/clawsec --skill clawsec-suite -a openclaw -y";

assert.match(
  homepage,
  new RegExp(`const curlCommand = \`${suiteInstallCommand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\`;`),
  "Homepage agent install command must use npx skills for clawsec-suite",
);

assert.match(
  homepage,
  new RegExp(`Please install clawsec-suite with ${suiteInstallCommand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
  "Homepage human instruction must tell agents to use npx skills for clawsec-suite",
);

assert.doesNotMatch(
  homepage,
  /npx clawhub@latest install clawsec-suite/,
  "Homepage must not advertise the deprecated clawhub install command for clawsec-suite",
);

assert.match(
  homepage,
  /https:\/\/github\.com\/prompt-security\/clawsec#skill-feature-matrix/,
  "Homepage install card must link non-OpenClaw harness users to the README Skill Feature Matrix",
);

assert.match(
  indexHtml,
  new RegExp(suiteInstallCommand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  "Static homepage shell instructions must use npx skills for clawsec-suite",
);

assert.doesNotMatch(
  indexHtml,
  /npx clawhub@latest install clawsec-suite/,
  "Static homepage shell instructions must not advertise the deprecated clawhub install command",
);
