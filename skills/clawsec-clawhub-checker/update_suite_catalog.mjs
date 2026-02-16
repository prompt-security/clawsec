#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

async function updateSuiteCatalog() {
  const suiteDir = "/home/david/.openclaw-clean/workspace/clawsec-suite";
  const skillJsonPath = path.join(suiteDir, "skill.json");
  
  try {
    const skillJson = JSON.parse(await fs.readFile(skillJsonPath, "utf8"));
    
    // Add clawsec-clawhub-checker to catalog
    if (!skillJson.catalog) {
      skillJson.catalog = {
        description: "Available protections in the ClawSec suite",
        base_url: "https://clawsec.prompt.security/releases/download",
        skills: {}
      };
    }
    
    skillJson.catalog.skills["clawsec-clawhub-checker"] = {
      description: "ClawHub reputation checker - enhances guarded installer with VirusTotal scores",
      default_install: false,
      compatible: ["openclaw", "moltbot", "clawdbot", "other"],
      note: "Requires clawsec-suite as base"
    };
    
    // Also update embedded_components if it exists
    if (skillJson.embedded_components) {
      skillJson.embedded_components["clawsec-clawhub-checker"] = {
        source_skill: "clawsec-clawhub-checker",
        source_version: "0.1.0",
        capabilities: [
          "ClawHub reputation checking",
          "VirusTotal Code Insight integration",
          "Skill age and author reputation analysis",
          "Enhanced double confirmation for suspicious skills"
        ],
        standalone_available: false,
        depends_on: ["clawsec-suite"]
      };
    }
    
    await fs.writeFile(skillJsonPath, JSON.stringify(skillJson, null, 2));
    console.log(`✓ Updated ${skillJsonPath} with clawsec-clawhub-checker catalog entry`);
    
    // Also update the local copy for PR
    const localSuiteDir = "/tmp/clawsec-repo/skills/clawsec-suite";
    const localSkillJsonPath = path.join(localSuiteDir, "skill.json");
    
    try {
      const localSkillJson = JSON.parse(await fs.readFile(localSkillJsonPath, "utf8"));
      
      if (localSkillJson.catalog) {
        localSkillJson.catalog.skills["clawsec-clawhub-checker"] = {
          description: "ClawHub reputation checker - enhances guarded installer with VirusTotal scores",
          default_install: false,
          compatible: ["openclaw", "moltbot", "clawdbot", "other"],
          note: "Requires clawsec-suite as base"
        };
        
        await fs.writeFile(localSkillJsonPath, JSON.stringify(localSkillJson, null, 2));
        console.log(`✓ Updated local repo ${localSkillJsonPath} for PR`);
      }
    } catch (localError) {
      console.log(`Note: Could not update local repo: ${localError.message}`);
    }
    
  } catch (error) {
    console.error("Failed to update suite catalog:", error.message);
    process.exit(1);
  }
}

updateSuiteCatalog().catch(console.error);