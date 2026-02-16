#!/usr/bin/env node
/**
 * Render a human-readable security audit report from openclaw JSON.
 *
 * Usage:
 *   node render_report.mjs --audit audit.json --deep deep.json --label "host label" [--enable-suppressions] [--config config.json]
 */

import fs from "node:fs";
import { loadSuppressionConfig } from "./load_suppression_config.mjs";

function readJsonSafe(p, label) {
  if (!p) return { findings: [], summary: {}, error: `${label} missing` };
  try {
    const s = fs.readFileSync(p, "utf8");
    return JSON.parse(s);
  } catch (e) {
    return { findings: [], summary: {}, error: `${label} parse failed: ${e?.message || String(e)}` };
  }
}

function pickFindings(report) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const bySev = (sev) => findings.filter((f) => f?.severity === sev);
  return {
    critical: bySev("critical"),
    warn: bySev("warn"),
    info: bySev("info"),
    summary: report?.summary ?? null,
  };
}

/**
 * Extract skill name from a finding object.
 * Tries multiple fields in priority order.
 *
 * @param {object} finding - The finding object
 * @returns {string|null} - The skill name or null if not found
 */
function extractSkillName(finding) {
  if (!finding) return null;

  // Try common fields where skill name might be stored
  if (finding.skill) return String(finding.skill).trim();
  if (finding.skillName) return String(finding.skillName).trim();
  if (finding.target) return String(finding.target).trim();

  // Attempt to extract from path (e.g., "skills/my-skill/...")
  if (finding.path && typeof finding.path === "string") {
    const pathMatch = finding.path.match(/skills\/([^/]+)/);
    if (pathMatch) return pathMatch[1];
  }

  // Attempt to extract from title (e.g., "[my-skill] some issue")
  if (finding.title && typeof finding.title === "string") {
    const titleMatch = finding.title.match(/^\[([^\]]+)\]/);
    if (titleMatch) return titleMatch[1];
  }

  return null;
}

/**
 * Filter findings into active and suppressed based on suppression config.
 * Matches require BOTH checkId AND skill name to match (exact match).
 *
 * @param {Array} findings - Array of finding objects
 * @param {Array} suppressions - Array of suppression rules
 * @returns {{active: Array, suppressed: Array}}
 */
function filterFindings(findings, suppressions) {
  if (!Array.isArray(findings)) {
    return { active: [], suppressed: [] };
  }

  if (!Array.isArray(suppressions) || suppressions.length === 0) {
    return { active: findings, suppressed: [] };
  }

  const active = [];
  const suppressed = [];

  for (const finding of findings) {
    const checkId = finding?.checkId ?? "";
    const skillName = extractSkillName(finding);

    // Check if this finding matches any suppression rule
    const isSuppressed = suppressions.some((rule) => {
      // BOTH checkId AND skill must match (exact match, case-sensitive)
      return rule.checkId === checkId && rule.skill === skillName;
    });

    if (isSuppressed) {
      // Find the matching rule to attach suppression metadata
      const matchingRule = suppressions.find(
        (rule) => rule.checkId === checkId && rule.skill === skillName
      );
      suppressed.push({
        ...finding,
        suppressionReason: matchingRule?.reason,
        suppressedAt: matchingRule?.suppressedAt,
      });
    } else {
      active.push(finding);
    }
  }

  return { active, suppressed };
}

function lineForFinding(f) {
  const id = f?.checkId ?? "(no-checkId)";
  const skillName = extractSkillName(f);
  const skillLabel = skillName ? `[${skillName}] ` : "";
  const title = f?.title ?? "(no-title)";
  const fix = (f?.remediation ?? "").trim();
  const fixLine = fix ? `Fix: ${fix}` : "";
  return `- ${id} ${skillLabel}${title}${fixLine ? `\n  ${fixLine}` : ""}`;
}

function lineForSuppressedFinding(f) {
  const id = f?.checkId ?? "(no-checkId)";
  const skillName = extractSkillName(f) ?? "(unknown-skill)";
  const title = f?.title ?? "(no-title)";
  const reason = f?.suppressionReason ?? "(no reason)";
  const date = f?.suppressedAt ?? "(no date)";
  return `- ${id} [${skillName}] ${title}\n  Suppressed: ${reason} (${date})`;
}

function render({ audit, deep, label, suppressedFindings = [] }) {
  const now = new Date().toISOString();
  const a = pickFindings(audit);
  const d = pickFindings(deep);

  const summary = a.summary || d.summary || { critical: 0, warn: 0, info: 0 };

  const lines = [];
  lines.push(`openclaw security audit report${label ? ` -- ${label}` : ""}`);
  lines.push(`Time: ${now}`);
  lines.push(`Summary: ${summary.critical ?? 0} critical · ${summary.warn ?? 0} warn · ${summary.info ?? 0} info`);

  const top = [];
  top.push(...a.critical, ...a.warn);
  const seen = new Set();
  const deduped = [];
  for (const f of top) {
    const key = `${f?.severity}:${f?.checkId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(f);
  }

  if (deduped.length) {
    lines.push("");
    lines.push("Findings (critical/warn):");
    for (const f of deduped.slice(0, 25)) lines.push(lineForFinding(f));
    if (deduped.length > 25) lines.push(`…${deduped.length - 25} more`);
  }

  // Surface deep probe failure if present
  const deepProbe = Array.isArray(deep?.findings)
    ? deep.findings.find((f) => f?.checkId === "gateway.probe_failed")
    : null;
  if (deepProbe) {
    lines.push("");
    lines.push("Deep probe:");
    lines.push(lineForFinding(deepProbe));
  }

  const errors = [audit?.error, deep?.error].filter(Boolean);
  if (errors.length) {
    lines.push("");
    lines.push("Errors:");
    for (const e of errors) lines.push(`- ${e}`);
  }

  // Show suppressed findings
  if (suppressedFindings.length) {
    lines.push("");
    lines.push("INFO-SUPPRESSED:");
    for (const f of suppressedFindings) {
      lines.push(lineForSuppressedFinding(f));
    }
  }

  return lines.join("\n");
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--audit") out.audit = argv[++i];
    else if (a === "--deep") out.deep = argv[++i];
    else if (a === "--label") out.label = argv[++i];
    else if (a === "--config") out.config = argv[++i];
    else if (a === "--enable-suppressions") out.enableSuppressions = true;
  }
  return out;
}

// Main execution
const args = parseArgs(process.argv.slice(2));

// Load suppression config (requires explicit opt-in)
const suppressionConfig = await loadSuppressionConfig(args.config || null, {
  enabled: !!args.enableSuppressions,
});
const suppressions = suppressionConfig.suppressions || [];

// Read audit results
const audit = readJsonSafe(args.audit, "audit");
const deep = readJsonSafe(args.deep, "deep");

// Apply suppression filtering to findings
const allFindings = [...(audit.findings || []), ...(deep.findings || [])];
const { active: activeFindings, suppressed: suppressedFindings } = filterFindings(
  allFindings,
  suppressions
);

// Replace findings in audit/deep with filtered active findings
if (audit.findings) {
  audit.findings = activeFindings.filter((f) =>
    (audit.findings || []).some((orig) => orig === f)
  );
  // Recalculate summary counts after filtering
  audit.summary = {
    critical: audit.findings.filter((f) => f?.severity === "critical").length,
    warn: audit.findings.filter((f) => f?.severity === "warn").length,
    info: audit.findings.filter((f) => f?.severity === "info").length,
  };
}
if (deep.findings) {
  deep.findings = activeFindings.filter((f) =>
    (deep.findings || []).some((orig) => orig === f)
  );
  // Recalculate summary counts after filtering
  deep.summary = {
    critical: deep.findings.filter((f) => f?.severity === "critical").length,
    warn: deep.findings.filter((f) => f?.severity === "warn").length,
    info: deep.findings.filter((f) => f?.severity === "info").length,
  };
}

// Render report with suppressed findings
const report = render({ audit, deep, label: args.label, suppressedFindings });
process.stdout.write(report + "\n");
