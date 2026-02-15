#!/usr/bin/env node
/**
 * Render a human-readable security audit report from openclaw JSON.
 *
 * Usage:
 *   node render_report.mjs --audit audit.json --deep deep.json --label "host label"
 */

import fs from "node:fs";

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

function lineForFinding(f) {
  const id = f?.checkId ?? "(no-checkId)";
  const title = f?.title ?? "(no-title)";
  const fix = (f?.remediation ?? "").trim();
  const fixLine = fix ? `Fix: ${fix}` : "";
  return `- ${id} ${title}${fixLine ? `\n  ${fixLine}` : ""}`;
}

function render({ audit, deep, label }) {
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

  return lines.join("\n");
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--audit") out.audit = argv[++i];
    else if (a === "--deep") out.deep = argv[++i];
    else if (a === "--label") out.label = argv[++i];
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const audit = readJsonSafe(args.audit, "audit");
const deep = readJsonSafe(args.deep, "deep");
const report = render({ audit, deep, label: args.label });
process.stdout.write(report + "\n");
