#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";

function parseArgs(argv) {
  const parsed = {
    handler: "",
    exportName: "default",
    eventB64: "",
    contextB64: "",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];

    if (token === "--handler") {
      parsed.handler = String(argv[i + 1] ?? "").trim();
      i += 1;
      continue;
    }

    if (token === "--export") {
      parsed.exportName = String(argv[i + 1] ?? "default").trim() || "default";
      i += 1;
      continue;
    }

    if (token === "--event") {
      parsed.eventB64 = String(argv[i + 1] ?? "").trim();
      i += 1;
      continue;
    }

    if (token === "--context") {
      parsed.contextB64 = String(argv[i + 1] ?? "").trim();
      i += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${token}`);
  }

  if (!parsed.handler) {
    throw new Error("Missing required --handler");
  }

  return parsed;
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readHookSource(handlerPath) {
  const fullPath = path.resolve(handlerPath);
  const exists = await fileExists(fullPath);
  if (!exists) {
    throw new Error(`Hook handler does not exist: ${fullPath}`);
  }

  const ext = path.extname(fullPath).toLowerCase();
  const allowedExtensions = new Set([".cjs", ".js", ".mjs", ".ts"]);
  if (!allowedExtensions.has(ext)) {
    throw new Error(`Unsupported hook handler extension: ${ext || "(none)"}`);
  }

  const source = await fs.readFile(fullPath, "utf8");
  return { fullPath, ext, source };
}

function detectHandlerExport(source, exportName) {
  if (exportName && exportName !== "default") {
    const escaped = exportName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`export\\s+(?:async\\s+)?function\\s+${escaped}\\b|export\\s*\\{[^}]*\\b${escaped}\\b`, "m").test(source);
  }

  return (
    /\bexport\s+default\b/m.test(source) ||
    /\bexport\s+(?:async\s+)?function\s+handler\b/m.test(source) ||
    /\bmodule\.exports\s*=|\bexports\.handler\s*=/m.test(source)
  );
}

function collectRiskSignals(source) {
  const rules = [
    ["child_process", /\bchild_process\b|\bfrom\s+["']node:child_process["']|\brequire\(["']child_process["']\)/m],
    ["dynamic-import", /\bimport\s*\(/m],
    ["eval", /\beval\s*\(|\bnew\s+Function\s*\(/m],
    ["shell-command", /\b(?:exec|spawn|execFile|fork)\s*\(/m],
    ["environment-access", /\bprocess\.env\b/m],
  ];

  const signals = [];
  for (const [name, pattern] of rules) {
    if (pattern.test(source)) {
      signals.push(name);
    }
  }
  return signals;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const startedAt = Date.now();

  try {
    const inspected = await readHookSource(args.handler);

    const payload = {
      ok: true,
      static_only: true,
      duration_ms: Date.now() - startedAt,
      handler_path: inspected.fullPath,
      handler_extension: inspected.ext,
      source_bytes: Buffer.byteLength(inspected.source, "utf8"),
      source_lines: inspected.source.split(/\r?\n/).length,
      handler_export_declared: detectHandlerExport(inspected.source, args.exportName),
      risk_signals: collectRiskSignals(inspected.source),
    };

    process.stdout.write(JSON.stringify(payload));
  } catch (error) {
    const payload = {
      ok: false,
      static_only: true,
      duration_ms: Date.now() - startedAt,
      error: error instanceof Error ? error.message : String(error),
    };

    process.stdout.write(JSON.stringify(payload));
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack || error.message : String(error)}\n`);
  process.exit(1);
});
