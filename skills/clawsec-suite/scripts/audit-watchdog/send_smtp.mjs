#!/usr/bin/env node
/**
 * Minimal SMTP sender (no auth) intended for localhost-relay MTAs.
 *
 * Env:
 * - PROMPTSEC_SMTP_HOST (default 127.0.0.1)
 * - PROMPTSEC_SMTP_PORT (default 25)
 * - PROMPTSEC_SMTP_HELO (default hostname)
 * - PROMPTSEC_SMTP_FROM (default security-checkup@<hostname>)
 *
 * Args:
 *   --to <email>
 *   --subject <text>
 *
 * Body is read from stdin.
 */

import net from "node:net";
import os from "node:os";

function argVal(name) {
  const i = process.argv.indexOf(name);
  if (i === -1) return null;
  return process.argv[i + 1] ?? null;
}

const to = argVal("--to");
const subjectRaw = argVal("--subject") ?? "openclaw daily security audit";
if (!to) {
  process.stderr.write("--to is required\n");
  process.exit(2);
}

const host = (process.env.PROMPTSEC_SMTP_HOST || "127.0.0.1").trim();
const port = Number(process.env.PROMPTSEC_SMTP_PORT || "25");
const hostname = (os.hostname?.() || "unknown-host").trim();
const helo = (process.env.PROMPTSEC_SMTP_HELO || hostname).trim();
const from = (process.env.PROMPTSEC_SMTP_FROM || `security-checkup@${hostname}`).trim();

function stripCrlf(s) {
  return String(s ?? "").replace(/[\r\n]+/g, " ").trim();
}

const subject = stripCrlf(subjectRaw);
const toClean = stripCrlf(to);
const fromClean = stripCrlf(from);

async function readStdin() {
  return await new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function expectCode(line, okPrefixes) {
  const code = line.slice(0, 3);
  if (!okPrefixes.includes(code)) {
    throw new Error(`SMTP unexpected response: ${line}`);
  }
}

function dotStuff(body) {
  // SMTP DATA terminates on <CRLF>.<CRLF>
  // Dot-stuff any line that begins with '.'
  return body.replace(/(^|\r?\n)\./g, "$1..");
}

async function send() {
  const body = await readStdin();
  const msg = [
    `From: ${fromClean}`,
    `To: ${toClean}`,
    `Subject: ${subject}`,
    `Content-Type: text/plain; charset=UTF-8`,
    "",
    dotStuff(body).replace(/\r?\n/g, "\r\n"),
  ].join("\r\n");

  const socket = net.createConnection({ host, port });
  socket.setTimeout(10000);

  let buffer = "";
  const readLine = () =>
    new Promise((resolve, reject) => {
      const onData = (chunk) => {
        buffer += chunk.toString("utf8");
        const idx = buffer.indexOf("\r\n");
        if (idx !== -1) {
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          cleanup();
          resolve(line);
        }
      };
      const onError = (e) => {
        cleanup();
        reject(e);
      };
      const onTimeout = () => {
        cleanup();
        reject(new Error("SMTP timeout"));
      };
      const cleanup = () => {
        socket.off("data", onData);
        socket.off("error", onError);
        socket.off("timeout", onTimeout);
      };
      socket.on("data", onData);
      socket.on("error", onError);
      socket.on("timeout", onTimeout);
    });

  const write = (line) => socket.write(line + "\r\n");

  try {
    const greet = await readLine();
    expectCode(greet, ["220"]);

    write(`EHLO ${helo}`);
    // Consume EHLO multi-line: 250-..., then 250 ...
    while (true) {
      const l = await readLine();
      if (l.startsWith("250-")) continue;
      expectCode(l, ["250"]);
      break;
    }

    write(`MAIL FROM:<${fromClean}>`);
    expectCode(await readLine(), ["250"]);

    write(`RCPT TO:<${toClean}>`);
    expectCode(await readLine(), ["250", "251"]);

    write("DATA");
    expectCode(await readLine(), ["354"]);

    socket.write(msg + "\r\n.\r\n");
    expectCode(await readLine(), ["250"]);

    write("QUIT");
    // best-effort
    try { await readLine(); } catch {}

    socket.end();
  } catch (e) {
    try { socket.destroy(); } catch {}
    throw e;
  }
}

send().catch((e) => {
  process.stderr.write(String(e?.stack || e) + "\n");
  process.exit(1);
});
