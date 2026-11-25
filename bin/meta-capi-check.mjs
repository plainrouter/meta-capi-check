#!/usr/bin/env node
import fs from "node:fs";
import { validateCapiPayload, normalizeAndHashUserData } from "../src/validator.mjs";

function printHelp() {
  console.log(`meta-capi-check - Local Meta Conversions API (CAPI) payload validator

Usage:
  meta-capi-check <payload.json> [--json] [--normalize]
  cat payload.json | meta-capi-check - [--json] [--normalize]

Options:
  --json       Output structured JSON diagnostics
  --normalize  Print normalized & SHA-256 hashed user_data preview (runs 100% locally)
  --help       Show this help message

Runs 100% locally with zero outbound network requests.
Web validator: https://plainrouter.com/tools/meta-capi-validator`);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  const jsonMode = args.includes("--json");
  const normalizeMode = args.includes("--normalize");
  const target = args.find((a) => !a.startsWith("--") && a !== "-h") || (args.includes("-") ? "-" : null);

  if (!target) {
    printHelp();
    process.exit(1);
  }

  const raw = target === "-" ? await readStdin() : fs.readFileSync(target, "utf8");
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (err) {
    console.error(`Invalid JSON: ${err.message}`);
    process.exit(1);
  }

  if (normalizeMode) {
    const events = Array.isArray(payload.data) ? payload.data : [payload];
    const normalized = {
      ...payload,
      data: events.map((ev) => ({
        ...ev,
        user_data: normalizeAndHashUserData(ev.user_data),
      })),
    };
    console.log(JSON.stringify(normalized, null, 2));
    process.exit(0);
  }

  const result = validateCapiPayload(payload);
  if (jsonMode) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    const status = result.ok ? "PASS" : "FAIL";
    console.log(`${status}: ${result.eventCount} event(s), ${result.errors} error(s), ${result.warnings} warning(s)`);
    for (const issue of result.issues) {
      console.log(`  [${issue.severity.toUpperCase()}] ${issue.code} (${issue.path}): ${issue.message}`);
    }
  }
  process.exit(result.ok ? 0 : 1);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
