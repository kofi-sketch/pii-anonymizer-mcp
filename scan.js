#!/usr/bin/env node

/**
 * PII Scanner — Read-Only CLI
 * 
 * Scans text for PII and reports what it finds. Never modifies the input.
 * 
 * Usage:
 *   echo "John Smith, SSN 123-45-6789" | pii-scan
 *   pii-scan --file support-ticket.txt
 *   pii-scan --file logs.txt --config kraken-pii.json
 *   pii-scan --file data.csv --json
 *   pii-scan --file data.csv --detectors email,credit_card
 *   find ./tickets -name "*.txt" -exec pii-scan --file {} --quiet \;
 */

import { readFileSync, existsSync } from "fs";
import { anonymize, loadConfig } from "./engine.js";

const args = process.argv.slice(2);

function getArg(flag) {
  const idx = args.indexOf(flag);
  if (idx === -1) return null;
  return args[idx + 1] || null;
}

function hasFlag(flag) {
  return args.includes(flag);
}

// ─── Colors (disable with --no-color or NO_COLOR env) ────────────────────────

const useColor = !hasFlag("--no-color") && !process.env.NO_COLOR && process.stderr.isTTY;
const c = {
  red: s => useColor ? `\x1b[31m${s}\x1b[0m` : s,
  yellow: s => useColor ? `\x1b[33m${s}\x1b[0m` : s,
  green: s => useColor ? `\x1b[32m${s}\x1b[0m` : s,
  cyan: s => useColor ? `\x1b[36m${s}\x1b[0m` : s,
  dim: s => useColor ? `\x1b[2m${s}\x1b[0m` : s,
  bold: s => useColor ? `\x1b[1m${s}\x1b[0m` : s,
};

// ─── Help ────────────────────────────────────────────────────────────────────

if (hasFlag("--help") || hasFlag("-h")) {
  console.log(`
PII Scanner — Read-Only

Scans text and reports PII findings. Never modifies the input.

USAGE:
  echo "text" | pii-scan                   Pipe text
  pii-scan --file input.txt                Scan a file
  pii-scan --file input.txt --json         JSON report
  pii-scan --file input.txt --verbose      Show surrounding context
  pii-scan --config kraken.json --file f   Use custom dictionary

OPTIONS:
  --file, -f <path>      Input file (otherwise reads stdin)
  --config <path>        Load custom names/patterns config
  --detectors <ids>      Comma-separated detector IDs
  --json                 Output JSON report
  --verbose, -v          Show context around each finding
  --quiet, -q            Exit code only (0=clean, 1=PII found)
  --no-color             Disable colored output
  --help, -h             Show this help

EXIT CODES:
  0  No PII found (clean)
  1  PII detected

EXAMPLES:
  # Quick scan
  echo "Call John at john@test.com" | pii-scan

  # Scan with context
  pii-scan --file ticket.txt --verbose

  # Batch scan a directory
  find ./logs -name "*.txt" -exec pii-scan --file {} -q \\;

  # CI/CD gate — fail if PII found
  pii-scan --file output.txt -q || echo "BLOCKED: PII detected"
`);
  process.exit(0);
}

// ─── Load config ─────────────────────────────────────────────────────────────

const configPath = getArg("--config");
if (configPath) {
  const result = loadConfig(configPath);
  if (!result.loaded) {
    console.error(`Error loading config: ${result.error}`);
    process.exit(2);
  }
}

// ─── Read input ──────────────────────────────────────────────────────────────

let inputText;
const filePath = getArg("--file") || getArg("-f");
const fileName = filePath || "stdin";

if (filePath) {
  if (!existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    process.exit(2);
  }
  inputText = readFileSync(filePath, "utf-8");
} else {
  try {
    inputText = readFileSync(0, "utf-8");
  } catch {
    console.error("No input. Pipe text or use --file <path>");
    process.exit(2);
  }
}

// ─── Scan ────────────────────────────────────────────────────────────────────

const detectorsArg = getArg("--detectors");
const enabledDetectors = detectorsArg ? detectorsArg.split(",").map(d => d.trim()) : null;

const result = anonymize(inputText, enabledDetectors);

// ─── Quiet mode (exit code only) ─────────────────────────────────────────────

if (hasFlag("--quiet") || hasFlag("-q")) {
  if (result.count > 0) {
    console.log(`${fileName}: ${result.count} PII items found`);
    process.exit(1);
  }
  process.exit(0);
}

// ─── JSON mode ───────────────────────────────────────────────────────────────

if (hasFlag("--json")) {
  const findings = [];
  // Rebuild findings from entityMap with positions
  const tempResult = anonymize(inputText, enabledDetectors);
  
  // Re-run to get positions (parse from anonymized output)
  let pos = 0;
  const tagRe = /\[([A-Z_]+(?:_\d+)?)\]/g;
  let tm;
  const tags = [];
  while ((tm = tagRe.exec(tempResult.anonymized)) !== null) {
    tags.push({ tag: tm[0], type: tm[1].replace(/_\d+$/, ""), index: tm.index });
  }

  for (const [tag, original] of Object.entries(result.entityMap)) {
    const type = tag.replace(/^\[/, "").replace(/_?\d*\]$/, "");
    // Find line number
    const idx = inputText.indexOf(original);
    let line = 1;
    if (idx >= 0) {
      for (let i = 0; i < idx; i++) if (inputText[i] === "\n") line++;
    }
    findings.push({ type, value: original, placeholder: tag, line });
  }

  console.log(JSON.stringify({
    file: fileName,
    piiCount: result.count,
    clean: result.count === 0,
    detectedTypes: result.detectedTypes,
    findings,
  }, null, 2));

  process.exit(result.count > 0 ? 1 : 0);
}

// ─── Human-readable report ───────────────────────────────────────────────────

const verbose = hasFlag("--verbose") || hasFlag("-v");

if (result.count === 0) {
  console.log(`${c.green("✓")} ${c.bold(fileName)}: ${c.green("No PII detected")}`);
  process.exit(0);
}

console.log(`\n${c.red("⚠")} ${c.bold(fileName)}: ${c.red(`${result.count} PII item${result.count === 1 ? "" : "s"} found`)}\n`);

// Group by type
const grouped = {};
for (const [tag, original] of Object.entries(result.entityMap)) {
  const type = tag.replace(/^\[/, "").replace(/_?\d*\]$/, "");
  if (!grouped[type]) grouped[type] = [];
  grouped[type].push({ tag, original });
}

for (const [type, items] of Object.entries(grouped)) {
  const typeColor = type.includes("CREDIT") || type.includes("SSN") || type.includes("BANK") 
    ? c.red : type.includes("NAME") ? c.yellow : c.cyan;
  
  console.log(`  ${typeColor(type)} (${items.length})`);
  
  for (const item of items) {
    const masked = maskValue(item.original, type);
    console.log(`    ${c.dim("→")} ${masked}`);

    if (verbose) {
      const idx = inputText.indexOf(item.original);
      if (idx >= 0) {
        const contextStart = Math.max(0, idx - 30);
        const contextEnd = Math.min(inputText.length, idx + item.original.length + 30);
        let context = inputText.slice(contextStart, contextEnd).replace(/\n/g, " ");
        if (contextStart > 0) context = "..." + context;
        if (contextEnd < inputText.length) context = context + "...";
        console.log(`      ${c.dim(context)}`);
      }
    }
  }
  console.log("");
}

// Summary line
const severity = result.detectedTypes.some(t => ["SSN", "CREDIT_CARD", "BANK_ACCOUNT", "ROUTING_NUMBER", "ACCESS_TOKEN"].includes(t))
  ? c.red("HIGH") : c.yellow("MEDIUM");
console.log(`  Severity: ${severity}`);
console.log(`  ${c.dim("Run with --verbose for context around each finding")}\n`);

process.exit(1);

// ─── Helpers ─────────────────────────────────────────────────────────────────

function maskValue(value, type) {
  if (type === "PERSON_NAME") return value[0] + "*".repeat(value.length - 1);
  if (type === "EMAIL") {
    const [local, domain] = value.split("@");
    return local[0] + "***@" + domain;
  }
  if (type === "PHONE_NUMBER") return value.slice(0, 4) + "***" + value.slice(-2);
  if (type === "SSN" || type === "CREDIT_CARD" || type === "BANK_ACCOUNT" || type === "ROUTING_NUMBER") {
    const digits = value.replace(/\D/g, "");
    return "***" + digits.slice(-4);
  }
  if (value.length <= 4) return "****";
  return value.slice(0, 2) + "*".repeat(value.length - 4) + value.slice(-2);
}
