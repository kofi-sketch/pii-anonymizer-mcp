#!/usr/bin/env node

/**
 * PII Anonymizer — CLI
 * 
 * Usage:
 *   echo "John Smith, SSN 123-45-6789" | pii-anonymize
 *   pii-anonymize < input.txt
 *   pii-anonymize < input.txt > clean.txt
 *   pii-anonymize --file input.txt
 *   pii-anonymize --file input.txt --output clean.txt
 *   pii-anonymize --file input.txt --json          # full output with entity map
 *   pii-anonymize --file input.txt --map map.json   # save entity map separately
 *   pii-anonymize --restore --file clean.txt --map map.json  # deanonymize
 *   pii-anonymize --config /path/to/pii-config.json --file input.txt
 *   pii-anonymize --list                           # list all detectors
 *   pii-anonymize --stats                          # show detection stats only
 */

import { readFileSync, writeFileSync, existsSync } from "fs";
import { anonymize, deanonymize, loadConfig } from "./engine.js";

const args = process.argv.slice(2);

function getArg(flag) {
  const idx = args.indexOf(flag);
  if (idx === -1) return null;
  return args[idx + 1] || null;
}

function hasFlag(flag) {
  return args.includes(flag);
}

// ─── Help ────────────────────────────────────────────────────────────────────

if (hasFlag("--help") || hasFlag("-h")) {
  console.log(`
PII Anonymizer CLI

USAGE:
  echo "text" | pii-anonymize              Pipe text, get anonymized output
  pii-anonymize --file input.txt           Read from file
  pii-anonymize --file in.txt -o out.txt   Write to file
  pii-anonymize --file in.txt --json       Full JSON output with entity map
  pii-anonymize --file in.txt --map m.json Save entity map to file
  pii-anonymize --restore --file clean.txt --map m.json  Restore originals
  pii-anonymize --list                     List all detectors
  pii-anonymize --stats --file in.txt      Show stats only (no output text)

OPTIONS:
  --file, -f <path>      Input file (otherwise reads stdin)
  --output, -o <path>    Output file (otherwise writes stdout)
  --json                 Output full JSON (anonymized text + entity map + stats)
  --map <path>           Save/load entity map to/from JSON file
  --restore              Deanonymize mode (requires --map)
  --config <path>        Load custom names/patterns from config file
  --detectors <ids>      Comma-separated detector IDs to use
  --list                 List all available detectors
  --stats                Show detection stats only
  --quiet, -q            Suppress stderr messages
  --help, -h             Show this help

EXAMPLES:
  # Basic pipe
  echo "Call John at john@test.com" | pii-anonymize
  # → Call [PERSON_NAME] at [EMAIL]

  # Process a file, save map for later restoration
  pii-anonymize --file support-ticket.txt --output clean.txt --map map.json

  # Restore after AI processing
  pii-anonymize --restore --file ai-response.txt --map map.json

  # Use custom org dictionary
  pii-anonymize --config kraken-pii.json --file logs.txt

  # Only detect financial PII
  pii-anonymize --detectors credit_card,iban,routing_number,account_number --file data.txt
`);
  process.exit(0);
}

// ─── List detectors ──────────────────────────────────────────────────────────

if (hasFlag("--list")) {
  const detectors = [
    { id: "eth_address", tier: "Crypto", desc: "Ethereum addresses" },
    { id: "btc_bech32", tier: "Crypto", desc: "Bitcoin Bech32 addresses" },
    { id: "btc_legacy", tier: "Crypto", desc: "Bitcoin legacy addresses" },
    { id: "jwt_token", tier: "Crypto", desc: "JWT tokens" },
    { id: "api_key_secret", tier: "Crypto", desc: "API keys (Stripe, GitHub, etc.)" },
    { id: "credit_card", tier: "Financial", desc: "Credit/debit cards (Luhn)" },
    { id: "iban", tier: "Financial", desc: "IBANs" },
    { id: "routing_number", tier: "Financial", desc: "US routing numbers" },
    { id: "account_number", tier: "Financial", desc: "Bank account numbers" },
    { id: "uk_sortcode", tier: "Financial", desc: "UK sort codes" },
    { id: "ssn", tier: "Identity", desc: "US SSNs" },
    { id: "uk_nino", tier: "Identity", desc: "UK NI numbers" },
    { id: "passport", tier: "Identity", desc: "Passport numbers" },
    { id: "drivers_license", tier: "Identity", desc: "Driver's licenses" },
    { id: "ipv4", tier: "Network", desc: "IPv4 addresses" },
    { id: "mac_address", tier: "Network", desc: "MAC addresses" },
    { id: "email", tier: "Contact", desc: "Email addresses" },
    { id: "phone_intl", tier: "Contact", desc: "International phone numbers" },
    { id: "phone_contextual", tier: "Contact", desc: "Phone numbers (contextual)" },
    { id: "uk_postcode", tier: "Address", desc: "UK postcodes" },
    { id: "us_zip", tier: "Address", desc: "US ZIP codes" },
    { id: "street_address", tier: "Address", desc: "Street addresses" },
    { id: "date_dob", tier: "Identity", desc: "Dates of birth" },
    { id: "date_full", tier: "Contact", desc: "Dates" },
    { id: "name_title", tier: "Names", desc: "Names with titles" },
    { id: "name_dictionary", tier: "Names", desc: "Known names (6000+)" },
    { id: "device_id", tier: "System", desc: "Device IDs" },
    { id: "session_id", tier: "System", desc: "Session tokens" },
    { id: "user_id", tier: "System", desc: "User IDs" },
    { id: "uuid", tier: "System", desc: "UUIDs" },
  ];

  let currentTier = "";
  for (const d of detectors) {
    if (d.tier !== currentTier) {
      currentTier = d.tier;
      console.log(`\n  ${currentTier}`);
    }
    console.log(`    ${d.id.padEnd(20)} ${d.desc}`);
  }
  console.log("");
  process.exit(0);
}

// ─── Load config ─────────────────────────────────────────────────────────────

const configPath = getArg("--config");
if (configPath) {
  const result = loadConfig(configPath);
  if (!result.loaded) {
    console.error(`Error loading config: ${result.error}`);
    process.exit(1);
  }
  if (!hasFlag("--quiet") && !hasFlag("-q")) {
    console.error(`Loaded config: ${result.namesLoaded} names, ${result.patternsLoaded} patterns`);
  }
}

// ─── Read input ──────────────────────────────────────────────────────────────

let inputText;
const filePath = getArg("--file") || getArg("-f");

if (filePath) {
  if (!existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    process.exit(1);
  }
  inputText = readFileSync(filePath, "utf-8");
} else {
  // Read from stdin
  try {
    inputText = readFileSync(0, "utf-8");
  } catch {
    console.error("No input. Pipe text or use --file <path>");
    process.exit(1);
  }
}

// ─── Restore mode ────────────────────────────────────────────────────────────

if (hasFlag("--restore")) {
  const mapPath = getArg("--map");
  if (!mapPath || !existsSync(mapPath)) {
    console.error("--restore requires --map <path> to an entity map JSON file");
    process.exit(1);
  }
  const entityMap = JSON.parse(readFileSync(mapPath, "utf-8"));
  const restored = deanonymize(inputText, entityMap);

  const outputPath = getArg("--output") || getArg("-o");
  if (outputPath) {
    writeFileSync(outputPath, restored);
    if (!hasFlag("--quiet") && !hasFlag("-q")) console.error(`Restored → ${outputPath}`);
  } else {
    process.stdout.write(restored);
  }
  process.exit(0);
}

// ─── Anonymize ───────────────────────────────────────────────────────────────

const detectorsArg = getArg("--detectors");
const enabledDetectors = detectorsArg ? detectorsArg.split(",").map(d => d.trim()) : null;

const result = anonymize(inputText, enabledDetectors);

// ─── Stats only ──────────────────────────────────────────────────────────────

if (hasFlag("--stats")) {
  console.log(`PII items found: ${result.count}`);
  if (result.count > 0) {
    const typeCounts = {};
    for (const [tag] of Object.entries(result.entityMap)) {
      const type = tag.replace(/^\[/, "").replace(/_?\d*\]$/, "");
      typeCounts[type] = (typeCounts[type] || 0) + 1;
    }
    for (const [type, count] of Object.entries(typeCounts)) {
      console.log(`  ${type}: ${count}`);
    }
  }
  process.exit(0);
}

// ─── Output ──────────────────────────────────────────────────────────────────

const outputPath = getArg("--output") || getArg("-o");
const mapPath = getArg("--map");

if (hasFlag("--json")) {
  const output = JSON.stringify({
    anonymized: result.anonymized,
    entityMap: result.entityMap,
    piiCount: result.count,
    detectedTypes: result.detectedTypes,
  }, null, 2);

  if (outputPath) {
    writeFileSync(outputPath, output);
    if (!hasFlag("--quiet") && !hasFlag("-q")) console.error(`JSON → ${outputPath}`);
  } else {
    process.stdout.write(output + "\n");
  }
} else {
  if (outputPath) {
    writeFileSync(outputPath, result.anonymized);
    if (!hasFlag("--quiet") && !hasFlag("-q")) console.error(`${result.count} PII items redacted → ${outputPath}`);
  } else {
    process.stdout.write(result.anonymized);
    if (!hasFlag("--quiet") && !hasFlag("-q") && result.count > 0) {
      console.error(`\n[${result.count} PII items redacted]`);
    }
  }
}

// Save entity map if requested
if (mapPath) {
  writeFileSync(mapPath, JSON.stringify(result.entityMap, null, 2));
  if (!hasFlag("--quiet") && !hasFlag("-q")) console.error(`Entity map → ${mapPath}`);
}
