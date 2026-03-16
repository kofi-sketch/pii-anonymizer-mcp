#!/usr/bin/env node

/**
 * PII Anonymizer — MCP Server
 * 
 * Tools:
 *   anonymize_text  — Detect and replace PII with typed placeholders
 *   deanonymize_text — Restore original values from entity map
 *   list_detectors  — Show all available PII detection patterns
 * 
 * Runs over stdio (standard MCP transport).
 * Zero network calls. All processing is local.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { anonymize, deanonymize, addCustomNames, addCustomPatterns, clearCustomDictionaries, getCustomStats, loadConfig } from "./engine.js";

const server = new McpServer({
  name: "pii-anonymizer",
  version: "1.0.0",
  description: "PII Anonymizer — detect and redact PII from text locally. No data leaves the machine.",
});

// ─── Tool: anonymize_text ────────────────────────────────────────────────────

server.tool(
  "anonymize_text",
  "Detect and replace PII (names, emails, phone numbers, SSNs, credit cards, crypto addresses, etc.) with typed placeholders. Returns anonymized text plus an entity map for later restoration. All processing is local — no data leaves the machine.",
  {
    text: z.string().describe("The text to anonymize"),
    detectors: z.array(z.string()).optional().describe("Optional list of detector IDs to use (default: all). Use list_detectors to see available IDs."),
  },
  async ({ text, detectors }) => {
    const result = anonymize(text, detectors || null);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            anonymized: result.anonymized,
            entityMap: result.entityMap,
            piiCount: result.count,
            detectedTypes: result.detectedTypes,
          }, null, 2),
        },
      ],
    };
  }
);

// ─── Tool: deanonymize_text ──────────────────────────────────────────────────

server.tool(
  "deanonymize_text",
  "Restore original PII values in anonymized text using the entity map from a previous anonymize_text call. Use this after the LLM has processed the sanitized text.",
  {
    anonymizedText: z.string().describe("Text containing placeholders like [PERSON_NAME_1], [EMAIL], etc."),
    entityMap: z.record(z.string(), z.string()).describe("The entityMap object returned by anonymize_text"),
  },
  async ({ anonymizedText, entityMap }) => {
    const restored = deanonymize(anonymizedText, entityMap);
    return {
      content: [{ type: "text", text: restored }],
    };
  }
);

// ─── Tool: list_detectors ────────────────────────────────────────────────────

const DETECTOR_INFO = [
  { id: "eth_address", tier: "Crypto", description: "Ethereum addresses (0x...)" },
  { id: "btc_bech32", tier: "Crypto", description: "Bitcoin Bech32 addresses (bc1...)" },
  { id: "btc_legacy", tier: "Crypto", description: "Bitcoin legacy addresses" },
  { id: "jwt_token", tier: "Crypto", description: "JWT tokens" },
  { id: "api_key_secret", tier: "Crypto", description: "API keys (Stripe, GitHub, GitLab, Slack)" },
  { id: "credit_card", tier: "Financial", description: "Credit/debit card numbers (Luhn validated)" },
  { id: "iban", tier: "Financial", description: "International Bank Account Numbers" },
  { id: "routing_number", tier: "Financial", description: "US routing numbers" },
  { id: "account_number", tier: "Financial", description: "Bank account numbers" },
  { id: "uk_sortcode", tier: "Financial", description: "UK sort codes (XX-XX-XX)" },
  { id: "ssn", tier: "Identity", description: "US Social Security Numbers" },
  { id: "uk_nino", tier: "Identity", description: "UK National Insurance Numbers" },
  { id: "passport", tier: "Identity", description: "Passport numbers (with keyword)" },
  { id: "drivers_license", tier: "Identity", description: "Driver's license numbers" },
  { id: "ipv4", tier: "Network", description: "IPv4 addresses" },
  { id: "mac_address", tier: "Network", description: "MAC addresses" },
  { id: "email", tier: "Contact", description: "Email addresses" },
  { id: "phone_intl", tier: "Contact", description: "International phone numbers" },
  { id: "phone_contextual", tier: "Contact", description: "Phone numbers with keyword context" },
  { id: "uk_postcode", tier: "Address", description: "UK postcodes" },
  { id: "us_zip", tier: "Address", description: "US ZIP codes" },
  { id: "street_address", tier: "Address", description: "Street addresses" },
  { id: "date_dob", tier: "Identity", description: "Dates of birth" },
  { id: "date_full", tier: "Contact", description: "General dates" },
  { id: "name_title", tier: "Names", description: "Names with titles (Mr, Dr, etc.)" },
  { id: "name_dictionary", tier: "Names", description: "Known first/last names (6000+ entries)" },
  { id: "device_id", tier: "System", description: "Device identifiers" },
  { id: "session_id", tier: "System", description: "Session tokens" },
  { id: "user_id", tier: "System", description: "User identifiers" },
  { id: "uuid", tier: "System", description: "UUIDs" },
];

server.tool(
  "list_detectors",
  "List all available PII detection patterns with their IDs, tiers, and descriptions. Use these IDs with the 'detectors' parameter of anonymize_text to run only specific detectors.",
  {},
  async () => {
    return {
      content: [{ type: "text", text: JSON.stringify(DETECTOR_INFO, null, 2) }],
    };
  }
);

// ─── Tool: add_custom_names ──────────────────────────────────────────────────

server.tool(
  "add_custom_names",
  "Add custom names to the detection dictionary. These will be flagged as PERSON_NAME in all future anonymize_text calls. Use this to add company-specific names, internal usernames, project codenames, or any terms that should be treated as PII. Persists for the session.",
  {
    names: z.array(z.string()).describe("List of names to add (case-insensitive). Example: ['Satoshi', 'Nakamoto', 'jsmith42']"),
  },
  async ({ names }) => {
    addCustomNames(names);
    const stats = getCustomStats();
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          added: names.length,
          totalCustomNames: stats.customNames,
          message: `Added ${names.length} custom name(s). These will be detected as [PERSON_NAME] in all future calls.`,
        }, null, 2),
      }],
    };
  }
);

// ─── Tool: add_custom_patterns ───────────────────────────────────────────────

server.tool(
  "add_custom_patterns",
  "Add custom regex patterns to detect organization-specific PII (employee IDs, internal codes, project names, etc.). Persists for the session.",
  {
    patterns: z.array(z.object({
      regex: z.string().describe("JavaScript regex pattern string (without delimiters). Example: 'EMP-\\\\d{6}'"),
      flags: z.string().optional().describe("Regex flags (default: 'gi'). Example: 'gi'"),
      label: z.string().optional().describe("Human-readable label. Example: 'Employee ID'"),
      placeholder: z.string().optional().describe("Placeholder type in output. Example: 'EMPLOYEE_ID'. Default: 'CUSTOM_PII'"),
    })).describe("List of custom pattern definitions"),
  },
  async ({ patterns }) => {
    addCustomPatterns(patterns);
    const stats = getCustomStats();
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          added: patterns.length,
          totalCustomPatterns: stats.customPatterns,
          message: `Added ${patterns.length} custom pattern(s). These will be detected in all future calls.`,
        }, null, 2),
      }],
    };
  }
);

// ─── Tool: clear_custom_dictionaries ─────────────────────────────────────────

server.tool(
  "clear_custom_dictionaries",
  "Remove all custom names and patterns added during this session. Built-in detectors are not affected.",
  {},
  async () => {
    clearCustomDictionaries();
    return {
      content: [{ type: "text", text: "All custom names and patterns cleared. Built-in detectors unchanged." }],
    };
  }
);

// ─── Tool: load_config ───────────────────────────────────────────────────────

server.tool(
  "load_config",
  "Load a JSON config file containing custom names, name files, and/or custom patterns. Use this to bulk-load an organization's PII dictionary from a file.",
  {
    path: z.string().describe("Absolute or relative path to a JSON config file. See README for format."),
  },
  async ({ path }) => {
    const result = loadConfig(path);
    const stats = getCustomStats();
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ ...result, totalCustomNames: stats.customNames, totalCustomPatterns: stats.customPatterns }, null, 2),
      }],
    };
  }
);

// ─── Start ───────────────────────────────────────────────────────────────────

// Load --config flag if passed
const configArg = process.argv.find(a => a.startsWith("--config="));
if (configArg) {
  const result = loadConfig(configArg.split("=")[1]);
  if (result.loaded) {
    console.error(`[pii-anonymizer] CLI config loaded: ${result.namesLoaded} names, ${result.patternsLoaded} patterns`);
  } else {
    console.error(`[pii-anonymizer] Config error: ${result.error}`);
  }
}

const transport = new StdioServerTransport();
await server.connect(transport);
