# PII Anonymizer — MCP Server

An MCP server that lets AI assistants (Claude, ChatGPT, Cursor, etc.) automatically detect and redact PII before processing sensitive text.

**All processing is local. Zero network calls. No data leaves the machine.**

---

## Quick Start (2 minutes)

```bash
# 1. Clone and install
git clone https://github.com/kofi-sketch/pii-anonymizer-mcp.git
cd pii-anonymizer-mcp
npm install

# 2. Verify it works
npm test
```

You should see:
```
✓ Detected 6 PII items
✓ anonymize_text works
✓ deanonymize_text works
✓ All tests passed
```

**That's it. The server is ready.**

---

## Connect to Your AI Client

The server runs over **stdio** (standard MCP transport). Add it to whichever client you use:

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "pii-anonymizer": {
      "command": "node",
      "args": ["/absolute/path/to/pii-anonymizer-mcp/server.js"]
    }
  }
}
```

### Cursor

Edit `.cursor/mcp.json` in your project root (or global settings):

```json
{
  "mcpServers": {
    "pii-anonymizer": {
      "command": "node",
      "args": ["/absolute/path/to/pii-anonymizer-mcp/server.js"]
    }
  }
}
```

### VS Code (GitHub Copilot)

Add to your VS Code `settings.json`:

```json
{
  "mcp": {
    "servers": {
      "pii-anonymizer": {
        "command": "node",
        "args": ["/absolute/path/to/pii-anonymizer-mcp/server.js"]
      }
    }
  }
}
```

### Any Other MCP Client

stdio transport — pipe JSON-RPC 2.0 over stdin/stdout:
```bash
node server.js
```

> **Note:** Replace `/absolute/path/to/` with the actual path where you cloned the repo. Run `pwd` in the repo directory to get it.

---

## What You Get: 6 Tools

### `anonymize_text`

Pass any text. Get back sanitized text + an entity map.

```
Input:  "Hi, I'm John Smith. SSN: 123-45-6789. Email: john@example.com"
Output: "Hi, I'm [PERSON_NAME_1] [PERSON_NAME_2]. SSN: [SSN]. Email: [EMAIL]"
```

The entity map lets you reverse it later:
```json
{
  "[PERSON_NAME_1]": "John",
  "[PERSON_NAME_2]": "Smith",
  "[SSN]": "123-45-6789",
  "[EMAIL]": "john@example.com"
}
```

**Parameters:**
- `text` (required) — the text to anonymize
- `detectors` (optional) — array of detector IDs to use (default: all). Get IDs from `list_detectors`.

### `deanonymize_text`

After the AI processes the sanitized text, restore the originals:

```
Input:  "[PERSON_NAME_1]'s account has been updated" + entityMap
Output: "John's account has been updated"
```

**Parameters:**
- `anonymizedText` (required) — text with placeholders
- `entityMap` (required) — the map from `anonymize_text`

### `list_detectors`

Returns all 30+ detector patterns with IDs, categories, and descriptions. Use this to selectively enable/disable detectors.

### `add_custom_names`

Add your own names, usernames, codenames, or any terms that should be flagged as PII:

```json
{ "names": ["Satoshi", "Nakamoto", "kraken_admin_42", "ProjectPhoenix"] }
```

These persist for the session and get detected as `[PERSON_NAME]`.

### `add_custom_patterns`

Add custom regex patterns for organization-specific PII — employee IDs, internal codes, ticket numbers:

```json
{
  "patterns": [
    { "regex": "EMP-\\d{6}", "label": "Employee ID", "placeholder": "EMPLOYEE_ID" },
    { "regex": "PROJ-[A-Z]{3}-\\d{4}", "label": "Project Code", "placeholder": "PROJECT_ID" },
    { "regex": "TICKET-\\d+", "label": "Support Ticket", "placeholder": "TICKET_ID" }
  ]
}
```

### `clear_custom_dictionaries`

Reset all custom names and patterns. Built-in detectors are unaffected.

---

## What It Detects

| Category | Examples |
|----------|---------|
| **Names** | 6,000+ first/last names across 40+ cultures. Context-aware — won't flag "Will" in "will do" but catches "Dear Will," |
| **Financial** | Credit cards (Luhn-validated), IBANs, routing numbers, account numbers, UK sort codes |
| **Identity** | US SSNs, UK NI numbers, passport numbers, driver's licenses, dates of birth |
| **Contact** | Email addresses, international phone numbers, street addresses, UK postcodes, US ZIP codes |
| **Crypto/Keys** | Ethereum/Bitcoin addresses, BIP-39 seed phrases, JWT tokens, API keys (Stripe, GitHub, GitLab, Slack) |
| **System** | UUIDs, session tokens, device IDs, user IDs |

Plus **context-aware classification** — catches standalone numbers near keywords like "account", "routing", "SSN" even without a fixed format.

---

## Typical Workflow

```
1. User pastes sensitive text into AI chat
2. AI calls anonymize_text → gets clean text + entity map
3. AI processes the sanitized text (summarize, classify, extract, translate, etc.)
4. AI calls deanonymize_text → restores originals in the output
5. User gets the result with real data intact
```

The user never has to manually scrub anything. The AI handles it automatically.

---

## CLI Tools

Two standalone command-line tools included — no MCP client needed.

### `pii-anonymize` — Scrub & Restore

```bash
# Pipe text
echo "John Smith, SSN 123-45-6789" | node cli.js
# → [PERSON_NAME_1] [PERSON_NAME_2], SSN [SSN]

# Scrub a file, save entity map for later
node cli.js --file ticket.txt -o clean.txt --map map.json

# Restore originals after AI processing
node cli.js --restore --file ai-response.txt --map map.json

# Full JSON output (anonymized text + entity map + stats)
node cli.js --file data.txt --json

# Use custom org dictionary
node cli.js --config kraken-pii.json --file logs.txt

# Only run specific detectors
node cli.js --detectors email,credit_card,ssn --file data.csv

# Stats only
node cli.js --stats --file data.txt
```

### `pii-scan` — Read-Only Scanner

Reports PII findings without modifying anything. Useful for audits and CI/CD gates.

```bash
# Scan a file
node scan.js --file ticket.txt

# ⚠ ticket.txt: 6 PII items found
#   PERSON_NAME (2)
#     → J***
#     → S****
#   SSN (1)
#     → ***6789
#   CREDIT_CARD (1)
#     → ***0366
#   Severity: HIGH

# Show context around each finding
node scan.js --file ticket.txt --verbose

# JSON report
node scan.js --file data.csv --json

# CI/CD gate — exit code 0=clean, 1=PII found
node scan.js --file output.txt -q || echo "BLOCKED: PII detected"

# Batch scan a directory
find ./logs -name "*.txt" -exec node scan.js --file {} -q \;
```

---

## Custom Dictionaries

Add your organization's own names and patterns via a config file.

Create `pii-config.json` next to `server.js` (auto-loaded on startup):

```json
{
  "names": ["Jesse Powell", "internal_admin_42"],
  "nameFiles": ["employees.txt", "contractors.csv"],
  "patterns": [
    { "regex": "EMP-\\d{6}", "label": "Employee ID", "placeholder": "EMPLOYEE_ID" },
    { "regex": "TICKET-\\d+", "label": "Support Ticket", "placeholder": "TICKET_ID" }
  ]
}
```

- `names` — inline list of names/terms to flag
- `nameFiles` — paths to text files (one name per line) or CSVs
- `patterns` — custom regex with label and placeholder type

For the CLI, pass `--config /path/to/config.json`. For the MCP server, pass `--config=` as an arg or drop `pii-config.json` next to `server.js`.

See `pii-config.example.json` for a full example.

---

## Works With Everything

This tool uses MCP (Model Context Protocol) — an open standard. It works alongside any other MCP server or data tool your team already uses.

```
┌─────────────────────────────────────────────────────┐
│                   AI Client (Claude, Cursor, etc.)   │
│                                                      │
│  "Get support tickets from Superset,                 │
│   summarize them, but scrub PII first"               │
└──────┬──────────────────────────┬────────────────────┘
       │                          │
       ▼                          ▼
┌──────────────┐          ┌──────────────────┐
│  Superset    │          │  PII Anonymizer  │
│  MCP Server  │          │  MCP Server      │
│  (your data) │          │  (scrubs PII)    │
└──────────────┘          └──────────────────┘
```

**Example flow:**
1. AI pulls query results from Superset (or DataHub, Postgres, Slack, any MCP server)
2. AI passes the results through `anonymize_text` → PII gets replaced
3. AI processes the clean data (summarize, classify, extract)
4. AI calls `deanonymize_text` → originals restored in final output

The CLI tools work the same way with any pipeline:

```bash
# Superset export → scrub → feed to AI
superset export --query 42 | pii-anonymize -o clean.csv --map map.json

# Scan any data source for PII without changing it
cat database_dump.csv | pii-scan

# CI/CD: block deploys that leak PII
pii-scan --file api-response.json -q || exit 1
```

**It doesn't need to know what your other tools are.** It just processes whatever text passes through it — queries, logs, tickets, chat transcripts, API responses, database exports. If it's text, it can be scrubbed.

---

## Architecture

```
┌─────────────┐     stdio (JSON-RPC)     ┌──────────────────┐
│  MCP Client  │ ◄──────────────────────► │  pii-anonymizer  │
│  (Claude,    │                          │  server.js       │
│   Cursor,    │    anonymize_text()      │  engine.js       │
│   VS Code)   │    deanonymize_text()    │  (all local)     │
└─────────────┘    list_detectors()       └──────────────────┘
                                                   │
                                            No network calls
                                            No external APIs
                                            No data storage
```

- **2 files** that matter: `server.js` (MCP wrapper) and `engine.js` (detection logic)
- **1 dependency**: `@modelcontextprotocol/sdk` (the MCP protocol library)
- **Runs in-process** — no Docker, no cloud, no accounts

---

## Docker

Run containerised — prints to STDOUT, no network required.

```bash
# Build
docker build -t pii-anonymizer .

# Pipe text through the container
echo "John Smith, SSN 123-45-6789" | docker run -i pii-anonymizer

# Scrub a file (mount it in)
docker run -i pii-anonymizer < ticket.txt > clean.txt

# JSON output
echo "John Smith, SSN 123-45-6789" | docker run -i pii-anonymizer cli.js --json

# Read-only scan
echo "John Smith, SSN 123-45-6789" | docker run -i pii-anonymizer scan.js

# MCP server mode (for AI client integration)
docker run -i pii-anonymizer server.js

# With custom config (mount your config file)
docker run -i -v /path/to/pii-config.json:/app/pii-config.json pii-anonymizer

# CI/CD gate — exit code 1 if PII found
echo "some text" | docker run -i pii-anonymizer scan.js -q || echo "BLOCKED"
```

**Image:** `node:18-alpine` (~50MB). Zero network calls at runtime. No volumes needed unless using custom dictionaries.

---

## Requirements

- Node.js 18+ (or Docker)
- That's it. No API keys, no accounts, no network.

## License

MIT

---

Built by @kofi.owusu on Slack
