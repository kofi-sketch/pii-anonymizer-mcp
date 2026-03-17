#!/usr/bin/env node

import {
  anonymize,
  deanonymize,
  addCustomNames,
  addCustomPatterns,
  clearCustomDictionaries,
} from "./engine.js";

const PREFIXES = [
  "",
  "Customer note: ",
  "Audit entry: ",
  "Input: ",
  "Transcript: ",
];

const SUFFIXES = [
  ".",
  " for review.",
  " in the ticket.",
  "\nPlease verify.",
  " before close.",
];

function pad(num, width) {
  return String(num).padStart(width, "0");
}

function hex(num, width) {
  return num.toString(16).padStart(width, "0").slice(-width);
}

function base36(num, width) {
  return num.toString(36).padStart(width, "0").slice(-width);
}

function decorate(base, i) {
  const prefix = PREFIXES[i % PREFIXES.length];
  const suffix = SUFFIXES[Math.floor(i / PREFIXES.length) % SUFFIXES.length];
  return `${prefix}${base}${suffix}`;
}

function uuidFor(i) {
  return `550e8400-e29b-41d4-a716-${hex(i + 1, 12)}`;
}

function emailFor(i) {
  return `alex${i}@example${i % 11}.com`;
}

function phoneFor(i) {
  return `+1 415 555 ${pad(1000 + i, 4)}`;
}

function phoneContextFor(i) {
  return `(415) 555-${pad(1000 + i, 4)}`;
}

function ethFor(i) {
  return `0x${hex(i + 1, 40)}`;
}

function jwtFor(i) {
  const payload = `payload${base36(i + 100, 12)}`.replace(/[^a-zA-Z0-9_-]/g, "A");
  const sig = `signature${base36(i + 200, 14)}`.replace(/[^a-zA-Z0-9_-]/g, "B");
  return `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.${sig}`;
}

function apiKeyFor(i) {
  return `sk_test_${base36(i + 5000, 24)}`;
}

function ssnFor(i) {
  return `123-45-${pad(1000 + i, 4)}`;
}

function accountFor(i) {
  return `${pad(12345678 + i, 8)}`;
}

function memberIdFor(i) {
  return `${pad(483920 + i, 6)}`;
}

function policyIdFor(i) {
  return `${pad(82000000 + i, 8)}`;
}

function valueTags(entityMap, type) {
  return Object.entries(entityMap).filter(([tag]) => new RegExp(`^\\[${type}(?:_\\d+)?\\]$`).test(tag));
}

function evaluateExpectations({ text, expectedTypes = [], forbiddenTypes = [], sensitiveValues = [], expectCount = null, expectRoundtrip = false }) {
  const result = anonymize(text);

  if (expectCount !== null && result.count !== expectCount) {
    return { ok: false, reason: `expected count ${expectCount}, got ${result.count}`, result };
  }

  for (const type of expectedTypes) {
    if (!result.detectedTypes.includes(type)) {
      return { ok: false, reason: `missing detected type ${type}`, result };
    }
    if (valueTags(result.entityMap, type).length === 0) {
      return { ok: false, reason: `missing entity map tag for ${type}`, result };
    }
  }

  for (const type of forbiddenTypes) {
    if (result.detectedTypes.includes(type)) {
      return { ok: false, reason: `unexpected detected type ${type}`, result };
    }
  }

  for (const value of sensitiveValues) {
    if (result.anonymized.includes(value)) {
      return { ok: false, reason: `sensitive value leaked: ${value}`, result };
    }
  }

  if (expectRoundtrip) {
    const restored = deanonymize(result.anonymized, result.entityMap);
    if (restored !== text) {
      return { ok: false, reason: "roundtrip deanonymize mismatch", result };
    }
  }

  return { ok: true, result };
}

function runScenario(scenario, i) {
  const spec = scenario.build(i);
  return evaluateExpectations(spec);
}

const builtinScenarios = [
  {
    name: "eth_address",
    category: "Crypto",
    build: (i) => {
      const value = ethFor(i);
      return {
        text: decorate(`Send funds to ${value}`, i),
        expectedTypes: ["CRYPTO_ADDRESS"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "btc_bech32",
    category: "Crypto",
    build: (i) => {
      const value = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
      return {
        text: decorate(`Use wallet ${value}`, i),
        expectedTypes: ["CRYPTO_ADDRESS"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "btc_legacy",
    category: "Crypto",
    build: (i) => {
      const value = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
      return {
        text: decorate(`Legacy wallet ${value}`, i),
        expectedTypes: ["CRYPTO_ADDRESS"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "jwt_token",
    category: "Crypto",
    build: (i) => {
      const value = jwtFor(i);
      return {
        text: decorate(`Bearer token ${value}`, i),
        expectedTypes: ["ACCESS_TOKEN"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "api_key_secret",
    category: "Crypto",
    build: (i) => {
      const value = apiKeyFor(i);
      return {
        text: decorate(`Provisioned key ${value}`, i),
        expectedTypes: ["API_KEY"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "credit_card",
    category: "Financial",
    build: (i) => {
      const value = "4532015112830366";
      return {
        text: decorate(`Card ${value} was provided`, i),
        expectedTypes: ["CREDIT_CARD"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "credit_card_invalid",
    category: "Financial",
    build: (i) => ({
      text: decorate(`Card 1234567890123456 is a placeholder ${base36(i, 4)}`, i),
      forbiddenTypes: ["CREDIT_CARD"],
      expectCount: 0,
    }),
  },
  {
    name: "iban",
    category: "Financial",
    build: (i) => {
      const value = "GB82 WEST 1234 5698 7654 32";
      return {
        text: decorate(`IBAN ${value}`, i),
        expectedTypes: ["BANK_ACCOUNT"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "routing_number",
    category: "Financial",
    build: (i) => {
      const value = "021000021";
      return {
        text: decorate(`routing ${value}`, i),
        expectedTypes: ["ROUTING_NUMBER"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "account_number",
    category: "Financial",
    build: (i) => {
      const value = accountFor(i);
      return {
        text: decorate(`account ${value}`, i),
        expectedTypes: ["BANK_ACCOUNT"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "uk_sortcode",
    category: "Financial",
    build: (i) => {
      const value = "12-34-56";
      return {
        text: decorate(`sort code ${value}`, i),
        expectedTypes: ["SORT_CODE"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "ssn",
    category: "Identity",
    build: (i) => {
      const value = ssnFor(i);
      return {
        text: decorate(`SSN ${value}`, i),
        expectedTypes: ["SSN"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "uk_nino",
    category: "Identity",
    build: (i) => {
      const value = "AB 12 34 56 C";
      return {
        text: decorate(`National Insurance ${value}`, i),
        expectedTypes: ["SSN"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "passport",
    category: "Identity",
    build: (i) => {
      const value = `X${pad(i + 1234567, 7)}`;
      return {
        text: decorate(`passport ${value}`, i),
        expectedTypes: ["PASSPORT_NUMBER"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "drivers_license",
    category: "Identity",
    build: (i) => {
      const value = `A${pad(i + 1234567, 7)}`;
      return {
        text: decorate(`DL ${value}`, i),
        expectedTypes: ["DRIVER_LICENSE"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "ipv4",
    category: "Network",
    build: (i) => {
      const value = `23.${10 + (i % 100)}.${20 + (i % 100)}.${30 + (i % 100)}`;
      return {
        text: decorate(`host ${value}`, i),
        expectedTypes: ["IP_ADDRESS"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "ipv4_negative",
    category: "Network",
    build: (i) => ({
      text: decorate(`host 0.10.20.${(i % 200) + 1}`, i),
      forbiddenTypes: ["IP_ADDRESS"],
      expectCount: 0,
    }),
  },
  {
    name: "mac_address",
    category: "Network",
    build: (i) => {
      const value = `02:00:00:ab:cd:${hex(i, 2)}`;
      return {
        text: decorate(`mac ${value}`, i),
        expectedTypes: ["MAC_ADDRESS"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "email",
    category: "Contact",
    build: (i) => {
      const value = emailFor(i);
      return {
        text: decorate(`Reach me at ${value}`, i),
        expectedTypes: ["EMAIL"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "phone_intl",
    category: "Contact",
    build: (i) => {
      const value = phoneFor(i);
      return {
        text: decorate(`Call ${value}`, i),
        expectedTypes: ["PHONE_NUMBER"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "phone_contextual",
    category: "Contact",
    build: (i) => {
      const value = phoneContextFor(i);
      return {
        text: decorate(`phone: ${value}`, i),
        expectedTypes: ["PHONE_NUMBER"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "uk_postcode",
    category: "Address",
    build: (i) => {
      const values = ["SW1A 1AA", "EC1A 1BB", "M1 1AE", "B33 8TH", "CR2 6XH"];
      const value = values[i % values.length];
      return {
        text: decorate(`Deliver to London ${value}`, i),
        expectedTypes: ["ZIP_CODE"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "uk_postcode_negative",
    category: "Address",
    build: (i) => ({
      text: decorate(`Invalid area ZZ1 1ZZ marker ${base36(i, 4)}`, i),
      forbiddenTypes: ["ZIP_CODE"],
      expectCount: 0,
    }),
  },
  {
    name: "us_zip",
    category: "Address",
    build: (i) => {
      const values = ["94105", "10001", "30301", "60601", "73301"];
      const value = values[i % values.length];
      return {
        text: decorate(`Ship to San Francisco, CA ${value}`, i),
        expectedTypes: ["ZIP_CODE"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "us_zip_negative",
    category: "Address",
    build: (i) => ({
      text: `{"zip": 94105, "marker": "${base36(i, 5)}"}`,
      forbiddenTypes: ["ZIP_CODE"],
      expectCount: 0,
    }),
  },
  {
    name: "street_address",
    category: "Address",
    build: (i) => {
      const value = `${100 + i} Main Street`;
      return {
        text: decorate(`deliver to ${value}`, i),
        expectedTypes: ["STREET_ADDRESS"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "date_dob",
    category: "Identity",
    build: (i) => {
      const value = `01-${pad((i % 28) + 1, 2)}-198${i % 10}`;
      return {
        text: decorate(`DOB: ${value}`, i),
        expectedTypes: ["DATE"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "date_full",
    category: "Contact",
    build: (i) => {
      const value = `2026-${pad((i % 12) + 1, 2)}-${pad((i % 28) + 1, 2)}`;
      return {
        text: decorate(`appointment date ${value}`, i),
        expectedTypes: ["DATE"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "date_full_negative",
    category: "Contact",
    build: (i) => ({
      text: `build: 2026-${pad((i % 12) + 1, 2)}-${pad((i % 28) + 1, 2)}`,
      forbiddenTypes: ["DATE"],
      expectCount: 0,
    }),
  },
  {
    name: "name_title",
    category: "Names",
    build: (i) => {
      const value = i % 2 === 0 ? "Dr. John Smith" : "Mr John Doe";
      return {
        text: decorate(`${value} arrived`, i),
        expectedTypes: ["PERSON_NAME"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "name_dictionary",
    category: "Names",
    build: (i) => {
      const first = ["John", "Maria", "Ava", "Carlos", "Elena"][i % 5];
      const last = ["Smith", "Lopez", "Parker", "Patel", "Kim"][i % 5];
      const valueA = first;
      const valueB = last;
      return {
        text: decorate(`${first} ${last} arrived`, i),
        expectedTypes: ["PERSON_NAME"],
        sensitiveValues: [valueA, valueB],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "ambiguous_name_positive",
    category: "Names",
    build: (i) => {
      const value = ["Chase", "Sterling", "Parker", "Reed", "Bailey"][i % 5];
      return {
        text: decorate(`manager: ${value}`, i),
        expectedTypes: ["PERSON_NAME"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "ambiguous_name_negative",
    category: "Names",
    build: (i) => ({
      text: decorate(`we will chase leads in spring mode ${base36(i, 4)}`, i),
      forbiddenTypes: ["PERSON_NAME"],
      expectCount: 0,
    }),
  },
  {
    name: "device_id",
    category: "System",
    build: (i) => {
      const value = `device_alpha_${base36(i + 1000, 8)}`;
      return {
        text: decorate(`tracked ${value}`, i),
        expectedTypes: ["DEVICE_ID"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "session_id",
    category: "System",
    build: (i) => {
      const value = `session_${base36(i + 2000, 12)}`;
      return {
        text: decorate(`session ${value}`, i),
        expectedTypes: ["SESSION_TOKEN"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "session_id_negative",
    category: "System",
    build: (i) => ({
      text: decorate(`session_summary_report_${base36(i + 3000, 4)}`, i),
      forbiddenTypes: ["SESSION_TOKEN"],
      expectCount: 0,
    }),
  },
  {
    name: "user_id",
    category: "System",
    build: (i) => {
      const value = `user_${base36(i + 4000, 10)}`;
      return {
        text: decorate(`user ref ${value}`, i),
        expectedTypes: ["USER_ID"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "uuid",
    category: "System",
    build: (i) => {
      const value = uuidFor(i);
      return {
        text: decorate(`uuid ${value}`, i),
        expectedTypes: ["UUID"],
        sensitiveValues: [value],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "context_ssn",
    category: "Identity",
    build: (i) => {
      const raw = `32145${pad(1000 + i, 4)}`;
      return {
        text: decorate(`social security ${raw}`, i),
        expectedTypes: ["SSN"],
        sensitiveValues: [raw],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "context_passport",
    category: "Identity",
    build: (i) => {
      const raw = `${pad(100000 + i, 6)}`;
      return {
        text: decorate(`passport ${raw}`, i),
        expectedTypes: ["PASSPORT_NUMBER"],
        sensitiveValues: [raw],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "context_license",
    category: "Identity",
    build: (i) => {
      const raw = `${pad(100000 + i, 6)}`;
      return {
        text: decorate(`license ${raw}`, i),
        expectedTypes: ["DRIVER_LICENSE"],
        sensitiveValues: [raw],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "context_member_id",
    category: "System",
    build: (i) => {
      const raw = memberIdFor(i);
      return {
        text: decorate(`employee number ${raw}`, i),
        expectedTypes: ["USER_ID"],
        sensitiveValues: [raw],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "context_policy_id",
    category: "System",
    build: (i) => {
      const raw = policyIdFor(i);
      return {
        text: decorate(`policy number ${raw}`, i),
        expectedTypes: ["USER_ID"],
        sensitiveValues: [raw],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "clean_text",
    category: "Negative",
    build: (i) => ({
      text: `pipeline status remains stable in preview mode token${String.fromCharCode(97 + (i % 26))}${String.fromCharCode(98 + (i % 25))}`,
      expectCount: 0,
    }),
  },
  {
    name: "deanonymize_roundtrip_mixed",
    category: "Mixed",
    build: (i) => {
      const first = ["John", "Maria", "Carlos", "Elena", "Ava"][i % 5];
      const last = ["Smith", "Lopez", "Torres", "Patel", "Kim"][i % 5];
      const ssn = ssnFor(i);
      const email = emailFor(i);
      return {
        text: `${first} ${last} emailed from ${email} with SSN ${ssn}.`,
        expectedTypes: ["PERSON_NAME", "EMAIL", "SSN"],
        sensitiveValues: [first, last, email, ssn],
        expectRoundtrip: true,
      };
    },
  },
  {
    name: "multi_match_mixed",
    category: "Mixed",
    build: (i) => {
      const email = emailFor(i);
      const wallet = ethFor(i);
      const uuid = uuidFor(i);
      return {
        text: `User email ${email}, wallet ${wallet}, uuid ${uuid}.`,
        expectedTypes: ["EMAIL", "CRYPTO_ADDRESS", "UUID"],
        sensitiveValues: [email, wallet, uuid],
        expectRoundtrip: true,
      };
    },
  },
];

const customPhases = [
  {
    name: "custom_name_positive",
    setup: () => {
      clearCustomDictionaries();
      addCustomNames(["Satoshi", "ProjectPhoenix", "kraken_admin_42"]);
    },
    scenarios: [
      {
        name: "custom_name_positive",
        category: "Custom",
        build: (i) => {
          const value = ["Satoshi", "ProjectPhoenix", "kraken_admin_42"][i % 3];
          return {
            text: decorate(`Owner ${value} replied`, i),
            expectedTypes: ["PERSON_NAME"],
            sensitiveValues: [value],
            expectRoundtrip: true,
          };
        },
      },
    ],
  },
  {
    name: "custom_pattern_positive",
    setup: () => {
      clearCustomDictionaries();
      addCustomPatterns([
        { regex: "EMP-\\d{6}", label: "Employee ID", placeholder: "EMPLOYEE_ID" },
        { regex: "PROJ-[A-Z]{3}-\\d{4}", label: "Project Code", placeholder: "PROJECT_ID" },
      ]);
    },
    scenarios: [
      {
        name: "custom_pattern_positive",
        category: "Custom",
        build: (i) => {
          const emp = `EMP-${pad(483920 + i, 6)}`;
          const proj = `PROJ-KRK-${pad(2026 + (i % 50), 4)}`;
          return {
            text: decorate(`Assignment ${emp} linked to ${proj}`, i),
            expectedTypes: ["EMPLOYEE_ID", "PROJECT_ID"],
            sensitiveValues: [emp, proj],
            expectRoundtrip: true,
          };
        },
      },
    ],
  },
  {
    name: "clear_custom_name_negative",
    setup: () => {
      clearCustomDictionaries();
    },
    scenarios: [
      {
        name: "clear_custom_name_negative",
        category: "Custom",
        build: (i) => ({
          text: decorate(`Owner kraken_admin_42 replied ${base36(i, 4)}`, i),
          forbiddenTypes: ["PERSON_NAME"],
          expectCount: 0,
        }),
      },
    ],
  },
  {
    name: "clear_custom_pattern_negative",
    setup: () => {
      clearCustomDictionaries();
    },
    scenarios: [
      {
        name: "clear_custom_pattern_negative",
        category: "Custom",
        build: (i) => ({
          text: decorate(`Project PROJ-KRK-${pad(2026 + (i % 50), 4)} is internal`, i),
          forbiddenTypes: ["PROJECT_ID", "EMPLOYEE_ID"],
          expectCount: 0,
        }),
      },
    ],
  },
];

const scenarioCount = builtinScenarios.length + customPhases.reduce((sum, phase) => sum + phase.scenarios.length, 0);
const requestedCases = Number.parseInt(process.argv[2] || "5000", 10);

if (!Number.isInteger(requestedCases) || requestedCases <= 0) {
  console.error(`Invalid case count: ${process.argv[2] || ""}`);
  process.exit(1);
}

if (requestedCases % scenarioCount !== 0) {
  console.error(`Case count must be divisible by scenario count (${scenarioCount}). Received ${requestedCases}.`);
  process.exit(1);
}

const VARIANTS_PER_SCENARIO = requestedCases / scenarioCount;

const failures = [];
const scenarioCounts = new Map();
const categoryCounts = new Map();
let passed = 0;
let failed = 0;

function recordPass(scenario) {
  passed++;
  scenarioCounts.set(scenario.name, (scenarioCounts.get(scenario.name) || 0) + 1);
  categoryCounts.set(scenario.category, (categoryCounts.get(scenario.category) || 0) + 1);
}

function recordFailure(scenario, i, outcome, text) {
  failed++;
  failures.push({
    scenario: scenario.name,
    category: scenario.category,
    index: i,
    reason: outcome.reason,
    text,
    detectedTypes: outcome.result?.detectedTypes || [],
    anonymized: outcome.result?.anonymized || "",
  });
}

console.log(`\nPII Anonymizer MCP - ${requestedCases}-case coverage suite\n`);

const start = Date.now();

clearCustomDictionaries();

for (const scenario of builtinScenarios) {
  for (let i = 0; i < VARIANTS_PER_SCENARIO; i++) {
    const spec = scenario.build(i);
    const outcome = evaluateExpectations(spec);
    if (outcome.ok) {
      recordPass(scenario);
    } else {
      recordFailure(scenario, i, outcome, spec.text);
    }
  }
}

for (const phase of customPhases) {
  phase.setup();
  for (const scenario of phase.scenarios) {
    for (let i = 0; i < VARIANTS_PER_SCENARIO; i++) {
      const spec = scenario.build(i);
      const outcome = evaluateExpectations(spec);
      if (outcome.ok) {
        recordPass(scenario);
      } else {
        recordFailure(scenario, i, outcome, spec.text);
      }
    }
  }
}

clearCustomDictionaries();

const durationMs = Date.now() - start;

console.log(`Cases run: ${passed + failed}`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Duration: ${durationMs}ms`);

console.log("\nCategory coverage:");
for (const [category, count] of [...categoryCounts.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
  console.log(`  ${category}: ${count}`);
}

if (failures.length > 0) {
  console.log("\nFailure samples:");
  for (const failure of failures.slice(0, 20)) {
    console.log(`  [${failure.category}] ${failure.scenario}#${failure.index} - ${failure.reason}`);
    console.log(`    text: ${failure.text}`);
    console.log(`    detected: ${failure.detectedTypes.join(", ") || "(none)"}`);
    console.log(`    anonymized: ${failure.anonymized}`);
  }
  process.exit(1);
}

console.log(`\nAll ${requestedCases} cases passed.\n`);
