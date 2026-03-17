#!/usr/bin/env node

/**
 * Quick smoke test — run with: npm test
 */

import { anonymize, deanonymize, addCustomNames, addCustomPatterns, clearCustomDictionaries } from "./engine.js";

let passed = 0;
let failed = 0;

function assert(name, condition) {
  if (condition) {
    console.log(`  ✓ ${name}`);
    passed++;
  } else {
    console.log(`  ✗ ${name}`);
    failed++;
  }
}

console.log("\nPII Anonymizer MCP — Tests\n");

// Test 1: Core anonymization
const input = "Hi, my name is John Smith. My SSN is 123-45-6789 and my email is john.smith@example.com. My card is 4532015112830366. Call me at +1 555-867-5309.";
const result = anonymize(input);

assert(`Detected ${result.count} PII items`, result.count >= 5);
assert("anonymize_text works", result.anonymized.includes("[PERSON_NAME") && result.anonymized.includes("[SSN]") && result.anonymized.includes("[EMAIL]"));
assert("No original PII in output", !result.anonymized.includes("John") && !result.anonymized.includes("123-45-6789"));
assert("Entity map has entries", Object.keys(result.entityMap).length >= 5);

// Test 2: Deanonymization
const restored = deanonymize(result.anonymized, result.entityMap);
assert("deanonymize_text works", restored.includes("John") && restored.includes("123-45-6789") && restored.includes("john.smith@example.com"));

// Test 3: Entity consistency
const input2 = "John called John again. Smith and Smith agreed.";
const result2 = anonymize(input2);
const johnTag = result2.entityMap && Object.entries(result2.entityMap).find(([k, v]) => v === "John");
assert("Consistent placeholders (same name = same tag)", johnTag && result2.anonymized.split(johnTag[0]).length - 1 === 2);

// Test 4: Context-aware detection
const input3 = "My routing number is 021000021 and account 12345678.";
const result3 = anonymize(input3);
assert("Context-aware: routing number detected", result3.anonymized.includes("[ROUTING_NUMBER"));
assert("Context-aware: account number detected", result3.anonymized.includes("[BANK_ACCOUNT"));

// Test 5: Crypto
const input4 = "Send to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08";
const result4 = anonymize(input4);
assert("Ethereum address detected", result4.anonymized.includes("[CRYPTO_ADDRESS]"));

// Test 6: Empty input
const result5 = anonymize("");
assert("Empty input handled", result5.anonymized === "" && result5.count === 0);

// Test 7: No PII
const result6 = anonymize("The weather is nice today.");
assert("No false positives on clean text", result6.count === 0);

// Test 8: Credit card Luhn validation
const input5 = "Card: 4532015112830366";
const result7 = anonymize(input5);
assert("Valid credit card caught", result7.detectedTypes.includes("CREDIT_CARD"));

const input6 = "Number: 1234567890123456";
const result8 = anonymize(input6);
const hasFalseCC = result8.detectedTypes.includes("CREDIT_CARD");
assert("Invalid Luhn number not flagged as card", !hasFalseCC);

console.log(`\n${passed} passed, ${failed} failed\n`);

// Test 9: Custom names
clearCustomDictionaries();
addCustomNames(["Satoshi", "Nakamoto", "kraken_admin_42"]);
const input7 = "Satoshi Nakamoto sent a message to kraken_admin_42 about the project.";
const result9 = anonymize(input7);
assert("Custom name 'Satoshi' detected", !result9.anonymized.includes("Satoshi"));
assert("Custom name 'kraken_admin_42' detected", !result9.anonymized.includes("kraken_admin_42"));

// Test 10: Custom patterns
addCustomPatterns([
  { regex: "EMP-\\d{6}", label: "Employee ID", placeholder: "EMPLOYEE_ID" },
  { regex: "PROJ-[A-Z]{3}-\\d{4}", label: "Project Code", placeholder: "PROJECT_ID" },
]);
const input8 = "Employee EMP-483920 is assigned to PROJ-KRK-2026.";
const result10 = anonymize(input8);
assert("Custom pattern 'EMP-483920' detected", result10.anonymized.includes("[EMPLOYEE_ID"));
assert("Custom pattern 'PROJ-KRK-2026' detected", result10.anonymized.includes("[PROJECT_ID"));

// Test 11: Clear custom dictionaries
clearCustomDictionaries();
const result11 = anonymize("Satoshi sent a message. EMP-483920.");
assert("Cleared: 'Satoshi' no longer caught by custom dict", !result11.detectedTypes.includes("CUSTOM_PII"));

if (failed > 0) process.exit(1);
console.log("✓ All tests passed\n");
