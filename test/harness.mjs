import { anonymize, deanonymize } from "../engine.js";
import { writeFileSync } from "fs";

function placeholderType(tag) {
  const m = tag.match(/^\[([A-Z_]+?)(?:_\d+)?\]$/);
  return m ? m[1] : tag;
}

function shuffle(arr, seed) {
  const out = [...arr];
  let x = seed >>> 0;
  for (let i = out.length - 1; i > 0; i--) {
    x = (1664525 * x + 1013904223) >>> 0;
    const j = x % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function finding(value, expectedType, options = {}) {
  return {
    value,
    expectedType,
    semanticType: options.semanticType || expectedType,
    allowTypeMismatch: options.allowTypeMismatch ?? false,
  };
}

function uniqueDigits(base, n, width) {
  return String(base + n).padStart(width, "0").slice(-width);
}

const FIRST_NAMES = [
  "John", "Maria", "Priya", "Ahmed", "Kofi", "Alice", "Kevin", "Julia", "David", "Sophia",
  "Nina", "Brian", "Leah", "Victor", "Maya", "Omar", "Diana", "Ethan", "Grace", "Rafael",
];

const LAST_NAMES = [
  "Smith", "Garcia", "Patel", "Khan", "Mensah", "Brown", "Lee", "Taylor", "Miller", "Johnson",
  "Nguyen", "Wright", "Chen", "Anderson", "Lopez", "Clark", "Owusu", "Martin", "Cruz", "Walker",
];

const CITIES = [
  ["Springfield", "CA", "90210"],
  ["Riverside", "CA", "92501"],
  ["Fremont", "CA", "94538"],
  ["Newark", "NJ", "07102"],
  ["Atlanta", "GA", "30303"],
  ["Seattle", "WA", "98101"],
  ["Boston", "MA", "02108"],
  ["Las Vegas", "NV", "89101"],
  ["Denver", "CO", "80202"],
  ["New York", "NY", "10001"],
  ["Austin", "TX", "78701"],
  ["Phoenix", "AZ", "85004"],
  ["Miami", "FL", "33130"],
  ["Chicago", "IL", "60601"],
  ["Portland", "OR", "97204"],
];

const STREETS = [
  "Main Street", "Oak Avenue", "Pine Road", "Cedar Drive", "Birch Lane",
  "Maple Court", "Walnut Boulevard", "Cherry Place", "Aspen Terrace", "Palm Way",
  "River Street", "Market Road", "Lake Drive", "Highland Avenue", "Sunset Boulevard",
];

const ROUTINGS = [
  "021000021", "011000015", "031000503", "026009593", "061000104",
  "071000013", "122105155", "121000248", "123103716", "124003116",
];

const IBANS = [
  "GB29NWBK60161331926819",
  "DE89370400440532013000",
  "FR7630006000011234567890189",
  "ES9121000418450200051332",
  "NL91ABNA0417164300",
  "IT60X0542811101000000123456",
  "IE29AIBK93115212345678",
  "BE68539007547034",
  "CH9300762011623852957",
  "AT611904300234573201",
];

const SORT_CODES = ["12-34-56", "20-45-67", "30-56-78", "40-67-89", "50-78-90", "60-12-34", "77-88-99", "11-22-33", "44-55-66", "70-11-22"];

const ETHS = [
  "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08",
  "0x52908400098527886E0F7030069857D2E4169EE7",
  "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
  "0xde709f2102306220921060314715629080e2fb77",
  "0x27b1fdb04752bbc536007a920d24acb045561c26",
  "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
  "0xdbF03B407c01E7cd3CBea99509d93f8dDdC8c6Fb",
  "0x583031D1113aD414F02576BD6afaBfb302140225",
  "0xdd870fa1b7c4700f2bd7f44238821c26f7392148",
  "0x66f820a414680B5bcda5eECA5dea238543F42054",
];

const BTCS = [
  "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
  "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
  "1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY",
  "1AJbsFZ64EpEfS5UAjAfcUG8pH8Jn3rn1F",
  "1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp",
  "1CounterpartyXXXXXXXXXXXXXXXUWLpVr",
  "1LuckyR1fFHEsXYyx5QK4UFzv3PEAepPMK",
  "1QLbz7JHiBTspS962RLKV8GndWFwi5j6Qr",
  "1Cdid9KFAaatwczBwBttQcwXYCpvK8h7FK",
  "1JHG5H6Z9hDRe8yz1o4JwYQ4pQF6UVxZ4T",
];

const BTC_BECH32 = [
  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
  "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
  "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf4dsk",
  "bc1q0ht9tyks4vh7p5p904t340cr9nvahy7um9c6lq",
  "bc1q9zpgru8f8d2v0f4av4t0u3mu3np4kdrn5y0f6k",
  "bc1q8c6fshw2dlux9f3h0j8wwr0z5zj8u0frl0ry4e",
  "bc1qvzvkjn4q3nszqxrv6gx2c2x6hfzmt9q3g7v4d8",
  "bc1qn4q9p7q7sx5nm5v5r3g5y36k0n7p3gh2m5n23m",
  "bc1q5cyxnuxmeuwuvkwfem96llytf7h4p8l7d6u2rx",
  "bc1q6r4q9fx8f3m8qu5d5v4uavtshyzf6l4gxk8d5p",
];

const VALID_CARDS = [
  "4532015112830366",
  "5555555555554444",
  "4111111111111111",
  "6011111111111117",
  "4000056655665556",
  "4242424242424242",
  "3530111333300000",
  "3566002020360505",
  "5105105105105100",
  "4000002760003184",
];

const API_KEYS = [
  "sk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
  "sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
  "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD",
  "glpat-abcdefghijklmnopqrstuvwxyz1234567890",
  "pk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
  "pk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
  "github_pat_abcdefghijklmnopqrstuvwxyz_1234567890",
  "xoxb-FAKE123456789012-FAKEabcdefghijklmnopqrstuvwxyz",
  "sk-abcdefghijklmnopqrstuvwxyz12345678901234567890",
  "ghp_zyxwvutsrqponmlkjihgfedcba1234567890ABCD",
];

function makeJwt(i, first) {
  return `eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoi${first.toLowerCase()}${i}Iiwicm9sZSI6InFhIn0.signature${uniqueDigits(987654321, i, 12)}`;
}

function makeUuid(i) {
  const a = uniqueDigits(10000000, i, 8);
  const b = uniqueDigits(2000, i, 4);
  const c = uniqueDigits(3000, i, 4);
  const d = uniqueDigits(4000, i, 4);
  const e = uniqueDigits(500000000000, i, 12);
  return `${a}-${b}-${c}-${d}-${e}`;
}

function makeIp(i) {
  return `${10 + (i % 200)}.${20 + (i % 200)}.${30 + (i % 200)}.${40 + (i % 200)}`;
}

function makeMac(i) {
  const hex = uniqueDigits(100000000000 + i, i, 12).match(/.{2}/g).map((x) => Number(x).toString(16).padStart(2, "0").toUpperCase());
  return hex.join(":");
}

function makeProfile(i) {
  const first = FIRST_NAMES[i % FIRST_NAMES.length];
  const last = LAST_NAMES[(i * 3) % LAST_NAMES.length];
  const [city, state, zip] = CITIES[i % CITIES.length];
  const streetNumber = 100 + i * 7;
  const street = `${streetNumber} ${STREETS[i % STREETS.length]}`;
  const phone = `+1 ${200 + (i % 700)}-555-${uniqueDigits(1000, i, 4)}`;
  const ssn = `${200 + (i % 700)}-${10 + (i % 89)}-${uniqueDigits(1000, i, 4)}`;
  const email = `${first.toLowerCase()}.${last.toLowerCase()}${i}@example${i % 2 === 0 ? ".com" : ".org"}`;
  const card = VALID_CARDS[i % VALID_CARDS.length];
  const eth = ETHS[i % ETHS.length];
  const btc = BTCS[i % BTCS.length];
  const btcBech32 = BTC_BECH32[i % BTC_BECH32.length];
  const apiKey = API_KEYS[i % API_KEYS.length];
  const jwt = makeJwt(i, first);
  const routing = ROUTINGS[i % ROUTINGS.length];
  const account = `${uniqueDigits(123456789000, i * 37, 12)}`;
  const iban = IBANS[i % IBANS.length];
  const sortCode = SORT_CODES[i % SORT_CODES.length];
  const passport = `${String.fromCharCode(65 + (i % 20))}${uniqueDigits(1234567, i * 13, 7)}`;
  const dl = `${String.fromCharCode(65 + ((i + 7) % 20))}${uniqueDigits(7654321, i * 19, 7)}`;
  const dob = `${String((i % 12) + 1).padStart(2, "0")}/${String((i % 27) + 1).padStart(2, "0")}/${1980 + (i % 20)}`;
  return {
    id: `P${String(i + 1).padStart(3, "0")}`,
    first,
    last,
    email,
    phone,
    ssn,
    card,
    eth,
    btc,
    btcBech32,
    apiKey,
    jwt,
    routing,
    account,
    iban,
    sortCode,
    ip: makeIp(i),
    uuid: makeUuid(i),
    deviceId: `DEVICE_${first.toUpperCase()}${uniqueDigits(7000, i, 4)}`,
    sessionId: `session_${last.toLowerCase()}${uniqueDigits(8000, i, 4)}`,
    userId: `USER_${first.toLowerCase()}${uniqueDigits(9000, i, 4)}`,
    mac: makeMac(i),
    street,
    city,
    state,
    zip,
    ukPostcode: ["SW1A 1AA", "EC1A 1BB", "W1A 0AX", "M1 1AE", "B1 1AA", "LS1 4AP", "EH1 1YZ", "G1 1XQ", "CF10 1EP", "BT1 5GS"][i % 10],
    passport,
    dl,
    dob,
  };
}

function orderedLines(seed, lines) {
  return shuffle(lines, seed).join("\n");
}

const positiveTemplates = [
  {
    id: "contact_note",
    category: "contact",
    build: (p, seed) => ({
      text: `${orderedLines(seed, [
        `Customer ${p.first} ${p.last}`,
        `Email ${p.email}`,
        `Call me at ${p.phone}`,
        `City ${p.city}`,
      ])}\n`,
      expected: [
        finding(p.first, "PERSON_NAME"),
        finding(p.last, "PERSON_NAME"),
        finding(p.email, "EMAIL"),
        finding(p.phone, "PHONE_NUMBER"),
      ],
    }),
  },
  {
    id: "labeled_identity",
    category: "identity",
    build: (p, seed) => ({
      text: `${orderedLines(seed, [
        `Name: ${p.first} ${p.last}`,
        `Phone: ${p.phone}`,
        `SSN: ${p.ssn}`,
      ])}\n`,
      expected: [
        finding(p.first, "PERSON_NAME"),
        finding(p.last, "PERSON_NAME"),
        finding(p.phone, "PHONE_NUMBER"),
        finding(p.ssn, "SSN"),
      ],
    }),
  },
  {
    id: "bank_form",
    category: "financial",
    build: (p, seed) => {
      const parts = shuffle([
        `Cardholder ${p.first} ${p.last}`,
        `card ${p.card}`,
        `routing ${p.routing}`,
        `account ${p.account}`,
      ], seed);
      return {
        text: parts.join("; "),
        expected: [
          finding(p.first, "PERSON_NAME"),
          finding(p.last, "PERSON_NAME"),
          finding(p.card, "CREDIT_CARD"),
          finding(p.routing, "ROUTING_NUMBER"),
          finding(p.account, "BANK_ACCOUNT"),
        ],
      };
    },
  },
  {
    id: "crypto_support",
    category: "crypto",
    build: (p, seed) => ({
      text: `${orderedLines(seed, [
        `From ${p.email}`,
        `Wallet ${p.eth}`,
        `Backup BTC ${p.btc}`,
        `Auth ${p.jwt}`,
        `Key ${p.apiKey}`,
      ])}\n`,
      expected: [
        finding(p.email, "EMAIL"),
        finding(p.eth, "CRYPTO_ADDRESS"),
        finding(p.btc, "CRYPTO_ADDRESS"),
        finding(p.jwt, "ACCESS_TOKEN"),
        finding(p.apiKey, "API_KEY"),
      ],
    }),
  },
  {
    id: "infra_log",
    category: "system",
    build: (p, seed) => {
      const parts = shuffle([
        `src_ip=${p.ip}`,
        `trace=${p.uuid}`,
        `user=${p.userId}`,
        `session=${p.sessionId}`,
        `device=${p.deviceId}`,
        `mac=${p.mac}`,
      ], seed);
      return {
        text: parts.join(" "),
        expected: [
          finding(p.ip, "IP_ADDRESS"),
          finding(p.uuid, "UUID"),
          finding(p.userId, "USER_ID"),
          finding(p.sessionId, "SESSION_TOKEN"),
          finding(p.deviceId, "DEVICE_ID"),
          finding(p.mac, "MAC_ADDRESS"),
        ],
      };
    },
  },
  {
    id: "shipping_block",
    category: "address",
    build: (p, seed) => ({
      text: `${orderedLines(seed, [
        `Ship to ${p.first} ${p.last}`,
        p.street,
        `${p.city}, ${p.state} ${p.zip}`,
        `Mobile ${p.phone}`,
      ])}\n`,
      expected: [
        finding(p.first, "PERSON_NAME"),
        finding(p.last, "PERSON_NAME"),
        finding(p.street, "STREET_ADDRESS"),
        finding(p.zip, "ZIP_CODE"),
        finding(p.phone, "PHONE_NUMBER"),
      ],
    }),
  },
  {
    id: "travel_doc",
    category: "identity",
    build: (p, seed) => {
      const parts = shuffle([
        `passport ${p.passport}`,
        `DL ${p.dl}`,
        `DOB ${p.dob}`,
        `Contact ${p.email}`,
      ], seed);
      return {
        text: parts.join("; "),
        expected: [
          finding(p.passport, "PASSPORT_NUMBER"),
          finding(p.dl, "DRIVER_LICENSE"),
          finding(p.dob, "DATE"),
          finding(p.email, "EMAIL"),
        ],
      };
    },
  },
  {
    id: "json_blob",
    category: "structured",
    build: (p, seed) => {
      const entries = shuffle([
        `"name":"${p.first} ${p.last}"`,
        `"email":"${p.email}"`,
        `"phone":"${p.phone}"`,
        `"wallet":"${p.eth}"`,
        `"apiKey":"${p.apiKey}"`,
      ], seed);
      return {
        text: `{${entries.join(",")}}`,
        expected: [
          finding(p.first, "PERSON_NAME"),
          finding(p.last, "PERSON_NAME"),
          finding(p.email, "EMAIL"),
          finding(p.phone, "PHONE_NUMBER"),
          finding(p.eth, "CRYPTO_ADDRESS"),
          finding(p.apiKey, "API_KEY"),
        ],
      };
    },
  },
  {
    id: "uk_finance",
    category: "financial",
    build: (p, seed) => {
      const parts = shuffle([
        `Beneficiary ${p.first} ${p.last}`,
        `IBAN ${p.iban}`,
        `sort code ${p.sortCode}`,
        `postcode ${p.ukPostcode}`,
        `BTC ${p.btcBech32}`,
      ], seed);
      return {
        text: parts.join(" | "),
        expected: [
          finding(p.first, "PERSON_NAME"),
          finding(p.last, "PERSON_NAME"),
          finding(p.iban, "BANK_ACCOUNT"),
          finding(p.sortCode, "SORT_CODE"),
          finding(p.ukPostcode, "ZIP_CODE"),
          finding(p.btcBech32, "CRYPTO_ADDRESS"),
        ],
      };
    },
  },
];

const negativeTemplates = [
  (i) => ({
    category: "negative",
    format: "plain_release",
    text: `Release ${2020 + (i % 8)}.${(i % 12) + 1}.${(i % 27) + 1} improves throughput to ${9000 + i} rows and keeps session-summary-${i} in docs only.`,
  }),
  (i) => ({
    category: "negative",
    format: "roadmap_note",
    text: `We will review the draft in May, hope to close by June, and move Grace mode behind feature flag beta-${i}.`,
  }),
  (i) => ({
    category: "negative",
    format: "jsonish_metrics",
    text: `{"status":"ok","count":${90210 + i},"build":"2026-03-${String((i % 28) + 1).padStart(2, "0")}","slug":"session-summary-${i}"}`,
  }),
  (i) => ({
    category: "negative",
    format: "csvish_metrics",
    text: `metric,value\nthroughput,${5550000 + i}\nwindow,2026-03-${String((i % 28) + 1).padStart(2, "0")}\nbucket,alpha-${10 + i}\n`,
  }),
  (i) => ({
    category: "negative",
    format: "docs_postcode",
    text: `Example postcode token ZZ0 0ZZ appears in docs sample ${i}; fake card 1234567890123456 remains invalid by design.`,
  }),
];

const PROFILE_COUNT = 1500;
const NEGATIVE_COUNT = 1500;
const FAILURE_SAMPLE_LIMIT = 200;
const REPORT_FAILURE_LIMIT = 50;

const cases = [];
let caseNum = 1;
for (let i = 0; i < PROFILE_COUNT; i++) {
  const profile = makeProfile(i);
  const orderedTemplates = shuffle(positiveTemplates, i * 7919 + 17);
  for (const template of orderedTemplates) {
    const built = template.build(profile, i * 104729 + caseNum);
    cases.push({
      id: `T${String(caseNum).padStart(3, "0")}`,
      template: template.id,
      category: template.category,
      format: template.id,
      profile: profile.id,
      text: built.text,
      expected: built.expected,
    });
    caseNum++;
  }
}
for (let i = 0; i < NEGATIVE_COUNT; i++) {
  const build = negativeTemplates[i % negativeTemplates.length];
  cases.push({
    id: `T${String(caseNum).padStart(3, "0")}`,
    template: build(i).format,
    category: "negative",
    format: build(i).format,
    profile: null,
    text: build(i).text,
    expected: [],
  });
  caseNum++;
}

const EXPECTED_TOTAL = PROFILE_COUNT * positiveTemplates.length + NEGATIVE_COUNT;
if (cases.length !== EXPECTED_TOTAL) {
  throw new Error(`Expected ${EXPECTED_TOTAL} cases, got ${cases.length}`);
}

function analyzeCase(testCase) {
  const result = anonymize(testCase.text);
  const restored = deanonymize(result.anonymized, result.entityMap);
  const actualEntries = Object.entries(result.entityMap).map(([tag, value]) => ({
    tag,
    type: placeholderType(tag),
    value,
  }));
  const unmatched = [...actualEntries];
  const issues = [];
  const warnings = [];

  for (const expected of testCase.expected) {
    let actualIndex = unmatched.findIndex((entry) => entry.value === expected.value);
    let matchKind = "exact";

    if (actualIndex === -1) {
      actualIndex = unmatched.findIndex((entry) => entry.value.includes(expected.value));
      if (actualIndex !== -1) matchKind = "overcapture";
    }

    if (actualIndex === -1) {
      issues.push({
        kind: "missing_detection",
        severity: "high",
        expectedType: expected.expectedType,
        semanticType: expected.semanticType,
        value: expected.value,
      });
      continue;
    }

    const actual = unmatched.splice(actualIndex, 1)[0];
    if (matchKind === "overcapture") {
      issues.push({
        kind: "overcapture",
        severity: "high",
        expectedType: expected.expectedType,
        actualType: actual.type,
        value: expected.value,
        actualValue: actual.value,
      });
    }

    if (actual.type !== expected.expectedType) {
      if (expected.allowTypeMismatch) {
        warnings.push({
          kind: "taxonomy_mismatch",
          severity: "medium",
          expectedType: expected.semanticType,
          actualType: actual.type,
          value: expected.value,
        });
      } else {
        issues.push({
          kind: "type_mismatch",
          severity: "high",
          expectedType: expected.expectedType,
          actualType: actual.type,
          value: expected.value,
        });
      }
    } else if (expected.semanticType !== expected.expectedType) {
      warnings.push({
        kind: "taxonomy_mismatch",
        severity: "medium",
        expectedType: expected.semanticType,
        actualType: actual.type,
        value: expected.value,
      });
    }
  }

  for (const extra of unmatched) {
    issues.push({
      kind: "unexpected_detection",
      severity: "medium",
      actualType: extra.type,
      actualValue: extra.value,
    });
  }

  if (restored !== testCase.text) {
    issues.push({
      kind: "restore_mismatch",
      severity: "critical",
    });
  }

  const strictPass = issues.length === 0 && warnings.length === 0;
  const corePass = !issues.some((issue) => ["missing_detection", "restore_mismatch", "type_mismatch", "unexpected_detection"].includes(issue.kind));

  return {
    id: testCase.id,
    template: testCase.template || testCase.format,
    category: testCase.category,
    profile: testCase.profile || null,
    expectedCount: testCase.expected.length,
    actualCount: result.count,
    corePass,
    strictPass,
    issues,
    warnings,
    anonymized: result.anonymized,
    actualEntries,
  };
}

const results = cases.map(analyzeCase);

const summary = {
  total: results.length,
  corePassed: results.filter((r) => r.corePass).length,
  strictPassed: results.filter((r) => r.strictPass).length,
  failed: results.filter((r) => !r.strictPass).length,
  byIssue: {},
  byWarning: {},
  byCategory: {},
  byTemplate: {},
};

for (const result of results) {
  summary.byCategory[result.category] ||= { total: 0, corePassed: 0, strictPassed: 0 };
  summary.byCategory[result.category].total++;
  if (result.corePass) summary.byCategory[result.category].corePassed++;
  if (result.strictPass) summary.byCategory[result.category].strictPassed++;

  summary.byTemplate[result.template] ||= { total: 0, corePassed: 0, strictPassed: 0 };
  summary.byTemplate[result.template].total++;
  if (result.corePass) summary.byTemplate[result.template].corePassed++;
  if (result.strictPass) summary.byTemplate[result.template].strictPassed++;

  for (const issue of result.issues) {
    summary.byIssue[issue.kind] = (summary.byIssue[issue.kind] || 0) + 1;
  }
  for (const warning of result.warnings) {
    summary.byWarning[warning.kind] = (summary.byWarning[warning.kind] || 0) + 1;
  }
}

const topFailures = results
  .filter((r) => r.issues.length || r.warnings.length)
  .map((r) => ({
    id: r.id,
    category: r.category,
    template: r.template,
    issues: r.issues,
    warnings: r.warnings,
    anonymized: r.anonymized,
  }));

const output = {
  summary,
  sample_failures: topFailures.slice(0, FAILURE_SAMPLE_LIMIT),
  sample_failure_count: Math.min(topFailures.length, FAILURE_SAMPLE_LIMIT),
  total_failure_cases: topFailures.length,
};
writeFileSync("/tmp/pii-anonymizer-qa-results.json", JSON.stringify(output, null, 2));

function issueLine(issue) {
  if (issue.kind === "missing_detection") return `missing ${issue.expectedType} for "${issue.value}"`;
  if (issue.kind === "overcapture") return `overcaptured ${issue.expectedType}: expected "${issue.value}" but matched "${issue.actualValue}"`;
  if (issue.kind === "type_mismatch") return `wrong placeholder type for "${issue.value}": expected ${issue.expectedType}, got ${issue.actualType}`;
  if (issue.kind === "unexpected_detection") return `unexpected ${issue.actualType}: "${issue.actualValue}"`;
  if (issue.kind === "restore_mismatch") return "restore output did not match original input";
  return issue.kind;
}

function warningLine(w) {
  if (w.kind === "taxonomy_mismatch") return `taxonomy mismatch for "${w.value}": semantic ${w.expectedType}, placeholder ${w.actualType}`;
  return w.kind;
}

const lines = [];
lines.push("# PII Anonymizer QA Report");
lines.push("");
lines.push(`Synthetic regression sweep using ${EXPECTED_TOTAL.toLocaleString()} deterministic test cases across mixed formats and PII types.`);
lines.push("");
lines.push(`- Total cases: ${summary.total}`);
lines.push(`- Core pass rate: ${summary.corePassed}/${summary.total}`);
lines.push(`- Strict quality pass rate: ${summary.strictPassed}/${summary.total}`);
lines.push(`- Failure cases sampled in JSON: ${Math.min(topFailures.length, FAILURE_SAMPLE_LIMIT)}/${topFailures.length}`);
lines.push("");
lines.push("## Issue Counts");
lines.push("");
for (const [kind, count] of Object.entries(summary.byIssue).sort((a, b) => b[1] - a[1])) {
  lines.push(`- ${kind}: ${count}`);
}
if (Object.keys(summary.byIssue).length === 0) lines.push("- none");
lines.push("");
lines.push("## Warning Counts");
lines.push("");
for (const [kind, count] of Object.entries(summary.byWarning).sort((a, b) => b[1] - a[1])) {
  lines.push(`- ${kind}: ${count}`);
}
if (Object.keys(summary.byWarning).length === 0) lines.push("- none");
lines.push("");
lines.push("## Category Breakdown");
lines.push("");
for (const [category, stats] of Object.entries(summary.byCategory)) {
  lines.push(`- ${category}: core ${stats.corePassed}/${stats.total}, strict ${stats.strictPassed}/${stats.total}`);
}
lines.push("");
lines.push("## Template Breakdown");
lines.push("");
for (const [template, stats] of Object.entries(summary.byTemplate)) {
  lines.push(`- ${template}: core ${stats.corePassed}/${stats.total}, strict ${stats.strictPassed}/${stats.total}`);
}
lines.push("");
lines.push("## Representative Failures");
lines.push("");
for (const failure of topFailures.slice(0, REPORT_FAILURE_LIMIT)) {
  lines.push(`### ${failure.id} ${failure.category} ${failure.template}`);
  lines.push("");
  for (const issue of failure.issues) lines.push(`- ${issueLine(issue)}`);
  for (const warning of failure.warnings) lines.push(`- ${warningLine(warning)}`);
  lines.push(`- anonymized: ${failure.anonymized}`);
  lines.push("");
}

writeFileSync("/tmp/pii-anonymizer-qa-report.md", lines.join("\n"));
console.log(JSON.stringify(summary, null, 2));
