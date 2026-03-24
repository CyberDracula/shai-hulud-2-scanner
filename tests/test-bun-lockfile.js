"use strict";

/**
 * Tests for parseBunLock()
 *
 * Covers:
 *  - exact and wildcard matches
 *  - scoped package exactness
 *  - token scan fallback behavior
 *  - dedupe when same package/version appears multiple times
 */

const { parseBunLock } = require("../scan");

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    failed++;
  }
}

function assertEqual(actual, expected, message) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    console.error(`    expected: ${JSON.stringify(expected)}`);
    console.error(`    actual  : ${JSON.stringify(actual)}`);
    failed++;
  }
}

function test(name, fn) {
  console.log(`\n${name}`);
  fn();
}

const LOCK_PATH = "/fake/project/bun.lock";

function parse(content, badPackages, campaignMap = new Map()) {
  return parseBunLock(content, badPackages, campaignMap, LOCK_PATH);
}

test("json packages object with specifier key yields exact hit", () => {
  const content = JSON.stringify({
    packages: {
      "@vendor/evil-pkg@1.2.3": ["@vendor/evil-pkg@1.2.3"],
    },
  });

  const hits = parse(content, { "@vendor/evil-pkg": new Set(["1.2.3"]) });
  assertEqual(hits.length, 1, "one exact hit detected");
  assertEqual(hits[0].type, "LOCKFILE_HIT", "exact hit type");
  assertEqual(hits[0].package, "@vendor/evil-pkg", "scoped package parsed");
});

test("json package key with wildcard denylist yields wildcard hit", () => {
  const content = JSON.stringify({
    packages: {
      "bad-any@7.8.9": ["bad-any@7.8.9"],
    },
  });

  const hits = parse(content, { "bad-any": new Set(["*"]) });
  assertEqual(hits.length, 1, "one wildcard hit detected");
  assertEqual(hits[0].type, "WILDCARD_LOCK_HIT", "wildcard hit type");
  assertEqual(hits[0].version, "7.8.9", "version captured");
});

test("unscoped wildcard IOC does not match scoped package", () => {
  const content = "@vendor/evil-pkg@1.0.0";
  const hits = parse(content, { "evil-pkg": new Set(["*"]) });
  assertEqual(hits.length, 0, "scope must match exactly");
});

test("token-scan fallback parses version with peer suffix", () => {
  const content = "evil-pkg@1.2.3(react@18.3.1)";
  const hits = parse(content, { "evil-pkg": new Set(["1.2.3"]) });
  assertEqual(hits.length, 1, "one hit from token scan");
  assertEqual(hits[0].version, "1.2.3", "peer suffix trimmed");
});

test("duplicate occurrences are deduplicated", () => {
  const content = [
    "evil-pkg@1.2.3",
    "evil-pkg@1.2.3",
    JSON.stringify({ packages: { "evil-pkg@1.2.3": ["evil-pkg@1.2.3"] } }),
  ].join("\n");

  const hits = parse(content, { "evil-pkg": new Set(["1.2.3"]) });
  assertEqual(hits.length, 1, "single deduped hit");
});

test("campaign is populated from campaignMap", () => {
  const content = "evil-pkg@1.2.3";
  const hits = parse(
    content,
    { "evil-pkg": new Set(["1.2.3"]) },
    new Map([["evil-pkg", "CANISTERWORM"]]),
  );
  assertEqual(hits.length, 1, "one hit detected");
  assertEqual(hits[0].campaign, "CANISTERWORM", "campaign mapped");
});

test("workspace specifier is skipped (no misleading exact hit)", () => {
  const content = JSON.stringify({
    packages: {
      "evil-pkg@workspace:*": ["evil-pkg@workspace:*"],
    },
  });

  const hits = parse(content, { "evil-pkg": new Set(["*"]) });
  assertEqual(hits.length, 0, "workspace specifier does not produce a hit");
});

console.log(`\n${"─".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  process.exit(1);
}
