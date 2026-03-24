"use strict";

/**
 * Tests for parseNpmLock()
 *
 * Focus: package-name matching must remain exact (including scope), while
 * wildcard applies only to versions for the matched package key.
 */

const { parseNpmLock } = require("../scan");

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

const LOCK_PATH = "/fake/project/package-lock.json";

function parse(json, badPackages, campaignMap = new Map()) {
  return parseNpmLock(
    JSON.stringify(json),
    badPackages,
    campaignMap,
    LOCK_PATH,
  );
}

test("v3 packages: unscoped wildcard IOC does not match scoped package", () => {
  const json = {
    lockfileVersion: 3,
    packages: {
      "": { name: "demo", version: "1.0.0" },
      "node_modules/@vendor/evil-pkg": { version: "1.2.3" },
    },
  };
  const badPackages = { "evil-pkg": new Set(["*"]) };

  const hits = parse(json, badPackages);
  assertEqual(hits.length, 0, "scope must match exactly");
});

test("v3 packages: scoped wildcard IOC matches scoped package", () => {
  const json = {
    lockfileVersion: 3,
    packages: {
      "node_modules/@vendor/evil-pkg": { version: "1.2.3" },
    },
  };
  const badPackages = { "@vendor/evil-pkg": new Set(["*"]) };

  const hits = parse(json, badPackages);
  assertEqual(hits.length, 1, "exact scoped key matched");
  assertEqual(hits[0].type, "WILDCARD_LOCK_HIT", "wildcard hit type");
  assertEqual(hits[0].package, "@vendor/evil-pkg", "scoped package preserved");
});

test("v3 packages: unscoped wildcard IOC matches unscoped package", () => {
  const json = {
    lockfileVersion: 3,
    packages: {
      "node_modules/evil-pkg": { version: "4.5.6" },
    },
  };
  const badPackages = { "evil-pkg": new Set(["*"]) };

  const hits = parse(json, badPackages);
  assertEqual(hits.length, 1, "unscoped exact key matched");
  assertEqual(hits[0].package, "evil-pkg", "unscoped package name");
});

test("v1 dependencies: unscoped wildcard IOC does not match scoped package", () => {
  const json = {
    lockfileVersion: 1,
    dependencies: {
      "@vendor/evil-pkg": { version: "9.9.9" },
    },
  };
  const badPackages = { "evil-pkg": new Set(["*"]) };

  const hits = parse(json, badPackages);
  assertEqual(
    hits.length,
    0,
    "scope must match exactly in v1 dependencies too",
  );
});

test("campaign map is populated for exact scoped package", () => {
  const json = {
    lockfileVersion: 3,
    packages: {
      "node_modules/@vendor/evil-pkg": { version: "1.0.0" },
    },
  };
  const badPackages = { "@vendor/evil-pkg": new Set(["1.0.0"]) };
  const campaignMap = new Map([["@vendor/evil-pkg", "CANISTERWORM"]]);

  const hits = parse(json, badPackages, campaignMap);
  assertEqual(hits.length, 1, "single exact match");
  assertEqual(hits[0].campaign, "CANISTERWORM", "campaign mapped");
});

console.log(`\n${"─".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  process.exit(1);
}
