"use strict";

/**
 * Tests for resolveEffectivePackageName()
 *
 * Ensures wildcard matching remains version-only and package-name matching
 * preserves npm scopes from package.json metadata.
 */

const { resolveEffectivePackageName } = require("../scan");

let passed = 0;
let failed = 0;

function assertEqual(actual, expected, message) {
  if (actual === expected) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    console.error(`    expected: ${expected}`);
    console.error(`    actual  : ${actual}`);
    failed++;
  }
}

function test(name, fn) {
  console.log(`\n${name}`);
  fn();
}

test("scoped package.json name wins over unscoped folder name", () => {
  const fallbackName = "legacy-ui";
  const packageJson = { name: "@team/legacy-ui", version: "1.2.3" };
  const result = resolveEffectivePackageName(fallbackName, packageJson);

  assertEqual(
    result,
    "@team/legacy-ui",
    "uses scoped package.json name for exact package matching",
  );
});

test("unscoped package.json name is still accepted", () => {
  const fallbackName = "folder-name";
  const packageJson = { name: "actual-name", version: "1.0.0" };
  const result = resolveEffectivePackageName(fallbackName, packageJson);

  assertEqual(result, "actual-name", "uses valid unscoped metadata name");
});

test("invalid metadata name falls back to discovered path name", () => {
  const fallbackName = "safe-fallback";
  const packageJson = { name: "not a valid npm name", version: "1.0.0" };
  const result = resolveEffectivePackageName(fallbackName, packageJson);

  assertEqual(
    result,
    "safe-fallback",
    "falls back when metadata name is invalid",
  );
});

test("missing package.json object falls back cleanly", () => {
  const fallbackName = "from-path";
  const result = resolveEffectivePackageName(fallbackName, null);

  assertEqual(result, "from-path", "falls back when metadata is unavailable");
});

console.log("\n──────────────────────────────────────────────────");
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  process.exit(1);
}
