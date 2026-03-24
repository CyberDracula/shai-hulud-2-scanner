"use strict";

/**
 * Tests for parsePnpmLock()
 *
 * Covers:
 *  - Exact and wildcard matches
 *  - Scoped package matching behavior
 *  - Legacy "/pkg@version" keys
 *  - Peer suffix handling (e.g. react@18.2.0(typescript@5.0.0))
 *  - Section scoping (only packages/snapshots)
 */

const { parsePnpmLock } = require("../scan");

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

const LOCK_PATH = "/fake/project/pnpm-lock.yaml";

function parse(content, badPackages, campaignMap = new Map()) {
  return parsePnpmLock(content, badPackages, campaignMap, LOCK_PATH);
}

test("packages section: exact match produces LOCKFILE_HIT", () => {
  const content = [
    "lockfileVersion: '9.0'",
    "packages:",
    "  evil-pkg@1.2.3:",
    "    resolution: {integrity: sha512-abc}",
  ].join("\n");

  const hits = parse(content, { "evil-pkg": new Set(["1.2.3"]) });
  assertEqual(hits.length, 1, "one hit detected");
  assertEqual(hits[0].type, "LOCKFILE_HIT", "strict hit type");
  assertEqual(hits[0].package, "evil-pkg", "package matches");
  assertEqual(hits[0].version, "1.2.3", "version matches");
});

test("packages section: wildcard version produces WILDCARD_LOCK_HIT", () => {
  const content = [
    "packages:",
    "  bad-any@7.8.9:",
    "    resolution: {integrity: sha512-abc}",
  ].join("\n");

  const hits = parse(content, { "bad-any": new Set(["*"]) });
  assertEqual(hits.length, 1, "one wildcard hit detected");
  assertEqual(hits[0].type, "WILDCARD_LOCK_HIT", "wildcard hit type");
  assertEqual(hits[0].version, "7.8.9", "installed version captured");
});

test("scoped package: unscoped IOC key does not match", () => {
  const content = [
    "packages:",
    "  '@vendor/evil-pkg@1.0.0':",
    "    resolution: {integrity: sha512-abc}",
  ].join("\n");

  const hits = parse(content, { "evil-pkg": new Set(["*"]) });
  assertEqual(hits.length, 0, "scope must match exactly");
});

test("scoped package: scoped IOC key matches", () => {
  const content = [
    "packages:",
    "  '@vendor/evil-pkg@1.0.0':",
    "    resolution: {integrity: sha512-abc}",
  ].join("\n");

  const hits = parse(content, { "@vendor/evil-pkg": new Set(["1.0.0"]) });
  assertEqual(hits.length, 1, "exact scoped hit");
  assertEqual(hits[0].package, "@vendor/evil-pkg", "scope preserved");
});

test("legacy keys with leading slash are supported", () => {
  const content = [
    "packages:",
    "  '/legacy-bad@4.5.6':",
    "    resolution: {integrity: sha512-abc}",
  ].join("\n");

  const hits = parse(content, { "legacy-bad": new Set(["4.5.6"]) });
  assertEqual(hits.length, 1, "legacy key parsed");
  assertEqual(hits[0].package, "legacy-bad", "leading slash trimmed");
});

test("peer suffix in version key is normalized", () => {
  const content = [
    "packages:",
    "  react-dom@18.2.0(react@18.2.0):",
    "    resolution: {integrity: sha512-abc}",
  ].join("\n");

  const hits = parse(content, { "react-dom": new Set(["18.2.0"]) });
  assertEqual(hits.length, 1, "peer suffix ignored for version match");
  assertEqual(hits[0].version, "18.2.0", "clean semver extracted");
});

test("snapshots section is parsed too", () => {
  const content = [
    "snapshots:",
    "  '@snapshot/bad@2.0.0':",
    "    dependencies:",
    "      any: 1.0.0",
  ].join("\n");

  const hits = parse(content, { "@snapshot/bad": new Set(["2.0.0"]) });
  assertEqual(hits.length, 1, "snapshot key matched");
});

test("importers section dependency versions generate hits", () => {
  const content = [
    "importers:",
    "  .:",
    "    dependencies:",
    "      evil-pkg:",
    "        specifier: 1.2.3",
    "        version: 1.2.3",
  ].join("\n");

  const hits = parse(content, { "evil-pkg": new Set(["1.2.3"]) });
  assertEqual(hits.length, 1, "importers dependency version matched");
  assertEqual(hits[0].package, "evil-pkg", "importers package captured");
  assertEqual(hits[0].version, "1.2.3", "importers version captured");
});

test("package seen in importers and packages is deduplicated", () => {
  const content = [
    "importers:",
    "  .:",
    "    dependencies:",
    "      evil-pkg:",
    "        specifier: 1.2.3",
    "        version: 1.2.3",
    "packages:",
    "  evil-pkg@1.2.3:",
    "    resolution: {integrity: sha512-abc}",
  ].join("\n");

  const hits = parse(content, { "evil-pkg": new Set(["1.2.3"]) });
  assertEqual(hits.length, 1, "single deduped hit emitted");
});

test("campaign is populated from campaignMap", () => {
  const content = [
    "packages:",
    "  evil-pkg@1.2.3:",
    "    resolution: {integrity: sha512-abc}",
  ].join("\n");

  const campaignMap = new Map([["evil-pkg", "CANISTERWORM"]]);
  const hits = parse(content, { "evil-pkg": new Set(["1.2.3"]) }, campaignMap);
  assertEqual(hits.length, 1, "one hit detected");
  assertEqual(hits[0].campaign, "CANISTERWORM", "campaign mapped");
});

console.log(`\n${"─".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  process.exit(1);
}
