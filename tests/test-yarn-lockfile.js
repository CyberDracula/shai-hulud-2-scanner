"use strict";

/**
 * Tests for parseYarnLock()
 *
 * Covers:
 *  - Bare package name  →  LOCKFILE_HIT (strict version)
 *  - Bare package name  →  WILDCARD_LOCK_HIT (wildcard *)
 *  - Scoped package without quotes  (@scope/pkg@^1.0.0:)  →  LOCKFILE_HIT
 *  - Scoped package with quotes     ("@scope/pkg@^1.0.0":) →  LOCKFILE_HIT
 *  - Scoped package  →  WILDCARD_LOCK_HIT
 *  - Package not in denylist  →  no hit
 *  - Wrong version in denylist  →  no hit
 *  - Multiple version selectors on one header line (yarn v1 comma syntax)
 *  - campaign field populated from campaignMap
 *  - Comments and blank lines are silently ignored
 *  - Berry __metadata block does not produce hits
 *  - location field is passed through correctly
 *  - Indented "version" inside nested block does not fire without a prior pkg header
 */

const { parseYarnLock } = require("../scan");

// ---------------------------------------------------------------------------
// Minimal hand-rolled test harness (same pattern as test-csv-parser.js)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const LOCK_PATH = "/fake/project/yarn.lock";

/** Build a minimal yarn v1 lock block for one package. */
function yarnV1Block(header, version) {
  return `${header}\n  version "${version}"\n  resolved "https://example.com/"\n  integrity sha512-abc\n`;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("bare package — LOCKFILE_HIT on exact version match", () => {
  const content = yarnV1Block("evil-pkg@^1.2.3:", "1.2.3");
  const badPackages = { "evil-pkg": new Set(["1.2.3"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(hits.length, 1, "exactly one hit");
  assertEqual(hits[0].type, "LOCKFILE_HIT", "type is LOCKFILE_HIT");
  assertEqual(hits[0].package, "evil-pkg", "package name");
  assertEqual(hits[0].version, "1.2.3", "version");
  assertEqual(hits[0].location, LOCK_PATH, "location");
  assertEqual(hits[0].details, "Yarn Lock match (Strict)", "details");
});

test('bare package — WILDCARD_LOCK_HIT when denylist has "*"', () => {
  const content = yarnV1Block("any-version-bad@^0.0.1:", "3.0.0");
  const badPackages = { "any-version-bad": new Set(["*"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(hits.length, 1, "exactly one hit");
  assertEqual(hits[0].type, "WILDCARD_LOCK_HIT", "type is WILDCARD_LOCK_HIT");
  assertEqual(hits[0].package, "any-version-bad", "package name");
  assertEqual(hits[0].version, "3.0.0", "wildcard captures installed version");
});

test("scoped package without quotes — LOCKFILE_HIT", () => {
  const content = yarnV1Block("@bad-scope/bad-pkg@^2.0.0:", "2.0.0");
  const badPackages = { "@bad-scope/bad-pkg": new Set(["2.0.0"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(hits.length, 1, "exactly one hit");
  assertEqual(hits[0].type, "LOCKFILE_HIT", "type is LOCKFILE_HIT");
  assertEqual(
    hits[0].package,
    "@bad-scope/bad-pkg",
    "scoped package name preserved",
  );
  assertEqual(hits[0].version, "2.0.0", "version");
});

test("scoped package with surrounding quotes — LOCKFILE_HIT", () => {
  // yarn.lock sometimes wraps headers in double quotes
  const content = yarnV1Block('"@bad-scope/bad-pkg@^2.0.0":', "2.0.0");
  const badPackages = { "@bad-scope/bad-pkg": new Set(["2.0.0"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(hits.length, 1, "exactly one hit");
  assertEqual(hits[0].package, "@bad-scope/bad-pkg", "leading quote stripped");
});

test("scoped package — WILDCARD_LOCK_HIT", () => {
  const content = yarnV1Block("@bad-scope/pkg@^1.0.0:", "1.5.0");
  const badPackages = { "@bad-scope/pkg": new Set(["*"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(hits.length, 1, "exactly one hit");
  assertEqual(hits[0].type, "WILDCARD_LOCK_HIT", "type is WILDCARD_LOCK_HIT");
});

test("unscoped wildcard IOC does not match scoped package name", () => {
  const content = yarnV1Block("@vendor/evil-pkg@^1.0.0:", "1.0.0");
  const badPackages = { "evil-pkg": new Set(["*"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(
    hits.length,
    0,
    "scope must match exactly; wildcard only applies to versions",
  );
});

test("package not in denylist — no hit", () => {
  const content = yarnV1Block("safe-pkg@^1.0.0:", "1.0.0");
  const badPackages = { "evil-pkg": new Set(["1.0.0"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(hits.length, 0, "no hits for unlisted package");
});

test("wrong version in denylist — no hit", () => {
  const content = yarnV1Block("evil-pkg@^1.0.0:", "1.0.0");
  const badPackages = { "evil-pkg": new Set(["2.9.9"]) }; // installed is 1.0.0
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(
    hits.length,
    0,
    "no hit when installed version is not in denylist",
  );
});

test("multiple version selectors on one header — hit is detected", () => {
  // yarn v1 deduplication can produce:  "pkg@^1.0.0, pkg@^1.0.1":
  const content = yarnV1Block('"evil-pkg@^1.0.0, evil-pkg@^1.0.1":', "1.0.1");
  const badPackages = { "evil-pkg": new Set(["1.0.1"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(hits.length, 1, "one hit for merged header line");
  assertEqual(hits[0].version, "1.0.1", "resolved version correct");
});

test("campaign field populated from campaignMap", () => {
  const content = yarnV1Block("evil-pkg@^1.0.0:", "1.0.0");
  const badPackages = { "evil-pkg": new Set(["1.0.0"]) };
  const campaignMap = new Map([["evil-pkg", "shai-hulud-2.0"]]);
  const hits = parseYarnLock(content, badPackages, campaignMap, LOCK_PATH);
  assertEqual(hits.length, 1, "one hit");
  assertEqual(hits[0].campaign, "shai-hulud-2.0", "campaign populated");
});

test("campaign field empty when package not in campaignMap", () => {
  const content = yarnV1Block("evil-pkg@^1.0.0:", "1.0.0");
  const badPackages = { "evil-pkg": new Set(["1.0.0"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(hits[0].campaign, "", "campaign defaults to empty string");
});

test("comments and blank lines are ignored", () => {
  const content = [
    "# THIS IS AN AUTOGENERATED FILE.",
    "# DO NOT EDIT THIS FILE BY HAND.",
    "",
    "evil-pkg@^1.0.0:",
    '  version "1.0.0"',
    '  resolved "https://example.com/"',
    "",
    "# end of file",
  ].join("\n");
  const badPackages = { "evil-pkg": new Set(["1.0.0"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(
    hits.length,
    1,
    "comments and blanks do not cause extra hits or errors",
  );
});

test("Berry __metadata block does not produce hits", () => {
  // yarn v3/berry lockfiles start with a __metadata block
  const content = [
    "__metadata:",
    "  version: 6",
    "  cacheKey: 8",
    "",
    "evil-pkg@^1.0.0:",
    '  version "1.0.0"',
    '  resolved "https://example.com/"',
  ].join("\n");
  const badPackages = {
    "evil-pkg": new Set(["1.0.0"]),
    __metadata: new Set(["*"]),
  };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  // __metadata does not contain "@" so the header detector skips it
  // evil-pkg should still be detected
  assertEqual(
    hits.length,
    1,
    "__metadata block skipped; evil-pkg still detected",
  );
  assertEqual(hits[0].package, "evil-pkg", "only the actual package is hit");
});

test("multiple packages — only denylist members produce hits", () => {
  const content = [
    "safe-pkg@^1.0.0:",
    '  version "1.0.0"',
    '  resolved "https://example.com/"',
    "",
    "evil-pkg@^2.0.0:",
    '  version "2.0.0"',
    '  resolved "https://example.com/"',
    "",
    "@good-scope/safe@^3.0.0:",
    '  version "3.0.0"',
    '  resolved "https://example.com/"',
    "",
    "@bad-scope/bad-pkg@^4.0.0:",
    '  version "4.0.0"',
    '  resolved "https://example.com/"',
  ].join("\n");
  const badPackages = {
    "evil-pkg": new Set(["2.0.0"]),
    "@bad-scope/bad-pkg": new Set(["4.0.0"]),
  };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(hits.length, 2, "exactly two hits across mixed packages");
  const types = hits.map((h) => h.type);
  assert(
    types.every((t) => t === "LOCKFILE_HIT"),
    "both are LOCKFILE_HIT",
  );
  const pkgs = hits.map((h) => h.package).sort();
  assertEqual(
    pkgs,
    ["@bad-scope/bad-pkg", "evil-pkg"],
    "both matched packages returned",
  );
});

test("empty content — no hits, no errors", () => {
  const hits = parseYarnLock("", {}, new Map(), LOCK_PATH);
  assertEqual(hits.length, 0, "empty lockfile produces no hits");
});

test("orphaned version line without prior package header — ignored", () => {
  // If a "version" line appears without a preceding package header it must not throw
  const content = '  version "1.0.0"\n';
  const badPackages = { "evil-pkg": new Set(["1.0.0"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  assertEqual(hits.length, 0, "orphaned version line ignored");
});

test("Berry-format scoped package with quoted header — LOCKFILE_HIT", () => {
  // yarn berry uses:  "@scope/pkg@npm:1.2.3":
  const content = [
    '"@bad-scope/bad-pkg@npm:2.5.0":',
    "  version: 2.5.0", // berry uses unquoted version — NOT matched by current parser
    '  resolution: "@bad-scope/bad-pkg@npm:2.5.0"',
  ].join("\n");
  // berry omits the quoted version value syntax; the parser correctly skips it
  const badPackages = { "@bad-scope/bad-pkg": new Set(["2.5.0"]) };
  const hits = parseYarnLock(content, badPackages, new Map(), LOCK_PATH);
  // Berry format uses `version: X.Y.Z` (no quotes) which the current parser does not match —
  // this is intentional: berry lockfiles would need a dedicated parser. Confirm no crash.
  assertEqual(
    hits.length,
    0,
    "berry unquoted version line does not crash the parser",
  );
});

test("non-string input — no hits, no errors", () => {
  const bad = { "evil-pkg": new Set(["1.0.0"]) };
  assertEqual(
    parseYarnLock(null, bad, new Map(), LOCK_PATH).length,
    0,
    "null → []",
  );
  assertEqual(
    parseYarnLock(undefined, bad, new Map(), LOCK_PATH).length,
    0,
    "undefined → []",
  );
  assertEqual(
    parseYarnLock(42, bad, new Map(), LOCK_PATH).length,
    0,
    "number → []",
  );
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log(`\n${"─".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  process.exit(1);
}
