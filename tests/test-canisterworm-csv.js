"use strict";

/**
 * Tests for parseCanisterWormCSV()
 *
 * Covers:
 *  - Header detection (case-insensitive column names)
 *  - Missing required columns (name/version) → empty result
 *  - Unscoped npm package → keyed by name alone
 *  - Scoped package (namespace present) → keyed as namespace/name
 *  - Ecosystem filtering — non-npm rows are skipped
 *  - Ecosystem column absent — all rows accepted
 *  - Version deduplication — same version twice yields one entry
 *  - Multiple distinct versions for the same package
 *  - Rows with name longer than 214 chars are skipped
 *  - Rows with version longer than 50 chars are skipped
 *  - fullName longer than 214 chars (namespace + name) is skipped
 *  - Quoted fields — quotes stripped correctly
 *  - Blank/empty lines between data rows are ignored
 *  - Only-header content (no data rows) → empty result
 *  - Non-string / falsy input → empty result
 *  - Real-world CanisterWorm CSV format (Ecosystem,Namespace,Name,Version,Published,Detected)
 */

const { parseCanisterWormCSV } = require("../scan");

// ---------------------------------------------------------------------------
// Minimal hand-rolled test harness (same pattern as other test files)
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

/** Build a CSV with the standard CanisterWorm header format. */
function cwCSV(rows) {
  return ["Ecosystem,Namespace,Name,Version,Published,Detected", ...rows].join(
    "\n",
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("non-string input → empty result", () => {
  assertEqual(parseCanisterWormCSV(null), {}, "null → {}");
  assertEqual(parseCanisterWormCSV(undefined), {}, "undefined → {}");
  assertEqual(parseCanisterWormCSV(42), {}, "number → {}");
  assertEqual(parseCanisterWormCSV(""), {}, "empty string → {}");
});

test("only header row (no data) → empty result", () => {
  const csv = "Ecosystem,Namespace,Name,Version,Published,Detected";
  assertEqual(parseCanisterWormCSV(csv), {}, "header-only returns {}");
});

test('missing required "name" column → empty result', () => {
  const csv = "Ecosystem,Version\nnpm,,1.0.0";
  assertEqual(parseCanisterWormCSV(csv), {}, "no name column → {}");
});

test('missing required "version" column → empty result', () => {
  const csv = "Ecosystem,Namespace,Name,Published\nnpm,,evil-pkg,2026-01-01";
  assertEqual(parseCanisterWormCSV(csv), {}, "no version column → {}");
});

test("unscoped npm package — keyed by name alone", () => {
  const csv = cwCSV(["npm,,evil-pkg,1.0.0,2026-01-01,2026-01-01"]);
  const result = parseCanisterWormCSV(csv);
  assertEqual(Object.keys(result).length, 1, "one entry");
  assertEqual(result["evil-pkg"], ["1.0.0"], "keyed by name, version correct");
});

test("scoped package (namespace present) — keyed as @namespace/name", () => {
  const csv = cwCSV(["npm,@bad-scope,bad-pkg,2.0.0,2026-01-01,2026-01-01"]);
  const result = parseCanisterWormCSV(csv);
  assertEqual(
    result["@bad-scope/bad-pkg"],
    ["2.0.0"],
    "scoped name constructed correctly",
  );
});

test("ecosystem filtering — non-npm rows skipped", () => {
  const csv = cwCSV([
    "npm,,npm-evil,1.0.0,2026-01-01,2026-01-01",
    "pypi,,pypi-evil,1.0.0,2026-01-01,2026-01-01",
    "maven,,maven-evil,1.0.0,2026-01-01,2026-01-01",
  ]);
  const result = parseCanisterWormCSV(csv);
  assertEqual(Object.keys(result), ["npm-evil"], "only npm row returned");
});

test("ecosystem filtering — empty ecosystem value treated as npm-compatible (included)", () => {
  // When the ecosystem cell is empty, the guard `if (eco && eco !== "npm")` lets it through
  const csv = cwCSV([",,no-eco-pkg,1.2.3,2026-01-01,2026-01-01"]);
  const result = parseCanisterWormCSV(csv);
  assert("no-eco-pkg" in result, "empty ecosystem row included");
});

test("ecosystem column absent — all rows accepted", () => {
  const csv = "Name,Version\nevil-pkg,1.0.0\nanother-pkg,2.0.0";
  const result = parseCanisterWormCSV(csv);
  assertEqual(
    result["evil-pkg"],
    ["1.0.0"],
    "evil-pkg included without ecosystem column",
  );
  assertEqual(
    result["another-pkg"],
    ["2.0.0"],
    "another-pkg included without ecosystem column",
  );
});

test("version deduplication — same version twice yields one entry", () => {
  const csv = cwCSV([
    "npm,,evil-pkg,1.0.0,2026-01-01,2026-01-01",
    "npm,,evil-pkg,1.0.0,2026-01-02,2026-01-02",
  ]);
  const result = parseCanisterWormCSV(csv);
  assertEqual(result["evil-pkg"], ["1.0.0"], "duplicate version deduped");
});

test("multiple distinct versions for the same package", () => {
  const csv = cwCSV([
    "npm,,evil-pkg,1.0.0,2026-01-01,2026-01-01",
    "npm,,evil-pkg,1.0.1,2026-01-02,2026-01-02",
    "npm,,evil-pkg,2.0.0,2026-01-03,2026-01-03",
  ]);
  const result = parseCanisterWormCSV(csv);
  assertEqual(
    result["evil-pkg"],
    ["1.0.0", "1.0.1", "2.0.0"],
    "all versions collected in order",
  );
});

test("name longer than 214 chars — row skipped", () => {
  const longName = "a".repeat(215);
  const csv = cwCSV([`npm,,${longName},1.0.0,2026-01-01,2026-01-01`]);
  const result = parseCanisterWormCSV(csv);
  assertEqual(result[longName], undefined, "over-long name skipped");
  assertEqual(Object.keys(result).length, 0, "result is empty");
});

test("version longer than 50 chars — row skipped", () => {
  const longVer = "1." + "0".repeat(50);
  const csv = cwCSV([`npm,,evil-pkg,${longVer},2026-01-01,2026-01-01`]);
  const result = parseCanisterWormCSV(csv);
  assertEqual(result["evil-pkg"], undefined, "over-long version skipped");
});

test("fullName (namespace + name) longer than 214 chars — row skipped", () => {
  const ns = "@" + "n".repeat(100);
  const nm = "p".repeat(120); // ns.length + 1 (/) + nm.length = 222 > 214
  const csv = cwCSV([`npm,${ns},${nm},1.0.0,2026-01-01,2026-01-01`]);
  const result = parseCanisterWormCSV(csv);
  assertEqual(Object.keys(result).length, 0, "over-long fullName skipped");
});

test("quoted fields — quotes stripped correctly", () => {
  const csv = cwCSV([
    '"npm","@scope","my-pkg","3.1.4","2026-01-01","2026-01-01"',
  ]);
  const result = parseCanisterWormCSV(csv);
  assertEqual(
    result["@scope/my-pkg"],
    ["3.1.4"],
    "quotes stripped from all fields",
  );
});

test("blank lines between data rows are ignored", () => {
  const csv = [
    "Ecosystem,Namespace,Name,Version,Published,Detected",
    "npm,,pkg-a,1.0.0,2026-01-01,2026-01-01",
    "",
    "   ",
    "npm,,pkg-b,2.0.0,2026-01-02,2026-01-02",
  ].join("\n");
  const result = parseCanisterWormCSV(csv);
  assertEqual(
    Object.keys(result).sort(),
    ["pkg-a", "pkg-b"],
    "both packages parsed, blanks skipped",
  );
});

test("case-insensitive column header matching", () => {
  const csv = [
    "ECOSYSTEM,NAMESPACE,NAME,VERSION,PUBLISHED,DETECTED",
    "npm,,ci-pkg,5.0.0,2026-01-01,2026-01-01",
  ].join("\n");
  const result = parseCanisterWormCSV(csv);
  assertEqual(result["ci-pkg"], ["5.0.0"], "uppercase headers recognized");
});

test("real-world CanisterWorm CSV format — multiple scoped + unscoped packages", () => {
  const csv = [
    "Ecosystem,Namespace,Name,Version,Published,Detected",
    "npm,@emilgroup,insurance-sdk,1.97.6,2026-03-20T23:43:28.951Z,2026-03-20T23:48:19.851Z",
    "npm,@emilgroup,insurance-sdk,1.97.5,2026-03-20T23:15:24.550Z,2026-03-20T23:21:34.109Z",
    "npm,,eslint-config-service-users,0.0.3,2026-03-21T00:23:36.691Z,2026-03-21T00:29:13.530Z",
    "npm,@teale.io,eslint-config,1.8.16,2026-03-20T23:42:55.221Z,2026-03-20T23:47:19.336Z",
    "npm,@teale.io,eslint-config,1.8.15,2026-03-20T23:27:58.704Z,2026-03-20T23:34:38.169Z",
  ].join("\n");

  const result = parseCanisterWormCSV(csv);

  assertEqual(
    result["@emilgroup/insurance-sdk"],
    ["1.97.6", "1.97.5"],
    "scoped package — two versions collected",
  );
  assertEqual(
    result["eslint-config-service-users"],
    ["0.0.3"],
    "unscoped package — version correct",
  );
  assertEqual(
    result["@teale.io/eslint-config"],
    ["1.8.16", "1.8.15"],
    "scoped package with dot in namespace — both versions collected",
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
